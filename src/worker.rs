//! Per-core event loop pumping one TUN queue and one steered raw socket through a [`Session`].

use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::OuterFamily;
use crate::session::{Session, Sink};
use crate::sys::{self, RAW_BATCH};

const ROUNDS: usize = 4;
/// Extra slot space beyond `overhead + mss` so incoming frames with IP/TCP options never truncate.
const OPT_HEADROOM: usize = 80;
const MIN_STRIDE: usize = 2048;
const MAX_POLL: Duration = Duration::from_millis(200);

struct RawSink<'a>(BorrowedFd<'a>);

impl Sink for RawSink<'_> {
    fn send(&mut self, frame: &[u8], dst: IpAddr) {
        if let Err(e) = sys::send_raw(self.0, frame, dst) {
            log::debug!("send to {dst}: {e}");
        }
    }
}

fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: read(2) into a buffer of the stated length.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    (n > 0).then_some(n as usize)
}

/// Runs until `stop` is set, then resets the outer connection so firewalls free its slot.
pub fn run(
    id: usize,
    cpu: Option<usize>,
    family: OuterFamily,
    mut session: Session,
    tun: OwnedFd,
    raw: OwnedFd,
    stop: &AtomicBool,
) {
    if let Err(e) = sys::pin_to_cpu(id, cpu) {
        log::warn!("worker {id}: cannot pin to CPU: {e}");
    }
    let overhead = family.overhead();
    let stride = (overhead + usize::from(session.mss()) + OPT_HEADROOM).max(MIN_STRIDE);
    let mut out = RawSink(raw.as_fd());
    session.start(Instant::now(), &mut out);

    // Reserve the selected outer headers in each slot so TUN payloads never need to be moved.
    let mut bufs = vec![0u8; RAW_BATCH * stride];
    let mut lens = [0usize; RAW_BATCH];
    let mut fds = [
        libc::pollfd {
            fd: tun.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: raw.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut now = Instant::now();
    let mut busy = false;
    while !stop.load(Ordering::Relaxed) {
        let timeout = if busy {
            0
        } else {
            let wait = session
                .next_deadline()
                .saturating_duration_since(now)
                .min(MAX_POLL);
            // Round up so we never wake just before a deadline and spin.
            wait.as_micros().div_ceil(1000) as libc::c_int
        };
        // SAFETY: fds is a valid array of two pollfd.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                log::error!("worker {id}: poll: {e}");
                break;
            }
        }
        now = Instant::now();
        busy = false;
        if fds[0].revents & libc::POLLIN != 0 {
            for round in 0..ROUNDS {
                let mut reads = 0;
                let mut count = 0;
                let mut batch_dst = None;
                while reads < RAW_BATCH {
                    let slot = &mut bufs[count * stride..(count + 1) * stride];
                    let Some(n) = read(tun.as_fd(), &mut slot[overhead..]) else {
                        break;
                    };
                    reads += 1;
                    if let Some((len, dst)) = session.encap(slot, n) {
                        lens[count] = len;
                        batch_dst = Some(dst);
                        count += 1;
                    }
                }
                if let Some(dst) = batch_dst {
                    if let Err(e) =
                        sys::send_raw_batch(raw.as_fd(), &bufs, stride, &lens[..count], dst)
                    {
                        log::debug!("worker {id}: send to {dst}: {e}");
                    }
                }
                if reads < RAW_BATCH {
                    break;
                }
                busy |= round + 1 == ROUNDS;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            for round in 0..ROUNDS {
                let m = match sys::recv_raw_batch(raw.as_fd(), family, &mut bufs, stride, &mut lens)
                {
                    Ok(m) => m,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!("worker {id}: raw receive: {e}");
                        break;
                    }
                };
                for (k, &n) in lens[..m].iter().enumerate() {
                    if n == 0 {
                        continue;
                    }
                    let frame = &bufs[k * stride..k * stride + n];
                    if let Some(inner) = session.on_outer(now, frame, &mut out) {
                        // SAFETY: write(2) of a slice of the stated length.
                        if unsafe {
                            libc::write(tun.as_raw_fd(), inner.as_ptr().cast(), inner.len())
                        } < 0
                        {
                            log::debug!(
                                "worker {id}: tun write: {}",
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                }
                if m < RAW_BATCH {
                    break;
                }
                busy |= round + 1 == ROUNDS;
            }
        }
        if now >= session.next_deadline() {
            session.on_tick(now, &mut out);
        }
    }
    session.shutdown(&mut out);
}
