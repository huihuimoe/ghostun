//! Per-core event loop pumping one TUN queue and one steered raw socket through a [`Session`].

use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::OuterFamily;
use crate::session::{Session, Sink};
use crate::sys;

const BATCH: usize = 256;
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
    let mut out = RawSink(raw.as_fd());
    session.start(Instant::now(), &mut out);

    // Reserve the selected outer headers so TUN payloads never need to be moved.
    let mut buf = vec![0u8; overhead + 65535];
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
            for i in 0..BATCH {
                let Some(n) = read(tun.as_fd(), &mut buf[overhead..]) else {
                    break;
                };
                if let Some((len, dst)) = session.encap(&mut buf, n) {
                    out.send(&buf[..len], dst);
                }
                busy |= i + 1 == BATCH;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            for i in 0..BATCH {
                let n = match sys::recv_raw(raw.as_fd(), family, &mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!("worker {id}: raw receive: {e}");
                        break;
                    }
                };
                if let Some(inner) = session.on_outer(now, &buf[..n], &mut out) {
                    // SAFETY: write(2) of a slice of the stated length.
                    if unsafe { libc::write(tun.as_raw_fd(), inner.as_ptr().cast(), inner.len()) }
                        < 0
                    {
                        log::debug!(
                            "worker {id}: tun write: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
                busy |= i + 1 == BATCH;
            }
        }
        if now >= session.next_deadline() {
            session.on_tick(now, &mut out);
        }
    }
    session.shutdown(&mut out);
}
