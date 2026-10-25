//! Per-core event loop pumping one TUN queue and one steered raw socket through a [`Session`].

use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{AuthKey, OuterFamily};
use crate::faketcp::{Session, Sink};
use crate::sys::{self, RAW_BATCH};

const ROUNDS: usize = 4;
/// Extra slot space beyond `overhead + mss` so incoming frames with IP/TCP options never truncate.
const OPT_HEADROOM: usize = 80;
const MIN_STRIDE: usize = 2048;
const MAX_POLL: Duration = Duration::from_millis(200);

pub struct Reload {
    pub auth_key: AuthKey,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
    pub cpu: Option<usize>,
}

pub struct Control {
    initial_cpu: Option<usize>,
    target_gen: AtomicU64,
    applied_gen: AtomicU64,
    wait_for_established: AtomicBool,
    established: AtomicBool,
    pending: Mutex<Option<(u64, Reload)>>,
}

impl Control {
    pub fn new(initial_cpu: Option<usize>) -> Self {
        Self {
            initial_cpu,
            target_gen: AtomicU64::new(0),
            applied_gen: AtomicU64::new(0),
            wait_for_established: AtomicBool::new(false),
            established: AtomicBool::new(false),
            pending: Mutex::new(None),
        }
    }

    pub fn publish(&self, generation: u64, reload: Reload) {
        *self.pending.lock().expect("reload lock") = Some((generation, reload));
        self.target_gen.store(generation, Ordering::Release);
    }

    pub fn is_step_complete(&self, generation: u64) -> bool {
        self.applied_gen.load(Ordering::Acquire) == generation
            && (!self.wait_for_established.load(Ordering::Acquire)
                || self.established.load(Ordering::Acquire))
    }

    pub fn initial_cpu(&self) -> Option<usize> {
        self.initial_cpu
    }

    pub fn take_reload(&self, applied: u64) -> Option<(u64, Reload)> {
        if self.target_gen.load(Ordering::Acquire) == applied {
            return None;
        }
        self.pending.lock().expect("reload lock").take()
    }

    pub fn report(&self, generation: u64, established: bool, wait: bool) {
        self.wait_for_established.store(wait, Ordering::Release);
        self.established.store(established, Ordering::Release);
        self.applied_gen.store(generation, Ordering::Release);
    }

    pub fn sync(
        &self,
        id: usize,
        cpu: &mut Option<usize>,
        applied_gen: &mut u64,
        now: Instant,
        session: &mut Session,
        out: &mut impl Sink,
    ) {
        let mut new_gen = None;
        if let Some((gen, reload)) = self.take_reload(*applied_gen) {
            if reload.cpu != *cpu {
                *cpu = reload.cpu;
                pin(id, *cpu);
            }
            let prior_wait =
                self.wait_for_established.load(Ordering::Relaxed) && !session.is_established();
            let wait = session.reload(
                now,
                reload.auth_key,
                reload.ping_interval,
                reload.dead_timeout,
                out,
            );
            *applied_gen = gen;
            self.wait_for_established
                .store(wait || prior_wait, Ordering::Release);
            new_gen = Some(gen);
        }
        self.established
            .store(session.is_established(), Ordering::Release);
        if let Some(gen) = new_gen {
            self.applied_gen.store(gen, Ordering::Release);
        }
    }
}

pub fn pin(id: usize, cpu: Option<usize>) {
    if let Some(target) = cpu {
        if let Err(e) = sys::pin_to_cpu(target) {
            log::warn!("worker {id}: cannot pin to CPU: {e}");
        }
    }
}
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
    family: OuterFamily,
    mut session: Session,
    tun: OwnedFd,
    raw: OwnedFd,
    stop: &AtomicBool,
    ctrl: &Control,
) {
    let mut cpu = ctrl.initial_cpu;
    pin(id, cpu);
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
    let mut applied_gen = 0;
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
            continue;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        now = Instant::now();
        let mut tun_ready = fds[0].revents & libc::POLLIN != 0;
        let mut raw_ready = fds[1].revents & libc::POLLIN != 0;
        for _ in 0..ROUNDS {
            if raw_ready {
                raw_ready =
                    match sys::recv_raw_batch(raw.as_fd(), family, &mut bufs, stride, &mut lens) {
                        Ok(m) => {
                            for (k, &n) in lens[..m].iter().enumerate() {
                                if n == 0 {
                                    continue;
                                }
                                let frame = &bufs[k * stride..k * stride + n];
                                if let Some(inner) = session.on_outer(now, frame, &mut out) {
                                    // SAFETY: write(2) of a slice of the stated length.
                                    if unsafe {
                                        libc::write(
                                            tun.as_raw_fd(),
                                            inner.as_ptr().cast(),
                                            inner.len(),
                                        )
                                    } < 0
                                    {
                                        log::debug!(
                                            "worker {id}: tun write: {}",
                                            std::io::Error::last_os_error()
                                        );
                                    } else {
                                        tun_ready = true;
                                    }
                                }
                            }
                            m == RAW_BATCH
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                log::debug!("worker {id}: raw receive: {e}");
                            }
                            false
                        }
                    };
            }
            if tun_ready {
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
                tun_ready = reads == RAW_BATCH;
            }
            if !raw_ready && !tun_ready {
                break;
            }
        }
        busy = raw_ready || tun_ready;
        if now >= session.next_deadline() {
            session.on_tick(now, &mut out);
        }
        ctrl.sync(id, &mut cpu, &mut applied_gen, now, &mut session, &mut out);
    }
    session.shutdown(&mut out);
}
