//! Per-core event loop pumping one TUN queue and one steered raw socket through a FakeTCP [`Session`].

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::filter::{entry_filter, exit_filter};
use super::queue::Pending;
use super::session::{Session, SessionConfig, Sink};
use super::tun_driver::TunDriver;
use crate::config::{Config, Mode};
use crate::net::OuterFamily;
use crate::sys::{self, raw};
use crate::transport::control::{self, Control};

#[cfg(test)]
mod tests;

const ROUNDS: usize = 4;
/// Extra slot space beyond `overhead + mss` so incoming frames with IP/TCP options never truncate.
const OPT_HEADROOM: usize = 80;
const MIN_STRIDE: usize = 2048;

struct RawSink<'a> {
    fd: BorrowedFd<'a>,
    sender: raw::Sender,
    pending: Pending<IpAddr>,
}

impl RawSink<'_> {
    fn room(&self, driver: &TunDriver<'_>, bytes: usize, count: usize) -> bool {
        let (reserved_bytes, reserved_slots) = driver.read_budget();
        self.pending
            .room_for(bytes + reserved_bytes, count + reserved_slots)
    }

    fn flush(&mut self) {
        let frames = self
            .pending
            .packets
            .iter()
            .take(raw::BATCH)
            .map(|p| (p.bytes.as_slice(), p.metadata));
        let completed = self.sender.send(self.fd, frames);
        for _ in 0..completed {
            self.pending.pop();
        }
    }

    fn data<'a>(&mut self, frames: impl ExactSizeIterator<Item = (&'a [u8], IpAddr)> + Clone) {
        let completed = if self.pending.packets.is_empty() {
            self.sender.send(self.fd, frames.clone())
        } else {
            0
        };
        for (bytes, dst) in frames.skip(completed) {
            let accepted = self.pending.push(bytes, dst, false);
            debug_assert!(accepted, "TUN reads reserve pending queue capacity");
        }
    }
}

impl Sink for RawSink<'_> {
    fn send(&mut self, frame: &[u8], dst: IpAddr) {
        if self.pending.packets.is_empty() {
            loop {
                match raw::send(self.fd, frame, dst) {
                    Ok(()) => return,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!("send to {dst}: {e}");
                        return;
                    }
                }
            }
        }
        if !self.pending.push(frame, dst, true) {
            log::debug!("raw control queue full; dropping new control packet");
        }
    }

    fn reset(&mut self) {
        self.pending.clear();
    }
}

#[inline]
fn apply_reload(
    ctrl: &Control,
    id: usize,
    cpu: &mut Option<usize>,
    applied_gen: &mut u64,
    now: Instant,
    session: &mut Session,
    out: &mut impl Sink,
) -> bool {
    let mut wait = ctrl.wait_for_established();
    if let Some((gen, reload)) = ctrl.take_reload(*applied_gen) {
        if reload.cpu != *cpu {
            *cpu = reload.cpu;
            control::pin(id, *cpu);
        }
        let prior_wait = wait && !session.is_established();
        wait = session.reload(
            now,
            reload.tunables.auth_key,
            reload.tunables.ping_interval,
            reload.tunables.dead_timeout,
            out,
        ) || prior_wait;
        *applied_gen = gen;
    }
    wait
}

pub struct Worker {
    id: usize,
    family: OuterFamily,
    session: Session,
    tun: OwnedFd,
    raw: OwnedFd,
}

impl Worker {
    /// Opens this worker's steered raw socket and session. Entry binds to `outer_dev`, the
    /// routed egress interface; exit binds to the configured `iface`.
    pub fn new(
        id: usize,
        cfg: &Config,
        local_ip: IpAddr,
        outer_dev: Option<&str>,
        outer_mtu: u32,
        tun: OwnedFd,
        seed: u64,
    ) -> Result<Self, String> {
        let worker = id as u16;
        let listen_port = cfg.listen.unwrap_or(0);
        let filter = match cfg.mode {
            Mode::Entry => entry_filter(
                cfg.remote.expect("validated"),
                cfg.base_port,
                cfg.conns,
                worker,
            ),
            Mode::Exit => exit_filter(
                cfg.outer_family,
                cfg.listen_ip,
                listen_port,
                cfg.conns,
                worker,
            ),
        };
        let bind_dev = match cfg.mode {
            Mode::Entry => outer_dev,
            Mode::Exit => cfg.iface.as_deref(),
        };
        let entry_addresses =
            (cfg.mode == Mode::Entry).then(|| (local_ip, cfg.remote.expect("validated").ip()));
        let raw = raw::socket(cfg.outer_family, bind_dev, &filter, entry_addresses)
            .map_err(|e| format!("raw socket: {e}"))?;
        let mss = (outer_mtu - cfg.outer_family.overhead() as u32) as u16;
        let scfg = SessionConfig::from_config(cfg, local_ip, listen_port, worker, mss);
        let session = Session::new(scfg, Instant::now(), seed ^ (u64::from(worker) << 48))
            .map_err(|e| format!("initializing worker {worker} authentication: {e}"))?;
        Ok(Self {
            id,
            family: cfg.outer_family,
            session,
            tun,
            raw,
        })
    }

    /// Runs until `stop` is set, then resets the outer connection so firewalls free its slot.
    pub fn run(self, stop: &AtomicBool, ctrl: &Control) {
        let Self {
            id,
            family,
            mut session,
            tun,
            raw,
        } = self;
        let mut cpu = ctrl.initial_cpu();
        control::pin(id, cpu);
        let overhead = family.overhead();
        let stride = (overhead + usize::from(session.mss()) + OPT_HEADROOM).max(MIN_STRIDE);
        let mut out = RawSink {
            fd: raw.as_fd(),
            sender: raw::Sender::new(family),
            pending: Pending::default(),
        };
        session.start(Instant::now(), &mut out);
        let mut generation = session.generation();
        let mut driver = TunDriver::new(tun.as_fd(), stride - overhead);
        let mut attached = false;
        let mut rx = raw::Receiver::new(family, stride);
        let mut fds = [
            sys::pollfd(tun.as_raw_fd(), libc::POLLIN),
            sys::pollfd(raw.as_raw_fd(), libc::POLLIN),
            sys::pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
            sys::pollfd(-1, libc::POLLIN),
        ];
        let mut busy = false;
        let mut applied_gen = 0;
        while !stop.load(Ordering::Relaxed) {
            fds[3].fd = if driver.read_fd() == tun.as_raw_fd() {
                -1
            } else {
                driver.read_fd()
            };
            fds[0].events = if fds[3].fd == -1 && out.room(&driver, stride, 1) {
                libc::POLLIN
            } else {
                0
            } | if driver.wants_write() {
                libc::POLLOUT
            } else {
                0
            };
            fds[1].events = libc::POLLIN
                | if out.pending.packets.is_empty() {
                    0
                } else {
                    libc::POLLOUT
                };
            let timeout = if busy || (driver.has_reads() && out.room(&driver, stride, 1)) {
                0
            } else {
                sys::poll_ms(
                    session
                        .next_deadline()
                        .saturating_duration_since(Instant::now()),
                )
            };
            match sys::poll(&mut fds, timeout) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    log::error!("worker {id}: poll: {e}");
                    break;
                }
            }
            sys::poll_wake(fds[2], ctrl.wake_fd());
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            let read_allowed = out.room(&driver, stride, 1);
            driver.service(attached, read_allowed);
            if fds[1].revents & sys::WRITE_READY != 0 {
                out.flush();
            }
            if fds[0].revents & sys::WRITE_READY != 0 {
                driver.flush();
            }
            let mut tun_ready = (fds[0].revents & libc::POLLIN != 0 || driver.has_reads())
                && out.room(&driver, stride, 1);
            let mut raw_ready = fds[1].revents & libc::POLLIN != 0;
            for _ in 0..ROUNDS {
                if raw_ready {
                    raw_ready = match rx.receive(raw.as_fd()) {
                        Ok(m) => {
                            for k in 0..m {
                                let n = rx.lens[k];
                                if n == 0 {
                                    continue;
                                }
                                let frame = &rx.buffers()[k * stride..k * stride + n];
                                let inner = session.on_outer(now, frame, &mut out);
                                if generation != session.generation() {
                                    driver.reset();
                                    generation = session.generation();
                                }
                                if let Some(inner) = inner {
                                    if !driver.write(inner) {
                                        log::debug!(
                                            "worker {id}: TUN queue full; dropping new data packet"
                                        );
                                    }
                                }
                            }
                            m == raw::BATCH
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                log::debug!("worker {id}: raw receive: {e}");
                            }
                            false
                        }
                    };
                }
                if tun_ready && out.room(&driver, stride, 1) {
                    let mut reads = 0;
                    let mut count = 0;
                    let mut bytes = 0;
                    let mut batch_dst = None;
                    while reads < raw::BATCH && out.room(&driver, bytes + stride, count + 1) {
                        let slot = &mut rx.buffers_mut()[count * stride..(count + 1) * stride];
                        let Ok(Some(n)) = driver.read(&mut slot[overhead..]) else {
                            break;
                        };
                        reads += 1;
                        if let Some((len, dst)) = session.encap(slot, n) {
                            rx.lens[count] = len;
                            bytes += len;
                            batch_dst = Some(dst);
                            count += 1;
                        }
                    }
                    if let Some(dst) = batch_dst {
                        out.data(
                            rx.lens[..count]
                                .iter()
                                .enumerate()
                                .map(|(k, &n)| (&rx.buffers()[k * stride..k * stride + n], dst)),
                        );
                    }
                    tun_ready = reads == raw::BATCH && out.room(&driver, stride, 1);
                } else {
                    tun_ready = false;
                }
                if !raw_ready && !tun_ready {
                    break;
                }
            }
            busy = raw_ready || tun_ready;
            if now >= session.next_deadline() {
                session.on_tick(now, &mut out);
            }
            let wait = apply_reload(
                ctrl,
                id,
                &mut cpu,
                &mut applied_gen,
                now,
                &mut session,
                &mut out,
            );
            if generation != session.generation() {
                driver.reset();
                generation = session.generation();
            }
            let established = session.is_established();
            control::sync_tun_queue(id, tun.as_fd(), &mut attached, established);
            let read_allowed = out.room(&driver, stride, 1);
            driver.service(attached, read_allowed);
            ctrl.report(applied_gen, established, wait);
        }
        session.shutdown(&mut out);
        out.flush();
    }
}
