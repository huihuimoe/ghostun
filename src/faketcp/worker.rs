//! Per-core event loop pumping one TUN queue and one steered raw socket through a FakeTCP [`Session`].

use std::io;
use std::net::IpAddr;

use super::queue::Pending;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::config::OuterFamily;
use crate::faketcp::{Session, Sink};
use crate::sys::{self, RAW_BATCH};
use crate::worker::{self, Control};

const ROUNDS: usize = 4;
/// Extra slot space beyond `overhead + mss` so incoming frames with IP/TCP options never truncate.
const OPT_HEADROOM: usize = 80;
const MIN_STRIDE: usize = 2048;

struct RawSink<'a> {
    fd: BorrowedFd<'a>,
    sender: sys::RawSender,
    pending: Pending<IpAddr>,
}

impl RawSink<'_> {
    fn flush(&mut self) {
        let frames = self
            .pending
            .packets
            .iter()
            .take(RAW_BATCH)
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
                match sys::send_raw(self.fd, frame, dst) {
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

fn write_tun(fd: BorrowedFd<'_>, packet: &[u8]) -> bool {
    match sys::tun_write(fd, packet) {
        Ok(done) => done,
        Err(e) => {
            log::debug!("TUN write: {e}; dropping packet");
            true
        }
    }
}

fn flush_tun(fd: BorrowedFd<'_>, pending: &mut Pending<()>) {
    for _ in 0..RAW_BATCH {
        let Some(packet) = pending.packets.front() else {
            break;
        };
        if !write_tun(fd, &packet.bytes) {
            break;
        }
        pending.pop();
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
            worker::pin(id, *cpu);
        }
        let prior_wait = wait && !session.is_established();
        wait = session.reload(
            now,
            reload.auth_key,
            reload.ping_interval,
            reload.dead_timeout,
            out,
        ) || prior_wait;
        *applied_gen = gen;
    }
    wait
}

#[cfg(test)]
pub fn sync_reload(
    ctrl: &Control,
    id: usize,
    cpu: &mut Option<usize>,
    applied_gen: &mut u64,
    now: Instant,
    session: &mut Session,
    out: &mut impl Sink,
) {
    let wait = apply_reload(ctrl, id, cpu, applied_gen, now, session, out);
    ctrl.report(*applied_gen, session.is_established(), wait);
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
    let mut cpu = ctrl.initial_cpu();
    worker::pin(id, cpu);
    let overhead = family.overhead();
    let stride = (overhead + usize::from(session.mss()) + OPT_HEADROOM).max(MIN_STRIDE);
    let mut out = RawSink {
        fd: raw.as_fd(),
        sender: sys::RawSender::new(family),
        pending: Pending::default(),
    };
    session.start(Instant::now(), &mut out);
    let mut generation = session.generation();
    let mut tun_pending = Pending::default();
    let mut attached = false;
    let mut rx = sys::RawReceiver::new(family, stride);
    let mut fds = [
        sys::pollfd(tun.as_raw_fd(), libc::POLLIN),
        sys::pollfd(raw.as_raw_fd(), libc::POLLIN),
        sys::pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
    ];
    let mut busy = false;
    let mut applied_gen = 0;
    while !stop.load(Ordering::Relaxed) {
        fds[0].events = if out.pending.room(stride) {
            libc::POLLIN
        } else {
            0
        } | if tun_pending.packets.is_empty() {
            0
        } else {
            libc::POLLOUT
        };
        fds[1].events = libc::POLLIN
            | if out.pending.packets.is_empty() {
                0
            } else {
                libc::POLLOUT
            };
        let timeout = if busy {
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
        if fds[1].revents & sys::WRITE_READY != 0 {
            out.flush();
        }
        if fds[0].revents & sys::WRITE_READY != 0 {
            flush_tun(tun.as_fd(), &mut tun_pending);
        }
        let mut tun_ready = fds[0].revents & libc::POLLIN != 0 && out.pending.room(stride);
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
                                tun_pending.clear();
                                generation = session.generation();
                            }
                            if let Some(inner) = inner {
                                if !(tun_pending.packets.is_empty()
                                    && write_tun(tun.as_fd(), inner))
                                    && !tun_pending.push(inner, (), false)
                                {
                                    log::debug!(
                                        "worker {id}: TUN queue full; dropping new data packet"
                                    );
                                }
                            }
                        }
                        m == RAW_BATCH
                    }
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            log::debug!("worker {id}: raw receive: {e}");
                        }
                        false
                    }
                };
            }
            if tun_ready && out.pending.room(stride) {
                let mut reads = 0;
                let mut count = 0;
                let mut bytes = 0;
                let mut batch_dst = None;
                while reads < RAW_BATCH && out.pending.room_for(bytes + stride, count + 1) {
                    let slot = &mut rx.buffers_mut()[count * stride..(count + 1) * stride];
                    let Ok(Some(n)) = sys::tun_read(tun.as_fd(), &mut slot[overhead..]) else {
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
                tun_ready = reads == RAW_BATCH && out.pending.room(stride);
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
            tun_pending.clear();
            generation = session.generation();
        }
        let established = session.is_established();
        worker::sync_tun_queue(id, tun.as_fd(), &mut attached, established);
        ctrl.report(applied_gen, established, wait);
    }
    out.reset();
    session.shutdown(&mut out);
    out.flush();
}
