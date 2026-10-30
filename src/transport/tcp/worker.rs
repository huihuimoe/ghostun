//! Per-core TCP worker: connects (entry) or adopts dispatched connections (exit) and pumps its TUN queue.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::auth::{Handshake, Params};
use super::listener::{Listener, Slots};
use super::{can_io, Connection, BATCH, ROUNDS};
use crate::config::{Config, Mode};
use crate::sys::{self, poll, poll_ms, pollfd, READ_READY};
use crate::transport::control;

pub(super) struct Backoff {
    pub(super) failures: u32,
}
impl Backoff {
    pub(super) fn delay(&mut self, sample: u32, stable: bool) -> Duration {
        if stable {
            self.failures = 0;
        }
        let base = [1, 2, 4, 8, 15][self.failures.min(4) as usize];
        self.failures = self.failures.saturating_add(1);
        Duration::from_millis(base * 500 + u64::from(sample) % (base * 500 + 1))
    }
}

pub struct Worker {
    id: usize,
    cfg: Config,
    mtu: u16,
    tun: OwnedFd,
    slots: Option<Slots>,
}

impl Worker {
    pub fn new(
        id: usize,
        cfg: Config,
        mtu: u16,
        tun: OwnedFd,
        listener: Option<&Listener>,
    ) -> Self {
        Self {
            id,
            cfg,
            mtu,
            tun,
            slots: listener.map(|l| Arc::clone(&l.slots)),
        }
    }

    pub fn run(mut self, stop: &AtomicBool, ctrl: &control::Control) {
        let id = self.id;
        let mut cpu = ctrl.initial_cpu();
        control::pin(id, cpu);
        let mut generation = 0;
        let mut wait = false;
        let mut attached = false;
        let mut connection: Option<Connection> = None;
        let mut retry_at = Instant::now();
        let mut backoff = Backoff { failures: 0 };
        let mut packet = vec![0; self.mtu as usize + 1];
        if let Some(slots) = &self.slots {
            slots[id].lock().unwrap().wake = ctrl.wake_fd().as_raw_fd();
        }
        let mut check_slot = true;
        let mut fds = [
            pollfd(-1, 0),
            pollfd(-1, 0),
            pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
        ];
        while !stop.load(Ordering::Relaxed) {
            check_slot |= sys::poll_wake(fds[2], ctrl.wake_fd());
            if let Some((gen, reload)) = ctrl.take_reload(generation) {
                wait &= !connection.as_ref().is_some_and(|c| c.auth.is_none());
                if cpu != reload.cpu {
                    cpu = reload.cpu;
                    control::pin(id, cpu);
                }
                if self.cfg.tunables.auth_key != reload.tunables.auth_key {
                    wait |= connection.as_ref().is_some_and(|c| c.auth.is_none());
                    connection = None;
                    fds[1] = pollfd(-1, 0);
                    retry_at = Instant::now();
                    if let Some(slots) = &self.slots {
                        let mut slot = slots[id].lock().unwrap();
                        slot.key = reload.tunables.auth_key.clone();
                        slot.epoch += 1;
                        slot.pending = None;
                    }
                }
                if let Some(slots) = &self.slots {
                    slots[id].lock().unwrap().timeout = reload.tunables.dead_timeout;
                }
                self.cfg.tunables = reload.tunables;
                generation = gen;
            }
            if check_slot {
                check_slot = false;
                if let Some(slots) = &self.slots {
                    if let Some(new) = slots[id].lock().unwrap().pending.take() {
                        if let Some(old) = &connection {
                            log::info!("worker {id}: authenticated takeover, closing {old}");
                        }
                        log::info!("worker {id}: established {new}");
                        connection = Some(new);
                        fds[1] = pollfd(-1, 0);
                    }
                }
            }
            let mut now = Instant::now();
            if connection.is_none() && self.cfg.mode == Mode::Entry && now >= retry_at {
                let remote = self.cfg.remote.unwrap();
                let result = sys::tcp::connect(remote, self.cfg.iface.as_deref()).and_then(|s| {
                    let mut c = Connection::new(s, remote, now, self.cfg.tcp_notsent)?;
                    let (auth, hello) = Handshake::entry(
                        &self.cfg.tunables.auth_key,
                        Params {
                            worker: id as u16,
                            conns: self.cfg.conns,
                            mtu: self.mtu,
                        },
                    )?;
                    c.auth = Some(auth);
                    c.tx.push(&hello);
                    Ok(c)
                });
                match result {
                    Ok(c) => {
                        connection = Some(c);
                        fds[1] = pollfd(-1, 0);
                    }
                    Err(e) => {
                        log::warn!("worker {id}: connection failure ({remote}): {e}");
                        retry_at = self.retry(&mut backoff, false);
                    }
                }
            }
            let mut busy = false;
            if let Some(c) = connection.as_mut() {
                let result = if c.auth.is_some() {
                    if fds[1].fd < 0
                        || fds[1].revents != 0
                        || now.duration_since(c.since) >= self.cfg.tunables.dead_timeout
                    {
                        c.authenticate(now, self.cfg.tunables.dead_timeout)
                            .map(|ready| {
                                if ready {
                                    c.establish(self.mtu);
                                    log::info!("worker {id}: established {c}");
                                }
                            })
                    } else {
                        Ok(())
                    }
                } else {
                    c.pump_io(
                        &self.tun,
                        self.mtu,
                        now,
                        self.cfg.tunables.ping_interval,
                        self.cfg.tunables.dead_timeout,
                        &fds,
                    )
                    .map(|more| busy = more)
                };
                if let Err(e) = result {
                    let stable =
                        c.auth.is_none() && c.since.elapsed() >= self.cfg.tunables.dead_timeout;
                    log::warn!(
                        "worker {id}: {} ({c}): {e}",
                        if c.auth.is_some() {
                            "connection/authentication failure"
                        } else {
                            "connection closed"
                        }
                    );
                    connection = None;
                    fds[1] = pollfd(-1, 0);
                    if self.cfg.mode == Mode::Entry {
                        retry_at = self.retry(&mut backoff, stable);
                    }
                }
            }
            let established = connection.as_ref().is_some_and(|c| c.auth.is_none());
            control::sync_tun_queue(id, self.tun.as_fd(), &mut attached, established);
            ctrl.report(generation, established, wait);
            if !established && can_io(fds[0], libc::POLLIN, READ_READY) {
                let mut drained = 0;
                while drained < ROUNDS * BATCH {
                    match sys::tun::read(self.tun.as_fd(), &mut packet) {
                        Ok(Some(_)) => drained += 1,
                        Ok(None) => break,
                        Err(e) => {
                            log::error!("worker {id}: TUN read: {e}");
                            return;
                        }
                    }
                }
                busy |= drained == ROUNDS * BATCH;
            }
            fds = [
                pollfd(self.tun.as_raw_fd(), libc::POLLIN),
                pollfd(-1, 0),
                pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
            ];
            if let Some(c) = &connection {
                fds[1] = pollfd(
                    c.socket.as_raw_fd(),
                    if c.tun_pending || c.rx.ready() {
                        0
                    } else {
                        libc::POLLIN
                    } | if c.tx.bytes() > 0 { libc::POLLOUT } else { 0 },
                );
                if established && !c.tx.room(self.mtu as usize) {
                    fds[0].events = 0;
                }
                if c.tun_pending {
                    fds[0].events |= libc::POLLOUT;
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let timeout = if busy {
                0
            } else {
                now = Instant::now();
                match &connection {
                    Some(c) => poll_ms(
                        c.next_deadline(
                            self.cfg.tunables.ping_interval,
                            self.cfg.tunables.dead_timeout,
                        )
                        .saturating_duration_since(now),
                    ),
                    None if self.cfg.mode == Mode::Entry => {
                        poll_ms(retry_at.saturating_duration_since(now))
                    }
                    None => -1,
                }
            };
            if let Err(e) = poll(&mut fds, timeout) {
                log::error!("worker {id}: poll: {e}");
                return;
            }
        }
    }

    fn retry(&self, backoff: &mut Backoff, stable: bool) -> Instant {
        let mut bytes = [0; 4];
        // Failure to obtain retry jitter must not produce a rapid reconnect loop.
        let delay = match sys::random(&mut bytes) {
            Ok(()) => backoff.delay(u32::from_ne_bytes(bytes), stable),
            Err(e) => {
                log::error!("worker {}: retry randomness: {e}", self.id);
                Duration::from_secs(15)
            }
        };
        log::info!("worker {}: retry in {:.3}s", self.id, delay.as_secs_f64());
        Instant::now() + delay
    }
}
