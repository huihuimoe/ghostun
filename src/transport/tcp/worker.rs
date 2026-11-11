//! Per-core TCP worker: connects (entry) or adopts dispatched connections (exit) and pumps its TUN queue.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::auth::{Handshake, Params};
use super::connection::TunIo;
use super::{Connection, ROUNDS};
use crate::config::{Config, Mode};
use crate::platform::{self, READ_READY, poll, poll_ms, pollfd};
use crate::transport::control::{self, Backoff};
use crate::transport::tun_driver::TunDriver;

pub struct Worker {
    id: usize,
    cfg: Config,
    remote: Option<SocketAddr>,
    mtu: u16,
    tun: OwnedFd,
    initial: Option<Connection>,
}

impl Worker {
    pub fn new_entry(id: usize, cfg: Config, remote: SocketAddr, mtu: u16, tun: OwnedFd) -> Self {
        Self {
            id,
            cfg,
            remote: Some(remote),
            mtu,
            tun,
            initial: None,
        }
    }

    pub fn new_exit(id: usize, cfg: Config, mtu: u16, tun: OwnedFd, conn: Connection) -> Self {
        Self {
            id,
            cfg,
            remote: None,
            mtu,
            tun,
            initial: Some(conn),
        }
    }

    pub fn run(mut self, stop: &AtomicBool, ctrl: &control::Control) {
        let id = self.id;
        let mut cpu = ctrl.initial_cpu();
        control::pin(id, cpu);
        let mut generation = 0;
        let mut wait = false;
        let mut attached = false;
        let mut connection = self.initial.take();
        if let Some(c) = &connection {
            log::info!("worker {id}: established {c}");
            control::sync_tun_queue(id, self.tun.as_fd(), &mut attached, true);
        }
        let mut retry_at = Instant::now();
        let mut backoff = Backoff::default();
        let mtu = usize::from(self.mtu);
        // Slots are exactly one MTU so read_batch's worst-case room check matches `tx.room(mtu)`;
        // a larger stride would strand the queue between the two bounds and spin the loop.
        let mut tun = TunIo {
            driver: TunDriver::new(self.tun.as_fd(), mtu, 0),
            scratch: vec![0; platform::BATCH * mtu],
            stride: mtu,
            attached,
        };
        let read_allowed = |c: &Option<Connection>| {
            c.as_ref()
                .is_some_and(|c| c.auth.is_none() && c.tx.room(mtu))
        };
        let mut fds = [
            pollfd(-1, 0),
            pollfd(-1, 0),
            pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
            pollfd(-1, 0),
        ];
        while !stop.load(Ordering::Relaxed) && !ctrl.is_stopped() {
            platform::poll_wake(fds[2], ctrl.wake_fd());
            if ctrl.is_stopped() {
                break;
            }
            tun.driver.service(tun.attached, read_allowed(&connection));
            if fds[0].revents & platform::WRITE_READY != 0 {
                tun.driver.flush();
            }
            if let Some((new_gen, reload)) = ctrl.take_reload(generation) {
                wait &= !connection.as_ref().is_some_and(|c| c.auth.is_none());
                if cpu != reload.cpu {
                    cpu = reload.cpu;
                    control::pin(id, cpu);
                }
                if self.cfg.tunables.auth_key != reload.tunables.auth_key {
                    wait |= connection.as_ref().is_some_and(|c| c.auth.is_none());
                    connection = None;
                    tun.driver.reset();
                    fds[1] = pollfd(-1, 0);
                    retry_at = Instant::now();
                }
                self.cfg.tunables = reload.tunables;
                generation = new_gen;
                if self.cfg.mode == Mode::Exit && connection.is_none() {
                    break;
                }
            }
            let mut now = Instant::now();
            if connection.is_none() && self.cfg.mode == Mode::Entry && now >= retry_at {
                let remote = self.remote.expect("entry worker has remote");
                let result =
                    platform::tcp::connect(remote, self.cfg.iface.as_deref()).and_then(|s| {
                        let mut c = Connection::new(s, remote, now, self.cfg.tcp_notsent)?;
                        let (auth, hello) = Handshake::entry(
                            &self.cfg.tunables.auth_key,
                            Params {
                                worker: id as u16,
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
                                    backoff.reset();
                                    log::info!("worker {id}: established {c}");
                                }
                            })
                    } else {
                        Ok(())
                    }
                } else {
                    c.pump_io(
                        &mut tun,
                        self.mtu,
                        now,
                        self.cfg.tunables.ping_interval,
                        self.cfg.tunables.dead_timeout,
                        &fds,
                    )
                    .map(|more| busy = more)
                };
                if let Err(e) = result {
                    let was_established = c.auth.is_none();
                    log::warn!(
                        "worker {id}: {} ({c}): {e}",
                        if was_established {
                            "connection closed"
                        } else {
                            "connection/authentication failure"
                        }
                    );
                    connection = None;
                    // Queued TUN writes and completed reads belong to the dead session.
                    tun.driver.reset();
                    fds[1] = pollfd(-1, 0);
                    if self.cfg.mode == Mode::Entry {
                        retry_at = if was_established {
                            backoff.reset();
                            Instant::now()
                        } else {
                            self.retry(&mut backoff, false)
                        };
                    } else {
                        break;
                    }
                }
            }
            let established = connection.as_ref().is_some_and(|c| c.auth.is_none());
            control::sync_tun_queue(id, self.tun.as_fd(), &mut tun.attached, established);
            ctrl.report(generation, established, wait);
            if !established && (fds[0].revents & READ_READY != 0 || tun.driver.has_reads()) {
                // Discard packets that reached the queue before detach or session loss.
                let mut drained = 0;
                for _ in 0..ROUNDS {
                    let (reads, _) = tun.driver.read_batch(
                        &mut tun.scratch,
                        tun.stride,
                        |_, _| true,
                        |_, _| false,
                    );
                    drained += reads;
                    if reads < platform::BATCH {
                        break;
                    }
                }
                busy |= drained == ROUNDS * platform::BATCH;
            }
            // Arm the multishot read right after a fresh attach; otherwise the ring stays silent
            // until an unrelated socket event or timer wakes the loop.
            tun.driver.service(tun.attached, read_allowed(&connection));
            let polled = tun.driver.read_fd() == self.tun.as_raw_fd();
            let tun_read = if polled { libc::POLLIN } else { 0 };
            let tun_write = if tun.driver.wants_write() {
                libc::POLLOUT
            } else {
                0
            };
            fds = [
                pollfd(self.tun.as_raw_fd(), tun_read | tun_write),
                pollfd(-1, 0),
                pollfd(ctrl.wake_fd().as_raw_fd(), libc::POLLIN),
                pollfd(if polled { -1 } else { tun.driver.read_fd() }, libc::POLLIN),
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
                    fds[0].events &= !libc::POLLIN;
                }
            }
            if stop.load(Ordering::Relaxed) || ctrl.is_stopped() {
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
        let delay = match platform::random(&mut bytes) {
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
