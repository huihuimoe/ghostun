//! Per-core TCP worker: connects (entry) or adopts dispatched connections (exit) and pumps its TUN queue.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::auth::{Handshake, Params};
use super::connection::{Ready, TunIo};
use super::{Connection, ROUNDS};
use crate::config::{Config, Mode};
use crate::platform::{self, Interest, Poller, TunDriver, TunQueue};
use crate::transport::control::{self, Backoff};

pub struct Worker {
    id: usize,
    cfg: Config,
    remote: Option<SocketAddr>,
    mtu: u16,
    tun: TunQueue,
    initial: Option<Connection>,
}

impl Worker {
    pub fn new_entry(id: usize, cfg: Config, remote: SocketAddr, mtu: u16, tun: TunQueue) -> Self {
        Self {
            id,
            cfg,
            remote: Some(remote),
            mtu,
            tun,
            initial: None,
        }
    }

    pub fn new_exit(id: usize, cfg: Config, mtu: u16, tun: TunQueue, conn: Connection) -> Self {
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
            control::sync_tun_queue(id, &self.tun, &mut attached, true);
        }
        let mut retry_at = Instant::now();
        let mut backoff = Backoff::default();
        let mtu = usize::from(self.mtu);
        // Slots are exactly one MTU so read_batch's worst-case room check matches `tx.room(mtu)`;
        // a larger stride would strand the queue between the two bounds and spin the loop.
        let mut tun = TunIo {
            driver: TunDriver::new(&self.tun, mtu, 0),
            scratch: vec![0; platform::BATCH * mtu],
            stride: mtu,
            attached,
        };
        let read_allowed = |c: &Option<Connection>| {
            c.as_ref()
                .is_some_and(|c| c.auth.is_none() && c.tx.room(mtu))
        };
        let mut poller = Poller::default();
        let tun_slot = poller.reserve();
        let socket_slot = poller.reserve();
        let wake_slot = poller.add(ctrl.waker(), Interest::READ);
        let ring_slot = poller.reserve();
        while !stop.load(Ordering::Relaxed) && !ctrl.is_stopped() {
            poller.woken(wake_slot, ctrl.waker());
            if ctrl.is_stopped() {
                break;
            }
            tun.driver.service(tun.attached, read_allowed(&connection));
            if poller.write_ready(tun_slot) {
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
                    poller.unbind(socket_slot);
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
                        poller.unbind(socket_slot);
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
                    if !poller.is_bound(socket_slot)
                        || poller.fired(socket_slot)
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
                        Ready {
                            tun: poller.read_ready(tun_slot),
                            socket_read: poller.can_read(socket_slot),
                            socket_write: poller.can_write(socket_slot),
                        },
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
                    poller.unbind(socket_slot);
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
            control::sync_tun_queue(id, &self.tun, &mut tun.attached, established);
            ctrl.report(generation, established, wait);
            if !established && (poller.read_ready(tun_slot) || tun.driver.has_reads()) {
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
            let polled = tun.driver.bind_ring(&mut poller, ring_slot);
            let mut tun_read = polled;
            match &connection {
                Some(c) => {
                    poller.bind(
                        socket_slot,
                        &c.socket,
                        Interest::READ.when(!c.tun_pending && !c.rx.ready())
                            | Interest::WRITE.when(c.tx.bytes() > 0),
                    );
                    tun_read &= !established || c.tx.room(mtu);
                }
                None => poller.unbind(socket_slot),
            }
            poller.bind(
                tun_slot,
                &self.tun,
                Interest::READ.when(tun_read) | Interest::WRITE.when(tun.driver.wants_write()),
            );
            if stop.load(Ordering::Relaxed) || ctrl.is_stopped() {
                break;
            }
            let timeout = if busy {
                Some(Duration::ZERO)
            } else {
                now = Instant::now();
                match &connection {
                    Some(c) => Some(
                        c.next_deadline(
                            self.cfg.tunables.ping_interval,
                            self.cfg.tunables.dead_timeout,
                        )
                        .saturating_duration_since(now),
                    ),
                    None if self.cfg.mode == Mode::Entry => {
                        Some(retry_at.saturating_duration_since(now))
                    }
                    None => None,
                }
            };
            if let Err(e) = poller.wait(timeout) {
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
