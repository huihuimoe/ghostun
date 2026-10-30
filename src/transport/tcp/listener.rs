//! Exit-side accept dispatcher: authenticates bounded candidates and hands them to workers.
//! The dispatcher never owns a TUN queue.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::auth::{self, Handshake, Params};
use super::{invalid, Connection, BATCH};
use crate::config::{AuthKey, Config};
use crate::sys::{self, poll, poll_ms, pollfd, READ_READY};
use crate::transport::control;

pub(super) struct Slot {
    pub(super) key: AuthKey,
    pub(super) epoch: u64,
    pub(super) timeout: Duration,
    pub(super) pending: Option<Connection>,
    pub(super) wake: RawFd,
}

pub(super) type Slots = Arc<Vec<Mutex<Slot>>>;

/// Owns listener setup before any workers start.
pub struct Listener {
    listener: TcpListener,
    wake: OwnedFd,
    pub(super) slots: Slots,
    mtu: u16,
    tcp_notsent: u32,
}

impl Listener {
    pub fn bind(cfg: &Config, mtu: u16) -> io::Result<Self> {
        // Explicit IPV6_V6ONLY keeps one selected outer family per instance.
        let listener = sys::tcp::listener(
            SocketAddr::new(cfg.exit_ip(), cfg.listen.unwrap()),
            cfg.iface.as_deref(),
        )?;
        listener.set_nonblocking(true)?;
        let wake = sys::eventfd()?;
        let slots = Arc::new(
            (0..cfg.conns)
                .map(|_| {
                    Mutex::new(Slot {
                        key: cfg.tunables.auth_key.clone(),
                        epoch: 0,
                        timeout: cfg.tunables.dead_timeout,
                        pending: None,
                        wake: -1,
                    })
                })
                .collect(),
        );
        Ok(Self {
            listener,
            wake,
            slots,
            mtu,
            tcp_notsent: cfg.tcp_notsent,
        })
    }

    pub fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    pub fn spawn(
        self,
        stop: &'static AtomicBool,
        main_wake: RawFd,
    ) -> io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name("ghostun-tcp-accept".into())
            .spawn(move || {
                let _guard = control::StopOnDrop(stop, main_wake);
                self.run(stop);
            })
    }

    fn run(self, stop: &AtomicBool) {
        let cap = (2 * self.slots.len()).min(256);
        let mut candidates: Vec<Candidate> = Vec::with_capacity(cap);
        let mut fds = Vec::with_capacity(cap + 2);
        while !stop.load(Ordering::Relaxed) {
            // Candidate count is bounded; poll all sockets and listener without per-candidate threads.
            fds.clear();
            fds.push(pollfd(self.listener.as_raw_fd(), libc::POLLIN));
            fds.push(pollfd(self.wake.as_raw_fd(), libc::POLLIN));
            for c in &candidates {
                fds.push(pollfd(
                    c.conn.socket.as_raw_fd(),
                    libc::POLLIN
                        | if c.conn.tx.bytes() > 0 {
                            libc::POLLOUT
                        } else {
                            0
                        },
                ));
            }
            let now = Instant::now();
            let timeout = candidates
                .iter()
                .map(|c| (c.conn.since + c.timeout).saturating_duration_since(now))
                .min()
                .map_or(-1, poll_ms);
            if let Err(e) = poll(&mut fds, timeout) {
                log::error!("accept poll: {e}");
                return;
            }
            sys::poll_wake(fds[1], self.wake.as_fd());
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            let mut i = 0;
            while i < candidates.len() {
                let expired = now.duration_since(candidates[i].conn.since) >= candidates[i].timeout;
                if fds[i + 2].revents == 0 && !expired {
                    i += 1;
                    continue;
                }
                match candidates[i].advance(&self.slots, self.mtu) {
                    Ok(false) => i += 1,
                    result => {
                        let candidate = candidates.swap_remove(i);
                        fds.swap_remove(i + 2);
                        let (id, local, peer) = (
                            candidate.identity.map(|v| v.0),
                            candidate.conn.local,
                            candidate.conn.peer,
                        );
                        if let Err(e) = result.and_then(|_| candidate.admit(&self.slots, self.mtu))
                        {
                            match id {
                                Some(id) => log::debug!(
                                    "worker {id}: candidate rejected ({local} <-> {peer}): {e}"
                                ),
                                None => {
                                    log::debug!("candidate rejected ({local} <-> {peer}): {e}")
                                }
                            }
                        }
                    }
                }
            }
            if fds[0].revents & READ_READY != 0 {
                // Bound accepts per turn so hostile arrivals cannot starve candidate deadlines.
                for _ in 0..BATCH {
                    match self.listener.accept() {
                        Ok((socket, peer)) => {
                            if candidates.len() == cap {
                                drop(socket);
                                continue;
                            }
                            match Connection::new(socket, peer, now, self.tcp_notsent) {
                                Ok(conn) => candidates.push(Candidate {
                                    conn,
                                    identity: None,
                                    timeout: self.slots[0].lock().unwrap().timeout,
                                }),
                                Err(e) => log::debug!("candidate setup ({peer}): {e}"),
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            log::error!("accept: {e}");
                            return;
                        }
                    }
                }
            }
        }
    }
}

pub(super) struct Candidate {
    pub(super) conn: Connection,
    pub(super) identity: Option<(usize, u64)>,
    pub(super) timeout: Duration,
}

impl Candidate {
    pub(super) fn advance(&mut self, slots: &Slots, mtu: u16) -> io::Result<bool> {
        let now = Instant::now();
        if now.duration_since(self.conn.since) >= self.timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "candidate authentication timeout",
            ));
        }
        if self.identity.is_none() {
            if !self.conn.rx.read(&mut self.conn.socket)? {
                return Ok(false);
            }
            let hello = self.conn.rx.payload();
            let p = auth::hello_params(hello)?;
            let slot = slots
                .get(p.worker as usize)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid worker ID {} (conns={})", p.worker, slots.len()),
                    )
                })?
                .lock()
                .unwrap();
            self.timeout = slot.timeout;
            self.identity = Some((p.worker as usize, slot.epoch));
            let (auth, challenge) = Handshake::exit(
                &slot.key,
                Params {
                    worker: p.worker,
                    conns: slots.len() as u16,
                    mtu,
                },
                hello,
            )?;
            self.conn.auth = Some(auth);
            self.conn.tx.push(&challenge);
            self.conn.rx.clear();
        }
        self.conn.authenticate(now, self.timeout)
    }

    pub(super) fn admit(mut self, slots: &Slots, mtu: u16) -> io::Result<()> {
        let (id, epoch) = self.identity.unwrap();
        let wake = {
            let mut slot = slots[id].lock().unwrap();
            if slot.epoch != epoch {
                return Err(invalid("authentication invalidated by key reload"));
            }
            self.conn.establish(mtu);
            slot.pending = Some(self.conn);
            slot.wake
        };
        sys::eventfd_notify(wake);
        Ok(())
    }
}
