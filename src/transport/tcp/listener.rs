//! Exit-side accept dispatcher: authenticates bounded candidates and hands them to workers.
//! The dispatcher never owns a TUN queue.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::auth::{self, Handshake};
use super::{BATCH, Connection, invalid};
use crate::config::{Config, MAX_CONNS};
use crate::platform::{self, READ_READY, poll, poll_ms, pollfd};
use crate::transport::control::{self, Admission};

pub const MAX_CANDIDATES: usize = MAX_CONNS;

pub type ExitState = Admission<(usize, Connection)>;

pub type SharedExitState = Arc<Mutex<ExitState>>;

/// Owns listener setup before the accept loop starts.
pub struct Listener {
    listeners: Vec<TcpListener>,
    wake: OwnedFd,
    pub(crate) state: SharedExitState,
    mtu: u16,
    tcp_notsent: u32,
}

impl Listener {
    pub fn bind(cfg: &Config, mtu: u16, main_wake: RawFd) -> io::Result<Self> {
        let mut listeners = Vec::new();
        for &family in cfg.socket_families() {
            let ip = cfg.listen_ip.unwrap_or_else(|| family.unspecified());
            let listener = platform::tcp::listener(
                SocketAddr::new(ip, cfg.listen.unwrap()),
                cfg.iface.as_deref(),
            )?;
            listener.set_nonblocking(true)?;
            listeners.push(listener);
        }
        let wake = platform::eventfd()?;
        let state = Arc::new(Mutex::new(ExitState::new(
            cfg.tunables.auth_key.clone(),
            cfg.tunables.dead_timeout,
            main_wake,
        )));
        Ok(Self {
            listeners,
            wake,
            state,
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
        let mut candidates: Vec<Candidate> = Vec::with_capacity(MAX_CANDIDATES);
        let candidate_offset = self.listeners.len() + 1;
        let mut fds = Vec::with_capacity(MAX_CANDIDATES + candidate_offset);
        while !stop.load(Ordering::Relaxed) {
            // Candidate count is bounded; poll all sockets and listener without per-candidate threads.
            fds.clear();
            for listener in &self.listeners {
                fds.push(pollfd(listener.as_raw_fd(), libc::POLLIN));
            }
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
            platform::poll_wake(fds[self.listeners.len()], self.wake.as_fd());
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            let mut i = 0;
            while i < candidates.len() {
                let expired = now.duration_since(candidates[i].conn.since) >= candidates[i].timeout;
                if fds[i + candidate_offset].revents == 0 && !expired {
                    i += 1;
                    continue;
                }
                match candidates[i].advance(&self.state, self.mtu) {
                    Ok(false) => i += 1,
                    result => {
                        let candidate = candidates.swap_remove(i);
                        fds.swap_remove(i + candidate_offset);
                        let (id, local, peer) = (
                            candidate.identity.map(|v| v.0),
                            candidate.conn.local,
                            candidate.conn.peer,
                        );
                        if let Err(e) = result.and_then(|_| candidate.admit(&self.state, self.mtu))
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
            for (index, listener) in self.listeners.iter().enumerate() {
                if fds[index].revents & READ_READY == 0 {
                    continue;
                }
                // Bound accepts per turn so hostile arrivals cannot starve candidate deadlines.
                for _ in 0..BATCH {
                    match listener.accept() {
                        Ok((socket, peer)) => {
                            if candidates.len() == MAX_CANDIDATES {
                                drop(socket);
                                continue;
                            }
                            match Connection::new(socket, peer, now, self.tcp_notsent) {
                                Ok(conn) => {
                                    let timeout = self.state.lock().unwrap().timeout;
                                    candidates.push(Candidate {
                                        conn,
                                        identity: None,
                                        timeout,
                                    });
                                }
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
    pub(super) fn advance(&mut self, state: &SharedExitState, mtu: u16) -> io::Result<bool> {
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
            let (key, epoch, timeout) = {
                let s = state.lock().unwrap();
                (s.key.clone(), s.epoch, s.timeout)
            };
            let (auth, challenge) = Handshake::exit(&key, mtu, hello)?;
            self.timeout = timeout;
            self.identity = Some((usize::from(p.worker), epoch));
            self.conn.auth = Some(auth);
            self.conn.tx.push(&challenge);
            self.conn.rx.clear();
        }
        self.conn.authenticate(now, self.timeout)
    }

    pub(super) fn admit(mut self, state: &SharedExitState, mtu: u16) -> io::Result<()> {
        let (id, epoch) = self.identity.unwrap();
        let mut s = state.lock().unwrap();
        if s.epoch != epoch {
            return Err(invalid("authentication invalidated by key reload"));
        }
        self.conn.establish(mtu);
        s.admit((id, self.conn));
        Ok(())
    }
}
