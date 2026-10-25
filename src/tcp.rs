//! Kernel TCP workers and bounded candidate dispatch; no raw-socket or port steering.
#[cfg(test)]
mod tests;
mod wire;

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{AuthKey, Config, Mode};
use crate::{sys, worker};
use wire::{invalid, Handshake, Params, Receive, SendQueue, AUTH_MAX, PING, PONG};

struct Connection {
    socket: TcpStream,
    connecting: bool,
    rx: Receive,
    tx: SendQueue,
    auth: Option<Handshake>,
    since: Instant,
    last_rx: Instant,
    last_ping: Instant,
    tun_pending: bool,
}

impl Connection {
    fn new(socket: TcpStream, now: Instant) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        Ok(Self {
            socket,
            connecting: false,
            rx: Receive::new(AUTH_MAX),
            tx: SendQueue::default(),
            auth: None,
            since: now,
            last_rx: now,
            last_ping: now,
            tun_pending: false,
        })
    }

    fn authenticate(&mut self, now: Instant, timeout: Duration) -> io::Result<bool> {
        if now.duration_since(self.since) >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "authentication/connection attempt timeout",
            ));
        }
        if self.connecting {
            let mut fds = [pollfd(self.socket.as_raw_fd(), libc::POLLOUT)];
            poll(&mut fds, 0)?;
            if fds[0].revents == 0 {
                return Ok(false);
            }
            if let Some(e) = self.socket.take_error()? {
                return Err(e);
            }
            self.connecting = false;
        }
        self.tx.flush(&mut self.socket)?;
        let auth = self.auth.as_mut().expect("handshake initialized");
        if auth.done() {
            return Ok(self.tx.bytes == 0);
        }
        if self.rx.read(&mut self.socket)? {
            if let Some(reply) = auth.receive(self.rx.payload())? {
                self.tx.push(&reply);
            }
            self.rx.clear();
        }
        self.tx.flush(&mut self.socket)?;
        Ok(auth.done() && self.tx.bytes == 0)
    }

    fn establish(&mut self, mtu: u16) {
        self.auth = None;
        self.rx = Receive::new(mtu as usize);
        self.since = Instant::now();
        self.last_rx = self.since;
        self.last_ping = self.since;
    }

    fn pump(
        &mut self,
        tun: &OwnedFd,
        packet: &mut [u8],
        ping: Duration,
        dead: Duration,
    ) -> io::Result<()> {
        let mtu = packet.len() - 1;
        let now = Instant::now();
        if now.duration_since(self.last_rx) >= dead {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer liveness timeout",
            ));
        }
        self.tx.flush(&mut self.socket)?;
        for _ in 0..64 {
            if self.tun_pending {
                if !tun_write(tun, self.rx.payload())? {
                    break;
                }
                self.rx.clear();
                self.tun_pending = false;
            }
            if !self.rx.read(&mut self.socket)? {
                break;
            }
            let p = self.rx.payload();
            if p.len() == 9 && matches!(p[0], PING | PONG) {
                if p[0] == PING {
                    if !self.tx.room(9) {
                        break;
                    }
                    let mut pong: [u8; 9] = p.try_into().unwrap();
                    pong[0] = PONG;
                    self.tx.push(&pong);
                }
                self.rx.clear();
            } else {
                wire::validate_packet(p, mtu)?;
                self.tun_pending = true;
            }
            self.last_rx = now;
        }
        for _ in 0..64 {
            if !self.tx.room(mtu) {
                break;
            }
            let Some(n) = tun_read(tun, packet)? else {
                break;
            };
            wire::validate_packet(&packet[..n], mtu)?;
            self.tx.push(&packet[..n]);
        }
        if now.duration_since(self.last_ping) >= ping && self.tx.room(9) {
            let mut msg = [PING; 9];
            wire::random(&mut msg[1..])?;
            self.tx.push(&msg);
            self.last_ping = now;
        }
        self.tx.flush(&mut self.socket)
    }
}

fn tun_read(tun: &OwnedFd, buf: &mut [u8]) -> io::Result<Option<usize>> {
    // SAFETY: valid nonblocking descriptor and writable buffer of the supplied length.
    let n = unsafe { libc::read(tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            Ok(None)
        } else {
            Err(e)
        }
    } else if n == 0 {
        Err(io::ErrorKind::UnexpectedEof.into())
    } else {
        Ok(Some(n as usize))
    }
}

fn tun_write(tun: &OwnedFd, packet: &[u8]) -> io::Result<bool> {
    // SAFETY: valid descriptor and readable packet slice. TUN writes preserve packet boundaries.
    let n = unsafe { libc::write(tun.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
    if n == packet.len() as isize {
        return Ok(true);
    }
    if n >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short TUN packet write",
        ));
    }
    let e = io::Error::last_os_error();
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(false)
    } else {
        Err(e)
    }
}

struct Slot {
    key: AuthKey,
    epoch: u64,
    timeout: Duration,
    pending: Option<Connection>,
}

type Slots = Arc<Vec<Mutex<Slot>>>;

/// Owns listener setup before any workers start. The dispatcher never owns a TUN queue.
pub struct Listener {
    listener: TcpListener,
    slots: Slots,
    mtu: u16,
}

impl Listener {
    pub fn bind(cfg: &Config, mtu: u16) -> io::Result<Self> {
        // Explicit IPV6_V6ONLY keeps one selected outer family per instance.
        let listener = sys::tcp_listener(SocketAddr::new(
            cfg.outer_family.unspecified(),
            cfg.listen.unwrap(),
        ))?;
        listener.set_nonblocking(true)?;
        let slots = Arc::new(
            (0..cfg.conns)
                .map(|_| {
                    Mutex::new(Slot {
                        key: cfg.auth_key.clone(),
                        epoch: 0,
                        timeout: cfg.dead_timeout,
                        pending: None,
                    })
                })
                .collect(),
        );
        Ok(Self {
            listener,
            slots,
            mtu,
        })
    }

    pub fn spawn(self, stop: &'static AtomicBool) -> io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name("ghostun-tcp-accept".into())
            .spawn(move || self.run(stop))
    }

    fn run(self, stop: &AtomicBool) {
        let cap = (2 * self.slots.len()).min(256);
        let mut candidates: Vec<Candidate> = Vec::with_capacity(cap);
        let mut fds = Vec::with_capacity(cap + 1);
        while !stop.load(Ordering::Relaxed) {
            // Bound accepts per turn so hostile arrivals cannot starve candidate deadlines.
            for _ in 0..64 {
                match self.listener.accept() {
                    Ok((socket, _)) => {
                        if candidates.len() == cap {
                            drop(socket);
                            continue;
                        }
                        match Connection::new(socket, Instant::now()) {
                            Ok(conn) => candidates.push(Candidate {
                                conn,
                                identity: None,
                                timeout: self.slots[0].lock().unwrap().timeout,
                            }),
                            Err(e) => log::warn!("tcp candidate setup: {e}"),
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        log::error!("tcp accept: {e}");
                        return;
                    }
                }
            }
            let mut i = 0;
            while i < candidates.len() {
                match candidates[i].advance(&self.slots, self.mtu) {
                    Ok(false) => i += 1,
                    result => {
                        let candidate = candidates.swap_remove(i);
                        let id = candidate.identity.map(|v| v.0);
                        if let Err(e) = result.and_then(|_| candidate.admit(&self.slots, self.mtu))
                        {
                            log::warn!("tcp candidate {id:?}: {e}");
                        }
                    }
                }
            }
            // Candidate count is bounded; poll all sockets and listener without per-candidate threads.
            fds.clear();
            fds.push(pollfd(self.listener.as_raw_fd(), libc::POLLIN));
            for c in &candidates {
                fds.push(pollfd(
                    c.conn.socket.as_raw_fd(),
                    libc::POLLIN
                        | if c.conn.tx.bytes > 0 {
                            libc::POLLOUT
                        } else {
                            0
                        },
                ));
            }
            if let Err(e) = poll(&mut fds, 20) {
                log::error!("tcp accept poll: {e}");
                return;
            }
        }
    }
}

struct Candidate {
    conn: Connection,
    identity: Option<(usize, u64)>,
    timeout: Duration,
}

impl Candidate {
    fn advance(&mut self, slots: &Slots, mtu: u16) -> io::Result<bool> {
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
            let p = wire::hello_params(hello)?;
            let slot = slots
                .get(p.worker as usize)
                .ok_or_else(|| invalid("invalid worker ID"))?
                .lock()
                .unwrap();
            let (auth, challenge) = Handshake::exit(
                &slot.key,
                Params {
                    worker: p.worker,
                    conns: slots.len() as u16,
                    mtu,
                },
                hello,
            )?;
            self.timeout = slot.timeout;
            self.identity = Some((p.worker as usize, slot.epoch));
            self.conn.auth = Some(auth);
            self.conn.tx.push(&challenge);
            self.conn.rx.clear();
        }
        self.conn.authenticate(now, self.timeout)
    }

    fn admit(mut self, slots: &Slots, mtu: u16) -> io::Result<()> {
        let (id, epoch) = self.identity.unwrap();
        let mut slot = slots[id].lock().unwrap();
        if slot.epoch != epoch {
            return Err(invalid("authentication invalidated by key reload"));
        }
        self.conn.establish(mtu);
        slot.pending = Some(self.conn);
        log::info!("tcp worker {id}: authenticated candidate admitted");
        Ok(())
    }
}

struct Backoff {
    failures: u32,
}
impl Backoff {
    fn delay(&mut self, sample: u32, stable: bool) -> Duration {
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

    pub fn run(mut self, stop: &AtomicBool, ctrl: &worker::Control) {
        let id = self.id;
        let mut cpu = ctrl.initial_cpu();
        worker::pin(id, cpu);
        let mut generation = 0;
        let mut wait = false;
        let mut connection: Option<Connection> = None;
        let mut retry_at = Instant::now();
        let mut backoff = Backoff { failures: 0 };
        let mut packet = vec![0; self.mtu as usize + 1];
        while !stop.load(Ordering::Relaxed) {
            if let Some((gen, reload)) = ctrl.take_reload(generation) {
                wait &= !connection.as_ref().is_some_and(|c| c.auth.is_none());
                if cpu != reload.cpu {
                    cpu = reload.cpu;
                    worker::pin(id, cpu);
                }
                if self.cfg.auth_key != reload.auth_key {
                    wait |= connection.as_ref().is_some_and(|c| c.auth.is_none());
                    connection = None;
                    retry_at = Instant::now();
                    if let Some(slots) = &self.slots {
                        let mut slot = slots[id].lock().unwrap();
                        slot.key = reload.auth_key.clone();
                        slot.epoch += 1;
                        slot.pending = None;
                    }
                }
                self.cfg.auth_key = reload.auth_key;
                self.cfg.ping_interval = reload.ping_interval;
                self.cfg.dead_timeout = reload.dead_timeout;
                if let Some(slots) = &self.slots {
                    slots[id].lock().unwrap().timeout = reload.dead_timeout;
                }
                generation = gen;
            }
            if let Some(slots) = &self.slots {
                if let Some(new) = slots[id].lock().unwrap().pending.take() {
                    if connection.is_some() {
                        log::info!(
                            "tcp worker {id}: authenticated takeover, closing old connection"
                        );
                    }
                    connection = Some(new);
                    log::info!("tcp worker {id}: established");
                }
            }
            if connection.is_none() && self.cfg.mode == Mode::Entry && Instant::now() >= retry_at {
                let now = Instant::now();
                let result = sys::tcp_connect(self.cfg.remote.unwrap(), self.cfg.iface.as_deref())
                    .and_then(|s| {
                        let mut c = Connection::new(s, now)?;
                        c.connecting = true;
                        let (auth, hello) = Handshake::entry(
                            &self.cfg.auth_key,
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
                    Ok(c) => connection = Some(c),
                    Err(e) => {
                        log::warn!("tcp worker {id}: connection failure: {e}");
                        retry_at = self.retry(&mut backoff, false);
                    }
                }
            }
            if let Some(c) = connection.as_mut() {
                let result = if c.auth.is_some() {
                    c.authenticate(Instant::now(), self.cfg.dead_timeout)
                        .map(|ready| {
                            if ready {
                                c.establish(self.mtu);
                                log::info!("tcp worker {id}: established");
                            }
                        })
                } else {
                    c.pump(
                        &self.tun,
                        &mut packet,
                        self.cfg.ping_interval,
                        self.cfg.dead_timeout,
                    )
                };
                if let Err(e) = result {
                    let stable = c.auth.is_none() && c.since.elapsed() >= self.cfg.dead_timeout;
                    log::warn!(
                        "tcp worker {id}: {}: {e}",
                        if c.auth.is_some() {
                            "connection/authentication failure"
                        } else {
                            "connection closed"
                        }
                    );
                    connection = None;
                    if self.cfg.mode == Mode::Entry {
                        retry_at = self.retry(&mut backoff, stable);
                    }
                }
            }
            let established = connection.as_ref().is_some_and(|c| c.auth.is_none());
            ctrl.report(generation, established, wait);
            if !established {
                for _ in 0..64 {
                    match tun_read(&self.tun, &mut packet) {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(e) => {
                            log::error!("tcp worker {id}: TUN read: {e}");
                            return;
                        }
                    }
                }
            }
            let mut fds = [pollfd(self.tun.as_raw_fd(), libc::POLLIN), pollfd(-1, 0)];
            if let Some(c) = &connection {
                fds[1] = pollfd(
                    c.socket.as_raw_fd(),
                    if c.tun_pending || c.rx.complete() {
                        0
                    } else {
                        libc::POLLIN
                    } | if c.tx.bytes > 0 { libc::POLLOUT } else { 0 },
                );
                if established && !c.tx.room(self.mtu as usize) {
                    fds[0].events = 0;
                }
                if c.tun_pending {
                    fds[0].events |= libc::POLLOUT;
                }
            }
            if let Err(e) = poll(&mut fds, 20) {
                log::error!("tcp worker {id}: poll: {e}");
                return;
            }
        }
    }

    fn retry(&self, backoff: &mut Backoff, stable: bool) -> Instant {
        let mut bytes = [0; 4];
        // Failure to obtain retry jitter must not produce a rapid reconnect loop.
        let delay = match wire::random(&mut bytes) {
            Ok(()) => backoff.delay(u32::from_ne_bytes(bytes), stable),
            Err(e) => {
                log::error!("tcp worker {}: retry randomness: {e}", self.id);
                Duration::from_secs(15)
            }
        };
        log::info!(
            "tcp worker {}: retry in {:.3}s",
            self.id,
            delay.as_secs_f64()
        );
        Instant::now() + delay
    }
}

fn pollfd(fd: i32, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}
fn poll(fds: &mut [libc::pollfd], timeout: i32) -> io::Result<()> {
    // SAFETY: valid pollfd array for the supplied count.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(())
}
