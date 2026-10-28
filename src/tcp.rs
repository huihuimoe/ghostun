//! Kernel TCP workers and bounded candidate dispatch; no raw-socket or port steering.
#[cfg(test)]
mod tests;
mod wire;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, io};

use crate::config::{AuthKey, Config, Mode};
use crate::faketcp::pkt::{Keepalive, CTRL_LEN};
use crate::sys::{poll, poll_ms, pollfd, READ_READY, WRITE_READY};
use crate::{sys, worker};
use wire::{invalid, Handshake, Params, Receive, SendQueue, AUTH_MAX, PING, PONG};

const ROUNDS: usize = 4;
const BATCH: usize = 64;

#[inline(always)]
const fn can_io(pfd: libc::pollfd, event: i16, ready: i16) -> bool {
    pfd.events & event == 0 || pfd.revents & ready != 0
}

struct Connection {
    socket: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
    rx: Receive,
    tx: SendQueue,
    auth: Option<Handshake>,
    since: Instant,
    last_rx: Instant,
    last_ping: Instant,
    tun_pending: bool,
}

impl fmt::Display for Connection {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <-> {}", self.local, self.peer)
    }
}

impl Connection {
    fn new(socket: TcpStream, peer: SocketAddr, now: Instant) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        sys::tcp_notsent_lowat(&socket)?;
        let local = socket.local_addr()?;
        Ok(Self {
            socket,
            local,
            peer,
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
        self.tx.flush(&mut self.socket)?;
        let auth = self.auth.as_mut().expect("handshake initialized");
        if auth.done() {
            return Ok(self.tx.bytes() == 0);
        }
        if self.rx.read(&mut self.socket)? {
            if let Some(reply) = auth.receive(self.rx.payload())? {
                self.tx.push(&reply);
            }
            self.rx.clear();
        }
        self.tx.flush(&mut self.socket)?;
        Ok(auth.done() && self.tx.bytes() == 0)
    }

    fn establish(&mut self, mtu: u16) {
        self.auth = None;
        self.rx.grow(mtu as usize);
        self.tx.grow();
        self.since = Instant::now();
        self.last_rx = self.since;
        self.last_ping = self.since;
    }

    #[inline]
    fn next_deadline(&self, ping: Duration, dead: Duration) -> Instant {
        if self.auth.is_some() {
            return self.since + dead;
        }
        let mut next = self.last_rx + dead;
        if self.tx.room(CTRL_LEN) {
            next = next.min(self.last_ping + ping);
        }
        next
    }

    #[inline]
    fn flush_tx(&mut self, sock_w: &mut bool) -> io::Result<()> {
        if self.tx.bytes() > 0 && *sock_w {
            self.tx.flush(&mut self.socket)?;
            *sock_w = self.tx.bytes() == 0;
        }
        Ok(())
    }

    #[cfg(test)]
    fn pump(&mut self, tun: &OwnedFd, mtu: u16, ping: Duration, dead: Duration) -> io::Result<()> {
        self.pump_io(
            tun,
            mtu,
            Instant::now(),
            ping,
            dead,
            &[pollfd(-1, 0), pollfd(-1, 0)],
        )
        .map(drop)
    }

    #[inline]
    fn pump_io(
        &mut self,
        tun: &OwnedFd,
        mtu: u16,
        now: Instant,
        ping: Duration,
        dead: Duration,
        fds: &[libc::pollfd],
    ) -> io::Result<bool> {
        let mtu = mtu as usize;
        if now.duration_since(self.last_rx) >= dead {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer liveness timeout",
            ));
        }
        let mut tun_r = can_io(fds[0], libc::POLLIN, READ_READY);
        let mut tun_w = can_io(fds[0], libc::POLLOUT, WRITE_READY);
        let mut sock_r = can_io(fds[1], libc::POLLIN, READ_READY);
        let mut sock_w = can_io(fds[1], libc::POLLOUT, WRITE_READY);
        self.flush_tx(&mut sock_w)?;
        let mut busy = false;
        for _ in 0..ROUNDS {
            let mut rx_count = 0;
            while rx_count < BATCH {
                if !self.tun_pending {
                    if !self.rx.ready() && !sock_r {
                        break;
                    }
                    if !self.rx.read(&mut self.socket)? {
                        sock_r = false;
                        break;
                    }
                    let p = self.rx.payload();
                    if let Some(ka) = Keepalive::decode(p).filter(|k| matches!(k.kind, PING | PONG))
                    {
                        if ka.kind == PING {
                            if !self.tx.room(CTRL_LEN) {
                                break;
                            }
                            let pong = Keepalive::new(PONG, ka.nonce).encode();
                            self.tx.push(&pong);
                        }
                        self.rx.clear();
                        self.last_rx = now;
                        rx_count += 1;
                        continue;
                    }
                    wire::validate_packet(p, mtu)?;
                    self.tun_pending = true;
                    self.last_rx = now;
                }
                if !tun_w {
                    break;
                }
                if !sys::tun_write(tun.as_fd(), self.rx.payload())? {
                    tun_w = false;
                    break;
                }
                self.rx.clear();
                self.tun_pending = false;
                rx_count += 1;
            }
            if tun_r {
                for _ in 0..BATCH {
                    let pushed = self.tx.push_in_place(mtu, |buf| {
                        let Some(n) = sys::tun_read(tun.as_fd(), buf)? else {
                            return Ok(None);
                        };
                        wire::validate_packet(&buf[..n], mtu)?;
                        Ok(Some(n))
                    })?;
                    if !pushed {
                        if self.tx.room(mtu) {
                            tun_r = false;
                        }
                        break;
                    }
                }
            }
            self.flush_tx(&mut sock_w)?;
            let rx_blocked_on_pong = self.rx.ready() && !self.tx.room(CTRL_LEN);
            let more_rx = !self.tun_pending && !rx_blocked_on_pong && (sock_r || self.rx.ready());
            let more_tx = tun_r && self.tx.room(mtu);
            busy = more_rx || more_tx;
            if !busy {
                break;
            }
        }
        if now.duration_since(self.last_ping) >= ping && self.tx.room(CTRL_LEN) {
            let mut nonce = [0u8; 8];
            sys::random(&mut nonce)?;
            let msg = Keepalive::new(PING, nonce).encode();
            self.tx.push(&msg);
            self.last_ping = now;
            self.flush_tx(&mut sock_w)?;
        }
        Ok(busy)
    }
}

struct Slot {
    key: AuthKey,
    epoch: u64,
    timeout: Duration,
    pending: Option<Connection>,
    wake: RawFd,
}

type Slots = Arc<Vec<Mutex<Slot>>>;

/// Owns listener setup before any workers start. The dispatcher never owns a TUN queue.
pub struct Listener {
    listener: TcpListener,
    wake: OwnedFd,
    slots: Slots,
    mtu: u16,
}

impl Listener {
    pub fn bind(cfg: &Config, mtu: u16) -> io::Result<Self> {
        // Explicit IPV6_V6ONLY keeps one selected outer family per instance.
        let listener = sys::tcp_listener(
            SocketAddr::new(cfg.exit_ip(), cfg.listen.unwrap()),
            cfg.iface.as_deref(),
        )?;
        listener.set_nonblocking(true)?;
        let wake = sys::eventfd()?;
        let slots = Arc::new(
            (0..cfg.conns)
                .map(|_| {
                    Mutex::new(Slot {
                        key: cfg.auth_key.clone(),
                        epoch: 0,
                        timeout: cfg.dead_timeout,
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
                let _guard = worker::StopOnDrop(stop, main_wake);
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
                            match Connection::new(socket, peer, now) {
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

    fn admit(mut self, slots: &Slots, mtu: u16) -> io::Result<()> {
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
                    worker::pin(id, cpu);
                }
                if self.cfg.auth_key != reload.auth_key {
                    wait |= connection.as_ref().is_some_and(|c| c.auth.is_none());
                    connection = None;
                    fds[1] = pollfd(-1, 0);
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
                let result = sys::tcp_connect(remote, self.cfg.iface.as_deref()).and_then(|s| {
                    let mut c = Connection::new(s, remote, now)?;
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
                        || now.duration_since(c.since) >= self.cfg.dead_timeout
                    {
                        c.authenticate(now, self.cfg.dead_timeout).map(|ready| {
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
                        self.cfg.ping_interval,
                        self.cfg.dead_timeout,
                        &fds,
                    )
                    .map(|more| busy = more)
                };
                if let Err(e) = result {
                    let stable = c.auth.is_none() && c.since.elapsed() >= self.cfg.dead_timeout;
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
            worker::sync_tun_queue(id, self.tun.as_fd(), &mut attached, established);
            ctrl.report(generation, established, wait);
            if !established && can_io(fds[0], libc::POLLIN, READ_READY) {
                let mut drained = 0;
                while drained < ROUNDS * BATCH {
                    match sys::tun_read(self.tun.as_fd(), &mut packet) {
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
                        c.next_deadline(self.cfg.ping_interval, self.cfg.dead_timeout)
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
