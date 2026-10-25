//! Kernel TCP workers and bounded candidate dispatch; no raw-socket or port steering.
#[cfg(test)]
mod tests;
mod wire;

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{AuthKey, Config, Mode};
use crate::{sys, worker};
use wire::{invalid, Handshake, Params, Receive, SendQueue, AUTH_MAX, PING, PONG};

const ROUNDS: usize = 4;
const BATCH: usize = 64;
const MAX_POLL: Duration = Duration::from_millis(50);
const READ_READY: i16 = libc::POLLIN | libc::POLLERR | libc::POLLHUP;
const WRITE_READY: i16 = libc::POLLOUT | libc::POLLERR | libc::POLLHUP;

struct Connection {
    socket: TcpStream,
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

    fn next_deadline(&self, ping: Duration, dead: Duration) -> Instant {
        if self.auth.is_some() {
            return self.since + dead;
        }
        let mut next = self.last_rx + dead;
        if self.tx.room(9) {
            next = next.min(self.last_ping + ping);
        }
        next
    }

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

    fn pump_io(
        &mut self,
        tun: &OwnedFd,
        mtu: u16,
        now: Instant,
        ping: Duration,
        dead: Duration,
        fds: &[libc::pollfd; 2],
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
                if !tun_write(tun, self.rx.payload())? {
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
                        let Some(n) = tun_read(tun, buf)? else {
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
            let rx_blocked_on_pong = self.rx.ready() && !self.tx.room(9);
            let more_rx = !self.tun_pending && !rx_blocked_on_pong && (sock_r || self.rx.ready());
            let more_tx = tun_r && self.tx.room(mtu);
            busy = more_rx || more_tx;
            if !busy {
                break;
            }
        }
        if now.duration_since(self.last_ping) >= ping && self.tx.room(9) {
            let mut msg = [PING; 9];
            wire::random(&mut msg[1..])?;
            self.tx.push(&msg);
            self.last_ping = now;
            self.flush_tx(&mut sock_w)?;
        }
        Ok(busy)
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
            // Candidate count is bounded; poll all sockets and listener without per-candidate threads.
            fds.clear();
            fds.push(pollfd(self.listener.as_raw_fd(), libc::POLLIN));
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
            let wait = candidates
                .iter()
                .map(|c| (c.conn.since + c.timeout).saturating_duration_since(now))
                .min()
                .unwrap_or(MAX_POLL)
                .min(MAX_POLL);
            if let Err(e) = poll(&mut fds, poll_ms(wait)) {
                log::error!("tcp accept poll: {e}");
                return;
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            let mut i = 0;
            while i < candidates.len() {
                let expired = now.duration_since(candidates[i].conn.since) >= candidates[i].timeout;
                if fds[i + 1].revents == 0 && !expired {
                    i += 1;
                    continue;
                }
                match candidates[i].advance(&self.slots, self.mtu) {
                    Ok(false) => i += 1,
                    result => {
                        let candidate = candidates.swap_remove(i);
                        fds.swap_remove(i + 1);
                        let id = candidate.identity.map(|v| v.0);
                        if let Err(e) = result.and_then(|_| candidate.admit(&self.slots, self.mtu))
                        {
                            log::debug!("tcp candidate {id:?}: {e}");
                        }
                    }
                }
            }
            if fds[0].revents & READ_READY != 0 {
                // Bound accepts per turn so hostile arrivals cannot starve candidate deadlines.
                for _ in 0..BATCH {
                    match self.listener.accept() {
                        Ok((socket, _)) => {
                            if candidates.len() == cap {
                                drop(socket);
                                continue;
                            }
                            match Connection::new(socket, now) {
                                Ok(conn) => candidates.push(Candidate {
                                    conn,
                                    identity: None,
                                    timeout: self.slots[0].lock().unwrap().timeout,
                                }),
                                Err(e) => log::debug!("tcp candidate setup: {e}"),
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
        let mut attached = false;
        let mut connection: Option<Connection> = None;
        let mut retry_at = Instant::now();
        let mut backoff = Backoff { failures: 0 };
        let mut packet = vec![0; self.mtu as usize + 1];
        let mut fds = [pollfd(-1, 0), pollfd(-1, 0)];
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
            if let Some(slots) = &self.slots {
                if let Some(new) = slots[id].lock().unwrap().pending.take() {
                    if connection.is_some() {
                        log::info!(
                            "tcp worker {id}: authenticated takeover, closing old connection"
                        );
                    }
                    connection = Some(new);
                    fds[1] = pollfd(-1, 0);
                    log::info!("tcp worker {id}: established");
                }
            }
            let mut now = Instant::now();
            if connection.is_none() && self.cfg.mode == Mode::Entry && now >= retry_at {
                let result = sys::tcp_connect(self.cfg.remote.unwrap(), self.cfg.iface.as_deref())
                    .and_then(|s| {
                        let mut c = Connection::new(s, now)?;
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
                        log::warn!("tcp worker {id}: connection failure: {e}");
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
                                log::info!("tcp worker {id}: established");
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
                        "tcp worker {id}: {}: {e}",
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
                    match tun_read(&self.tun, &mut packet) {
                        Ok(Some(_)) => drained += 1,
                        Ok(None) => break,
                        Err(e) => {
                            log::error!("tcp worker {id}: TUN read: {e}");
                            return;
                        }
                    }
                }
                busy |= drained == ROUNDS * BATCH;
            }
            fds = [pollfd(self.tun.as_raw_fd(), libc::POLLIN), pollfd(-1, 0)];
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
            let timeout = if busy {
                0
            } else {
                now = Instant::now();
                let deadline = match &connection {
                    Some(c) => c.next_deadline(self.cfg.ping_interval, self.cfg.dead_timeout),
                    None if self.cfg.mode == Mode::Entry => retry_at,
                    None => now + MAX_POLL,
                };
                poll_ms(deadline.saturating_duration_since(now).min(MAX_POLL))
            };
            if let Err(e) = poll(&mut fds, timeout) {
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
fn can_io(pfd: libc::pollfd, event: i16, ready: i16) -> bool {
    pfd.events & event == 0 || pfd.revents & ready != 0
}
fn poll_ms(wait: Duration) -> libc::c_int {
    wait.as_micros().div_ceil(1000) as libc::c_int
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
