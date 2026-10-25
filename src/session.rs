//! Per-worker FakeTCP session: handshake, seq/ack upkeep, health ping/pong and reconnect.
//! Pure logic: frames in, frames out through [`Sink`]; the worker owns all I/O.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::auth::{self, Auth, Isns, CHALLENGE_LEN, FINISHED_LEN, HELLO_LEN, PROOF_LEN};
use crate::config::{AuthKey, Mode, OuterFamily};
use crate::pkt::{self, flags, TcpMeta, CTRL_LEN, CTRL_PING, CTRL_PONG, MAX_OVERHEAD};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    SynSent,
    Authenticating,
    Established,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub mode: Mode,
    pub auth_key: AuthKey,
    pub local_ip: IpAddr,
    /// Exit node address; entry only.
    pub remote: Option<SocketAddr>,
    /// Outer listen port; exit only.
    pub listen_port: u16,
    pub worker: u16,
    pub conns: u16,
    pub base_port: u16,
    /// Advertised in SYN / SYN-ACK.
    pub mss: u16,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
}

pub trait Sink {
    fn send(&mut self, frame: &[u8], dst: IpAddr);
}

/// Received payload bytes after which a bare ACK is sent even without outbound traffic,
/// keeping one-way bulk transfers inside the firewall's tracked TCP window.
pub const ACK_THRESHOLD: u32 = 1 << 20;
pub const SYN_RETRY: Duration = Duration::from_secs(1);
const WINDOW: u16 = 65535;
const IDLE: Duration = Duration::from_secs(3600);

struct EntryAuth {
    frame: [u8; PROOF_LEN],
    len: usize,
    seq: u32,
}

struct Completion {
    request: TcpMeta,
    proof: [u8; PROOF_LEN],
    finished: [u8; FINISHED_LEN],
}

fn emit(scratch: &mut [u8], meta: &TcpMeta, payload: &[u8], id: u16, out: &mut impl Sink) {
    let overhead = OuterFamily::of(meta.src.ip()).overhead();
    scratch[overhead..overhead + payload.len()].copy_from_slice(payload);
    let len = pkt::write_headers(scratch, meta, payload.len(), id);
    out.send(&scratch[..len], meta.dst.ip());
}

pub struct Session {
    cfg: SessionConfig,
    auth: Auth,
    pending: Option<EntryAuth>,
    completion: Option<Completion>,
    state: State,
    local: SocketAddr,
    peer: Option<SocketAddr>,
    iss: u32,
    irs: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    unacked: u32,
    last_rx: Instant,
    next_ping: Instant,
    next_syn: Instant,
    ip_id: u16,
    rng: u64,
    nonce: u64,
    scratch: [u8; MAX_OVERHEAD + PROOF_LEN],
}

/// `a` is later than `b` in 32-bit sequence space.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

impl Session {
    pub fn new(cfg: SessionConfig, now: Instant, seed: u64) -> io::Result<Self> {
        let auth = Auth::new(&cfg.auth_key, cfg.mode, now, cfg.dead_timeout)?;
        let (local, peer) = match cfg.mode {
            Mode::Entry => {
                let (first, count) = port_pool(&cfg);
                let port = first + (seed % u64::from(count)) as u16 * cfg.conns;
                (SocketAddr::new(cfg.local_ip, port), cfg.remote)
            }
            Mode::Exit => (SocketAddr::new(cfg.local_ip, cfg.listen_port), None),
        };
        Ok(Session {
            cfg,
            auth,
            pending: None,
            completion: None,
            state: State::Closed,
            local,
            peer,
            iss: 0,
            irs: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            unacked: 0,
            last_rx: now,
            next_ping: now,
            next_syn: now,
            ip_id: seed as u16,
            rng: seed ^ 0x9e37_79b9_7f4a_7c15,
            nonce: 0,
            scratch: [0; MAX_OVERHEAD + PROOF_LEN],
        })
    }

    #[cfg(test)]
    pub fn state(&self) -> State {
        self.state
    }

    pub fn mss(&self) -> u16 {
        self.cfg.mss
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Updates session timers and key; returns `true` when this update reset a previously
    /// `Established` session and the reload coordinator must wait for re-establishment.
    pub fn reload(
        &mut self,
        now: Instant,
        auth_key: AuthKey,
        ping_interval: Duration,
        dead_timeout: Duration,
        out: &mut impl Sink,
    ) -> bool {
        let was_established = self.state == State::Established;
        self.cfg.ping_interval = ping_interval;
        self.cfg.dead_timeout = dead_timeout;
        self.auth.reload(&auth_key, dead_timeout);
        if self.cfg.auth_key == auth_key {
            if was_established {
                self.next_ping = now + ping_interval;
            }
            return false;
        }
        self.cfg.auth_key = auth_key;
        match self.cfg.mode {
            Mode::Entry => {
                if self.state != State::Closed {
                    self.reconnect(now, true, out);
                }
            }
            Mode::Exit => self.shutdown(out),
        }
        was_established
    }

    pub fn start(&mut self, now: Instant, out: &mut impl Sink) {
        if self.cfg.mode == Mode::Entry {
            self.connect(now, out);
        }
    }

    pub fn encap(&mut self, buf: &mut [u8], len: usize) -> Option<(usize, IpAddr)> {
        if self.state != State::Established {
            return None;
        }
        let peer = self.peer?;
        let meta = self.meta(peer, flags::PSH | flags::ACK);
        self.snd_nxt = self.snd_nxt.wrapping_add(len as u32);
        self.unacked = 0;
        Some((
            pkt::write_headers(buf, &meta, len, self.next_ip_id()),
            peer.ip(),
        ))
    }

    pub fn on_outer<'a>(
        &mut self,
        now: Instant,
        frame: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        let p = pkt::parse(frame)?;
        let m = p.meta;
        match self.cfg.mode {
            Mode::Entry => {
                if Some(m.src) != self.peer || m.dst != self.local {
                    if Some(m.src) == self.peer
                        && m.dst.ip() == self.local.ip()
                        && m.flags & (flags::RST | flags::SYN) == 0
                        && m.flags & flags::ACK != 0
                        && !p.payload.is_empty()
                    {
                        self.send_rst_to(m.dst, m.src, m.ack, out);
                    }
                    return None;
                }
                if matches!(self.state, State::SynSent | State::Authenticating)
                    && now.duration_since(self.last_rx) >= self.cfg.dead_timeout
                {
                    self.reconnect(now, true, out);
                    return None;
                }
                if m.flags & flags::RST != 0 {
                    // Pre-established attempts wait for SYN_RETRY / dead_timeout so a down peer's
                    // kernel RSTs cannot spin port rotation or extend the attempt deadline.
                    if self.state == State::Established {
                        self.reconnect(now, false, out);
                    }
                    return None;
                }
                if self.state == State::SynSent {
                    if m.flags & (flags::SYN | flags::ACK) == flags::SYN | flags::ACK
                        && m.ack == self.snd_nxt
                        && p.payload.is_empty()
                    {
                        self.irs = m.seq;
                        self.rcv_nxt = m.seq.wrapping_add(1);
                        self.state = State::Authenticating;
                        self.send_ctrl(flags::ACK, &[], out);
                        self.snd_nxt = self.snd_nxt.wrapping_add(HELLO_LEN as u32);
                        self.next_syn = now + SYN_RETRY;
                        self.send_pending(out);
                    }
                    return None;
                }
                if m.flags & flags::SYN != 0 {
                    if matches!(self.state, State::Authenticating | State::Established)
                        && m.seq == self.irs
                        && m.ack == self.iss.wrapping_add(1)
                    {
                        self.send_ctrl(flags::ACK, &[], out);
                    }
                    return None;
                }
                if m.flags & flags::ACK == 0 {
                    return None;
                }
                if self.state == State::Authenticating {
                    self.on_auth_reply(now, &m, p.payload, out);
                    return None;
                }
                if p.payload.first() == Some(&auth::CONTROL) {
                    return None;
                }
                if self.state == State::Established {
                    return self.on_segment(now, &m, p.payload, out);
                }
                None
            }
            Mode::Exit => {
                if m.dst.port() != self.cfg.listen_port {
                    return None;
                }
                let from_peer = self.state == State::Established
                    && Some(m.src) == self.peer
                    && m.dst == self.local;
                if m.flags & flags::RST != 0 {
                    if from_peer {
                        self.close();
                    }
                    return None;
                }
                if m.flags & flags::SYN != 0 {
                    if m.flags & flags::ACK == 0 && p.payload.is_empty() {
                        self.accept_syn(now, &m, out);
                    }
                    return None;
                }
                if m.flags & flags::ACK == 0 {
                    return None;
                }
                if p.payload.first() == Some(&auth::CONTROL) {
                    self.on_auth_request(now, &m, p.payload, out);
                    return None;
                }
                if !from_peer {
                    // A transport ACK alone neither admits nor keeps a candidate alive.
                    if !p.payload.is_empty() {
                        self.send_rst_to(m.dst, m.src, m.ack, out);
                    }
                    return None;
                }
                self.on_segment(now, &m, p.payload, out)
            }
        }
    }

    pub fn on_tick(&mut self, now: Instant, out: &mut impl Sink) {
        let dead = now.saturating_duration_since(self.last_rx) >= self.cfg.dead_timeout;
        match (self.cfg.mode, self.state) {
            (Mode::Entry, State::Closed) if now >= self.next_syn => self.connect(now, out),
            (_, State::Closed) => {}
            (Mode::Entry, _) if dead => {
                log::warn!(
                    "worker {}: peer silent for {:?}, reconnecting",
                    self.cfg.worker,
                    self.cfg.dead_timeout
                );
                self.reconnect(now, true, out);
            }
            (Mode::Exit, _) if dead => {
                log::info!("worker {}: peer {:?} timed out", self.cfg.worker, self.peer);
                self.close();
            }
            (Mode::Entry, State::SynSent) if now >= self.next_syn => {
                self.next_syn = now + SYN_RETRY;
                self.send_syn(out);
            }
            (Mode::Entry, State::Authenticating) if now >= self.next_syn => {
                self.next_syn = now + SYN_RETRY;
                self.send_pending(out);
            }
            (_, State::Established) if now >= self.next_ping => {
                self.next_ping = now + self.cfg.ping_interval;
                self.nonce = self.nonce.wrapping_add(1);
                let mut frame = [0u8; CTRL_LEN];
                frame[0] = CTRL_PING;
                frame[1..].copy_from_slice(&self.nonce.to_be_bytes());
                self.send_ctrl(flags::PSH | flags::ACK, &frame, out);
            }
            _ => {}
        }
    }

    pub fn next_deadline(&self) -> Instant {
        let dead = self.last_rx + self.cfg.dead_timeout;
        match self.state {
            State::Closed if self.cfg.mode == Mode::Entry => self.next_syn,
            State::Closed => self.last_rx.max(Instant::now()) + IDLE,
            State::SynSent | State::Authenticating => dead.min(self.next_syn),
            State::Established => dead.min(self.next_ping),
        }
    }

    pub fn shutdown(&mut self, out: &mut impl Sink) {
        if self.state != State::Closed && self.peer.is_some() {
            self.send_rsts(out);
        }
        self.close();
    }

    fn close(&mut self) {
        self.state = State::Closed;
        self.pending = None;
        self.completion = None;
        if self.cfg.mode == Mode::Exit {
            self.peer = None;
        }
    }

    fn established(&mut self, now: Instant) {
        self.state = State::Established;
        self.last_rx = now;
        self.unacked = 0;
        self.next_ping = now + self.cfg.ping_interval;
        log::info!(
            "worker {}: established {} <-> {}",
            self.cfg.worker,
            self.local,
            self.peer.map_or_else(String::new, |p| p.to_string())
        );
    }

    fn on_segment<'a>(
        &mut self,
        now: Instant,
        m: &TcpMeta,
        payload: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        if payload.is_empty() {
            return None;
        }
        self.last_rx = now;
        let end = m.seq.wrapping_add(payload.len() as u32);
        if seq_after(end, self.rcv_nxt) {
            self.rcv_nxt = end;
        }
        self.unacked = self.unacked.saturating_add(payload.len() as u32);
        match payload[0] >> 4 {
            4 | 6 => {
                if self.unacked >= ACK_THRESHOLD {
                    self.send_ctrl(flags::ACK, &[], out);
                }
                Some(payload)
            }
            0 if payload[0] == CTRL_PING && payload.len() >= CTRL_LEN => {
                let mut pong = [0u8; CTRL_LEN];
                pong[0] = CTRL_PONG;
                pong[1..].copy_from_slice(&payload[1..CTRL_LEN]);
                self.send_ctrl(flags::PSH | flags::ACK, &pong, out);
                None
            }
            _ => None,
        }
    }

    fn accept_syn(&mut self, now: Instant, m: &TcpMeta, out: &mut impl Sink) {
        let duplicate = self.state == State::Established
            && Some(m.src) == self.peer
            && m.dst == self.local
            && m.seq == self.irs;
        let meta = TcpMeta {
            src: m.dst,
            dst: m.src,
            seq: if duplicate {
                self.iss
            } else {
                self.auth.syn_cookie(now, m)
            },
            ack: m.seq.wrapping_add(1),
            flags: flags::SYN | flags::ACK,
            window: WINDOW,
        };
        let id = self.next_ip_id();
        let len = pkt::write_syn(&mut self.scratch, &meta, self.cfg.mss, id);
        out.send(&self.scratch[..len], meta.dst.ip());
    }

    fn on_auth_reply(&mut self, now: Instant, m: &TcpMeta, payload: &[u8], out: &mut impl Sink) {
        if m.flags != flags::PSH | flags::ACK {
            return;
        }
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let isns = Isns {
            entry: self.iss,
            exit: self.irs,
        };
        if pending.len == HELLO_LEN {
            if m.seq != self.irs.wrapping_add(1) || m.ack != self.snd_nxt {
                return;
            }
            let Some(proof) = self.auth.proof(isns, &pending.frame[3..HELLO_LEN], payload) else {
                return;
            };
            self.rcv_nxt = m.seq.wrapping_add(CHALLENGE_LEN as u32);
            self.pending = Some(EntryAuth {
                frame: proof,
                len: PROOF_LEN,
                seq: self.snd_nxt,
            });
            self.snd_nxt = self.snd_nxt.wrapping_add(PROOF_LEN as u32);
            self.next_syn = now + SYN_RETRY;
            self.send_pending(out);
        } else if m.seq == self.irs.wrapping_add(1 + CHALLENGE_LEN as u32)
            && m.ack == self.snd_nxt
            && self.auth.finished(isns, &pending.frame, payload)
        {
            self.rcv_nxt = self.irs.wrapping_add(1 + auth::EXIT_BYTES);
            self.pending = None;
            self.established(now);
            self.send_ctrl(flags::ACK, &[], out);
        }
    }

    fn on_auth_request(&mut self, now: Instant, m: &TcpMeta, payload: &[u8], out: &mut impl Sink) {
        if m.flags != flags::PSH | flags::ACK {
            return;
        }
        if auth::is_message(payload, auth::HELLO, HELLO_LEN) {
            match self.auth.challenge(now, m, payload) {
                Ok(Some(challenge)) => {
                    let meta = TcpMeta {
                        src: m.dst,
                        dst: m.src,
                        seq: m.ack,
                        ack: m.seq.wrapping_add(HELLO_LEN as u32),
                        flags: flags::PSH | flags::ACK,
                        window: WINDOW,
                    };
                    let id = self.next_ip_id();
                    emit(&mut self.scratch, &meta, &challenge, id, out);
                }
                Err(e) => log::error!("worker {}: authentication randomness: {e}", self.cfg.worker),
                Ok(None) => {}
            }
            return;
        }
        if self.state == State::Established
            && self
                .completion
                .as_ref()
                .is_some_and(|c| c.request == *m && payload == &c.proof[..])
        {
            self.send_completion(out);
            return;
        }
        let Some(verified) = self.auth.accept(now, m, payload) else {
            return;
        };
        // Do not reset a reused tuple: conntrack may already associate it with this handshake.
        if self.state == State::Established && (self.peer != Some(m.src) || self.local != m.dst) {
            self.send_rsts(out);
        }
        self.local = m.dst;
        self.peer = Some(m.src);
        self.iss = verified.isns.exit;
        self.irs = verified.isns.entry;
        self.snd_nxt = self.iss.wrapping_add(1 + auth::EXIT_BYTES);
        self.rcv_nxt = self.irs.wrapping_add(1 + auth::ENTRY_BYTES);
        self.completion = Some(Completion {
            request: *m,
            proof: payload.try_into().unwrap(),
            finished: verified.finished,
        });
        self.established(now);
        self.send_completion(out);
    }

    fn send_pending(&mut self, out: &mut impl Sink) {
        let Some(peer) = self.peer else { return };
        let id = self.next_ip_id();
        let mut meta = self.meta(peer, flags::PSH | flags::ACK);
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        meta.seq = pending.seq;
        emit(
            &mut self.scratch,
            &meta,
            &pending.frame[..pending.len],
            id,
            out,
        );
    }

    fn send_completion(&mut self, out: &mut impl Sink) {
        let id = self.next_ip_id();
        let completion = self
            .completion
            .as_ref()
            .expect("successful proof has a completion");
        let request = completion.request;
        let meta = TcpMeta {
            src: request.dst,
            dst: request.src,
            seq: request.ack,
            ack: request.seq.wrapping_add(PROOF_LEN as u32),
            flags: flags::PSH | flags::ACK,
            window: WINDOW,
        };
        emit(&mut self.scratch, &meta, &completion.finished, id, out);
    }

    fn connect(&mut self, now: Instant, out: &mut impl Sink) {
        let hello = match auth::hello() {
            Ok(frame) => frame,
            Err(e) => {
                log::error!("worker {}: authentication randomness: {e}", self.cfg.worker);
                self.close();
                self.next_syn = now + SYN_RETRY;
                return;
            }
        };
        self.iss = self.next_isn();
        self.snd_nxt = self.iss.wrapping_add(1);
        let mut frame = [0; PROOF_LEN];
        frame[..HELLO_LEN].copy_from_slice(&hello);
        self.pending = Some(EntryAuth {
            frame,
            len: HELLO_LEN,
            seq: self.snd_nxt,
        });
        self.rcv_nxt = 0;
        self.state = State::SynSent;
        self.last_rx = now;
        self.next_syn = now + SYN_RETRY;
        self.send_syn(out);
    }

    fn reconnect(&mut self, now: Instant, send_rst: bool, out: &mut impl Sink) {
        if send_rst {
            self.send_rsts(out);
        }
        let (first, count) = port_pool(&self.cfg);
        let last = first + (count - 1) * self.cfg.conns;
        let port = self.local.port();
        let next = if port >= last {
            first
        } else {
            port + self.cfg.conns
        };
        self.local.set_port(next);
        log::info!(
            "worker {}: rotating source port {port} -> {next}",
            self.cfg.worker
        );
        self.connect(now, out);
    }

    /// Two RSTs on the current tuple so a firewall still tracking it frees the conntrack slot.
    fn send_rsts(&mut self, out: &mut impl Sink) {
        for _ in 0..2 {
            self.send_ctrl(flags::RST | flags::ACK, &[], out);
        }
    }

    fn send_syn(&mut self, out: &mut impl Sink) {
        let Some(peer) = self.peer else { return };
        let meta = TcpMeta {
            seq: self.iss,
            ack: 0,
            ..self.meta(peer, flags::SYN)
        };
        let id = self.next_ip_id();
        let len = pkt::write_syn(&mut self.scratch, &meta, self.cfg.mss, id);
        out.send(&self.scratch[..len], peer.ip());
    }

    fn send_ctrl(&mut self, tcp_flags: u8, payload: &[u8], out: &mut impl Sink) {
        let Some(peer) = self.peer else { return };
        let meta = self.meta(peer, tcp_flags);
        self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
        self.unacked = 0;
        let id = self.next_ip_id();
        emit(&mut self.scratch, &meta, payload, id, out);
    }

    fn send_rst_to(&mut self, local: SocketAddr, to: SocketAddr, seq: u32, out: &mut impl Sink) {
        let meta = TcpMeta {
            src: local,
            dst: to,
            seq,
            ack: 0,
            flags: flags::RST,
            window: 0,
        };
        let id = self.next_ip_id();
        let len = pkt::write_headers(&mut self.scratch, &meta, 0, id);
        out.send(&self.scratch[..len], to.ip());
    }

    fn meta(&self, peer: SocketAddr, tcp_flags: u8) -> TcpMeta {
        TcpMeta {
            src: self.local,
            dst: peer,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: tcp_flags,
            window: WINDOW,
        }
    }

    fn next_ip_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    /// splitmix64; ISNs only need to differ between reconnects, not be unpredictable.
    fn next_isn(&mut self) -> u32 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) as u32
    }
}

/// Smallest entry source port `>= base_port` in this worker's residue class, and how many exist.
fn port_pool(cfg: &SessionConfig) -> (u16, u16) {
    let n = u32::from(cfg.conns);
    let base = u32::from(cfg.base_port);
    let first = base + (u32::from(cfg.worker) + n - base % n) % n;
    let count = (65535 - first) / n + 1;
    (first as u16, count as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkt::Parsed;
    use std::net::Ipv4Addr;

    const ENTRY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const EXIT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    const MS: Duration = Duration::from_millis(1);

    #[derive(Default)]
    struct Wire(Vec<Vec<u8>>);

    impl Sink for Wire {
        fn send(&mut self, frame: &[u8], _dst: IpAddr) {
            assert!(
                (frame[0] >> 4 == 6 || pkt::ipv4_header_checksum_ok(frame))
                    && pkt::tcp_checksum_ok(frame)
            );
            self.0.push(frame.to_vec());
        }
    }

    impl Wire {
        fn take(&mut self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.0)
        }
    }

    fn parsed(f: &[u8]) -> Parsed<'_> {
        pkt::parse(f).unwrap()
    }

    fn cfg(mode: Mode, worker: u16, conns: u16) -> SessionConfig {
        SessionConfig {
            mode,
            auth_key: AuthKey([0xa7; 32]),
            local_ip: if mode == Mode::Entry {
                ENTRY_IP
            } else {
                EXIT.ip()
            },
            remote: (mode == Mode::Entry).then_some(EXIT),
            listen_port: EXIT.port(),
            worker,
            conns,
            base_port: 32768,
            mss: 1460,
            ping_interval: Duration::from_secs(5),
            dead_timeout: Duration::from_secs(15),
        }
    }

    /// Entry + exit connected through an in-memory wire.
    struct Pair {
        t: Instant,
        entry: Session,
        exit: Session,
    }

    impl Pair {
        fn new(worker: u16, conns: u16, seed: u64) -> Self {
            let t = Instant::now();
            Pair {
                t,
                entry: Session::new(cfg(Mode::Entry, worker, conns), t, seed).unwrap(),
                exit: Session::new(cfg(Mode::Exit, worker, conns), t, seed + 1).unwrap(),
            }
        }

        /// Delivers frames back and forth until quiet; returns inner packets seen as (to_exit, to_entry).
        fn pump(&mut self, mut to_exit: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let (mut at_exit, mut at_entry) = (Vec::new(), Vec::new());
            while !to_exit.is_empty() {
                let mut back = Wire::default();
                for f in &to_exit {
                    if let Some(inner) = self.exit.on_outer(self.t, f, &mut back) {
                        at_exit.push(inner.to_vec());
                    }
                }
                let mut fwd = Wire::default();
                for f in back.take() {
                    if let Some(inner) = self.entry.on_outer(self.t, &f, &mut fwd) {
                        at_entry.push(inner.to_vec());
                    }
                }
                to_exit = fwd.take();
            }
            (at_exit, at_entry)
        }

        fn connect(&mut self) -> TcpMeta {
            let mut w = Wire::default();
            self.entry.start(self.t, &mut w);
            let syn = parsed(&w.0[0]).meta;
            self.pump(w.take());
            assert_eq!(self.entry.state(), State::Established);
            assert_eq!(self.exit.state(), State::Established);
            syn
        }
    }

    fn encap(s: &mut Session, inner: &[u8], overhead: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; overhead + inner.len()];
        buf[overhead..].copy_from_slice(inner);
        s.encap(&mut buf, inner.len())
            .map(|(len, _)| buf[..len].to_vec())
    }

    struct AuthExchange {
        syn: Vec<u8>,
        ack: Vec<u8>,
        hello: Vec<u8>,
        challenge: Vec<u8>,
    }

    fn start_auth(entry: &mut Session, exit: &mut Session, now: Instant) -> AuthExchange {
        let mut wire = Wire::default();
        entry.start(now, &mut wire);
        let syn = wire.take().remove(0);
        exit.on_outer(now, &syn, &mut wire);
        let syn_ack = wire.take().remove(0);
        entry.on_outer(now, &syn_ack, &mut wire);
        let mut frames = wire.take();
        let ack = frames.remove(0);
        let hello = frames.remove(0);
        exit.on_outer(now, &ack, &mut wire);
        exit.on_outer(now, &hello, &mut wire);
        let challenge = wire.take().remove(0);
        AuthExchange {
            syn,
            ack,
            hello,
            challenge,
        }
    }

    fn frame(meta: TcpMeta, payload: &[u8]) -> Vec<u8> {
        let overhead = OuterFamily::of(meta.src.ip()).overhead();
        let mut buf = vec![0; overhead + payload.len()];
        buf[overhead..].copy_from_slice(payload);
        pkt::write_headers(&mut buf, &meta, payload.len(), 0);
        buf
    }

    #[test]
    fn old_proofs_fail_against_a_fresh_handshake_and_challenge() {
        let mut pair = Pair::new(0, 1, 91);
        let first = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &first.challenge, &mut wire);
        let old_proof = wire.take().remove(0);
        pair.t += Duration::from_secs(1);
        pair.entry = Session::new(cfg(Mode::Entry, 0, 1), pair.t, 92).unwrap();
        let second = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let stale_reply = frame(
            parsed(&second.challenge).meta,
            parsed(&first.challenge).payload,
        );
        pair.entry.on_outer(pair.t, &stale_reply, &mut wire);
        assert!(wire.take().is_empty());
        pair.entry.on_outer(pair.t, &second.challenge, &mut wire);
        let proof = wire.take().remove(0);
        let replay = frame(parsed(&proof).meta, parsed(&old_proof).payload);
        pair.exit.on_outer(pair.t, &replay, &mut wire);
        assert!(wire.take().is_empty());
        assert!(encap(&mut pair.exit, &[0x45; 20], 40).is_none());
        let mut body = parsed(&proof).payload.to_vec();
        body[147..].copy_from_slice(&parsed(&old_proof).payload[147..]);
        pair.exit
            .on_outer(pair.t, &frame(parsed(&proof).meta, &body), &mut wire);
        assert!(wire.take().is_empty());
        pair.pump(vec![proof]);
        let data = encap(&mut pair.entry, &[0x45; 20], 40).unwrap();
        assert_eq!(
            pair.exit.on_outer(pair.t, &data, &mut wire),
            Some(&[0x45; 20][..])
        );
    }

    #[test]
    fn finished_received_at_or_after_the_attempt_deadline_cannot_authorize() {
        for delay in [
            Duration::from_secs(15) - MS,
            Duration::from_secs(15),
            Duration::from_secs(16),
        ] {
            let mut pair = Pair::new(0, 1, 111);
            let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
            let mut wire = Wire::default();
            pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
            let proof = wire.take().remove(0);
            pair.exit.on_outer(pair.t, &proof, &mut wire);
            let finished = wire.take().remove(0);
            pair.entry.on_outer(pair.t + delay, &finished, &mut wire);
            let data = encap(&mut pair.entry, &[0x45; 20], 40);
            if delay < Duration::from_secs(15) {
                assert!(data.is_some());
            } else {
                assert!(
                    data.is_none(),
                    "receive processing must enforce the deadline before on_tick"
                );
                let outgoing = wire.take();
                let syn = outgoing
                    .iter()
                    .find(|f| parsed(f).meta.flags == flags::SYN)
                    .unwrap();
                assert_ne!(parsed(syn).meta.src.port(), parsed(&proof).meta.src.port());
            }
        }
    }

    #[test]
    fn authentication_timeout_rotates_the_port_and_expired_cookies_cannot_admit() {
        let mut pair = Pair::new(0, 1, 101);
        let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
        let proof = wire.take().remove(0);
        let old = parsed(&proof).meta;
        pair.entry.on_outer(
            pair.t + Duration::from_secs(14),
            &exchange.challenge,
            &mut wire,
        );
        assert!(wire.take().is_empty());
        pair.entry
            .on_tick(pair.t + Duration::from_secs(15), &mut wire);
        let retry = wire.take();
        let syn = retry
            .iter()
            .find(|f| parsed(f).meta.flags == flags::SYN)
            .unwrap();
        assert_ne!(parsed(syn).meta.src.port(), old.src.port());
        assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
        pair.exit
            .on_outer(pair.t + Duration::from_secs(30) + MS, &proof, &mut wire);
        assert!(wire.take().is_empty());
        assert!(encap(&mut pair.exit, &[0x45; 20], 40).is_none());
        pair.t += Duration::from_secs(31);
        pair.entry = Session::new(cfg(Mode::Entry, 0, 1), pair.t, 102).unwrap();
        pair.connect();
        let data = encap(&mut pair.entry, &[0x45; 20], 40).unwrap();
        assert_eq!(
            pair.exit.on_outer(pair.t, &data, &mut wire),
            Some(&[0x45; 20][..])
        );
    }

    #[test]
    fn each_lost_authentication_message_recovers_without_reconsuming_sequence_space() {
        use std::collections::{BTreeMap, VecDeque};
        for lost_kind in [auth::HELLO, auth::CHALLENGE, auth::PROOF, auth::FINISHED] {
            let mut pair = Pair::new(0, 1, 81);
            let mut wire = Wire::default();
            pair.entry.start(pair.t, &mut wire);
            let syn = wire.take().remove(0);
            let entry_isn = parsed(&syn).meta.seq;
            let mut exit_isn = None;
            let mut queue = VecDeque::from([(true, syn)]);
            let mut dropped = false;
            let mut requests = BTreeMap::new();
            let mut proof = None;
            for round in 0..3 {
                let now = pair.t + Duration::from_secs(round);
                let mut count = 0;
                while let Some((to_exit, packet)) = queue.pop_front() {
                    count += 1;
                    assert!(count < 100, "authentication must not form a response loop");
                    let p = parsed(&packet);
                    if p.meta.flags == flags::SYN | flags::ACK {
                        exit_isn = Some(p.meta.seq);
                    }
                    if p.payload.first() == Some(&auth::CONTROL) {
                        let kind = p.payload[2];
                        if to_exit {
                            let value = (p.meta, p.payload.to_vec());
                            if let Some(previous) = requests.insert(kind, value.clone()) {
                                assert_eq!(previous, value);
                            }
                            if kind == auth::PROOF {
                                proof = Some(packet.clone());
                            }
                        }
                        if kind == lost_kind && !dropped {
                            dropped = true;
                            continue;
                        }
                    }
                    if to_exit {
                        pair.exit.on_outer(now, &packet, &mut wire);
                    } else {
                        pair.entry.on_outer(now, &packet, &mut wire);
                    }
                    queue.extend(wire.take().into_iter().map(|f| (!to_exit, f)));
                }
                pair.entry.on_tick(now + SYN_RETRY, &mut wire);
                queue.extend(wire.take().into_iter().map(|f| (true, f)));
            }
            assert!(dropped);
            pair.t += Duration::from_secs(3);
            let first = encap(&mut pair.entry, &[0x45; 100], 40).unwrap();
            let back = encap(&mut pair.exit, &[0x60; 80], 40).unwrap();
            assert_eq!(parsed(&first).meta.seq, entry_isn.wrapping_add(215));
            assert_eq!(parsed(&back).meta.seq, exit_isn.unwrap().wrapping_add(191));
            assert_eq!(
                pair.exit.on_outer(pair.t, &first, &mut wire),
                Some(&[0x45; 100][..])
            );
            assert_eq!(
                pair.entry.on_outer(pair.t, &back, &mut wire),
                Some(&[0x60; 80][..])
            );
            pair.exit.on_outer(pair.t, &proof.unwrap(), &mut wire);
            for duplicate in wire.take() {
                pair.entry.on_outer(pair.t, &duplicate, &mut wire);
            }
            let after = encap(&mut pair.entry, &[0x45; 1], 40).unwrap();
            assert_eq!(
                parsed(&after).meta.seq,
                parsed(&first).meta.seq.wrapping_add(100)
            );
            assert_eq!(
                parsed(&after).meta.ack,
                parsed(&back).meta.seq.wrapping_add(80)
            );
        }
    }

    #[test]
    fn legitimate_replacement_survives_unrelated_attempts_and_old_proof_replays() {
        let mut pair = Pair::new(0, 1, 71);
        let original = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &original.challenge, &mut wire);
        let old_proof = wire.take().remove(0);
        pair.pump(vec![old_proof.clone()]);
        let mut config = cfg(Mode::Entry, 0, 1);
        config.local_ip = "203.0.113.7".parse().unwrap();
        let mut replacement = Session::new(config, pair.t, 72).unwrap();
        let now = pair.t + Duration::from_secs(1);
        let exchange = start_auth(&mut replacement, &mut pair.exit, now);
        replacement.on_outer(now, &exchange.challenge, &mut wire);
        let proof = wire.take().remove(0);
        for i in 0..128 {
            let mut wrong = cfg(Mode::Entry, 0, 1);
            wrong.local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20 + i));
            wrong.auth_key = AuthKey([0xb8; 32]);
            let mut wrong = Session::new(wrong, now, u64::from(i) + 100).unwrap();
            let attempt = start_auth(&mut wrong, &mut pair.exit, now);
            wrong.on_outer(now, &attempt.challenge, &mut wire);
            assert!(wire.take().is_empty());
            let data = encap(&mut pair.exit, &[0x45; 20], 40).unwrap();
            assert_eq!(
                pair.entry.on_outer(now, &data, &mut wire),
                Some(&[0x45; 20][..])
            );
        }
        pair.exit.on_outer(now, &proof, &mut wire);
        let mut promoted = wire.take();
        let resets: Vec<_> = promoted
            .iter()
            .filter(|f| parsed(f).meta.flags & flags::RST != 0)
            .collect();
        assert_eq!(
            resets.len(),
            2,
            "verified replacement must release the old firewall tuple"
        );
        assert!(resets
            .iter()
            .all(|f| parsed(f).meta.dst == parsed(&original.syn).meta.src));
        let finished = promoted.pop().unwrap();
        replacement.on_outer(now, &finished, &mut wire);
        wire.take();
        let inner = [0x60; 40];
        let data = encap(&mut replacement, &inner, 40).unwrap();
        assert_eq!(pair.exit.on_outer(now, &data, &mut wire), Some(&inner[..]));
        pair.exit.on_outer(now, &old_proof, &mut wire);
        pair.exit.on_outer(now, &original.hello, &mut wire);
        wire.take();
        let reply = encap(&mut pair.exit, &inner, 40).unwrap();
        assert_eq!(parsed(&reply).meta.dst, parsed(&proof).meta.src);
        assert_eq!(
            replacement.on_outer(now, &reply, &mut wire),
            Some(&inner[..])
        );
    }

    #[test]
    fn unauthenticated_candidates_cannot_replace_or_keep_an_active_peer_alive() {
        let mut pair = Pair::new(0, 1, 61);
        let original = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &original.challenge, &mut wire);
        let proof = wire.take().remove(0);
        pair.pump(vec![proof.clone()]);
        let before = parsed(&encap(&mut pair.exit, &[0x45; 7], 40).unwrap()).meta;
        let mut candidate = cfg(Mode::Entry, 0, 1);
        candidate.local_ip = "192.0.2.77".parse().unwrap();
        candidate.auth_key = AuthKey([0xb8; 32]);
        let mut candidate = Session::new(candidate, pair.t, 62).unwrap();
        let now = pair.t + Duration::from_secs(14);
        let exchange = start_auth(&mut candidate, &mut pair.exit, now);
        candidate.on_outer(now, &exchange.challenge, &mut wire);
        assert!(wire.take().is_empty());
        for packet in [
            &original.syn,
            &original.ack,
            &original.hello,
            &proof,
            &exchange.hello,
        ] {
            assert!(pair.exit.on_outer(now, packet, &mut wire).is_none());
            wire.take();
        }
        let mut invalid = parsed(&proof).payload.to_vec();
        invalid[178] ^= 1;
        assert!(pair
            .exit
            .on_outer(now, &frame(parsed(&proof).meta, &invalid), &mut wire)
            .is_none());
        assert!(pair
            .exit
            .on_outer(
                now,
                &frame(parsed(&exchange.hello).meta, &[0x45; 20]),
                &mut wire
            )
            .is_none());
        let after = encap(&mut pair.exit, &[0x60; 40], 40).unwrap();
        assert_eq!(parsed(&after).meta.dst, before.dst);
        assert_eq!(parsed(&after).meta.seq, before.seq.wrapping_add(7));
        assert_eq!(
            pair.entry.on_outer(now, &after, &mut wire),
            Some(&[0x60; 40][..])
        );
        pair.exit
            .on_tick(pair.t + Duration::from_secs(15), &mut wire);
        assert!(
            encap(&mut pair.exit, &[0x45; 20], 40).is_none(),
            "candidate traffic must not postpone active expiry"
        );
        pair.exit
            .on_outer(pair.t + Duration::from_secs(16), &proof, &mut wire);
        assert!(
            encap(&mut pair.exit, &[0x45; 20], 40).is_none(),
            "a completed proof must not resurrect an expired peer"
        );
    }

    #[test]
    fn invalid_or_reflected_proofs_cannot_authorize_either_role() {
        let mut pair = Pair::new(0, 1, 51);
        let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let challenge = parsed(&exchange.challenge);
        let mut malformed = Vec::new();
        for index in [1, 2, 19, 146] {
            let mut body = challenge.payload.to_vec();
            body[index] ^= 0xff;
            malformed.push(body);
        }
        malformed.push(challenge.payload[..146].to_vec());
        malformed.push([challenge.payload, &[0]].concat());
        let mut wire = Wire::default();
        for body in malformed {
            pair.entry
                .on_outer(pair.t, &frame(challenge.meta, &body), &mut wire);
            assert!(wire.take().is_empty());
            assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
        }
        pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
        let proof = wire.take().remove(0);
        let request = parsed(&proof);
        let mut reflected = request.payload.to_vec();
        reflected[147..179].copy_from_slice(&request.payload[115..147]);
        let mut malformed = vec![
            reflected,
            request.payload[..178].to_vec(),
            [request.payload, &[0]].concat(),
        ];
        for index in [1, 2, 3, 11, 51, 83, 178] {
            let mut body = request.payload.to_vec();
            body[index] ^= 0xff;
            malformed.push(body);
        }
        for body in malformed {
            assert!(pair
                .exit
                .on_outer(pair.t, &frame(request.meta, &body), &mut wire)
                .is_none());
            assert!(wire.take().is_empty());
            assert!(encap(&mut pair.exit, &[0x60; 40], 40).is_none());
        }
        assert!(pair
            .exit
            .on_outer(pair.t, &frame(request.meta, &[0x45; 20]), &mut wire)
            .is_none());
        wire.take();
        pair.exit.on_outer(pair.t, &proof, &mut wire);
        let finished = wire.take().remove(0);
        let parsed_finished = parsed(&finished);
        let mut bad = parsed_finished.payload.to_vec();
        bad[11..].copy_from_slice(&request.payload[147..]);
        pair.entry
            .on_outer(pair.t, &frame(parsed_finished.meta, &bad), &mut wire);
        assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
        pair.entry.on_outer(pair.t, &finished, &mut wire);
        let inner = [0x45; 20];
        let packet = encap(&mut pair.entry, &inner, 40).unwrap();
        assert_eq!(
            pair.exit.on_outer(pair.t, &packet, &mut wire),
            Some(&inner[..])
        );
    }

    #[test]
    fn mismatched_keys_deny_forwarding_in_both_directions() {
        let mut pair = Pair::new(0, 1, 41);
        let mut wrong = cfg(Mode::Entry, 0, 1);
        wrong.auth_key = AuthKey([0xb8; 32]);
        pair.entry = Session::new(wrong, pair.t, 41).unwrap();
        let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
        assert!(
            wire.take().is_empty(),
            "Entry must not prove itself to an untrusted Exit"
        );
        assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
        assert!(encap(&mut pair.exit, &[0x60; 40], 40).is_none());
        pair.entry
            .on_tick(pair.t + Duration::from_secs(15), &mut wire);
        assert!(wire
            .take()
            .iter()
            .any(|f| parsed(f).meta.flags == flags::SYN));
    }

    #[test]
    fn entry_source_port_stays_in_worker_residue_class() {
        for seed in 0..50 {
            let t = Instant::now();
            let mut s = Session::new(cfg(Mode::Entry, 3, 4), t, seed * 7919).unwrap();
            let mut w = Wire::default();
            s.start(t, &mut w);
            let port = parsed(&w.take()[0]).meta.src.port();
            assert_eq!(port % 4, 3);
            assert!(port >= 32768);
        }
    }

    #[test]
    fn handshake_options_are_preserved_but_forwarding_requires_mutual_authentication() {
        let mut p = Pair::new(1, 4, 42);
        let mut w = Wire::default();
        p.entry.start(p.t, &mut w);
        let syn = w.take();
        let s = parsed(&syn[0]);
        assert_eq!(s.meta.flags, flags::SYN);
        assert_eq!(s.meta.dst, EXIT);
        assert_eq!(syn[0].len(), pkt::SYN_FRAME_LEN);
        assert_eq!(p.entry.state(), State::SynSent);

        let mut w = Wire::default();
        assert!(p.exit.on_outer(p.t, &syn[0], &mut w).is_none());
        assert!(encap(&mut p.exit, &[0x45; 20], 40).is_none());
        let synack = w.take();
        let sa = parsed(&synack[0]);
        assert_eq!(sa.meta.flags, flags::SYN | flags::ACK);
        assert_eq!(sa.meta.ack, s.meta.seq.wrapping_add(1));
        assert_eq!(sa.meta.dst, s.meta.src);

        let mut w = Wire::default();
        p.entry.on_outer(p.t, &synack[0], &mut w);
        assert!(encap(&mut p.entry, &[0x45; 20], 40).is_none());
        let ack = w.take();
        assert_eq!(parsed(&ack[0]).meta.flags, flags::ACK);
        p.pump(ack);
        assert_eq!(p.entry.state(), State::Established);
        assert_eq!(p.exit.state(), State::Established);
        let reply = encap(&mut p.exit, &[0x45; 20], 40).unwrap();
        assert_eq!(parsed(&reply).meta.dst, s.meta.src);
        assert_eq!(
            p.entry.on_outer(p.t, &reply, &mut Wire::default()),
            Some(&[0x45; 20][..])
        );
    }

    #[test]
    fn inner_dual_stack_flows_over_both_outer_families_without_extra_control() {
        for ipv6 in [false, true] {
            let mut p = Pair::new(0, 2, 7);
            if ipv6 {
                let mut entry = cfg(Mode::Entry, 0, 2);
                entry.local_ip = "2001:db8:1::1".parse().unwrap();
                entry.remote = Some("[2001:db8:2::1]:443".parse().unwrap());
                let mut exit = cfg(Mode::Exit, 0, 2);
                exit.local_ip = "::".parse().unwrap();
                p.entry = Session::new(entry, p.t, 7).unwrap();
                p.exit = Session::new(exit, p.t, 8).unwrap();
            }
            p.connect();
            let overhead = if ipv6 { 60 } else { 40 };
            let v4 = [0x45, 0, 0, 20, 1, 2, 3];
            let v6 = [0x60, 0, 0, 0, 9];
            let f4 = encap(&mut p.entry, &v4, overhead).unwrap();
            assert_eq!(f4.len(), v4.len() + overhead);
            let f6 = encap(&mut p.entry, &v6, overhead).unwrap();
            let (at_exit, _) = p.pump(vec![f4, f6]);
            assert_eq!(at_exit, vec![v4.to_vec(), v6.to_vec()]);
            let back = encap(&mut p.exit, &v6, overhead).unwrap();
            let mut w = Wire::default();
            assert_eq!(p.entry.on_outer(p.t, &back, &mut w), Some(&v6[..]));
            assert!(w.0.is_empty(), "no reply below ACK threshold");
        }
    }

    #[test]
    fn sequence_numbers_advance_by_payload_and_ack_tracks_peer() {
        let mut p = Pair::new(0, 1, 3);
        p.connect();
        let a = parsed(&encap(&mut p.entry, &[0x45; 100], 40).unwrap()).meta;
        let b = parsed(&encap(&mut p.entry, &[0x45; 10], 40).unwrap()).meta;
        assert_eq!(b.seq, a.seq.wrapping_add(100));
        let from_exit = encap(&mut p.exit, &[0x60; 30], 40).unwrap();
        let exit_seq = parsed(&from_exit).meta.seq;
        p.entry.on_outer(p.t, &from_exit, &mut Wire::default());
        let c = parsed(&encap(&mut p.entry, &[0x45; 1], 40).unwrap()).meta;
        assert_eq!(c.ack, exit_seq.wrapping_add(30));
        assert_eq!(c.flags, flags::PSH | flags::ACK);
    }

    #[test]
    fn encap_drops_until_established() {
        let mut s = Session::new(cfg(Mode::Entry, 0, 1), Instant::now(), 1).unwrap();
        assert!(encap(&mut s, &[0x45; 20], 40).is_none());
        s.start(Instant::now(), &mut Wire::default());
        assert!(encap(&mut s, &[0x45; 20], 40).is_none());
    }

    #[test]
    fn ping_is_answered_with_pong_echoing_nonce() {
        let mut p = Pair::new(0, 1, 9);
        p.connect();
        let mut w = Wire::default();
        p.entry.on_tick(p.t + Duration::from_secs(5), &mut w);
        let ping = w.take();
        assert_eq!(ping.len(), 1);
        let payload = parsed(&ping[0]).payload.to_vec();
        assert_eq!((payload[0], payload.len()), (CTRL_PING, CTRL_LEN));

        let mut w = Wire::default();
        assert!(p.exit.on_outer(p.t, &ping[0], &mut w).is_none());
        let pong = w.take();
        let pong_payload = parsed(&pong[0]).payload;
        assert_eq!(pong_payload[0], CTRL_PONG);
        assert_eq!(pong_payload[1..], payload[1..]);
        assert!(p
            .entry
            .on_outer(p.t, &pong[0], &mut Wire::default())
            .is_none());
    }

    #[test]
    fn traffic_from_peer_defers_dead_timeout() {
        let mut p = Pair::new(0, 1, 11);
        let original = p.connect().src;
        for _ in 0..5 {
            p.t += Duration::from_secs(5);
            let mut w = Wire::default();
            p.entry.on_tick(p.t, &mut w);
            let frames = w.take();
            assert!(frames.iter().all(|f| parsed(f).meta.src == original));
            p.pump(frames);
        }
        assert_eq!(p.entry.state(), State::Established);
        assert!(p.entry.next_deadline() <= p.t + Duration::from_secs(5));
    }

    #[test]
    fn bulk_receive_triggers_bare_ack_at_threshold() {
        let mut p = Pair::new(0, 1, 5);
        p.connect();
        let chunk = vec![0x45u8; 60000];
        let mut acks = Vec::new();
        let mut received = 0u32;
        for _ in 0..20 {
            let f = encap(&mut p.exit, &chunk, 40).unwrap();
            let end = parsed(&f).meta.seq.wrapping_add(chunk.len() as u32);
            let mut w = Wire::default();
            p.entry.on_outer(p.t, &f, &mut w);
            received += chunk.len() as u32;
            for a in w.take() {
                acks.push((received, end, parsed(&a).meta));
            }
        }
        assert_eq!(acks.len(), 1);
        let (at, end, meta) = acks[0];
        assert!(at >= ACK_THRESHOLD && at - (chunk.len() as u32) < ACK_THRESHOLD);
        assert_eq!(meta.flags, flags::ACK);
        assert_eq!(meta.ack, end, "acks everything received so far");
    }

    #[test]
    fn dead_entry_sends_two_rsts_then_resyncs_on_rotated_port() {
        let mut p = Pair::new(2, 4, 13);
        let old = p.connect().src.port();
        let mut w = Wire::default();
        p.entry.on_tick(p.t + Duration::from_secs(15) - MS, &mut w);
        assert!(
            w.0.iter().all(|f| parsed(f).meta.flags & flags::RST == 0),
            "not dead yet"
        );
        w.take();

        p.entry.on_tick(p.t + Duration::from_secs(15), &mut w);
        let frames = w.take();
        let metas: Vec<_> = frames.iter().map(|f| parsed(f).meta).collect();
        assert_eq!(metas.len(), 3);
        for rst in &metas[..2] {
            assert_eq!(rst.flags, flags::RST | flags::ACK);
            assert_eq!(rst.src.port(), old);
        }
        assert_eq!(metas[2].flags, flags::SYN);
        assert_eq!(metas[2].src.port(), old + 4);
        assert_eq!(metas[2].src.port() % 4, 2);
        assert_eq!(p.entry.state(), State::SynSent);

        // Exit side accepts the new tuple and replaces its stale peer.
        p.pump(vec![frames[2].clone()]);
        let reply = encap(&mut p.exit, &[0x45; 20], 40).unwrap();
        assert_eq!(parsed(&reply).meta.dst, metas[2].src);
        assert_eq!(
            p.entry.on_outer(p.t, &reply, &mut Wire::default()),
            Some(&[0x45; 20][..])
        );
        assert_eq!(p.entry.state(), State::Established);
    }

    #[test]
    fn source_port_rotation_wraps_to_start_of_pool() {
        let mut c = cfg(Mode::Entry, 1, 2);
        c.base_port = 65530;
        let t = Instant::now();
        let mut s = Session::new(c, t, 2).unwrap(); // pool: 65531, 65533, 65535
        let mut w = Wire::default();
        s.start(t, &mut w);
        assert_eq!(parsed(&w.take()[0]).meta.src.port(), 65535);
        s.on_tick(t + Duration::from_secs(15), &mut w);
        let frames = w.take();
        assert_eq!(parsed(frames.last().unwrap()).meta.src.port(), 65531);
    }

    #[test]
    fn syn_is_retried_then_port_rotates_after_dead_timeout() {
        let t = Instant::now();
        let mut s = Session::new(cfg(Mode::Entry, 0, 1), t, 1).unwrap();
        let mut w = Wire::default();
        s.start(t, &mut w);
        let first = parsed(&w.take()[0]).meta;
        assert_eq!(s.next_deadline(), t + SYN_RETRY);
        let rst = frame(
            TcpMeta {
                src: first.dst,
                dst: first.src,
                seq: 0,
                ack: first.seq.wrapping_add(1),
                flags: flags::RST | flags::ACK,
                window: 0,
            },
            &[],
        );
        assert!(s.on_outer(t, &rst, &mut w).is_none());
        assert!(
            w.take().is_empty(),
            "SynSent RST must not spin immediate reconnect"
        );
        s.on_tick(t + SYN_RETRY, &mut w);
        let retry = parsed(&w.take()[0]).meta;
        assert_eq!(
            (retry.flags, retry.seq, retry.src),
            (flags::SYN, first.seq, first.src)
        );
        s.on_tick(t + Duration::from_secs(15), &mut w);
        let reconnect = w.take();
        assert_ne!(
            parsed(reconnect.last().unwrap()).meta.src.port(),
            first.src.port()
        );
        assert_eq!(s.state(), State::SynSent);
    }

    #[test]
    fn exit_resets_unknown_peers_and_entry_reconnects_on_rst() {
        let mut p = Pair::new(0, 1, 17);
        p.connect();
        // Exit lost its state (e.g. restarted).
        p.exit = Session::new(cfg(Mode::Exit, 0, 1), p.t, 99).unwrap();
        let data = encap(&mut p.entry, &[0x45; 20], 40).unwrap();
        let mut w = Wire::default();
        assert!(p.exit.on_outer(p.t, &data, &mut w).is_none());
        let rst = w.take();
        let r = parsed(&rst[0]).meta;
        assert_eq!(r.flags, flags::RST);
        assert_eq!(r.seq, parsed(&data).meta.ack);

        let old = parsed(&data).meta.src.port();
        let mut w = Wire::default();
        p.entry.on_outer(p.t, &rst[0], &mut w);
        let syn = w.take();
        assert_eq!(syn.len(), 1, "peer already reset: no RST of our own");
        assert_eq!(parsed(&syn[0]).meta.flags, flags::SYN);
        assert_ne!(parsed(&syn[0]).meta.src.port(), old);
        p.pump(syn);
        assert_eq!(p.exit.state(), State::Established);
    }

    #[test]
    fn exit_times_out_silently() {
        let mut p = Pair::new(0, 1, 19);
        p.connect();
        let mut w = Wire::default();
        p.exit.on_tick(p.t + Duration::from_secs(15), &mut w);
        assert!(w.0.is_empty());
        assert_eq!(p.exit.state(), State::Closed);
        assert!(encap(&mut p.exit, &[0x45; 20], 40).is_none());
    }

    #[test]
    fn frames_for_other_tuples_are_ignored() {
        let mut p = Pair::new(0, 1, 23);
        p.connect();
        let mut stray = encap(&mut p.exit, &[0x45; 8], 40).unwrap();
        let port = parsed(&stray).meta.dst.port();
        stray[22..24].copy_from_slice(&(port + 1).to_be_bytes()); // dport
        let mut w = Wire::default();
        assert!(p.entry.on_outer(p.t, &stray, &mut w).is_none());
        let mut w2 = Wire::default();
        p.entry.on_tick(p.t + Duration::from_secs(15), &mut w2);
        assert!(
            w2.take()
                .iter()
                .any(|f| parsed(f).meta.flags & flags::RST != 0),
            "stray frame did not refresh liveness"
        );
    }

    #[test]
    fn duplicate_syn_gets_identical_synack() {
        let t = Instant::now();
        let mut entry = Session::new(cfg(Mode::Entry, 0, 1), t, 1).unwrap();
        let mut exit = Session::new(cfg(Mode::Exit, 0, 1), t, 2).unwrap();
        let mut w = Wire::default();
        entry.start(t, &mut w);
        let syn = w.take().remove(0);
        exit.on_outer(t, &syn, &mut w);
        exit.on_outer(t, &syn, &mut w);
        let sa = w.take();
        assert_eq!(parsed(&sa[0]).meta.seq, parsed(&sa[1]).meta.seq);
    }

    #[test]
    fn delayed_duplicate_syn_preserves_established_sequence_space() {
        for (entry_ip, remote, overhead) in [
            (ENTRY_IP, EXIT, 40),
            (
                "2001:db8:1::1".parse().unwrap(),
                "[2001:db8:2::1]:443".parse().unwrap(),
                60,
            ),
        ] {
            for data_first in [false, true] {
                let mut entry = cfg(Mode::Entry, 0, 1);
                entry.local_ip = entry_ip;
                entry.remote = Some(remote);
                let mut exit = cfg(Mode::Exit, 0, 1);
                exit.local_ip = remote.ip();
                let t = Instant::now();
                let mut p = Pair {
                    t,
                    entry: Session::new(entry, t, 31).unwrap(),
                    exit: Session::new(exit, t, 32).unwrap(),
                };
                let mut w = Wire::default();
                p.entry.start(p.t, &mut w);
                let syn = w.take().remove(0);
                p.exit.on_outer(p.t, &syn, &mut w);
                let synack = w.take().remove(0);
                let original = parsed(&synack).meta;
                p.entry.on_outer(p.t, &synack, &mut w);
                p.pump(w.take());

                if data_first {
                    let inner = [0x45; 100];
                    let data = encap(&mut p.entry, &inner, overhead).unwrap();
                    assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
                    let reply = encap(&mut p.exit, &inner, overhead).unwrap();
                    assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
                }
                p.t += Duration::from_secs(2);
                p.exit.on_outer(p.t, &syn, &mut w);
                let duplicate = w.take().remove(0);
                assert_eq!(parsed(&duplicate).meta, original);
                p.entry.on_outer(p.t, &duplicate, &mut w);
                let ack = w.take().remove(0);
                p.exit.on_outer(p.t, &ack, &mut w);

                let inner = [0x45; 20];
                let data = encap(&mut p.entry, &inner, overhead).unwrap();
                assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
                let reply = encap(&mut p.exit, &inner, overhead).unwrap();
                assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
                let expected = original
                    .seq
                    .wrapping_add(1 + auth::EXIT_BYTES + if data_first { 100 } else { 0 });
                assert_eq!(parsed(&data).meta.ack, expected);
                assert_eq!(parsed(&reply).meta.seq, expected);
            }
        }
    }

    #[test]
    fn new_syn_on_same_tuple_can_replace_established_peer() {
        let mut p = Pair::new(0, 1, 31);
        let original = p.connect();
        p.t += Duration::from_secs(2);
        p.entry = Session::new(cfg(Mode::Entry, 0, 1), p.t, 31 + 32768).unwrap();
        let mut w = Wire::default();
        p.entry.start(p.t, &mut w);
        let frames = w.take();
        let replacement = parsed(&frames[0]).meta;
        assert_eq!(replacement.src, original.src);
        assert_ne!(replacement.seq, original.seq);
        p.pump(frames);
        let inner = [0x45; 20];
        let data = encap(&mut p.entry, &inner, 40).unwrap();
        assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
        let reply = encap(&mut p.exit, &inner, 40).unwrap();
        assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
    }

    #[test]
    fn shutdown_resets_live_session() {
        let mut p = Pair::new(0, 1, 29);
        p.connect();
        let mut w = Wire::default();
        p.entry.shutdown(&mut w);
        let f = w.take();
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| parsed(f).meta.flags & flags::RST != 0));
        assert_eq!(p.entry.state(), State::Closed);
        p.entry.shutdown(&mut w);
        assert!(w.0.is_empty());
    }

    #[test]
    fn reload_updates_timers_in_place_and_rotates_session_on_key_change() {
        let mut p = Pair::new(0, 2, 41);
        let first_tuple = p.connect();
        let key1 = AuthKey([0xa7; 32]);
        let key2 = AuthKey([0xb8; 32]);

        // 1. In-place timer update with unchanged key emits no frames and keeps the session live.
        let mut w = Wire::default();
        assert!(!p.entry.reload(
            p.t,
            key1.clone(),
            Duration::from_secs(2),
            Duration::from_secs(9),
            &mut w,
        ));
        assert!(w.0.is_empty());
        assert!(p.entry.is_established());
        assert_eq!(p.entry.next_deadline(), p.t + Duration::from_secs(2));

        let inner = [0x45; 20];
        let data = encap(&mut p.entry, &inner, 40).unwrap();
        assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));

        // 2. Entry key rotation emits RSTs on the old tuple + SYN on the next port in its pool.
        p.t += Duration::from_secs(1);
        assert!(p.entry.reload(
            p.t,
            key2.clone(),
            Duration::from_secs(2),
            Duration::from_secs(9),
            &mut w,
        ));
        assert!(!p.entry.is_established());
        let frames = w.take();
        assert!(frames.iter().any(|f| {
            let m = parsed(f).meta;
            m.src == first_tuple.src && m.flags & flags::RST != 0
        }));
        let syn = frames
            .iter()
            .find(|f| parsed(f).meta.flags == flags::SYN)
            .expect("entry reload must initiate a new SYN");
        assert_eq!(parsed(syn).meta.src.port(), first_tuple.src.port() + 2);

        // Before Exit reloads its key, handshake cannot complete.
        p.pump(frames);
        assert!(!p.entry.is_established());
        assert!(!p.exit.is_established());

        // Once Exit reloads to key2 (while Closed, so no RST emitted), the next retry establishes.
        assert!(!p.exit.reload(
            p.t,
            key2.clone(),
            Duration::from_secs(2),
            Duration::from_secs(9),
            &mut w,
        ));
        assert!(w.0.is_empty());
        p.t += SYN_RETRY;
        p.entry.on_tick(p.t, &mut w);
        let retry = w.take();
        p.pump(retry);
        assert!(p.entry.is_established());
        assert!(p.exit.is_established());

        // 3. Exit-first key rotation on an Established session emits RST, prompting Entry to
        // immediately reconnect; once Entry also reloads key1, session re-establishes immediately.
        p.t += Duration::from_secs(1);
        assert!(p.exit.reload(
            p.t,
            key1.clone(),
            Duration::from_secs(2),
            Duration::from_secs(9),
            &mut w,
        ));
        assert!(!p.exit.is_established());
        let exit_rst = w.take();
        assert!(exit_rst
            .iter()
            .all(|f| parsed(f).meta.flags & flags::RST != 0));
        for f in &exit_rst {
            p.entry.on_outer(p.t, f, &mut w);
        }
        p.pump(w.take());
        assert!(!p.entry.is_established());

        assert!(!p.entry.reload(
            p.t,
            key1,
            Duration::from_secs(2),
            Duration::from_secs(9),
            &mut w,
        ));
        let entry_reconn = w.take();
        p.pump(entry_reconn);
        assert!(p.entry.is_established());
        assert!(p.exit.is_established());

        let data = encap(&mut p.entry, &inner, 40).unwrap();
        assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
    }
}
