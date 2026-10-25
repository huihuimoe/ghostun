//! Per-worker FakeTCP session: handshake, seq/ack upkeep, health ping/pong and reconnect.
//! Pure logic: frames in, frames out through [`Sink`]; the worker owns all I/O.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub mod auth;
pub mod pkt;
#[cfg(test)]
mod tests;
pub mod worker;

use crate::config::{AuthKey, Mode, OuterFamily};
pub use auth::{Auth, EntryStep, ExitStep, HELLO_LEN, PROOF_LEN};
pub use pkt::{
    entry_filter, exit_filter, flags, TcpMeta, CTRL_LEN, CTRL_PING, CTRL_PONG, MAX_OVERHEAD,
};
pub use worker::run;
#[cfg(test)]
pub use worker::sync_reload;

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

fn emit(scratch: &mut [u8], meta: &TcpMeta, payload: &[u8], id: u16, out: &mut impl Sink) {
    let overhead = OuterFamily::of(meta.src.ip()).overhead();
    scratch[overhead..overhead + payload.len()].copy_from_slice(payload);
    let len = pkt::write_headers(scratch, meta, payload.len(), id);
    out.send(&scratch[..len], meta.dst.ip());
}

pub struct Session {
    cfg: SessionConfig,
    auth: Auth,
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
        match self.cfg.mode {
            Mode::Entry => self.on_entry_outer(now, &p.meta, p.payload, out),
            Mode::Exit => self.on_exit_outer(now, &p.meta, p.payload, out),
        }
    }

    fn on_entry_outer<'a>(
        &mut self,
        now: Instant,
        m: &TcpMeta,
        payload: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        if Some(m.src) != self.peer || m.dst != self.local {
            if Some(m.src) == self.peer
                && m.dst.ip() == self.local.ip()
                && m.flags & (flags::RST | flags::SYN) == 0
                && m.flags & flags::ACK != 0
                && !payload.is_empty()
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
                && payload.is_empty()
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
            self.on_auth_reply(now, m, payload, out);
            return None;
        }
        if payload.first() == Some(&auth::CONTROL) {
            return None;
        }
        if self.state == State::Established {
            return self.on_segment(now, m, payload, out);
        }
        None
    }

    fn on_exit_outer<'a>(
        &mut self,
        now: Instant,
        m: &TcpMeta,
        payload: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        if m.dst.port() != self.cfg.listen_port {
            return None;
        }
        let from_peer =
            self.state == State::Established && Some(m.src) == self.peer && m.dst == self.local;
        if m.flags & flags::RST != 0 {
            if from_peer {
                self.close();
            }
            return None;
        }
        if m.flags & flags::SYN != 0 {
            if m.flags & flags::ACK == 0 && payload.is_empty() {
                self.accept_syn(now, m, out);
            }
            return None;
        }
        if m.flags & flags::ACK == 0 {
            return None;
        }
        if payload.first() == Some(&auth::CONTROL) {
            self.on_auth_request(now, m, payload, out);
            return None;
        }
        if !from_peer {
            // A transport ACK alone neither admits nor keeps a candidate alive.
            if !payload.is_empty() {
                self.send_rst_to(m.dst, m.src, m.ack, out);
            }
            return None;
        }
        self.on_segment(now, m, payload, out)
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
        self.auth.reset();
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
        match self
            .auth
            .on_entry_reply(self.iss, self.irs, self.snd_nxt, m, payload)
        {
            Some(EntryStep::SendProof { rcv_nxt, snd_nxt }) => {
                self.rcv_nxt = rcv_nxt;
                self.snd_nxt = snd_nxt;
                self.next_syn = now + SYN_RETRY;
                self.send_pending(out);
            }
            Some(EntryStep::Established { rcv_nxt }) => {
                self.rcv_nxt = rcv_nxt;
                self.established(now);
                self.send_ctrl(flags::ACK, &[], out);
            }
            None => {}
        }
    }

    fn on_auth_request(&mut self, now: Instant, m: &TcpMeta, payload: &[u8], out: &mut impl Sink) {
        if m.flags != flags::PSH | flags::ACK {
            return;
        }
        let established = self.state == State::Established;
        match self.auth.on_exit_request(now, established, m, payload) {
            Ok(ExitStep::Ignore) => {}
            Ok(ExitStep::Challenge(challenge)) => {
                self.reply_auth(m, payload.len(), &challenge, out);
            }
            Ok(ExitStep::Finished(finished)) => {
                self.reply_auth(m, payload.len(), &finished, out);
            }
            Ok(ExitStep::Promote(p)) => {
                // Do not reset a reused tuple: conntrack may already associate it with this handshake.
                if established && (self.peer != Some(m.src) || self.local != m.dst) {
                    self.send_rsts(out);
                }
                self.local = m.dst;
                self.peer = Some(m.src);
                self.iss = p.iss;
                self.irs = p.irs;
                self.snd_nxt = p.snd_nxt;
                self.rcv_nxt = p.rcv_nxt;
                self.established(now);
                self.reply_auth(m, payload.len(), &p.finished, out);
            }
            Err(e) => log::error!("worker {}: authentication randomness: {e}", self.cfg.worker),
        }
    }

    fn reply_auth(&mut self, req: &TcpMeta, req_len: usize, reply: &[u8], out: &mut impl Sink) {
        let meta = TcpMeta {
            src: req.dst,
            dst: req.src,
            seq: req.ack,
            ack: req.seq.wrapping_add(req_len as u32),
            flags: flags::PSH | flags::ACK,
            window: WINDOW,
        };
        let id = self.next_ip_id();
        emit(&mut self.scratch, &meta, reply, id, out);
    }

    fn send_pending(&mut self, out: &mut impl Sink) {
        let Some(peer) = self.peer else { return };
        let id = self.next_ip_id();
        let mut meta = self.meta(peer, flags::PSH | flags::ACK);
        let Some((seq, frame)) = self.auth.pending() else {
            return;
        };
        meta.seq = seq;
        emit(&mut self.scratch, &meta, frame, id, out);
    }

    fn connect(&mut self, now: Instant, out: &mut impl Sink) {
        let iss = self.next_isn();
        let snd_nxt = iss.wrapping_add(1);
        if let Err(e) = self.auth.begin_entry(snd_nxt) {
            log::error!("worker {}: authentication randomness: {e}", self.cfg.worker);
            self.close();
            self.next_syn = now + SYN_RETRY;
            return;
        }
        self.iss = iss;
        self.snd_nxt = snd_nxt;
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
