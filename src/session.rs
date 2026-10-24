//! Per-worker FakeTCP session: handshake, seq/ack upkeep, health ping/pong and reconnect.
//! Pure logic: frames in, frames out through [`Sink`]; the worker owns all I/O.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::config::{Mode, OuterFamily};
use crate::pkt::{self, flags, TcpMeta, CTRL_LEN, CTRL_PING, CTRL_PONG, MAX_OVERHEAD};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    SynSent,
    SynReceived,
    Established,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub mode: Mode,
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

pub struct Session {
    cfg: SessionConfig,
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
    scratch: [u8; MAX_OVERHEAD + 16],
}

/// `a` is later than `b` in 32-bit sequence space.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

impl Session {
    pub fn new(cfg: SessionConfig, now: Instant, seed: u64) -> Self {
        let (local, peer) = match cfg.mode {
            Mode::Entry => {
                let (first, count) = port_pool(&cfg);
                let port = first + (seed % u64::from(count)) as u16 * cfg.conns;
                (SocketAddr::new(cfg.local_ip, port), cfg.remote)
            }
            Mode::Exit => (SocketAddr::new(cfg.local_ip, cfg.listen_port), None),
        };
        Session {
            cfg,
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
            scratch: [0; MAX_OVERHEAD + 16],
        }
    }

    #[cfg(test)]
    pub fn state(&self) -> State {
        self.state
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
                if Some(m.src) != self.peer || m.dst.port() != self.local.port() {
                    return None;
                }
                if m.flags & flags::RST != 0 {
                    if matches!(self.state, State::SynSent | State::Established) {
                        self.reconnect(now, false, out);
                    }
                    return None;
                }
                match self.state {
                    State::SynSent => {
                        if m.flags & (flags::SYN | flags::ACK) == flags::SYN | flags::ACK
                            && m.ack == self.snd_nxt
                        {
                            self.rcv_nxt = m.seq.wrapping_add(1);
                            self.established(now);
                            self.send_ctrl(flags::ACK, &[], out);
                        }
                        None
                    }
                    State::Established if m.flags & flags::SYN != 0 => {
                        // Our handshake ACK was lost and the exit retransmitted SYN-ACK.
                        self.send_ctrl(flags::ACK, &[], out);
                        None
                    }
                    State::Established => self.on_segment(now, &m, p.payload, out),
                    State::Closed | State::SynReceived => None,
                }
            }
            Mode::Exit => {
                if m.dst.port() != self.cfg.listen_port {
                    return None;
                }
                let from_peer = Some(m.src) == self.peer;
                if m.flags & flags::RST != 0 {
                    if from_peer {
                        self.close();
                    }
                    return None;
                }
                if m.flags & flags::SYN != 0 {
                    if m.flags & flags::ACK == 0 {
                        self.accept(now, &m, out);
                    }
                    return None;
                }
                if !from_peer || self.state == State::Closed {
                    // Tell an entry that lost its session here to reconnect instead of waiting for its dead timer.
                    self.send_rst_to(m.dst, m.src, m.ack, out);
                    return None;
                }
                if self.state == State::SynReceived {
                    if m.flags & flags::ACK == 0 || m.ack != self.snd_nxt {
                        return None;
                    }
                    self.established(now);
                }
                self.on_segment(now, &m, p.payload, out)
            }
        }
    }

    pub fn on_tick(&mut self, now: Instant, out: &mut impl Sink) {
        let dead = now.saturating_duration_since(self.last_rx) >= self.cfg.dead_timeout;
        match (self.cfg.mode, self.state) {
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
            State::Closed => self.last_rx.max(Instant::now()) + IDLE,
            State::SynSent => dead.min(self.next_syn),
            State::SynReceived => dead,
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
        if self.cfg.mode == Mode::Exit {
            self.peer = None;
        }
    }

    fn established(&mut self, now: Instant) {
        self.state = State::Established;
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
        self.last_rx = now;
        if payload.is_empty() {
            return None;
        }
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

    fn accept(&mut self, now: Instant, m: &TcpMeta, out: &mut impl Sink) {
        // A late retransmission must not reset a connection whose data sequence has advanced.
        let duplicate = matches!(self.state, State::SynReceived | State::Established)
            && Some(m.src) == self.peer
            && m.dst == self.local
            && m.seq == self.irs;
        if !duplicate {
            if self.peer.is_some_and(|p| p != m.src) {
                log::info!(
                    "worker {}: replacing peer {:?} with {}",
                    self.cfg.worker,
                    self.peer,
                    m.src
                );
            }
            self.peer = Some(m.src);
            self.local = m.dst;
            self.irs = m.seq;
            self.rcv_nxt = m.seq.wrapping_add(1);
            self.iss = self.next_isn();
            self.snd_nxt = self.iss.wrapping_add(1);
            self.state = State::SynReceived;
        }
        self.last_rx = now;
        self.send_syn(out);
    }

    fn connect(&mut self, now: Instant, out: &mut impl Sink) {
        self.iss = self.next_isn();
        self.snd_nxt = self.iss.wrapping_add(1);
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
        let syn_flags = match self.cfg.mode {
            Mode::Entry => flags::SYN,
            Mode::Exit => flags::SYN | flags::ACK,
        };
        let meta = TcpMeta {
            seq: self.iss,
            ack: if self.cfg.mode == Mode::Exit {
                self.irs.wrapping_add(1)
            } else {
                0
            },
            ..self.meta(peer, syn_flags)
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
        let overhead = OuterFamily::of(self.local.ip()).overhead();
        self.scratch[overhead..overhead + payload.len()].copy_from_slice(payload);
        let len = pkt::write_headers(&mut self.scratch, &meta, payload.len(), id);
        out.send(&self.scratch[..len], peer.ip());
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
                entry: Session::new(cfg(Mode::Entry, worker, conns), t, seed),
                exit: Session::new(cfg(Mode::Exit, worker, conns), t, seed + 1),
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

    #[test]
    fn entry_source_port_stays_in_worker_residue_class() {
        for seed in 0..50 {
            let t = Instant::now();
            let mut s = Session::new(cfg(Mode::Entry, 3, 4), t, seed * 7919);
            let mut w = Wire::default();
            s.start(t, &mut w);
            let port = parsed(&w.take()[0]).meta.src.port();
            assert_eq!(port % 4, 3);
            assert!(port >= 32768);
        }
    }

    #[test]
    fn handshake_carries_options_and_establishes_both_sides() {
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
        assert_eq!(p.exit.state(), State::SynReceived);
        let synack = w.take();
        let sa = parsed(&synack[0]);
        assert_eq!(sa.meta.flags, flags::SYN | flags::ACK);
        assert_eq!(sa.meta.ack, s.meta.seq.wrapping_add(1));
        assert_eq!(sa.meta.dst, s.meta.src);

        let mut w = Wire::default();
        p.entry.on_outer(p.t, &synack[0], &mut w);
        assert_eq!(p.entry.state(), State::Established);
        let ack = w.take();
        assert_eq!(parsed(&ack[0]).meta.flags, flags::ACK);
        p.exit.on_outer(p.t, &ack[0], &mut Wire::default());
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
                p.entry = Session::new(entry, p.t, 7);
                p.exit = Session::new(exit, p.t, 8);
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
        let mut s = Session::new(cfg(Mode::Entry, 0, 1), Instant::now(), 1);
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
        let mut s = Session::new(c, t, 2); // pool: 65531, 65533, 65535
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
        let mut s = Session::new(cfg(Mode::Entry, 0, 1), t, 1);
        let mut w = Wire::default();
        s.start(t, &mut w);
        let first = parsed(&w.take()[0]).meta;
        assert_eq!(s.next_deadline(), t + SYN_RETRY);
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
        p.exit = Session::new(cfg(Mode::Exit, 0, 1), p.t, 99);
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
        let mut entry = Session::new(cfg(Mode::Entry, 0, 1), t, 1);
        let mut exit = Session::new(cfg(Mode::Exit, 0, 1), t, 2);
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
                    entry: Session::new(entry, t, 31),
                    exit: Session::new(exit, t, 32),
                };
                let mut w = Wire::default();
                p.entry.start(p.t, &mut w);
                let syn = w.take().remove(0);
                p.exit.on_outer(p.t, &syn, &mut w);
                let synack = w.take().remove(0);
                let original = parsed(&synack).meta;
                p.entry.on_outer(p.t, &synack, &mut w);
                let ack = w.take().remove(0);
                p.exit.on_outer(p.t, &ack, &mut w);

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
                    .wrapping_add(1 + if data_first { 100 } else { 0 });
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
        p.entry = Session::new(cfg(Mode::Entry, 0, 1), p.t, 31 + 32768);
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
}
