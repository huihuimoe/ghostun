//! Per-worker UDP session: stateless-cookie handshake, health ping/pong, and reconnect.
//! Pure state machine: datagrams in, datagrams out through [`Sink`]; the worker owns all I/O.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::auth::{self, Auth, EntryStep, Promoted};
use crate::config::{AuthKey, Config, Mode};
use crate::net::{self, ipv4, ipv6};
use crate::transport::control::Backoff;
use crate::transport::keepalive::{self, Keepalive};

/// Control frames use a first byte whose high nibble is 0, which no IPv4 (4) or IPv6 (6) packet can have.
pub const CTRL_PING: u8 = 0x01;
pub const CTRL_PONG: u8 = 0x02;

pub const RETRANSMIT_BASE: Duration = Duration::from_secs(1);
const IDLE: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
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
    /// Agreed inner TUN MTU; validated during handshake and on incoming inner packets.
    pub mtu: u16,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
}

impl SessionConfig {
    pub fn from_config(
        cfg: &Config,
        local_ip: IpAddr,
        remote: Option<SocketAddr>,
        listen_port: u16,
        worker: u16,
        mtu: u16,
    ) -> Self {
        Self {
            mode: cfg.mode,
            auth_key: cfg.tunables.auth_key.clone(),
            local_ip,
            remote,
            listen_port,
            worker,
            mtu,
            ping_interval: cfg.tunables.ping_interval,
            dead_timeout: cfg.tunables.dead_timeout,
        }
    }
}

pub trait Sink {
    fn send(&mut self, frame: &[u8]);
    fn reset(&mut self) {}
    /// Rebinds the Entry socket to a fresh ephemeral port before a new handshake attempt.
    fn rebind(&mut self, default_local: SocketAddr) -> io::Result<SocketAddr> {
        self.reset();
        Ok(default_local)
    }
}

pub struct Session {
    cfg: SessionConfig,
    auth: Auth,
    state: State,
    generation: u64,
    local: SocketAddr,
    peer: Option<SocketAddr>,
    last_rx: Instant,
    next_ping: Instant,
    next_retry: Instant,
    retransmits: u32,
    backoff: Backoff,
    rng: u64,
    nonce: u64,
}

impl Session {
    pub fn new(cfg: SessionConfig, now: Instant, seed: u64) -> Self {
        let auth = Auth::new(&cfg.auth_key, cfg.mtu, now, cfg.dead_timeout);
        let (local, peer) = match cfg.mode {
            Mode::Entry => (SocketAddr::new(cfg.local_ip, 0), cfg.remote),
            Mode::Exit => (SocketAddr::new(cfg.local_ip, cfg.listen_port), None),
        };
        Self {
            cfg,
            auth,
            state: State::Closed,
            generation: 0,
            local,
            peer,
            last_rx: now,
            next_ping: now,
            next_retry: now,
            retransmits: 0,
            backoff: Backoff::default(),
            rng: seed ^ 0x9e37_79b9_7f4a_7c15,
            nonce: 0,
        }
    }

    pub fn new_exit_established(
        cfg: SessionConfig,
        promo: &Promoted,
        now: Instant,
        seed: u64,
        out: &mut impl Sink,
    ) -> Self {
        let mut session = Self::new(cfg, now, seed);
        session.local = promo.local;
        session.peer = Some(promo.peer);
        session.established(now);
        out.send(&promo.finished);
        session
    }

    #[cfg(test)]
    pub fn state(&self) -> State {
        self.state
    }

    #[inline(always)]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[inline(always)]
    pub fn mtu(&self) -> u16 {
        self.cfg.mtu
    }

    #[inline(always)]
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    #[inline(always)]
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    #[inline(always)]
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
        self.backoff.reset();
        match self.cfg.mode {
            Mode::Entry => self.connect(now, out),
            Mode::Exit => self.close(out),
        }
        was_established
    }

    pub fn start(&mut self, now: Instant, out: &mut impl Sink) {
        if self.cfg.mode == Mode::Entry {
            self.connect(now, out);
        }
    }

    /// Re-establishes an Exit worker session in place when the same `(local, peer)` 4-tuple
    /// completes a fresh handshake for the same worker slot.
    pub fn accept_in_place(&mut self, now: Instant, finished: &[u8], out: &mut impl Sink) {
        self.reset_output(out);
        if self.state == State::Established
            && let Some(peer) = self.peer
        {
            log::info!(
                "worker {}: authenticated takeover, resetting {} <-> {}",
                self.cfg.worker,
                self.local,
                peer
            );
        }
        self.established(now);
        out.send(finished);
    }

    #[inline]
    pub fn on_outer<'a>(
        &mut self,
        now: Instant,
        payload: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        if self.state == State::Authenticating {
            if now.saturating_duration_since(self.last_rx) >= self.cfg.dead_timeout {
                self.fail_attempt(now, out);
            } else if payload.first() == Some(&auth::CONTROL) {
                self.on_auth_reply(now, payload, out);
            }
            return None;
        }
        if self.state == State::Established {
            return self.on_datagram(now, payload, out);
        }
        None
    }

    pub fn on_tick(&mut self, now: Instant, out: &mut impl Sink) {
        let dead = now.saturating_duration_since(self.last_rx) >= self.cfg.dead_timeout;
        match (self.cfg.mode, self.state) {
            (Mode::Entry, State::Closed) if now >= self.next_retry => self.connect(now, out),
            (_, State::Closed) => {}
            (Mode::Entry, State::Established) if dead => {
                let peer = self.peer.expect("entry has remote");
                log::warn!(
                    "worker {}: peer silent for {:?} ({} <-> {}), reconnecting",
                    self.cfg.worker,
                    self.cfg.dead_timeout,
                    self.local,
                    peer
                );
                self.connect(now, out);
            }
            (Mode::Entry, State::Authenticating) if dead => self.fail_attempt(now, out),
            (Mode::Exit, _) if dead => {
                if let Some(peer) = self.peer {
                    log::warn!(
                        "worker {}: peer silent for {:?} ({} <-> {}), closing",
                        self.cfg.worker,
                        self.cfg.dead_timeout,
                        self.local,
                        peer
                    );
                }
                self.close(out);
            }
            (Mode::Entry, State::Authenticating) if now >= self.next_retry => {
                self.advance_retransmit(now);
                self.send_pending(out);
            }
            (_, State::Established) if now >= self.next_ping => {
                self.next_ping = now + self.cfg.ping_interval;
                self.nonce = self.nonce.wrapping_add(1);
                let frame = Keepalive::new(CTRL_PING, self.nonce.to_be_bytes()).encode();
                out.send(&frame);
            }
            _ => {}
        }
    }

    #[inline]
    pub fn next_deadline(&self) -> Instant {
        let dead = self.last_rx + self.cfg.dead_timeout;
        match self.state {
            State::Closed if self.cfg.mode == Mode::Entry => self.next_retry,
            State::Closed => self.last_rx.max(Instant::now()) + IDLE,
            State::Authenticating => dead.min(self.next_retry),
            State::Established => dead.min(self.next_ping),
        }
    }

    pub fn close(&mut self, out: &mut impl Sink) {
        self.reset_output(out);
        self.close_state();
    }

    fn close_state(&mut self) {
        self.state = State::Closed;
        self.auth.reset();
        if self.cfg.mode == Mode::Exit {
            self.peer = None;
        }
    }

    fn established(&mut self, now: Instant) {
        self.state = State::Established;
        self.last_rx = now;
        self.retransmits = 0;
        self.backoff.reset();
        self.next_ping = now + self.cfg.ping_interval;
        log::info!(
            "worker {}: established {} <-> {}",
            self.cfg.worker,
            self.local,
            self.peer.map_or_else(String::new, |p| p.to_string())
        );
    }

    #[inline]
    fn on_datagram<'a>(
        &mut self,
        now: Instant,
        payload: &'a [u8],
        out: &mut impl Sink,
    ) -> Option<&'a [u8]> {
        let first = *payload.first()?;
        match first >> 4 {
            ipv4::VERSION | ipv6::VERSION => {
                if !net::is_valid_inner_ip(payload, usize::from(self.cfg.mtu)) {
                    return None;
                }
                self.last_rx = now;
                Some(payload)
            }
            0 if first == CTRL_PING && payload.len() == keepalive::LEN => {
                let ping = Keepalive::decode(payload)?;
                self.last_rx = now;
                let pong = Keepalive::new(CTRL_PONG, ping.nonce).encode();
                out.send(&pong);
                None
            }
            0 if first == CTRL_PONG && payload.len() == keepalive::LEN => {
                let _pong = Keepalive::decode(payload)?;
                self.last_rx = now;
                None
            }
            _ => None,
        }
    }

    fn on_auth_reply(&mut self, now: Instant, payload: &[u8], out: &mut impl Sink) {
        match self.auth.on_entry_reply(payload) {
            Some(EntryStep::SendProof) => {
                self.reset_retransmit(now);
                self.send_pending(out);
            }
            Some(EntryStep::Established) => {
                self.established(now);
            }
            Some(EntryStep::AuthFailed(reason)) => {
                if let Some(peer) = self.peer {
                    log::warn!(
                        "worker {}: authentication failed ({} <-> {}): {reason}",
                        self.cfg.worker,
                        self.local,
                        peer
                    );
                }
            }
            None => {}
        }
    }

    #[cfg(test)]
    pub fn on_auth_request(
        &mut self,
        now: Instant,
        local: SocketAddr,
        peer: SocketAddr,
        payload: &[u8],
        out: &mut impl Sink,
    ) {
        match self.auth.on_exit_request(now, local, peer, payload) {
            Ok(auth::ExitStep::Ignore) => {}
            Ok(auth::ExitStep::Challenge(challenge)) => out.send(&challenge),
            Ok(auth::ExitStep::Finished(finished)) => out.send(&finished),
            Ok(auth::ExitStep::Promote(p)) => {
                self.local = p.local;
                self.peer = Some(p.peer);
                self.accept_in_place(now, &p.finished, out);
            }
            Err(e) => log::error!("worker {}: authentication randomness: {e}", self.cfg.worker),
        }
    }

    fn send_pending(&mut self, out: &mut impl Sink) {
        if let Some(frame) = self.auth.pending() {
            out.send(frame);
        }
    }

    fn reset_output(&mut self, out: &mut impl Sink) {
        self.generation = self.generation.wrapping_add(1);
        out.reset();
    }

    #[inline]
    fn reset_retransmit(&mut self, now: Instant) {
        self.retransmits = 0;
        self.next_retry = now + RETRANSMIT_BASE;
    }

    #[inline]
    fn advance_retransmit(&mut self, now: Instant) {
        self.retransmits = self.retransmits.saturating_add(1);
        let secs = 1u64 << self.retransmits.min(3);
        self.next_retry = now + Duration::from_secs(secs);
    }

    fn connect(&mut self, now: Instant, out: &mut impl Sink) {
        self.generation = self.generation.wrapping_add(1);
        match out.rebind(self.local) {
            Ok(local) => self.local = local,
            Err(e) => {
                let peer = self.peer.expect("entry has remote");
                log::warn!("worker {}: socket setup ({peer}): {e}", self.cfg.worker);
                self.schedule_retry(now, out);
                return;
            }
        }
        if let Err(e) = self.auth.begin_entry(self.cfg.worker) {
            log::error!("worker {}: authentication randomness: {e}", self.cfg.worker);
            self.schedule_retry(now, out);
            return;
        }
        self.state = State::Authenticating;
        self.last_rx = now;
        self.reset_retransmit(now);
        self.send_pending(out);
    }

    fn fail_attempt(&mut self, now: Instant, out: &mut impl Sink) {
        let peer = self.peer.expect("entry has remote");
        log::warn!(
            "worker {}: handshake timed out after {:?} ({} <-> {}), backing off",
            self.cfg.worker,
            self.cfg.dead_timeout,
            self.local,
            peer
        );
        self.schedule_retry(now, out);
    }

    fn schedule_retry(&mut self, now: Instant, out: &mut impl Sink) {
        self.close(out);
        let sample = self.next_random_u32();
        let delay = self.backoff.delay(sample, false);
        self.next_retry = now + delay;
        log::info!(
            "worker {}: retry in {:.3}s",
            self.cfg.worker,
            delay.as_secs_f64()
        );
    }

    #[inline]
    fn next_random_u32(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = if x == 0 { 1 } else { x };
        (self.rng >> 32) as u32
    }
}
