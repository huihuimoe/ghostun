//! Connection-time authentication only; ordinary tunnel packets never enter this module.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use super::pkt::{be64, put_be64, TcpMeta};
use crate::config::{AuthKey, Mode};
use crate::sys;

pub const CONTROL: u8 = 3;
const VERSION: u8 = 1;
pub(crate) const HELLO: u8 = 1;
pub(crate) const CHALLENGE: u8 = 2;
pub(crate) const PROOF: u8 = 3;
pub(crate) const FINISHED: u8 = 4;

const HDR_LEN: usize = 3;
const TICKET_LEN: usize = 8;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;

const OFF_KIND: usize = 2;
const OFF_TICKET: usize = HDR_LEN;
const OFF_ISSUED: usize = OFF_TICKET + TICKET_LEN;
const OFF_ENTRY_NONCE: usize = OFF_ISSUED + 8;
const OFF_EXIT_NONCE: usize = OFF_ENTRY_NONCE + NONCE_LEN;
const OFF_COOKIE: usize = OFF_EXIT_NONCE + NONCE_LEN;
const OFF_EXIT_TAG: usize = OFF_COOKIE + TAG_LEN;
const OFF_ENTRY_TAG: usize = OFF_EXIT_TAG + TAG_LEN;
const OFF_FINISHED_TAG: usize = OFF_TICKET + TICKET_LEN;

pub const HELLO_LEN: usize = HDR_LEN + NONCE_LEN;
const CHALLENGE_LEN: usize = OFF_EXIT_TAG + TAG_LEN;
pub const PROOF_LEN: usize = OFF_ENTRY_TAG + TAG_LEN;
const FINISHED_LEN: usize = OFF_FINISHED_TAG + TAG_LEN;

const ENTRY_BYTES: u32 = (HELLO_LEN + PROOF_LEN) as u32;
pub(crate) const EXIT_BYTES: u32 = (CHALLENGE_LEN + FINISHED_LEN) as u32;
const EXIT_DOMAIN: &[u8] = b"ghostun-auth-v1/exit";
const ENTRY_DOMAIN: &[u8] = b"ghostun-auth-v1/entry";
const FINISHED_DOMAIN: &[u8] = b"ghostun-auth-v1/finished";

#[derive(Clone, Copy)]
struct Isns {
    entry: u32,
    exit: u32,
}

struct Server {
    cookie_key: HmacSha256,
    next_ticket: u64,
    accepted: u64,
}

struct EntryState {
    frame: [u8; PROOF_LEN],
    len: usize,
    seq: u32,
    warned: bool,
}

struct Completion {
    request: TcpMeta,
    proof: [u8; PROOF_LEN],
    finished: [u8; FINISHED_LEN],
}

pub enum EntryStep {
    SendProof { rcv_nxt: u32, snd_nxt: u32 },
    Established { rcv_nxt: u32 },
    AuthFailed(&'static str),
}

pub struct Promotion {
    pub iss: u32,
    pub irs: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub finished: [u8; FINISHED_LEN],
}

pub enum ExitStep {
    Ignore,
    Challenge([u8; CHALLENGE_LEN]),
    Finished([u8; FINISHED_LEN]),
    Promote(Promotion),
}

pub struct Auth {
    key: HmacSha256,
    server: Option<Server>,
    entry: Option<EntryState>,
    completion: Option<Completion>,
    origin: Instant,
    timeout: Duration,
}

#[inline]
fn header(kind: u8) -> [u8; HDR_LEN] {
    [CONTROL, VERSION, kind]
}

#[inline]
fn is_message(payload: &[u8], kind: u8, len: usize) -> bool {
    payload.len() == len && payload[..HDR_LEN] == header(kind)
}

impl Auth {
    pub fn new(key: &AuthKey, mode: Mode, now: Instant, timeout: Duration) -> io::Result<Self> {
        let server = if mode == Mode::Exit {
            let mut secret = [0; NONCE_LEN];
            sys::random(&mut secret)?;
            Some(Server {
                cookie_key: HmacSha256::new_from_slice(&secret)
                    .expect("HMAC accepts a 32-byte key"),
                next_ticket: 0,
                accepted: 0,
            })
        } else {
            None
        };
        Ok(Self {
            key: HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key"),
            server,
            entry: None,
            completion: None,
            origin: now,
            timeout,
        })
    }

    pub fn reload(&mut self, key: &AuthKey, timeout: Duration) {
        self.key = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
        self.timeout = timeout;
    }

    pub fn reset(&mut self) {
        self.entry = None;
        self.completion = None;
    }

    pub fn begin_entry(&mut self, seq: u32) -> io::Result<()> {
        let mut frame = [0; PROOF_LEN];
        frame[..HDR_LEN].copy_from_slice(&header(HELLO));
        sys::random(&mut frame[HDR_LEN..HELLO_LEN])?;
        self.entry = Some(EntryState {
            frame,
            len: HELLO_LEN,
            seq,
            warned: false,
        });
        Ok(())
    }

    #[inline]
    pub fn pending(&self) -> Option<(u32, &[u8])> {
        self.entry.as_ref().map(|p| (p.seq, &p.frame[..p.len]))
    }

    pub fn on_entry_reply(
        &mut self,
        iss: u32,
        irs: u32,
        snd_nxt: u32,
        m: &TcpMeta,
        payload: &[u8],
    ) -> Option<EntryStep> {
        let pending = self.entry.as_ref()?;
        let isns = Isns {
            entry: iss,
            exit: irs,
        };
        let reason = if pending.len == HELLO_LEN {
            if m.seq != irs.wrapping_add(1)
                || m.ack != snd_nxt
                || !is_message(payload, CHALLENGE, CHALLENGE_LEN)
                || payload[OFF_ENTRY_NONCE..OFF_EXIT_NONCE] != pending.frame[HDR_LEN..HELLO_LEN]
            {
                return None;
            }
            if let Some(proof) = self.proof(isns, payload) {
                self.entry = Some(EntryState {
                    frame: proof,
                    len: PROOF_LEN,
                    seq: snd_nxt,
                    warned: false,
                });
                return Some(EntryStep::SendProof {
                    rcv_nxt: m.seq.wrapping_add(CHALLENGE_LEN as u32),
                    snd_nxt: snd_nxt.wrapping_add(PROOF_LEN as u32),
                });
            }
            "challenge verification failed"
        } else {
            if m.seq != irs.wrapping_add(1 + CHALLENGE_LEN as u32)
                || m.ack != snd_nxt
                || !is_message(payload, FINISHED, FINISHED_LEN)
                || payload[OFF_TICKET..OFF_FINISHED_TAG]
                    != pending.frame[OFF_TICKET..OFF_FINISHED_TAG]
            {
                return None;
            }
            if self.verify(
                FINISHED_DOMAIN,
                isns,
                &pending.frame[HDR_LEN..OFF_EXIT_TAG],
                &payload[OFF_FINISHED_TAG..],
            ) {
                self.entry = None;
                return Some(EntryStep::Established {
                    rcv_nxt: irs.wrapping_add(1 + EXIT_BYTES),
                });
            }
            "finished verification failed"
        };
        let pending = self.entry.as_mut()?;
        (!std::mem::replace(&mut pending.warned, true)).then_some(EntryStep::AuthFailed(reason))
    }

    pub fn on_exit_request(
        &mut self,
        now: Instant,
        established: bool,
        m: &TcpMeta,
        payload: &[u8],
    ) -> io::Result<ExitStep> {
        if is_message(payload, HELLO, HELLO_LEN) {
            return Ok(match self.challenge(now, m, payload)? {
                Some(challenge) => ExitStep::Challenge(challenge),
                None => ExitStep::Ignore,
            });
        }
        if let Some(c) = self
            .completion
            .as_ref()
            .filter(|c| established && c.request == *m && payload == &c.proof[..])
        {
            return Ok(ExitStep::Finished(c.finished));
        }
        Ok(match self.accept(now, m, payload) {
            Some(promotion) => ExitStep::Promote(promotion),
            None => ExitStep::Ignore,
        })
    }

    /// SYN cookies bind the observed tuple and Entry ISN, without storing a candidate.
    pub fn syn_cookie(&self, now: Instant, meta: &TcpMeta) -> u32 {
        self.syn_cookie_at(meta, self.bucket(now))
    }

    #[inline]
    fn bucket(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.origin).as_secs() / self.timeout.as_secs()
    }

    fn syn_cookie_at(&self, meta: &TcpMeta, bucket: u64) -> u32 {
        let key = &self
            .server
            .as_ref()
            .expect("Exit owns cookie key")
            .cookie_key;
        let mut mac = tuple_mac(key, b"ghostun-syn-v1", meta);
        mac.update(&meta.seq.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        u32::from_be_bytes(tag[..4].try_into().unwrap())
    }

    fn challenge(
        &mut self,
        now: Instant,
        meta: &TcpMeta,
        payload: &[u8],
    ) -> io::Result<Option<[u8; CHALLENGE_LEN]>> {
        if !is_message(payload, HELLO, HELLO_LEN) {
            return Ok(None);
        }
        let isns = Isns {
            entry: meta.seq.wrapping_sub(1),
            exit: meta.ack.wrapping_sub(1),
        };
        let syn = TcpMeta {
            seq: isns.entry,
            ..*meta
        };
        let bucket = self.bucket(now);
        if ![bucket, bucket.saturating_sub(1)]
            .into_iter()
            .any(|b| self.syn_cookie_at(&syn, b) == isns.exit)
        {
            return Ok(None);
        }
        let server = self.server.as_mut().expect("Exit owns cookie key");
        let Some(ticket) = server.next_ticket.checked_add(1) else {
            return Ok(None);
        };
        server.next_ticket = ticket;
        let mut frame = [0; CHALLENGE_LEN];
        frame[..HDR_LEN].copy_from_slice(&header(CHALLENGE));
        put_be64(&mut frame, OFF_TICKET, ticket);
        let issued_ms = now.saturating_duration_since(self.origin).as_millis() as u64;
        put_be64(&mut frame, OFF_ISSUED, issued_ms);
        frame[OFF_ENTRY_NONCE..OFF_EXIT_NONCE].copy_from_slice(&payload[HDR_LEN..]);
        sys::random(&mut frame[OFF_EXIT_NONCE..OFF_COOKIE])?;
        let cookie = cookie_mac(&server.cookie_key, meta, isns, &frame[HDR_LEN..OFF_COOKIE])
            .finalize()
            .into_bytes();
        frame[OFF_COOKIE..OFF_EXIT_TAG].copy_from_slice(cookie.as_ref());
        let tag = self.sign(EXIT_DOMAIN, isns, &frame[HDR_LEN..OFF_EXIT_TAG]);
        frame[OFF_EXIT_TAG..].copy_from_slice(tag.as_ref());
        Ok(Some(frame))
    }

    #[inline]
    fn proof(&self, isns: Isns, challenge: &[u8]) -> Option<[u8; PROOF_LEN]> {
        if !self.verify(
            EXIT_DOMAIN,
            isns,
            &challenge[HDR_LEN..OFF_EXIT_TAG],
            &challenge[OFF_EXIT_TAG..],
        ) {
            return None;
        }
        let mut frame = [0; PROOF_LEN];
        frame[..CHALLENGE_LEN].copy_from_slice(challenge);
        frame[OFF_KIND] = PROOF;
        let tag = self.sign(ENTRY_DOMAIN, isns, &challenge[HDR_LEN..OFF_EXIT_TAG]);
        frame[OFF_ENTRY_TAG..].copy_from_slice(tag.as_ref());
        Some(frame)
    }

    /// A verified ticket is consumed before promotion; failed requests never move the watermark.
    fn accept(&mut self, now: Instant, meta: &TcpMeta, proof: &[u8]) -> Option<Promotion> {
        if !is_message(proof, PROOF, PROOF_LEN) {
            return None;
        }
        let ticket = be64(proof, OFF_TICKET);
        if ticket <= self.server.as_ref()?.accepted {
            return None;
        }
        let issued = be64(proof, OFF_ISSUED);
        let elapsed = now.saturating_duration_since(self.origin).as_millis();
        if u128::from(issued) > elapsed
            || elapsed - u128::from(issued) > self.timeout.as_millis() * 2
        {
            return None;
        }
        let isns = Isns {
            entry: meta.seq.wrapping_sub(1 + HELLO_LEN as u32),
            exit: meta.ack.wrapping_sub(1 + CHALLENGE_LEN as u32),
        };
        let transcript = &proof[HDR_LEN..OFF_EXIT_TAG];
        if cookie_mac(
            &self.server.as_ref()?.cookie_key,
            meta,
            isns,
            &proof[HDR_LEN..OFF_COOKIE],
        )
        .verify_slice(&proof[OFF_COOKIE..OFF_EXIT_TAG])
        .is_err()
            || !self.verify(
                EXIT_DOMAIN,
                isns,
                transcript,
                &proof[OFF_EXIT_TAG..OFF_ENTRY_TAG],
            )
            || !self.verify(ENTRY_DOMAIN, isns, transcript, &proof[OFF_ENTRY_TAG..])
        {
            return None;
        }
        let mut finished = [0; FINISHED_LEN];
        finished[..HDR_LEN].copy_from_slice(&header(FINISHED));
        put_be64(&mut finished, OFF_TICKET, ticket);
        finished[OFF_FINISHED_TAG..]
            .copy_from_slice(self.sign(FINISHED_DOMAIN, isns, transcript).as_ref());
        self.server.as_mut()?.accepted = ticket;
        self.completion = Some(Completion {
            request: *meta,
            proof: proof.try_into().unwrap(),
            finished,
        });
        Some(Promotion {
            iss: isns.exit,
            irs: isns.entry,
            snd_nxt: isns.exit.wrapping_add(1 + EXIT_BYTES),
            rcv_nxt: isns.entry.wrapping_add(1 + ENTRY_BYTES),
            finished,
        })
    }

    #[inline]
    fn mac(&self, domain: &[u8], isns: Isns, body: &[u8]) -> HmacSha256 {
        let mut mac = self.key.clone();
        mac.update(domain);
        mac.update(&[VERSION]);
        mac.update(&isns.entry.to_be_bytes());
        mac.update(&isns.exit.to_be_bytes());
        mac.update(body);
        mac
    }

    #[inline]
    fn sign(&self, domain: &[u8], isns: Isns, body: &[u8]) -> [u8; TAG_LEN] {
        self.mac(domain, isns, body).finalize().into_bytes().into()
    }

    #[inline]
    fn verify(&self, domain: &[u8], isns: Isns, body: &[u8], tag: &[u8]) -> bool {
        self.mac(domain, isns, body).verify_slice(tag).is_ok()
    }
}

#[inline]
fn address(mac: &mut HmacSha256, addr: SocketAddr) {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            mac.update(&[4]);
            mac.update(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            mac.update(&[6]);
            mac.update(&ip.octets());
        }
    }
    mac.update(&addr.port().to_be_bytes());
}

#[inline]
fn tuple_mac(key: &HmacSha256, domain: &[u8], meta: &TcpMeta) -> HmacSha256 {
    let mut mac = key.clone();
    mac.update(domain);
    address(&mut mac, meta.src);
    address(&mut mac, meta.dst);
    mac
}

#[inline]
fn cookie_mac(key: &HmacSha256, meta: &TcpMeta, isns: Isns, body: &[u8]) -> HmacSha256 {
    let mut mac = tuple_mac(key, b"ghostun-cookie-v1", meta);
    mac.update(&isns.entry.to_be_bytes());
    mac.update(&isns.exit.to_be_bytes());
    mac.update(body);
    mac
}
