//! Connection-time authentication only; ordinary tunnel packets never enter this module.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zerocopy::byteorder::network_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

type HmacSha256 = Hmac<Sha256>;

use super::frame::TcpMeta;
use crate::config::{AuthKey, Mode};
use crate::sys;

pub const CONTROL: u8 = 3;
const VERSION: u8 = 1;
pub(crate) const HELLO: u8 = 1;
pub(crate) const CHALLENGE: u8 = 2;
pub(crate) const PROOF: u8 = 3;
pub(crate) const FINISHED: u8 = 4;

const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, PartialEq, Eq)]
#[repr(C)]
struct Header {
    control: u8,
    version: u8,
    kind: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Hello {
    header: Header,
    nonce: [u8; NONCE_LEN],
}

// The cookie authenticates these fields; the peer tags also cover the cookie.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ChallengeTranscript {
    ticket: U64,
    issued_ms: U64,
    entry_nonce: [u8; NONCE_LEN],
    exit_nonce: [u8; NONCE_LEN],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ChallengeBody {
    transcript: ChallengeTranscript,
    cookie: [u8; TAG_LEN],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Challenge {
    header: Header,
    body: ChallengeBody,
    exit_tag: [u8; TAG_LEN],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Proof {
    header: Header,
    body: ChallengeBody,
    exit_tag: [u8; TAG_LEN],
    entry_tag: [u8; TAG_LEN],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Finished {
    header: Header,
    ticket: U64,
    tag: [u8; TAG_LEN],
}

pub const HELLO_LEN: usize = mem::size_of::<Hello>();
const CHALLENGE_LEN: usize = mem::size_of::<Challenge>();
pub const PROOF_LEN: usize = mem::size_of::<Proof>();
const FINISHED_LEN: usize = mem::size_of::<Finished>();

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
fn header(kind: u8) -> Header {
    Header {
        control: CONTROL,
        version: VERSION,
        kind,
    }
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
        let hello = Hello::mut_from_bytes(&mut frame[..HELLO_LEN]).expect("Hello buffer");
        hello.header = header(HELLO);
        sys::random(&mut hello.nonce)?;
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
            let challenge = Challenge::ref_from_bytes(payload).ok()?;
            let hello = Hello::ref_from_bytes(&pending.frame[..HELLO_LEN]).expect("pending Hello");
            if m.seq != irs.wrapping_add(1)
                || m.ack != snd_nxt
                || challenge.header != header(CHALLENGE)
                || challenge.body.transcript.entry_nonce != hello.nonce
            {
                return None;
            }
            if let Some(proof) = self.proof(isns, challenge) {
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
            let finished = Finished::ref_from_bytes(payload).ok()?;
            let proof = Proof::ref_from_bytes(&pending.frame).expect("pending Proof");
            if m.seq != irs.wrapping_add(1 + CHALLENGE_LEN as u32)
                || m.ack != snd_nxt
                || finished.header != header(FINISHED)
                || finished.ticket != proof.body.transcript.ticket
            {
                return None;
            }
            if self.verify(FINISHED_DOMAIN, isns, proof.body.as_bytes(), &finished.tag) {
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
        if let Some(hello) = Hello::ref_from_bytes(payload)
            .ok()
            .filter(|hello| hello.header == header(HELLO))
        {
            return Ok(match self.challenge(now, m, hello)? {
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
        hello: &Hello,
    ) -> io::Result<Option<[u8; CHALLENGE_LEN]>> {
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
        let challenge = Challenge::mut_from_bytes(&mut frame).expect("Challenge buffer");
        challenge.header = header(CHALLENGE);
        challenge.body.transcript.ticket.set(ticket);
        let issued_ms = now.saturating_duration_since(self.origin).as_millis() as u64;
        challenge.body.transcript.issued_ms.set(issued_ms);
        challenge.body.transcript.entry_nonce = hello.nonce;
        sys::random(&mut challenge.body.transcript.exit_nonce)?;
        challenge.body.cookie = cookie_mac(
            &server.cookie_key,
            meta,
            isns,
            challenge.body.transcript.as_bytes(),
        )
        .finalize()
        .into_bytes()
        .into();
        challenge.exit_tag = self.sign(EXIT_DOMAIN, isns, challenge.body.as_bytes());
        Ok(Some(frame))
    }

    #[inline]
    fn proof(&self, isns: Isns, challenge: &Challenge) -> Option<[u8; PROOF_LEN]> {
        if !self.verify(
            EXIT_DOMAIN,
            isns,
            challenge.body.as_bytes(),
            &challenge.exit_tag,
        ) {
            return None;
        }
        let mut frame = [0; PROOF_LEN];
        frame[..CHALLENGE_LEN].copy_from_slice(challenge.as_bytes());
        let proof = Proof::mut_from_bytes(&mut frame).expect("Proof buffer");
        proof.header.kind = PROOF;
        proof.entry_tag = self.sign(ENTRY_DOMAIN, isns, challenge.body.as_bytes());
        Some(frame)
    }

    /// A verified ticket is consumed before promotion; failed requests never move the watermark.
    fn accept(&mut self, now: Instant, meta: &TcpMeta, proof: &[u8]) -> Option<Promotion> {
        let proof = Proof::ref_from_bytes(proof).ok()?;
        if proof.header != header(PROOF) {
            return None;
        }
        let ticket = proof.body.transcript.ticket.get();
        if ticket <= self.server.as_ref()?.accepted {
            return None;
        }
        let issued = proof.body.transcript.issued_ms.get();
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
        let transcript = proof.body.as_bytes();
        if cookie_mac(
            &self.server.as_ref()?.cookie_key,
            meta,
            isns,
            proof.body.transcript.as_bytes(),
        )
        .verify_slice(&proof.body.cookie)
        .is_err()
            || !self.verify(EXIT_DOMAIN, isns, transcript, &proof.exit_tag)
            || !self.verify(ENTRY_DOMAIN, isns, transcript, &proof.entry_tag)
        {
            return None;
        }
        let mut finished = [0; FINISHED_LEN];
        let message = Finished::mut_from_bytes(&mut finished).expect("Finished buffer");
        message.header = header(FINISHED);
        message.ticket.set(ticket);
        message.tag = self.sign(FINISHED_DOMAIN, isns, transcript);
        self.server.as_mut()?.accepted = ticket;
        self.completion = Some(Completion {
            request: *meta,
            proof: proof.as_bytes().try_into().unwrap(),
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
