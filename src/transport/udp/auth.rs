//! Stateless-cookie UDP mutual authentication handshake.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{KeyInit, Mac};
use zerocopy::byteorder::network_endian::{U16, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::config::{AuthKey, MAX_CONNS};
use crate::platform;
pub(crate) use crate::transport::auth::{CHALLENGE, CONTROL, FINISHED, FINISHED_LEN, HELLO, PROOF};
use crate::transport::auth::{
    Finished, Header, HmacSha256, NONCE_LEN, TAG_LEN, address, header, is_fresh, mac,
};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Hello {
    header: Header,
    worker: U16,
    mtu: U16,
    nonce: [u8; NONCE_LEN],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ChallengeTranscript {
    ticket: U64,
    issued_ms: U64,
    worker: U16,
    mtu: U16,
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

pub const HELLO_LEN: usize = mem::size_of::<Hello>();
pub const CHALLENGE_LEN: usize = mem::size_of::<Challenge>();
pub const PROOF_LEN: usize = mem::size_of::<Proof>();

const EXIT_DOMAIN: &[u8] = b"ghostun-udp-v1/exit";
const ENTRY_DOMAIN: &[u8] = b"ghostun-udp-v1/entry";
const FINISHED_DOMAIN: &[u8] = b"ghostun-udp-v1/finished";

struct Server {
    cookie_key: HmacSha256,
    next_ticket: u64,
    accepted: Box<[u64; MAX_CONNS]>,
    completions: Box<[Option<Completion>; MAX_CONNS]>,
}

struct EntryState {
    frame: [u8; PROOF_LEN],
    len: usize,
    warned: bool,
}

#[derive(Clone, Copy)]
struct Completion {
    local: SocketAddr,
    peer: SocketAddr,
    proof: [u8; PROOF_LEN],
    finished: [u8; FINISHED_LEN],
}

pub enum EntryStep {
    SendProof,
    Established,
    AuthFailed(&'static str),
}

#[derive(Clone, Copy)]
pub struct Promoted {
    pub worker: usize,
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub finished: [u8; FINISHED_LEN],
}

pub enum ExitStep {
    Ignore,
    Challenge([u8; CHALLENGE_LEN]),
    Finished([u8; FINISHED_LEN]),
    Promote(Promoted),
}

pub struct Auth {
    key: HmacSha256,
    server: Option<Server>,
    entry: Option<EntryState>,
    origin: Instant,
    timeout: Duration,
    mtu: u16,
}

impl Auth {
    pub fn new(key: &AuthKey, mtu: u16, now: Instant, timeout: Duration) -> Self {
        Self {
            key: HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key"),
            server: None,
            entry: None,
            origin: now,
            timeout,
            mtu,
        }
    }

    pub fn reload(&mut self, key: &AuthKey, timeout: Duration) {
        self.key = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
        self.timeout = timeout;
    }

    pub fn reset(&mut self) {
        self.entry = None;
        if let Some(server) = &mut self.server {
            server.completions.fill(None);
        }
    }

    pub fn begin_entry(&mut self, worker: u16) -> io::Result<()> {
        let mut frame = [0; PROOF_LEN];
        let hello = Hello::mut_from_bytes(&mut frame[..HELLO_LEN]).expect("Hello buffer");
        hello.header = header(HELLO);
        hello.worker.set(worker);
        hello.mtu.set(self.mtu);
        platform::random(&mut hello.nonce)?;
        self.entry = Some(EntryState {
            frame,
            len: HELLO_LEN,
            warned: false,
        });
        Ok(())
    }

    #[inline]
    pub fn pending(&self) -> Option<&[u8]> {
        self.entry.as_ref().map(|p| &p.frame[..p.len])
    }

    pub fn on_entry_reply(&mut self, payload: &[u8]) -> Option<EntryStep> {
        let pending = self.entry.as_ref()?;
        let reason = if pending.len == HELLO_LEN {
            let challenge = Challenge::ref_from_bytes(payload).ok()?;
            let hello = Hello::ref_from_bytes(&pending.frame[..HELLO_LEN]).expect("pending Hello");
            if challenge.header != header(CHALLENGE)
                || challenge.body.transcript.worker != hello.worker
                || challenge.body.transcript.mtu != hello.mtu
                || challenge.body.transcript.entry_nonce != hello.nonce
            {
                return None;
            }
            if let Some(proof) = self.proof(challenge) {
                self.entry = Some(EntryState {
                    frame: proof,
                    len: PROOF_LEN,
                    warned: false,
                });
                return Some(EntryStep::SendProof);
            }
            "challenge verification failed"
        } else {
            let finished = Finished::ref_from_bytes(payload).ok()?;
            let proof = Proof::ref_from_bytes(&pending.frame).expect("pending Proof");
            if finished.header != header(FINISHED)
                || finished.ticket != proof.body.transcript.ticket
            {
                return None;
            }
            if self.verify(FINISHED_DOMAIN, proof.body.as_bytes(), &finished.tag) {
                self.entry = None;
                return Some(EntryStep::Established);
            }
            "finished verification failed"
        };
        let pending = self.entry.as_mut()?;
        (!std::mem::replace(&mut pending.warned, true)).then_some(EntryStep::AuthFailed(reason))
    }

    pub fn on_exit_request(
        &mut self,
        now: Instant,
        local: SocketAddr,
        peer: SocketAddr,
        payload: &[u8],
    ) -> io::Result<ExitStep> {
        if let Some(hello) = Hello::ref_from_bytes(payload)
            .ok()
            .filter(|hello| hello.header == header(HELLO))
        {
            return Ok(match self.challenge(now, local, peer, hello)? {
                Some(challenge) => ExitStep::Challenge(challenge),
                None => ExitStep::Ignore,
            });
        }
        if let Some(proof) = Proof::ref_from_bytes(payload)
            .ok()
            .filter(|proof| proof.header == header(PROOF))
        {
            let worker = usize::from(proof.body.transcript.worker.get());
            if let Some(c) = self
                .server
                .as_ref()
                .and_then(|s| s.completions.get(worker))
                .and_then(Option::as_ref)
                .filter(|c| c.local == local && c.peer == peer && payload == &c.proof[..])
            {
                return Ok(ExitStep::Finished(c.finished));
            }
        }
        Ok(match self.accept(now, local, peer, payload) {
            Some(promoted) => ExitStep::Promote(promoted),
            None => ExitStep::Ignore,
        })
    }

    fn challenge(
        &mut self,
        now: Instant,
        local: SocketAddr,
        peer: SocketAddr,
        hello: &Hello,
    ) -> io::Result<Option<[u8; CHALLENGE_LEN]>> {
        let worker = hello.worker.get();
        let mtu = hello.mtu.get();
        if usize::from(worker) >= MAX_CONNS || mtu != self.mtu {
            if mtu != self.mtu {
                log::debug!(
                    "worker {worker}: rejecting UDP Hello from {peer}: peer mtu={mtu}, local mtu={}",
                    self.mtu
                );
            }
            return Ok(None);
        }
        let server = match &mut self.server {
            Some(server) => server,
            None => {
                let mut secret = [0; NONCE_LEN];
                platform::random(&mut secret)?;
                self.server.insert(Server {
                    cookie_key: HmacSha256::new_from_slice(&secret)
                        .expect("HMAC accepts a 32-byte key"),
                    next_ticket: 0,
                    accepted: Box::new([0; MAX_CONNS]),
                    completions: Box::new([None; MAX_CONNS]),
                })
            }
        };
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
        challenge.body.transcript.worker.set(worker);
        challenge.body.transcript.mtu.set(mtu);
        challenge.body.transcript.entry_nonce = hello.nonce;
        platform::random(&mut challenge.body.transcript.exit_nonce)?;
        challenge.body.cookie = cookie_mac(
            &server.cookie_key,
            local,
            peer,
            challenge.body.transcript.as_bytes(),
        )
        .finalize()
        .into_bytes()
        .into();
        challenge.exit_tag = self.sign(EXIT_DOMAIN, challenge.body.as_bytes());
        Ok(Some(frame))
    }

    #[inline]
    fn proof(&self, challenge: &Challenge) -> Option<[u8; PROOF_LEN]> {
        if !self.verify(EXIT_DOMAIN, challenge.body.as_bytes(), &challenge.exit_tag) {
            return None;
        }
        let mut frame = [0; PROOF_LEN];
        frame[..CHALLENGE_LEN].copy_from_slice(challenge.as_bytes());
        let proof = Proof::mut_from_bytes(&mut frame).expect("Proof buffer");
        proof.header = header(PROOF);
        proof.entry_tag = self.sign(ENTRY_DOMAIN, challenge.body.as_bytes());
        Some(frame)
    }

    fn accept(
        &mut self,
        now: Instant,
        local: SocketAddr,
        peer: SocketAddr,
        proof: &[u8],
    ) -> Option<Promoted> {
        let proof = Proof::ref_from_bytes(proof).ok()?;
        if proof.header != header(PROOF) {
            return None;
        }
        let worker = usize::from(proof.body.transcript.worker.get());
        if worker >= MAX_CONNS || proof.body.transcript.mtu.get() != self.mtu {
            return None;
        }
        let ticket = proof.body.transcript.ticket.get();
        if ticket <= self.server.as_ref()?.accepted[worker] {
            return None;
        }
        if !is_fresh(
            proof.body.transcript.issued_ms.get(),
            now.saturating_duration_since(self.origin),
            self.timeout,
        ) {
            return None;
        }
        let transcript = proof.body.as_bytes();
        if cookie_mac(
            &self.server.as_ref()?.cookie_key,
            local,
            peer,
            proof.body.transcript.as_bytes(),
        )
        .verify_slice(&proof.body.cookie)
        .is_err()
            || !self.verify(EXIT_DOMAIN, transcript, &proof.exit_tag)
            || !self.verify(ENTRY_DOMAIN, transcript, &proof.entry_tag)
        {
            return None;
        }
        let mut finished = [0; FINISHED_LEN];
        let message = Finished::mut_from_bytes(&mut finished).expect("Finished buffer");
        message.header = header(FINISHED);
        message.ticket.set(ticket);
        message.tag = self.sign(FINISHED_DOMAIN, transcript);
        let server = self.server.as_mut()?;
        server.accepted[worker] = ticket;
        server.completions[worker] = Some(Completion {
            local,
            peer,
            proof: proof.as_bytes().try_into().unwrap(),
            finished,
        });
        Some(Promoted {
            worker,
            local,
            peer,
            finished,
        })
    }

    #[inline]
    fn mac(&self, domain: &[u8], body: &[u8]) -> HmacSha256 {
        let mut mac = mac(&self.key, domain);
        mac.update(body);
        mac
    }

    #[inline]
    fn sign(&self, domain: &[u8], body: &[u8]) -> [u8; TAG_LEN] {
        self.mac(domain, body).finalize().into_bytes().into()
    }

    #[inline]
    fn verify(&self, domain: &[u8], body: &[u8], tag: &[u8]) -> bool {
        self.mac(domain, body).verify_slice(tag).is_ok()
    }
}

#[inline]
fn cookie_mac(key: &HmacSha256, local: SocketAddr, peer: SocketAddr, body: &[u8]) -> HmacSha256 {
    let mut mac = key.clone();
    mac.update(b"ghostun-udp-cookie-v1");
    address(&mut mac, peer);
    address(&mut mac, local);
    mac.update(body);
    mac
}
