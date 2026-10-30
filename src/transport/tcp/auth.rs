//! TCP v1 mutual authentication handshake. See docs/261025-dual-transport-spec.md.

use std::io;
use std::mem;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::invalid;
use crate::config::AuthKey;
use crate::sys;

const MSG_HELLO: u8 = 1;
const MSG_CHALLENGE: u8 = 2;
const MSG_PROOF: u8 = 3;
const MSG_FINISHED: u8 = 4;
const MSG_READY: u8 = 5;

const HELLO_MAGIC: &[u8; 4] = b"GTCP";
const PROTOCOL_VERSION: u8 = 1;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct HelloWire {
    kind: u8,
    magic: [u8; 4],
    version: u8,
    worker: U16,
    conns: U16,
    mtu: U16,
    nonce: [u8; NONCE_LEN],
}

pub const HELLO_LEN: usize = mem::size_of::<HelloWire>();

const CHALLENGE_PREFIX_LEN: usize = 1 + NONCE_LEN;
pub const CHALLENGE_LEN: usize = CHALLENGE_PREFIX_LEN + TAG_LEN;
pub const TAG_MSG_LEN: usize = 1 + TAG_LEN;
pub const AUTH_MAX: usize = CHALLENGE_LEN;

const TRANSCRIPT_PREFIX: &[u8; 14] = b"ghostun-tcp\x01\x01\x02";
const OFF_TRANSCRIPT_HELLO: usize = TRANSCRIPT_PREFIX.len();
const OFF_TRANSCRIPT_CHALLENGE: usize = OFF_TRANSCRIPT_HELLO + HELLO_LEN;
const TRANSCRIPT_LEN: usize = OFF_TRANSCRIPT_CHALLENGE + CHALLENGE_PREFIX_LEN;

const DOMAIN_EXIT: &[u8] = b"ghostun-tcp-v1/exit";
const DOMAIN_ENTRY: &[u8] = b"ghostun-tcp-v1/entry";
const DOMAIN_FINISHED: &[u8] = b"ghostun-tcp-v1/finished";
const DOMAIN_READY: &[u8] = b"ghostun-tcp-v1/ready";

#[derive(Clone, Copy)]
pub struct Params {
    pub worker: u16,
    pub conns: u16,
    pub mtu: u16,
}

impl Params {
    fn encode_hello(self) -> io::Result<[u8; HELLO_LEN]> {
        let mut bytes = [0; HELLO_LEN];
        let hello = HelloWire::mut_from_bytes(&mut bytes).expect("fixed-size Hello buffer");
        hello.kind = MSG_HELLO;
        hello.magic = *HELLO_MAGIC;
        hello.version = PROTOCOL_VERSION;
        hello.worker.set(self.worker);
        hello.conns.set(self.conns);
        hello.mtu.set(self.mtu);
        sys::random(&mut hello.nonce)?;
        Ok(bytes)
    }
}

#[inline]
pub fn hello_params(hello: &[u8]) -> io::Result<Params> {
    let hello =
        HelloWire::ref_from_bytes(hello).map_err(|_| invalid("malformed authentication Hello"))?;
    if hello.kind != MSG_HELLO || &hello.magic != HELLO_MAGIC {
        return Err(invalid("malformed authentication Hello"));
    }
    if hello.version != PROTOCOL_VERSION {
        return Err(invalid("unsupported TCP protocol version"));
    }
    Ok(Params {
        worker: hello.worker.get(),
        conns: hello.conns.get(),
        mtu: hello.mtu.get(),
    })
}

#[inline]
fn init_transcript(hello: &[u8]) -> [u8; TRANSCRIPT_LEN] {
    let mut buf = [0; TRANSCRIPT_LEN];
    buf[..OFF_TRANSCRIPT_HELLO].copy_from_slice(TRANSCRIPT_PREFIX);
    buf[OFF_TRANSCRIPT_HELLO..OFF_TRANSCRIPT_CHALLENGE].copy_from_slice(hello);
    buf
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    WaitChallenge,
    WaitEntryProof,
    WaitFinished,
    WaitReady,
    Done,
}

pub struct Handshake {
    key: Hmac<Sha256>,
    transcript: [u8; TRANSCRIPT_LEN],
    phase: Phase,
}

impl Handshake {
    pub fn entry(key: &AuthKey, p: Params) -> io::Result<(Self, [u8; HELLO_LEN])> {
        let hello = p.encode_hello()?;
        Ok((
            Self {
                key: Hmac::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key"),
                transcript: init_transcript(&hello),
                phase: Phase::WaitChallenge,
            },
            hello,
        ))
    }

    pub fn exit(key: &AuthKey, p: Params, hello: &[u8]) -> io::Result<(Self, [u8; CHALLENGE_LEN])> {
        let peer = hello_params(hello)?;
        if peer.worker != p.worker || peer.worker >= p.conns {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid worker ID {} (conns={})", peer.worker, p.conns),
            ));
        }
        if peer.conns != p.conns || peer.mtu != p.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "incompatible peer parameters (peer conns={}, mtu={}; local conns={}, mtu={})",
                    peer.conns, peer.mtu, p.conns, p.mtu
                ),
            ));
        }
        let mut challenge = [0; CHALLENGE_LEN];
        challenge[0] = MSG_CHALLENGE;
        sys::random(&mut challenge[1..CHALLENGE_PREFIX_LEN])?;
        let mut transcript = init_transcript(hello);
        transcript[OFF_TRANSCRIPT_CHALLENGE..].copy_from_slice(&challenge[..CHALLENGE_PREFIX_LEN]);
        let auth = Self {
            key: Hmac::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key"),
            transcript,
            phase: Phase::WaitEntryProof,
        };
        challenge[CHALLENGE_PREFIX_LEN..].copy_from_slice(&auth.tag(DOMAIN_EXIT));
        Ok((auth, challenge))
    }

    fn mac(&self, domain: &[u8]) -> Hmac<Sha256> {
        let mut mac = self.key.clone();
        mac.update(domain);
        mac.update(&self.transcript);
        mac
    }

    fn tag(&self, domain: &[u8]) -> [u8; TAG_LEN] {
        self.mac(domain).finalize().into_bytes().into()
    }

    fn encode_tag_msg(&self, kind: u8, domain: &[u8]) -> [u8; TAG_MSG_LEN] {
        let mut msg = [0; TAG_MSG_LEN];
        msg[0] = kind;
        msg[1..].copy_from_slice(&self.tag(domain));
        msg
    }

    #[inline(always)]
    pub fn done(&self) -> bool {
        self.phase == Phase::Done
    }

    pub fn receive(&mut self, payload: &[u8]) -> io::Result<Option<[u8; TAG_MSG_LEN]>> {
        let (expected_kind, expected_len) = match self.phase {
            Phase::WaitChallenge => (MSG_CHALLENGE, CHALLENGE_LEN),
            Phase::WaitEntryProof => (MSG_PROOF, TAG_MSG_LEN),
            Phase::WaitFinished => (MSG_FINISHED, TAG_MSG_LEN),
            Phase::WaitReady => (MSG_READY, TAG_MSG_LEN),
            Phase::Done => return Err(invalid("illegal authentication message or phase")),
        };
        if payload.len() != expected_len || payload[0] != expected_kind {
            return Err(invalid("illegal authentication message or phase"));
        }
        let (domain, next, reply) = match self.phase {
            Phase::WaitChallenge => {
                self.transcript[OFF_TRANSCRIPT_CHALLENGE..]
                    .copy_from_slice(&payload[..CHALLENGE_PREFIX_LEN]);
                (
                    DOMAIN_EXIT,
                    Phase::WaitFinished,
                    Some((MSG_PROOF, DOMAIN_ENTRY)),
                )
            }
            Phase::WaitEntryProof => (
                DOMAIN_ENTRY,
                Phase::WaitReady,
                Some((MSG_FINISHED, DOMAIN_FINISHED)),
            ),
            Phase::WaitFinished => (
                DOMAIN_FINISHED,
                Phase::Done,
                Some((MSG_READY, DOMAIN_READY)),
            ),
            Phase::WaitReady => (DOMAIN_READY, Phase::Done, None),
            Phase::Done => unreachable!(),
        };
        self.mac(domain)
            .verify_slice(&payload[payload.len() - TAG_LEN..])
            .map_err(|_| invalid("authentication proof verification failed"))?;
        self.phase = next;
        Ok(reply.map(|(kind, reply_domain)| self.encode_tag_msg(kind, reply_domain)))
    }
}
