//! The TCP v1 codec and mutual authentication. See docs/261025-dual-transport-spec.md.
use std::collections::VecDeque;
use std::io::{self, IoSlice, Read, Write};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::config::AuthKey;

pub const TX_LIMIT: usize = 256 * 1024;
pub const AUTH_MAX: usize = 65;
pub const PING: u8 = 0x10;
pub const PONG: u8 = 0x11;

pub fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

pub fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|_| io::Error::other("OS cryptographic randomness unavailable"))
}

pub const RX_LIMIT: usize = 64 * 1024;

/// Decodes bounded frames; unauthenticated candidates stay single-frame until `grow`.
pub struct Receive {
    bytes: Vec<u8>,
    head: usize,
    tail: usize,
    max: usize,
}

impl Receive {
    pub fn new(max: usize) -> Self {
        Self {
            bytes: vec![0; max + 2],
            head: 0,
            tail: 0,
            max,
        }
    }

    pub fn grow(&mut self, max: usize) {
        self.max = max;
        self.bytes.resize(RX_LIMIT.max(max + 2), 0);
    }

    fn frame_len(&self) -> Option<usize> {
        (self.tail - self.head >= 2).then(|| {
            u16::from_be_bytes([self.bytes[self.head], self.bytes[self.head + 1]]) as usize
        })
    }

    pub fn ready(&self) -> bool {
        self.frame_len()
            .is_some_and(|len| len == 0 || len > self.max || self.tail - self.head >= 2 + len)
    }

    pub fn read(&mut self, input: &mut impl Read) -> io::Result<bool> {
        loop {
            let avail = self.tail - self.head;
            let need = match self.frame_len() {
                Some(len) if len == 0 || len > self.max => {
                    return Err(invalid("invalid framing: zero or oversized length"));
                }
                Some(len) if avail >= 2 + len => return Ok(true),
                Some(len) => 2 + len,
                None => 2,
            };
            if self.head > 0 && self.bytes.len() - self.tail < self.max + 2 {
                self.bytes.copy_within(self.head..self.tail, 0);
                self.tail -= self.head;
                self.head = 0;
            }
            let end = if self.bytes.len() > self.max + 2 {
                self.bytes.len()
            } else {
                self.head + need
            };
            match input.read(&mut self.bytes[self.tail..end]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer EOF")),
                Ok(n) => self.tail += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.frame_len().expect("complete frame");
        &self.bytes[self.head + 2..self.head + 2 + len]
    }

    pub fn clear(&mut self) {
        self.head += 2 + self.frame_len().expect("complete frame");
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }
}

#[derive(Default)]
pub struct SendQueue {
    pending: VecDeque<u8>,
}

impl SendQueue {
    pub fn bytes(&self) -> usize {
        self.pending.len()
    }

    pub fn room(&self, payload: usize) -> bool {
        self.bytes() + payload + 2 <= TX_LIMIT
    }

    pub fn push(&mut self, payload: &[u8]) -> bool {
        if !self.room(payload.len()) {
            return false;
        }
        let required = self.bytes() + payload.len() + 2;
        if required > self.pending.capacity() {
            // Bound retained storage without allocating the full budget for idle candidates.
            let capacity = (self.pending.capacity() * 2).max(required).min(TX_LIMIT);
            self.pending.reserve_exact(capacity - self.bytes());
        }
        self.pending.extend((payload.len() as u16).to_be_bytes());
        self.pending.extend(payload);
        true
    }

    pub fn flush(&mut self, output: &mut impl Write) -> io::Result<()> {
        while !self.pending.is_empty() {
            let (first, second) = self.pending.as_slices();
            match output.write_vectored(&[IoSlice::new(first), IoSlice::new(second)]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Params {
    pub worker: u16,
    pub conns: u16,
    pub mtu: u16,
}

pub fn hello_params(hello: &[u8]) -> io::Result<Params> {
    if hello.len() != 44 || hello[0] != 1 || &hello[1..5] != b"GTCP" {
        return Err(invalid("malformed authentication Hello"));
    }
    if hello[5] != 1 {
        return Err(invalid("unsupported TCP protocol version"));
    }
    Ok(Params {
        worker: u16::from_be_bytes([hello[6], hello[7]]),
        conns: u16::from_be_bytes([hello[8], hello[9]]),
        mtu: u16::from_be_bytes([hello[10], hello[11]]),
    })
}

pub struct Handshake {
    key: Hmac<Sha256>,
    hello: Vec<u8>,
    transcript: Vec<u8>,
    expected: u8,
}

impl Handshake {
    pub fn entry(key: &AuthKey, p: Params) -> io::Result<(Self, Vec<u8>)> {
        let mut hello = vec![1];
        hello.extend_from_slice(b"GTCP\x01");
        for v in [p.worker, p.conns, p.mtu] {
            hello.extend_from_slice(&v.to_be_bytes());
        }
        hello.resize(44, 0);
        random(&mut hello[12..])?;
        Ok((
            Self {
                key: Hmac::new_from_slice(&key.0).unwrap(),
                hello: hello.clone(),
                transcript: Vec::new(),
                expected: 2,
            },
            hello,
        ))
    }

    pub fn exit(key: &AuthKey, p: Params, hello: &[u8]) -> io::Result<(Self, Vec<u8>)> {
        let peer = hello_params(hello)?;
        if peer.worker != p.worker || peer.worker >= p.conns {
            return Err(invalid("invalid worker ID"));
        }
        if peer.conns != p.conns || peer.mtu != p.mtu {
            return Err(invalid("incompatible peer conns or effective TUN MTU"));
        }
        let mut challenge = vec![2; 33];
        random(&mut challenge[1..])?;
        let mut auth = Self {
            key: Hmac::new_from_slice(&key.0).unwrap(),
            hello: hello.to_vec(),
            transcript: Vec::new(),
            expected: 3,
        };
        auth.set_transcript(&challenge);
        challenge.extend_from_slice(&auth.tag(b"ghostun-tcp-v1/exit"));
        Ok((auth, challenge))
    }

    fn set_transcript(&mut self, challenge: &[u8]) {
        self.transcript = b"ghostun-tcp\x01\x01\x02".to_vec();
        self.transcript.extend_from_slice(&self.hello);
        self.transcript.extend_from_slice(&challenge[..33]);
    }

    fn mac(&self, domain: &[u8]) -> Hmac<Sha256> {
        let mut mac = self.key.clone();
        mac.update(domain);
        mac.update(&self.transcript);
        mac
    }
    fn tag(&self, domain: &[u8]) -> [u8; 32] {
        self.mac(domain).finalize().into_bytes().into()
    }
    pub fn done(&self) -> bool {
        self.expected == 0
    }

    pub fn receive(&mut self, payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let expected_len = if self.expected == 2 { 65 } else { 33 };
        if payload.len() != expected_len || payload[0] != self.expected || self.done() {
            return Err(invalid("illegal authentication message or phase"));
        }
        let (domain, next, reply, reply_domain): (&[u8], u8, u8, &[u8]) = match self.expected {
            2 => {
                self.set_transcript(payload);
                (b"ghostun-tcp-v1/exit", 4, 3, b"ghostun-tcp-v1/entry")
            }
            3 => (b"ghostun-tcp-v1/entry", 5, 4, b"ghostun-tcp-v1/finished"),
            4 => (b"ghostun-tcp-v1/finished", 0, 5, b"ghostun-tcp-v1/ready"),
            5 => (b"ghostun-tcp-v1/ready", 0, 0, b""),
            _ => return Err(invalid("illegal authentication phase")),
        };
        self.mac(domain)
            .verify_slice(&payload[payload.len() - 32..])
            .map_err(|_| invalid("authentication proof verification failed"))?;
        self.expected = next;
        Ok(if reply == 0 {
            None
        } else {
            let mut msg = vec![reply];
            msg.extend_from_slice(&self.tag(reply_domain));
            Some(msg)
        })
    }
}

pub fn validate_packet(p: &[u8], mtu: usize) -> io::Result<()> {
    let valid = p.len() <= mtu
        && match p.first().map(|v| v >> 4) {
            Some(4) if p.len() >= 20 => {
                let header = (p[0] & 15) as usize * 4;
                header >= 20
                    && header <= p.len()
                    && u16::from_be_bytes([p[2], p[3]]) as usize == p.len()
            }
            Some(6) if p.len() >= 40 => u16::from_be_bytes([p[4], p[5]]) as usize + 40 == p.len(),
            _ => false,
        };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "invalid framing: malformed inner packet or MTU exceeded",
        ))
    }
}
