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

/// Reads exactly one bounded frame without consuming the next frame from the stream.
pub struct Receive {
    bytes: Vec<u8>,
    used: usize,
    len: usize,
}

impl Receive {
    pub fn new(max: usize) -> Self {
        Self {
            bytes: vec![0; max + 2],
            used: 0,
            len: 0,
        }
    }

    pub fn read(&mut self, input: &mut impl Read) -> io::Result<bool> {
        loop {
            let end = if self.used < 2 { 2 } else { self.len + 2 };
            if self.used == end && self.used >= 2 {
                return Ok(true);
            }
            match input.read(&mut self.bytes[self.used..end]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer EOF")),
                Ok(n) => self.used += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            if self.used == 2 {
                self.len = u16::from_be_bytes([self.bytes[0], self.bytes[1]]) as usize;
                if self.len == 0 || self.len > self.bytes.len() - 2 {
                    return Err(invalid("invalid framing: zero or oversized length"));
                }
            }
        }
    }

    pub fn complete(&self) -> bool {
        self.used >= 2 && self.used == self.len + 2
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[2..2 + self.len]
    }
    pub fn clear(&mut self) {
        self.used = 0;
        self.len = 0;
    }
}

#[derive(Default)]
pub struct SendQueue {
    frames: VecDeque<Vec<u8>>,
    offset: usize,
    pub bytes: usize,
}

impl SendQueue {
    pub fn room(&self, payload: usize) -> bool {
        self.bytes + payload + 2 <= TX_LIMIT
    }

    pub fn push(&mut self, payload: &[u8]) -> bool {
        if !self.room(payload.len()) {
            return false;
        }
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.bytes += frame.len();
        self.frames.push_back(frame);
        true
    }

    pub fn flush(&mut self, output: &mut impl Write) -> io::Result<()> {
        while !self.frames.is_empty() {
            let mut slices = [IoSlice::new(&[]); 64];
            let count = self.frames.len().min(slices.len());
            for (i, frame) in self.frames.iter().take(count).enumerate() {
                slices[i] = IoSlice::new(&frame[if i == 0 { self.offset } else { 0 }..]);
            }
            match output.write_vectored(&slices[..count]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(mut n) => {
                    self.bytes -= n;
                    while n > 0 {
                        let len = self.frames.front().unwrap().len();
                        let consumed = n.min(len - self.offset);
                        self.offset += consumed;
                        n -= consumed;
                        if self.offset == len {
                            self.frames.pop_front();
                            self.offset = 0;
                        }
                    }
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
