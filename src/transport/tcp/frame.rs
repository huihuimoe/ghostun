//! TCP v1 length-prefixed framing: constants and bounded receive decoding.

use std::io::{self, Read};

use super::invalid;
use crate::net::is_valid_inner_ip;

pub const FRAME_PREFIX_LEN: usize = 2;
pub const TX_LIMIT: usize = crate::transport::budget::BYTES;
pub const RX_LIMIT: usize = 64 * 1024;
pub const PING: u8 = 0x10;
pub const PONG: u8 = 0x11;

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
            bytes: vec![0; max + FRAME_PREFIX_LEN],
            head: 0,
            tail: 0,
            max,
        }
    }

    pub fn grow(&mut self, max: usize) {
        self.max = max;
        self.bytes.resize(RX_LIMIT.max(max + FRAME_PREFIX_LEN), 0);
    }

    #[inline(always)]
    fn frame_len(&self) -> Option<usize> {
        (self.tail - self.head >= FRAME_PREFIX_LEN).then(|| {
            usize::from(u16::from_be_bytes([
                self.bytes[self.head],
                self.bytes[self.head + 1],
            ]))
        })
    }

    #[inline(always)]
    pub fn ready(&self) -> bool {
        self.frame_len().is_some_and(|len| {
            len == 0 || len > self.max || self.tail - self.head >= FRAME_PREFIX_LEN + len
        })
    }

    #[inline]
    pub fn read(&mut self, input: &mut impl Read) -> io::Result<bool> {
        loop {
            let avail = self.tail - self.head;
            let need = match self.frame_len() {
                Some(len) if len == 0 || len > self.max => {
                    return Err(invalid("invalid framing: zero or oversized length"));
                }
                Some(len) if avail >= FRAME_PREFIX_LEN + len => return Ok(true),
                Some(len) => FRAME_PREFIX_LEN + len,
                None => FRAME_PREFIX_LEN,
            };
            if self.head > 0 && self.bytes.len() - self.tail < self.max + FRAME_PREFIX_LEN {
                self.bytes.copy_within(self.head..self.tail, 0);
                self.tail -= self.head;
                self.head = 0;
            }
            let end = if self.bytes.len() > self.max + FRAME_PREFIX_LEN {
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

    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        let len = self.frame_len().expect("complete frame");
        let start = self.head + FRAME_PREFIX_LEN;
        &self.bytes[start..start + len]
    }

    #[inline]
    pub fn clear(&mut self) {
        self.head += FRAME_PREFIX_LEN + self.frame_len().expect("complete frame");
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }
}

#[inline]
pub fn validate_packet(p: &[u8], mtu: usize) -> io::Result<()> {
    if is_valid_inner_ip(p, mtu) {
        Ok(())
    } else {
        Err(invalid(
            "invalid framing: malformed inner packet or MTU exceeded",
        ))
    }
}
