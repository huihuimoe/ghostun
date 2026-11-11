//! Wire header and keyed-MAC pieces common to the UDP and FakeTCP handshakes.
//!
//! The two handshakes exchange the same four messages but bind different transcripts, so only
//! the byte-identical parts live here.

use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zerocopy::byteorder::network_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub type HmacSha256 = Hmac<Sha256>;

pub const CONTROL: u8 = 3;
const VERSION: u8 = 1;
pub const HELLO: u8 = 1;
pub const CHALLENGE: u8 = 2;
pub const PROOF: u8 = 3;
pub const FINISHED: u8 = 4;

pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, PartialEq, Eq)]
#[repr(C)]
pub struct Header {
    control: u8,
    version: u8,
    kind: u8,
}

#[inline]
pub fn header(kind: u8) -> Header {
    Header {
        control: CONTROL,
        version: VERSION,
        kind,
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Finished {
    pub header: Header,
    pub ticket: U64,
    pub tag: [u8; TAG_LEN],
}

pub const FINISHED_LEN: usize = mem::size_of::<Finished>();

/// Starts a peer-key MAC over `domain` and the protocol version; the caller appends its transcript.
#[inline]
pub fn mac(key: &HmacSha256, domain: &[u8]) -> HmacSha256 {
    let mut mac = key.clone();
    mac.update(domain);
    mac.update(&[VERSION]);
    mac
}

#[inline]
pub fn address(mac: &mut HmacSha256, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            mac.update(&[4]);
            mac.update(&ip.octets());
        }
        IpAddr::V6(ip) => {
            mac.update(&[6]);
            mac.update(&ip.octets());
        }
    }
    mac.update(&addr.port().to_be_bytes());
}

/// Whether a challenge issued `issued_ms` after the Exit's origin is still redeemable at `elapsed`.
#[inline]
pub fn is_fresh(issued_ms: u64, elapsed: Duration, timeout: Duration) -> bool {
    let (issued, elapsed) = (u128::from(issued_ms), elapsed.as_millis());
    issued <= elapsed && elapsed - issued <= timeout.as_millis() * 2
}
