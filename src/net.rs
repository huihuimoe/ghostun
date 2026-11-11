//! IP-level primitives shared by every layer: header layouts, checksums, and address types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use argh::FromArgValue;
use serde::Deserialize;
use zerocopy::FromBytes;

const IPPROTO_TCP: u8 = 6;

pub mod ipv4 {
    use std::mem;
    use std::net::Ipv4Addr;

    use zerocopy::byteorder::network_endian::U16;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

    pub const VERSION: u8 = 4;
    pub const HDR_LEN: usize = mem::size_of::<Header>();
    pub const MIN_MTU: u32 = 576;
    pub const OFF_SRC: usize = mem::offset_of!(Header, src);
    pub const OFF_DST: usize = mem::offset_of!(Header, dst);

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct Header {
        pub version_ihl: u8,
        pub tos: u8,
        pub total_len: U16,
        pub id: U16,
        pub flags_frag: U16,
        pub ttl: u8,
        pub protocol: u8,
        pub checksum: U16,
        pub src: [u8; 4],
        pub dst: [u8; 4],
    }

    #[inline]
    pub fn write_header(buf: &mut [u8], total_len: u16, id: u16, src: Ipv4Addr, dst: Ipv4Addr) {
        let (ip, _) = Header::mut_from_prefix(buf).expect("IPv4 header buffer");
        ip.version_ihl = (VERSION << 4) | ((HDR_LEN / 4) as u8);
        ip.tos = 0;
        ip.total_len.set(total_len);
        ip.id.set(id);
        ip.flags_frag.set(0x4000); // DF
        ip.ttl = 64;
        ip.protocol = super::IPPROTO_TCP;
        ip.checksum.set(0);
        ip.src = src.octets();
        ip.dst = dst.octets();
        let csum = super::fold(super::sum16(ip.as_bytes()));
        ip.checksum.set(csum);
    }
}

pub mod ipv6 {
    use std::mem;
    use std::net::Ipv6Addr;

    use zerocopy::byteorder::network_endian::{U16, U32};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

    pub const VERSION: u8 = 6;
    pub const HDR_LEN: usize = mem::size_of::<Header>();
    pub const MIN_MTU: u32 = 1280;
    pub const OFF_SRC: usize = mem::offset_of!(Header, src);
    pub const OFF_DST: usize = mem::offset_of!(Header, dst);

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct Header {
        pub version_tc_flow: U32,
        pub payload_len: U16,
        pub next_header: u8,
        pub hop_limit: u8,
        pub src: [u8; 16],
        pub dst: [u8; 16],
    }

    /// Writes only the base header; raw IPv6 receive also uses it to normalize headerless frames.
    #[inline]
    pub fn write_header(buf: &mut [u8], payload_len: u16, src: Ipv6Addr, dst: Ipv6Addr) {
        let (ip, _) = Header::mut_from_prefix(buf).expect("IPv6 header buffer");
        ip.version_tc_flow.set(u32::from(VERSION) << 28);
        ip.payload_len.set(payload_len);
        ip.next_header = super::IPPROTO_TCP;
        ip.hop_limit = 64;
        ip.src = src.octets();
        ip.dst = dst.octets();
    }
}

pub mod tcp {
    use std::mem;

    use zerocopy::byteorder::network_endian::{U16, U32};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

    pub const HDR_LEN: usize = mem::size_of::<Header>();
    pub const OFF_SPORT: usize = mem::offset_of!(Header, src_port);
    pub const OFF_DPORT: usize = mem::offset_of!(Header, dst_port);

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct Header {
        pub src_port: U16,
        pub dst_port: U16,
        pub seq: U32,
        pub ack: U32,
        pub data_offset: u8,
        pub flags: u8,
        pub window: U16,
        pub checksum: U16,
        pub urgent: U16,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, FromArgValue)]
#[serde(rename_all = "lowercase")]
pub enum OuterFamily {
    #[default]
    Ipv4,
    Ipv6,
}

impl OuterFamily {
    #[inline(always)]
    pub const fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() { Self::Ipv4 } else { Self::Ipv6 }
    }

    /// Outer IP plus TCP header bytes in front of each tunneled packet.
    #[inline(always)]
    pub const fn overhead(self) -> usize {
        match self {
            Self::Ipv4 => ipv4::HDR_LEN + tcp::HDR_LEN,
            Self::Ipv6 => ipv6::HDR_LEN + tcp::HDR_LEN,
        }
    }

    #[inline(always)]
    pub const fn min_mtu(self) -> u32 {
        match self {
            Self::Ipv4 => ipv4::MIN_MTU,
            Self::Ipv6 => ipv6::MIN_MTU,
        }
    }

    pub fn unspecified(self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::Ipv6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr<A> {
    pub addr: A,
    pub prefix: u8,
}

impl<A: fmt::Display> fmt::Display for Cidr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

trait CidrAddr: FromStr + Copy {
    const BITS: u8;
    fn mask(self, prefix: u8) -> Self;
}

impl CidrAddr for Ipv4Addr {
    const BITS: u8 = 32;
    fn mask(self, prefix: u8) -> Self {
        let m = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
        Ipv4Addr::from(u32::from(self) & m)
    }
}

impl CidrAddr for Ipv6Addr {
    const BITS: u8 = 128;
    fn mask(self, prefix: u8) -> Self {
        let m = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
        Ipv6Addr::from(u128::from(self) & m)
    }
}

#[allow(private_bounds)]
impl<A: CidrAddr> Cidr<A> {
    /// Same prefix with host bits cleared.
    pub fn network(&self) -> Cidr<A> {
        Cidr {
            addr: self.addr.mask(self.prefix),
            prefix: self.prefix,
        }
    }
}

impl<A: CidrAddr> FromStr for Cidr<A> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR {s:?}: missing /prefix"))?;
        let addr = addr
            .parse()
            .map_err(|_| format!("invalid CIDR {s:?}: bad address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid CIDR {s:?}: bad prefix"))?;
        if prefix > A::BITS {
            return Err(format!("invalid CIDR {s:?}: prefix exceeds {}", A::BITS));
        }
        Ok(Cidr { addr, prefix })
    }
}

/// Validates that `p` is a well-formed IPv4 or IPv6 packet within `mtu`.
#[inline]
pub fn is_valid_inner_ip(p: &[u8], mtu: usize) -> bool {
    if p.len() > mtu {
        return false;
    }
    match p.first().map(|v| v >> 4) {
        Some(ipv4::VERSION) => {
            let Ok((ip, _)) = ipv4::Header::ref_from_prefix(p) else {
                return false;
            };
            let header = usize::from(ip.version_ihl & 0x0f) * 4;
            header >= ipv4::HDR_LEN
                && header <= p.len()
                && usize::from(ip.total_len.get()) == p.len()
        }
        Some(ipv6::VERSION) => ipv6::Header::ref_from_prefix(p)
            .is_ok_and(|(ip, _)| usize::from(ip.payload_len.get()) + ipv6::HDR_LEN == p.len()),
        _ => false,
    }
}

/// Native-byte-order one's-complement sum of `data` before folding to 16 bits.
///
/// Words are summed in native byte order and [`fold`] swaps the folded result once
/// (RFC 1071 §2(B)): per-word big-endian loads cost ~9 shuffles per 16 bytes on
/// baseline SSE2, which has no `pshufb`, dominating the vectorized loop.
#[inline]
fn sum16(data: &[u8]) -> u64 {
    let mut sum = 0u64;
    let (chunks, mut tail) = data.as_chunks::<8>();
    for &chunk in chunks {
        let w = u64::from_ne_bytes(chunk);
        sum += (w >> 32) + (w & 0xffff_ffff);
    }
    if let Some((&w, rest)) = tail.split_first_chunk::<4>() {
        sum += u64::from(u32::from_ne_bytes(w));
        tail = rest;
    }
    if let Some((&w, rest)) = tail.split_first_chunk::<2>() {
        sum += u64::from(u16::from_ne_bytes(w));
        tail = rest;
    }
    if let [last] = *tail {
        sum += u64::from(u16::from_ne_bytes([last, 0]));
    }
    sum
}

#[inline]
fn fold(sum: u64) -> u16 {
    let mut s = (sum >> 32) + (sum & 0xffff_ffff);
    // Three 16-bit folds: two can still leave a carry in bit 16, which the byte swap would drop.
    s = (s >> 16) + (s & 0xffff);
    s = (s >> 16) + (s & 0xffff);
    s = (s >> 16) + (s & 0xffff);
    !u16::from_be(s as u16)
}

/// Checksum of the TCP segment at `frame[ihl..ihl + tcp_len]`, including the IP pseudo-header.
#[inline]
pub fn tcp_checksum(frame: &[u8], ihl: usize, tcp_len: usize) -> u16 {
    let addr_sum = if frame[0] >> 4 == ipv4::VERSION {
        sum16(&frame[ipv4::OFF_SRC..ipv4::OFF_DST + 4])
    } else {
        sum16(&frame[ipv6::OFF_SRC..ipv6::OFF_DST + 16])
    };
    let pseudo =
        addr_sum + u64::from(u16::from(IPPROTO_TCP).to_be()) + u64::from((tcp_len as u16).to_be());
    fold(pseudo + sum16(&frame[ihl..ihl + tcp_len]))
}

#[cfg(test)]
pub fn ipv4_header_checksum_ok(frame: &[u8]) -> bool {
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    fold(sum16(&frame[..ihl])) == 0
}

#[cfg(test)]
pub fn tcp_checksum_ok(frame: &[u8]) -> bool {
    let (ihl, total) = if frame[0] >> 4 == ipv4::VERSION {
        let (ip, _) = ipv4::Header::ref_from_prefix(frame).unwrap();
        (
            usize::from(ip.version_ihl & 0x0f) * 4,
            usize::from(ip.total_len.get()),
        )
    } else {
        let (ip, _) = ipv6::Header::ref_from_prefix(frame).unwrap();
        (
            ipv6::HDR_LEN,
            ipv6::HDR_LEN + usize::from(ip.payload_len.get()),
        )
    };
    tcp_checksum(frame, ihl, total - ihl) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum16_matches_big_endian_reference() {
        let reference = |data: &[u8], acc: u32| -> u16 {
            let mut s = data.chunks(2).fold(u64::from(acc), |s, w| {
                s + u64::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]))
            });
            while s > 0xffff {
                s = (s >> 16) + (s & 0xffff);
            }
            !(s as u16)
        };
        let noise: Vec<u8> = (0..1600u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        // All-ones data maximizes end-around carries through every fold.
        for data in [noise, vec![0xff; 1600]] {
            for len in (0..=64).chain([127, 128, 129, 1399, 1400, 1461]) {
                for offset in 0..3 {
                    let d = &data[offset..offset + len];
                    assert_eq!(
                        fold(sum16(d) + u64::from(0x1_fffeu32.to_be())),
                        reference(d, 0x1_fffe),
                        "len {len} +{offset}"
                    );
                }
            }
        }
    }
    #[test]
    fn cidr_network_clears_host_bits() {
        let v4: Cidr<Ipv4Addr> = "10.200.0.2/30".parse().unwrap();
        assert_eq!(v4.network().to_string(), "10.200.0.0/30");
        assert_eq!(
            "1.2.3.4/0"
                .parse::<Cidr<Ipv4Addr>>()
                .unwrap()
                .network()
                .to_string(),
            "0.0.0.0/0"
        );
        let v6: Cidr<Ipv6Addr> = "fd00:200::2/126".parse().unwrap();
        assert_eq!(v6.network().to_string(), "fd00:200::/126");
        assert_eq!(
            "fd00::5/128"
                .parse::<Cidr<Ipv6Addr>>()
                .unwrap()
                .network()
                .to_string(),
            "fd00::5/128"
        );
    }
}
