//! FakeTCP outer frames: TCP segment metadata, in-place IP + TCP header emission, and parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use zerocopy::FromBytes;

use crate::net::{self, ipv4, ipv6, tcp, OuterFamily};

pub const MAX_OVERHEAD: usize = ipv6::HDR_LEN + tcp::HDR_LEN;

const SYN_OPTS_TEMPLATE: [u8; 12] = [2, 4, 0, 0, 1, 1, 4, 2, 1, 3, 3, 14];
const SYN_OPT_MSS_OFF: usize = 2;
#[cfg(test)]
pub const SYN_FRAME_LEN: usize = ipv4::HDR_LEN + tcp::HDR_LEN + SYN_OPTS_TEMPLATE.len();

pub mod flags {
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpMeta {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

impl TcpMeta {
    #[inline]
    fn write_to(&self, buf: &mut [u8], opts: &[u8], ihl: usize, tcp_len: usize) {
        let (tcp, options) =
            tcp::Header::mut_from_prefix(&mut buf[ihl..ihl + tcp::HDR_LEN + opts.len()])
                .expect("TCP header buffer");
        tcp.src_port.set(self.src.port());
        tcp.dst_port.set(self.dst.port());
        tcp.seq.set(self.seq);
        tcp.ack.set(self.ack);
        tcp.data_offset = (((tcp::HDR_LEN + opts.len()) / 4) as u8) << 4;
        tcp.flags = self.flags;
        tcp.window.set(self.window);
        tcp.checksum.set(0);
        tcp.urgent.set(0);
        options.copy_from_slice(opts);
        let csum = net::tcp_checksum(buf, ihl, tcp_len);
        let (tcp, _) = tcp::Header::mut_from_prefix(&mut buf[ihl..]).expect("TCP header buffer");
        tcp.checksum.set(csum);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub meta: TcpMeta,
    pub payload: &'a [u8],
}

/// Parses a complete outer frame. IPv6 raw receive reconstructs the base header from pktinfo.
#[inline]
pub fn parse(buf: &[u8]) -> Option<Parsed<'_>> {
    let (ihl, total, src, dst) = match buf.first()? >> 4 {
        ipv4::VERSION => {
            let (ip, _) = ipv4::Header::ref_from_prefix(buf).ok()?;
            if ip.protocol != libc::IPPROTO_TCP as u8 {
                return None;
            }
            let ihl = usize::from(ip.version_ihl & 0x0f) * 4;
            let total = usize::from(ip.total_len.get());
            if ihl < ipv4::HDR_LEN || ip.flags_frag.get() & 0x3fff != 0 {
                return None;
            }
            (
                ihl,
                total,
                IpAddr::V4(Ipv4Addr::from(ip.src)),
                IpAddr::V4(Ipv4Addr::from(ip.dst)),
            )
        }
        ipv6::VERSION => {
            let (ip, _) = ipv6::Header::ref_from_prefix(buf).ok()?;
            if ip.next_header != libc::IPPROTO_TCP as u8 {
                return None;
            }
            (
                ipv6::HDR_LEN,
                ipv6::HDR_LEN + usize::from(ip.payload_len.get()),
                IpAddr::V6(Ipv6Addr::from(ip.src)),
                IpAddr::V6(Ipv6Addr::from(ip.dst)),
            )
        }
        _ => return None,
    };
    if total > buf.len() || total < ihl + tcp::HDR_LEN {
        return None;
    }
    let tcp_slice = &buf[ihl..total];
    let (tcp, _) = tcp::Header::ref_from_prefix(tcp_slice).ok()?;
    let doff = usize::from(tcp.data_offset >> 4) * 4;
    if doff < tcp::HDR_LEN || doff > tcp_slice.len() {
        return None;
    }
    Some(Parsed {
        meta: TcpMeta {
            src: SocketAddr::new(src, tcp.src_port.get()),
            dst: SocketAddr::new(dst, tcp.dst_port.get()),
            seq: tcp.seq.get(),
            ack: tcp.ack.get(),
            flags: tcp.flags,
            window: tcp.window.get(),
        },
        payload: &tcp_slice[doff..],
    })
}

#[inline]
fn write_frame(
    buf: &mut [u8],
    meta: &TcpMeta,
    opts: &[u8],
    payload_len: usize,
    ip_id: u16,
) -> usize {
    let tcp_len = tcp::HDR_LEN + opts.len() + payload_len;
    let ihl = OuterFamily::of(meta.src.ip()).overhead() - tcp::HDR_LEN;
    let total = ihl + tcp_len;
    match (meta.src.ip(), meta.dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ipv4::write_header(buf, total as u16, ip_id, src, dst);
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6::write_header(buf, tcp_len as u16, src, dst);
        }
        _ => unreachable!("session endpoints have the same address family"),
    }
    meta.write_to(buf, opts, ihl, tcp_len);
    total
}

/// Prepends headers in place; payload starts at the source address family's encapsulation offset.
#[inline]
pub fn write_headers(buf: &mut [u8], meta: &TcpMeta, payload_len: usize, ip_id: u16) -> usize {
    write_frame(buf, meta, &[], payload_len, ip_id)
}

/// SYN or SYN|ACK (per `meta.flags`) carrying MSS, SACK_PERM and Window Scale 14.
#[inline]
pub fn write_syn(buf: &mut [u8], meta: &TcpMeta, mss: u16, ip_id: u16) -> usize {
    let mut opts = SYN_OPTS_TEMPLATE;
    opts[SYN_OPT_MSS_OFF..SYN_OPT_MSS_OFF + 2].copy_from_slice(&mss.to_be_bytes());
    write_frame(buf, meta, &opts, 0, ip_id)
}

/// Builds an IPv4 frame with `ip_opts` IPv4 option bytes and `tcp_opts` TCP option bytes.
#[cfg(test)]
pub fn frame_with_options(
    ip_opts: usize,
    tcp_opts: usize,
    payload: &[u8],
    src: std::net::SocketAddrV4,
    dst: std::net::SocketAddrV4,
) -> Vec<u8> {
    let ihl = ipv4::HDR_LEN + ip_opts;
    let doff = tcp::HDR_LEN + tcp_opts;
    let total = ihl + doff + payload.len();
    let mut f = vec![0u8; total];
    f[0] = 0x40 | (ihl / 4) as u8;
    f[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    f[8] = 64;
    f[9] = 6;
    f[12..16].copy_from_slice(&src.ip().octets());
    f[16..20].copy_from_slice(&dst.ip().octets());
    f[20..ihl].fill(1); // NOP options
    f[ihl..ihl + 2].copy_from_slice(&src.port().to_be_bytes());
    f[ihl + 2..ihl + 4].copy_from_slice(&dst.port().to_be_bytes());
    f[ihl + 12] = ((doff / 4) as u8) << 4;
    f[ihl + 13] = flags::ACK;
    f[ihl + doff..].copy_from_slice(payload);
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{ipv4_header_checksum_ok, tcp_checksum_ok};
    use std::net::SocketAddrV4;
    const OUTER_OVERHEAD: usize = ipv4::HDR_LEN + tcp::HDR_LEN;

    const A: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40001);
    const B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 443);

    fn meta(flags: u8) -> TcpMeta {
        TcpMeta {
            src: A.into(),
            dst: B.into(),
            seq: 0xdead_beef,
            ack: 0x0102_0304,
            flags,
            window: 65535,
        }
    }

    #[test]
    fn data_frame_round_trips_with_valid_checksums() {
        let mut storage = [0u8; 129];
        let buf = &mut storage[1..];
        let payload = [0x45, 1, 2, 3, 4, 5, 6];
        buf[OUTER_OVERHEAD..OUTER_OVERHEAD + payload.len()].copy_from_slice(&payload);
        let len = write_headers(buf, &meta(flags::PSH | flags::ACK), payload.len(), 7);
        assert_eq!(len, 47);
        let frame = &buf[..len];
        assert_eq!(
            frame,
            &[
                0x45, 0x00, 0x00, 0x2f, 0x00, 0x07, 0x40, 0x00, 0x40, 0x06, 0x4e, 0x86, 0xc0, 0x00,
                0x02, 0x01, 0xc6, 0x33, 0x64, 0x07, 0x9c, 0x41, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef,
                0x01, 0x02, 0x03, 0x04, 0x50, 0x18, 0xff, 0xff, 0x32, 0xe0, 0x00, 0x00, 0x45, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06,
            ]
        );
        assert!(ipv4_header_checksum_ok(frame));
        assert!(tcp_checksum_ok(frame));
        assert_eq!(&frame[6..8], &[0x40, 0], "DF set");
        let p = parse(frame).unwrap();
        assert_eq!(p.meta, meta(flags::PSH | flags::ACK));
        assert_eq!(p.payload, &payload);
    }

    #[test]
    fn odd_length_payload_checksum_matches_reference() {
        let mut buf = [0u8; 64];
        buf[OUTER_OVERHEAD..OUTER_OVERHEAD + 3].copy_from_slice(&[1, 2, 3]);
        let len = write_headers(&mut buf, &meta(flags::ACK), 3, 0);
        assert!(tcp_checksum_ok(&buf[..len]));
        buf[OUTER_OVERHEAD + 2] ^= 0xff;
        assert!(!tcp_checksum_ok(&buf[..len]));
        let mut max_addrs = meta(flags::ACK);
        max_addrs.dst = "63.255.253.254:443".parse().unwrap();
        let len = write_headers(&mut buf, &max_addrs, 3, 0);
        assert!(ipv4_header_checksum_ok(&buf[..len]) && tcp_checksum_ok(&buf[..len]));
    }

    #[test]
    fn syn_frame_carries_mss_sack_and_wscale() {
        let mut buf = [0u8; 64];
        let len = write_syn(&mut buf, &meta(flags::SYN), 1460, 1);
        assert_eq!(len, SYN_FRAME_LEN);
        let frame = &buf[..len];
        assert_eq!(frame[ipv4::HDR_LEN + 12] >> 4, 8, "32-byte TCP header");
        assert_eq!(
            &frame[OUTER_OVERHEAD..],
            &[2, 4, 0x05, 0xb4, 1, 1, 4, 2, 1, 3, 3, 14]
        );
        assert!(ipv4_header_checksum_ok(frame) && tcp_checksum_ok(frame));
        let p = parse(frame).unwrap();
        assert_eq!(p.meta.flags, flags::SYN);
        assert!(p.payload.is_empty());
    }

    #[test]
    fn parse_honors_ip_and_tcp_options_and_total_length() {
        let mut f = frame_with_options(4, 12, &[0x60, 9, 9], A, B);
        f.extend_from_slice(&[0xee; 5]); // trailing link padding beyond total_len
        let mut padded = vec![0xff];
        padded.extend_from_slice(&f);
        let p = parse(&padded[1..]).unwrap();
        assert_eq!(p.meta.src, SocketAddr::V4(A));
        assert_eq!(p.meta.dst, SocketAddr::V4(B));
        assert_eq!(p.payload, &[0x60, 9, 9]);
    }

    #[test]
    fn parse_rejects_malformed_frames() {
        let good = frame_with_options(0, 0, &[1, 2], A, B);
        assert!(parse(&good).is_some());
        assert!(parse(&good[..19]).is_none(), "short");
        let mutate = |f: fn(&mut Vec<u8>)| {
            let mut v = good.clone();
            f(&mut v);
            parse(&v).is_none()
        };
        assert!(mutate(|v| v[0] = 0x65), "version 6");
        assert!(mutate(|v| v[0] = 0x44), "ihl < 5");
        assert!(mutate(|v| v[9] = 17), "udp");
        assert!(mutate(|v| v[6] = 0x20), "more fragments");
        assert!(mutate(|v| v[7] = 0x01), "fragment offset");
        assert!(mutate(|v| v[3] = 0xff), "total_len > buffer");
        assert!(mutate(|v| v[32] = 0x40), "doff < 5");
        assert!(mutate(|v| v[32] = 0xf0), "doff beyond segment");
    }

    #[test]
    fn ipv6_frames_preserve_payload_and_reject_invalid_lengths() {
        let meta = TcpMeta {
            src: "[2001:db8:1::1]:40001".parse().unwrap(),
            dst: "[2001:db8:2::1]:443".parse().unwrap(),
            ..meta(flags::PSH | flags::ACK)
        };
        let mut buf = [0u8; 128];
        let payload = [0x60, 1, 2, 3, 4];
        buf[60..65].copy_from_slice(&payload);
        let len = write_headers(&mut buf, &meta, payload.len(), 0);
        assert_eq!(len, 65);
        assert_eq!(&buf[4..8], &[0, 25, 6, 64]);
        assert!(tcp_checksum_ok(&buf[..len]));
        let p = parse(&buf[..len]).unwrap();
        assert_eq!(p.meta, meta);
        assert_eq!(p.payload, payload);
        assert!(parse(&buf[..len - 1]).is_none());
        buf[5] = 19;
        assert!(parse(&buf[..len]).is_none());
        buf[5] = 25;
        buf[6] = 17;
        assert!(parse(&buf[..len]).is_none());
        buf[6] = 6;
        buf[8] ^= 1;
        assert!(
            !tcp_checksum_ok(&buf[..len]),
            "IPv6 pseudo-header covers source address"
        );
    }
}
