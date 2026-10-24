//! Outer IP + FakeTCP frame codec and classic BPF steering filters.

use crate::config::OuterFamily;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const IPV4_HDR: usize = 20;
pub const IPV6_HDR: usize = 40;
pub const TCP_HDR: usize = 20;
pub const MAX_OVERHEAD: usize = IPV6_HDR + TCP_HDR;
/// Control frames use a first byte whose high nibble is 0, which no IPv4 (4) or IPv6 (6) packet can have.
pub const CTRL_PING: u8 = 0x01;
pub const CTRL_PONG: u8 = 0x02;
/// Type byte + 8-byte big-endian nonce.
pub const CTRL_LEN: usize = 9;

const SYN_OPTS: [u8; 12] = [2, 4, 0, 0, 1, 1, 4, 2, 1, 3, 3, 14];
#[cfg(test)]
pub const SYN_FRAME_LEN: usize = IPV4_HDR + TCP_HDR + SYN_OPTS.len();

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

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub meta: TcpMeta,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

/// Parses a complete outer frame. IPv6 raw receive reconstructs the base header from pktinfo.
pub fn parse(buf: &[u8]) -> Option<Parsed<'_>> {
    let (ihl, total, src, dst) = match buf.first()? >> 4 {
        4 => {
            if buf.len() < IPV4_HDR || buf[9] != libc::IPPROTO_TCP as u8 {
                return None;
            }
            let ihl = usize::from(buf[0] & 0x0f) * 4;
            let total = usize::from(be16(buf, 2));
            if ihl < IPV4_HDR || be16(buf, 6) & 0x3fff != 0 {
                return None;
            }
            (
                ihl,
                total,
                IpAddr::V4(ip_at(buf, 12)),
                IpAddr::V4(ip_at(buf, 16)),
            )
        }
        6 => {
            if buf.len() < IPV6_HDR || buf[6] != libc::IPPROTO_TCP as u8 {
                return None;
            }
            (
                IPV6_HDR,
                IPV6_HDR + usize::from(be16(buf, 4)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?)),
            )
        }
        _ => return None,
    };
    if total > buf.len() || total < ihl + TCP_HDR {
        return None;
    }
    let tcp = &buf[ihl..total];
    let doff = usize::from(tcp[12] >> 4) * 4;
    if doff < TCP_HDR || doff > tcp.len() {
        return None;
    }
    Some(Parsed {
        meta: TcpMeta {
            src: SocketAddr::new(src, be16(tcp, 0)),
            dst: SocketAddr::new(dst, be16(tcp, 2)),
            seq: be32(tcp, 4),
            ack: be32(tcp, 8),
            flags: tcp[13],
            window: be16(tcp, 14),
        },
        payload: &tcp[doff..],
    })
}

fn sum16(data: &[u8], acc: u32) -> u32 {
    let mut acc = u64::from(acc);
    let (chunks, tail) = data.as_chunks::<8>();
    for &chunk in chunks {
        let w = u64::from_be_bytes(chunk);
        acc += (w >> 32) + (w & 0xffff_ffff);
    }
    let (pairs, rest) = tail.as_chunks::<2>();
    for &pair in pairs {
        acc += u64::from(u16::from_be_bytes(pair));
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    let mut s = (acc >> 32) + (acc & 0xffff_ffff);
    s = (s >> 16) + (s & 0xffff);
    ((s >> 16) + (s & 0xffff)) as u32
}

fn fold(mut acc: u32) -> u16 {
    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);
    !(acc as u16)
}

fn tcp_pseudo_sum(frame: &[u8], ihl: usize, tcp_len: usize) -> u32 {
    let addresses = if frame[0] >> 4 == 4 {
        &frame[12..20]
    } else {
        &frame[8..40]
    };
    let acc = sum16(addresses, 0) + u32::from(libc::IPPROTO_TCP as u16) + tcp_len as u32;
    sum16(&frame[ihl..ihl + tcp_len], acc)
}

#[cfg(test)]
pub fn ipv4_header_checksum_ok(frame: &[u8]) -> bool {
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    fold(sum16(&frame[..ihl], 0)) == 0
}

#[cfg(test)]
pub fn tcp_checksum_ok(frame: &[u8]) -> bool {
    let (ihl, total) = if frame[0] >> 4 == 4 {
        (
            usize::from(frame[0] & 0x0f) * 4,
            usize::from(be16(frame, 2)),
        )
    } else {
        (IPV6_HDR, IPV6_HDR + usize::from(be16(frame, 4)))
    };
    fold(tcp_pseudo_sum(frame, ihl, total - ihl)) == 0
}

/// Writes only the IPv6 base header, also used to normalize headerless raw receives in place.
pub fn write_ipv6_header(buf: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr, tcp_len: usize) {
    buf[..4].copy_from_slice(&[0x60, 0, 0, 0]);
    buf[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    buf[6] = libc::IPPROTO_TCP as u8;
    buf[7] = 64;
    buf[8..24].copy_from_slice(&src.octets());
    buf[24..40].copy_from_slice(&dst.octets());
}

fn write_frame(
    buf: &mut [u8],
    meta: &TcpMeta,
    opts: &[u8],
    payload_len: usize,
    ip_id: u16,
) -> usize {
    let tcp_len = TCP_HDR + opts.len() + payload_len;
    let ihl = OuterFamily::of(meta.src.ip()).overhead() - TCP_HDR;
    let total = ihl + tcp_len;
    match (meta.src.ip(), meta.dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = &mut buf[..IPV4_HDR];
            ip[0] = 0x45;
            ip[1] = 0;
            ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
            ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            ip[8] = 64;
            ip[9] = libc::IPPROTO_TCP as u8;
            ip[10..12].fill(0);
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let csum = fold(sum16(ip, 0));
            ip[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => write_ipv6_header(buf, src, dst, tcp_len),
        _ => unreachable!("session endpoints have the same address family"),
    }

    let tcp = &mut buf[ihl..ihl + TCP_HDR + opts.len()];
    tcp[0..2].copy_from_slice(&meta.src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&meta.dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&meta.seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&meta.ack.to_be_bytes());
    tcp[12] = (((TCP_HDR + opts.len()) / 4) as u8) << 4;
    tcp[13] = meta.flags;
    tcp[14..16].copy_from_slice(&meta.window.to_be_bytes());
    tcp[16..20].fill(0);
    tcp[20..].copy_from_slice(opts);
    let csum = fold(tcp_pseudo_sum(buf, ihl, tcp_len));
    buf[ihl + 16..ihl + 18].copy_from_slice(&csum.to_be_bytes());
    total
}

/// Prepends headers in place; payload starts at the source address family's encapsulation offset.
pub fn write_headers(buf: &mut [u8], meta: &TcpMeta, payload_len: usize, ip_id: u16) -> usize {
    write_frame(buf, meta, &[], payload_len, ip_id)
}

/// SYN or SYN|ACK (per `meta.flags`) carrying MSS, SACK_PERM and Window Scale 14.
pub fn write_syn(buf: &mut [u8], meta: &TcpMeta, mss: u16, ip_id: u16) -> usize {
    let mut opts = SYN_OPTS;
    opts[2..4].copy_from_slice(&mss.to_be_bytes());
    write_frame(buf, meta, &opts, 0, ip_id)
}

const ACCEPT: u32 = u32::MAX;

/// Linear cBPF builder: conditions fall through on success and share one rejection tail.
struct Prog(Vec<libc::sock_filter>);

impl Prog {
    fn stmt(&mut self, code: u32, k: u32) -> &mut Self {
        self.0.push(libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        });
        self
    }

    fn finish(&mut self) -> Vec<libc::sock_filter> {
        let reject = self.0.len() + 1;
        for (pc, ins) in self.0.iter_mut().enumerate() {
            if u32::from(ins.code) & 0x07 == libc::BPF_JMP {
                ins.jf = (reject - pc - 1) as u8;
            }
        }
        let ret = libc::BPF_RET | libc::BPF_K;
        self.stmt(ret, ACCEPT).stmt(ret, 0);
        std::mem::take(&mut self.0)
    }
}

const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const LDX_IHL: u32 = libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH;
const LD_H_IND: u32 = libc::BPF_LD | libc::BPF_H | libc::BPF_IND;
const JEQ: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGE: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const MOD: u32 = libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K;

// Raw sockets only see reassembled datagrams, so the filters need no fragment handling.

/// Entry worker `i`: `saddr == exit.ip && sport == exit.port && dport >= base_port && dport % n == i`.
pub fn entry_filter(exit: SocketAddr, base_port: u16, n: u16, i: u16) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    match exit.ip() {
        IpAddr::V4(_) => p.stmt(LDX_IHL, 0),
        IpAddr::V6(_) => p.stmt(libc::BPF_LDX | libc::BPF_IMM, 0),
    };
    // Check worker port residue before source address words so N-1 sockets reject early.
    p.stmt(LD_H_IND, 0)
        .stmt(JEQ, u32::from(exit.port()))
        .stmt(LD_H_IND, 2)
        .stmt(JGE, u32::from(base_port))
        .stmt(MOD, u32::from(n))
        .stmt(JEQ, u32::from(i));
    match exit.ip() {
        IpAddr::V4(ip) => {
            p.stmt(LD_W_ABS, 12).stmt(JEQ, u32::from(ip));
        }
        IpAddr::V6(ip) => {
            // IPv6 raw socket filters see TCP at offset zero; source IP is network-header relative.
            for (idx, word) in ip.octets().as_chunks::<4>().0.iter().enumerate() {
                p.stmt(LD_W_ABS, (libc::SKF_NET_OFF + 8 + idx as i32 * 4) as u32)
                    .stmt(JEQ, u32::from_be_bytes(*word));
            }
        }
    }
    p.finish()
}

/// Exit worker `i`: `dport == listen_port && sport % n == i`.
pub fn exit_filter(
    family: OuterFamily,
    listen_port: u16,
    n: u16,
    i: u16,
) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    match family {
        OuterFamily::Ipv4 => {
            p.stmt(LDX_IHL, 0);
        }
        OuterFamily::Ipv6 => {
            p.stmt(libc::BPF_LDX | libc::BPF_IMM, 0);
        }
    }
    p.stmt(LD_H_IND, 2)
        .stmt(JEQ, u32::from(listen_port))
        .stmt(LD_H_IND, 0)
        .stmt(MOD, u32::from(n))
        .stmt(JEQ, u32::from(i))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    const OUTER_OVERHEAD: usize = IPV4_HDR + TCP_HDR;

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
        let mut buf = [0u8; 128];
        let payload = [0x45, 1, 2, 3, 4, 5, 6];
        buf[OUTER_OVERHEAD..OUTER_OVERHEAD + payload.len()].copy_from_slice(&payload);
        let len = write_headers(&mut buf, &meta(flags::PSH | flags::ACK), payload.len(), 7);
        assert_eq!(len, 47);
        let frame = &buf[..len];
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
        assert_eq!(frame[IPV4_HDR + 12] >> 4, 8, "32-byte TCP header");
        assert_eq!(
            &frame[OUTER_OVERHEAD..],
            &[2, 4, 0x05, 0xb4, 1, 1, 4, 2, 1, 3, 3, 14]
        );
        assert!(ipv4_header_checksum_ok(frame) && tcp_checksum_ok(frame));
        let p = parse(frame).unwrap();
        assert_eq!(p.meta.flags, flags::SYN);
        assert!(p.payload.is_empty());
    }

    /// Builds a frame with `ip_opts` IPv4 option bytes and `tcp_opts` TCP option bytes.
    fn frame_with_options(
        ip_opts: usize,
        tcp_opts: usize,
        payload: &[u8],
        src: SocketAddrV4,
        dst: SocketAddrV4,
    ) -> Vec<u8> {
        let ihl = IPV4_HDR + ip_opts;
        let doff = TCP_HDR + tcp_opts;
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

    #[test]
    fn parse_honors_ip_and_tcp_options_and_total_length() {
        let mut f = frame_with_options(4, 12, &[0x60, 9, 9], A, B);
        f.extend_from_slice(&[0xee; 5]); // trailing link padding beyond total_len
        let p = parse(&f).unwrap();
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

    /// Minimal interpreter using the same network/transport offsets as Linux raw sockets.
    fn run_bpf(prog: &[libc::sock_filter], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let transport = if pkt[0] >> 4 == 6 { IPV6_HDR } else { 0 };
        let offset = |k: u32| {
            if (k as i32) < 0 {
                (k as i32 - libc::SKF_NET_OFF) as usize
            } else {
                transport + k as usize
            }
        };
        let h = |at: usize| u32::from(u16::from_be_bytes([pkt[at], pkt[at + 1]]));
        loop {
            let ins = prog[pc];
            pc += 1;
            let code = u32::from(ins.code);
            let k = ins.k;
            match code {
                LD_W_ABS => {
                    let at = offset(k);
                    a = u32::from_be_bytes(pkt[at..at + 4].try_into().unwrap())
                }
                LDX_IHL => x = u32::from(pkt[k as usize] & 0x0f) * 4,
                LD_H_IND => a = h(offset(x + k)),
                MOD => a %= k,
                c if c == libc::BPF_LDX | libc::BPF_IMM => x = k,
                JEQ | JGE => {
                    let taken = if code == JEQ { a == k } else { a >= k };
                    pc += usize::from(if taken { ins.jt } else { ins.jf });
                }
                c if c == libc::BPF_RET | libc::BPF_K => return k,
                c => panic!("unexpected opcode {c:#x}"),
            }
        }
    }

    #[test]
    fn entry_filter_steers_by_dport_residue() {
        let exit = B;
        let me = Ipv4Addr::new(192, 0, 2, 1);
        let f = |n, i| entry_filter(exit.into(), 32768, n, i);
        let pkt = |src: SocketAddrV4, dport: u16| {
            frame_with_options(0, 0, &[], src, SocketAddrV4::new(me, dport))
        };
        let to = |dport| pkt(exit, dport);
        assert_eq!(run_bpf(&f(4, 1), &to(32769)), ACCEPT);
        assert_eq!(run_bpf(&f(4, 1), &to(32773)), ACCEPT);
        assert_eq!(run_bpf(&f(4, 2), &to(32769)), 0, "other residue");
        assert_eq!(run_bpf(&f(4, 1), &to(32765)), 0, "below base port");
        assert_eq!(
            run_bpf(&f(4, 1), &pkt(SocketAddrV4::new(*exit.ip(), 444), 32769)),
            0,
            "wrong sport"
        );
        assert_eq!(
            run_bpf(
                &f(4, 1),
                &pkt(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443), 32769)
            ),
            0,
            "wrong saddr"
        );
        assert_eq!(
            run_bpf(&f(1, 0), &to(50000)),
            ACCEPT,
            "single worker takes all"
        );
        let with_opts = frame_with_options(4, 0, &[], exit, SocketAddrV4::new(me, 32769));
        assert_eq!(run_bpf(&f(4, 1), &with_opts), ACCEPT, "IHL=24");
    }

    #[test]
    fn exit_filter_steers_by_sport_residue() {
        let me = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 443);
        let from = |sport| {
            frame_with_options(
                0,
                0,
                &[],
                SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), sport),
                me,
            )
        };
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv4, 443, 3, 2), &from(40001)),
            ACCEPT
        ); // 40001 % 3 == 2
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv4, 443, 3, 0), &from(40001)),
            0
        );
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv4, 444, 3, 2), &from(40001)),
            0,
            "wrong dport"
        );
        let with_opts = frame_with_options(
            8,
            0,
            &[],
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40001),
            me,
        );
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv4, 443, 3, 2), &with_opts),
            ACCEPT,
            "IHL=28"
        );
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

    #[test]
    fn ipv6_filters_match_all_address_words_and_worker_ports() {
        let exit: SocketAddr = "[2001:db8:2::1]:443".parse().unwrap();
        let entry: SocketAddr = "[2001:db8:1::1]:40001".parse().unwrap();
        let mut buf = [0u8; 128];
        let mut m = TcpMeta {
            src: exit,
            dst: entry,
            ..meta(flags::ACK)
        };
        let len = write_headers(&mut buf, &m, 0, 0);
        let filter = entry_filter(exit, 32768, 3, 2);
        assert_eq!(run_bpf(&filter, &buf[..len]), ACCEPT);
        assert_eq!(run_bpf(&entry_filter(exit, 32768, 3, 1), &buf[..len]), 0);
        assert_eq!(run_bpf(&entry_filter(exit, 40002, 3, 2), &buf[..len]), 0);
        for at in [8, 12, 16, 20] {
            buf[at] ^= 1;
            assert_eq!(
                run_bpf(&filter, &buf[..len]),
                0,
                "source address word at {at}"
            );
            buf[at] ^= 1;
        }
        m.src.set_port(444);
        write_headers(&mut buf, &m, 0, 0);
        assert_eq!(run_bpf(&filter, &buf[..len]), 0);
        m.src = entry;
        m.dst = exit;
        write_headers(&mut buf, &m, 0, 0);
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv6, 443, 3, 2), &buf[..len]),
            ACCEPT
        );
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv6, 443, 3, 1), &buf[..len]),
            0
        );
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv6, 444, 3, 2), &buf[..len]),
            0
        );
    }
}
