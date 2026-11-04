//! Classic BPF filters that steer each outer FakeTCP flow to its worker's raw socket.

use std::net::{IpAddr, SocketAddr};

use super::frame::flags;
use crate::net::{OuterFamily, ipv4, ipv6, tcp};

const ACCEPT: u32 = u32::MAX;
const OFF_DATA_OFFSET: u32 = 12;
const OFF_FLAGS: u32 = 13;

/// Linear cBPF builder: conditions fall through on success and share one rejection tail.
struct Prog(Vec<libc::sock_filter>);

impl Prog {
    fn init(&mut self, family: OuterFamily) -> &mut Self {
        match family {
            OuterFamily::Ipv4 => self.stmt(LDX_IHL, 0),
            OuterFamily::Ipv6 => self.stmt(libc::BPF_LDX | libc::BPF_IMM, 0),
        }
    }

    fn stmt(&mut self, code: u32, k: u32) -> &mut Self {
        self.0.push(libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        });
        self
    }

    fn branch_eq(&mut self, k: u32) -> &mut Self {
        self.0.push(libc::sock_filter {
            code: JEQ as u16,
            jt: 1,
            jf: 0,
            k,
        });
        self
    }

    fn ip(&mut self, ip: IpAddr, v4_off: usize, v6_off: usize) -> &mut Self {
        match ip {
            IpAddr::V4(ip) => {
                self.stmt(LD_W_ABS, v4_off as u32).stmt(JEQ, u32::from(ip));
            }
            IpAddr::V6(ip) => {
                // IPv6 raw socket filters see TCP at offset zero; IP headers are network-header relative.
                for (idx, word) in ip.octets().as_chunks::<4>().0.iter().enumerate() {
                    self.stmt(
                        LD_W_ABS,
                        (libc::SKF_NET_OFF + v6_off as i32 + idx as i32 * 4) as u32,
                    )
                    .stmt(JEQ, u32::from_be_bytes(*word));
                }
            }
        }
        self
    }

    fn finish(&mut self) -> Vec<libc::sock_filter> {
        self.finish_at(self.0.len())
    }

    fn finish_at(&mut self, tail: usize) -> Vec<libc::sock_filter> {
        let accept = self.0.len();
        let reject = accept + 1;
        for (pc, ins) in self.0.iter_mut().enumerate() {
            if u32::from(ins.code) & 0x07 == libc::BPF_JMP {
                if ins.jt != 0 {
                    ins.jt = (tail - pc - 1) as u8;
                } else {
                    ins.jf = (reject - pc - 1) as u8;
                }
            }
        }
        let ret = libc::BPF_RET | libc::BPF_K;
        self.stmt(ret, ACCEPT).stmt(ret, 0);
        std::mem::take(&mut self.0)
    }
}
const LD_LEN: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_LEN;
const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const LDX_IHL: u32 = libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH;
const LD_H_IND: u32 = libc::BPF_LD | libc::BPF_H | libc::BPF_IND;
const LD_B_IND: u32 = libc::BPF_LD | libc::BPF_B | libc::BPF_IND;
const JEQ: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGE: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const MOD: u32 = libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K;
const AND: u32 = libc::BPF_ALU | libc::BPF_AND | libc::BPF_K;
const LSH: u32 = libc::BPF_ALU | libc::BPF_LSH | libc::BPF_K;
const RSH: u32 = libc::BPF_ALU | libc::BPF_RSH | libc::BPF_K;
const ADD_X: u32 = libc::BPF_ALU | libc::BPF_ADD | libc::BPF_X;
const TAX: u32 = libc::BPF_MISC | libc::BPF_TAX;
// Raw sockets only see reassembled datagrams, so the filters need no fragment handling.

/// Entry worker `i`: `saddr == exit.ip && sport == exit.port && dport >= base_port && dport % n == i`.
pub fn entry_filter(exit: SocketAddr, base_port: u16, n: u16, i: u16) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    // Check worker port residue before source address words so N-1 sockets reject early.
    p.init(OuterFamily::of(exit.ip()))
        .stmt(LD_H_IND, tcp::OFF_SPORT as u32)
        .stmt(JEQ, u32::from(exit.port()))
        .stmt(LD_H_IND, tcp::OFF_DPORT as u32)
        .stmt(JGE, u32::from(base_port))
        .stmt(MOD, u32::from(n))
        .stmt(JEQ, u32::from(i))
        .ip(exit.ip(), ipv4::OFF_SRC, ipv6::OFF_SRC)
        .finish()
}

/// Exit listener: `dport == listen_port` (and `daddr == listen_ip` when set), accepting only
/// `SYN` or control frames (`PSH|ACK` with `payload[0] < 4`) so tunnel data never wakes the listener.
pub fn exit_listener_filter(
    family: OuterFamily,
    listen_ip: Option<IpAddr>,
    listen_port: u16,
) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    // Valid SYN and control frames (Proof is 181 B) are always < 256 B; reject bulk data immediately.
    p.stmt(LD_LEN, 0)
        .stmt(AND, !0xff)
        .stmt(JEQ, 0)
        .init(family)
        .stmt(LD_H_IND, tcp::OFF_DPORT as u32)
        .stmt(JEQ, u32::from(listen_port))
        .stmt(LD_B_IND, OFF_FLAGS)
        .stmt(AND, u32::from(flags::SYN | flags::ACK | flags::RST))
        .branch_eq(u32::from(flags::SYN))
        .stmt(LD_B_IND, OFF_FLAGS)
        .stmt(
            AND,
            u32::from(flags::PSH | flags::ACK | flags::SYN | flags::RST),
        )
        .stmt(JEQ, u32::from(flags::PSH | flags::ACK))
        .stmt(LD_B_IND, OFF_DATA_OFFSET)
        .stmt(RSH, 4)
        .stmt(JGE, 5)
        .stmt(LSH, 2)
        .stmt(ADD_X, 0)
        .stmt(TAX, 0)
        .stmt(LD_B_IND, 0)
        .stmt(AND, 0xfc)
        .stmt(JEQ, 0);
    let tail = p.0.len();
    if let Some(ip) = listen_ip {
        p.ip(ip, ipv4::OFF_DST, ipv6::OFF_DST);
    }
    p.finish_at(tail)
}

/// Exit worker: steers by `(sport == peer.port() && dport == local.port() && !SYN)`.
/// Full 32-bit/128-bit endpoint addresses are verified in userspace by `Session::on_exit_outer`
/// without per-packet `SKF_NET_OFF` kernel helper calls.
pub fn exit_worker_filter(local: SocketAddr, peer: SocketAddr) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    p.init(OuterFamily::of(local.ip()))
        .stmt(LD_H_IND, tcp::OFF_SPORT as u32)
        .stmt(JEQ, u32::from(peer.port()))
        .stmt(LD_H_IND, tcp::OFF_DPORT as u32)
        .stmt(JEQ, u32::from(local.port()))
        .stmt(LD_B_IND, OFF_FLAGS)
        .stmt(AND, u32::from(flags::SYN))
        .stmt(JEQ, 0)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::faketcp::frame::{TcpMeta, flags, frame_with_options, write_headers};
    use std::net::{Ipv4Addr, SocketAddrV4};

    const B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 443);

    /// Minimal interpreter using the same network/transport offsets as Linux raw sockets.
    fn run_bpf(prog: &[libc::sock_filter], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let transport = if pkt[0] >> 4 == 6 { ipv6::HDR_LEN } else { 0 };
        let offset = |k: u32| {
            if (k as i32) < 0 {
                (k as i32 - libc::SKF_NET_OFF) as usize
            } else {
                transport + k as usize
            }
        };
        loop {
            let ins = prog[pc];
            pc += 1;
            let code = u32::from(ins.code);
            let k = ins.k;
            match code {
                LD_LEN => a = (pkt.len() - transport) as u32,
                LD_W_ABS => {
                    let at = offset(k);
                    if at + 4 > pkt.len() {
                        return 0;
                    }
                    a = u32::from_be_bytes(pkt[at..at + 4].try_into().unwrap())
                }
                LDX_IHL => x = u32::from(pkt[k as usize] & 0x0f) * 4,
                LD_H_IND => {
                    let at = offset(x + k);
                    if at + 2 > pkt.len() {
                        return 0;
                    }
                    a = u32::from(u16::from_be_bytes([pkt[at], pkt[at + 1]]));
                }
                LD_B_IND => {
                    let at = offset(x + k);
                    if at >= pkt.len() {
                        return 0;
                    }
                    a = u32::from(pkt[at]);
                }
                MOD => a %= k,
                AND => a &= k,
                LSH => a <<= k,
                RSH => a >>= k,
                ADD_X => a = a.wrapping_add(x),
                TAX => x = a,
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
    fn exit_listener_and_worker_filters_separate_handshakes_from_4tuple_data() {
        let me = SocketAddr::from(B);
        let peer: SocketAddr = "192.0.2.1:40001".parse().unwrap();
        let other_peer: SocketAddr = "192.0.2.1:40002".parse().unwrap();
        let listener = exit_listener_filter(OuterFamily::Ipv4, None, 443);
        let bound_listener = exit_listener_filter(OuterFamily::Ipv4, Some(me.ip()), 443);
        let worker = exit_worker_filter(me, peer);
        let make = |src: SocketAddr, dst: SocketAddr, fl: u8, payload: &[u8]| {
            let mut buf = vec![0u8; 40 + payload.len()];
            buf[40..].copy_from_slice(payload);
            let m = TcpMeta {
                src,
                dst,
                seq: 1,
                ack: 2,
                flags: fl,
                window: 65535,
            };
            let n = write_headers(&mut buf, &m, payload.len(), 0);
            buf.truncate(n);
            buf
        };
        let syn = make(peer, me, flags::SYN, &[]);
        let hello = make(peer, me, flags::PSH | flags::ACK, &[3, 1, 1]);
        let ping = make(peer, me, flags::PSH | flags::ACK, &[1, 0, 0]);
        let v4_data = make(peer, me, flags::PSH | flags::ACK, &[0x45, 0, 0, 20]);
        let v6_data = make(peer, me, flags::PSH | flags::ACK, &[0x60, 0, 0, 0]);
        let bare_ack = make(peer, me, flags::ACK, &[]);
        let rst = make(peer, me, flags::RST | flags::ACK, &[]);

        assert_eq!(run_bpf(&listener, &syn), ACCEPT);
        assert_eq!(run_bpf(&bound_listener, &syn), ACCEPT);
        assert_eq!(run_bpf(&listener, &hello), ACCEPT);
        assert_eq!(run_bpf(&listener, &ping), ACCEPT);
        assert_eq!(run_bpf(&listener, &v4_data), 0, "listener drops inner IPv4");
        assert_eq!(run_bpf(&listener, &v6_data), 0, "listener drops inner IPv6");
        assert_eq!(run_bpf(&listener, &bare_ack), 0, "listener drops bare ACK");
        assert_eq!(run_bpf(&listener, &rst), 0, "listener drops RST");
        assert_eq!(
            run_bpf(
                &exit_listener_filter(
                    OuterFamily::Ipv4,
                    Some(Ipv4Addr::new(198, 51, 100, 8).into()),
                    443
                ),
                &syn
            ),
            0,
            "wrong destination IP"
        );

        assert_eq!(run_bpf(&worker, &syn), 0, "worker drops SYN");
        assert_eq!(run_bpf(&worker, &v4_data), ACCEPT);
        assert_eq!(run_bpf(&worker, &v6_data), ACCEPT);
        assert_eq!(run_bpf(&worker, &bare_ack), ACCEPT);
        assert_eq!(run_bpf(&worker, &rst), ACCEPT);
        assert_eq!(
            run_bpf(
                &worker,
                &make(other_peer, me, flags::PSH | flags::ACK, &[0x45])
            ),
            0,
            "wrong peer port"
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
            seq: 0xdead_beef,
            ack: 0x0102_0304,
            flags: flags::ACK,
            window: 65535,
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
        let worker_filter = exit_worker_filter(exit, entry);
        assert_eq!(run_bpf(&worker_filter, &buf[..len]), ACCEPT);
        m.src.set_port(40002);
        write_headers(&mut buf, &m, 0, 0);
        assert_eq!(run_bpf(&worker_filter, &buf[..len]), 0);
        m.src = entry;
        m.flags = flags::SYN;
        let len = write_headers(&mut buf, &m, 0, 0);
        assert_eq!(
            run_bpf(
                &exit_listener_filter(OuterFamily::Ipv6, Some(exit.ip()), 443),
                &buf[..len]
            ),
            ACCEPT
        );
        assert_eq!(
            run_bpf(
                &exit_listener_filter(OuterFamily::Ipv6, Some(entry.ip()), 443),
                &buf[..len]
            ),
            0
        );
    }
}
