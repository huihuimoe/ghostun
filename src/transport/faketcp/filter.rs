//! Classic BPF filters that steer each outer FakeTCP flow to its worker's raw socket.

use std::net::{IpAddr, SocketAddr};

use crate::net::{ipv4, ipv6, tcp, OuterFamily};

const ACCEPT: u32 = u32::MAX;

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

/// Exit worker `i`: `dport == listen_port && sport % n == i` (and `daddr == listen_ip` when set).
pub fn exit_filter(
    family: OuterFamily,
    listen_ip: Option<IpAddr>,
    listen_port: u16,
    n: u16,
    i: u16,
) -> Vec<libc::sock_filter> {
    let mut p = Prog(Vec::new());
    p.init(family)
        .stmt(LD_H_IND, tcp::OFF_DPORT as u32)
        .stmt(JEQ, u32::from(listen_port))
        .stmt(LD_H_IND, tcp::OFF_SPORT as u32)
        .stmt(MOD, u32::from(n))
        .stmt(JEQ, u32::from(i));
    if let Some(ip) = listen_ip {
        p.ip(ip, ipv4::OFF_DST, ipv6::OFF_DST);
    }
    p.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::faketcp::frame::{flags, frame_with_options, write_headers, TcpMeta};
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
            run_bpf(
                &exit_filter(OuterFamily::Ipv4, None, 443, 3, 2),
                &from(40001)
            ),
            ACCEPT
        ); // 40001 % 3 == 2
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv4, None, 443, 3, 0),
                &from(40001)
            ),
            0
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv4, None, 444, 3, 2),
                &from(40001)
            ),
            0,
            "wrong dport"
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv4, Some((*me.ip()).into()), 443, 3, 2),
                &from(40001)
            ),
            ACCEPT
        );
        assert_eq!(
            run_bpf(
                &exit_filter(
                    OuterFamily::Ipv4,
                    Some(Ipv4Addr::new(198, 51, 100, 8).into()),
                    443,
                    3,
                    2
                ),
                &from(40001)
            ),
            0,
            "wrong destination IP"
        );
        let with_opts = frame_with_options(
            8,
            0,
            &[],
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40001),
            me,
        );
        assert_eq!(
            run_bpf(&exit_filter(OuterFamily::Ipv4, None, 443, 3, 2), &with_opts),
            ACCEPT,
            "IHL=28"
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
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv6, None, 443, 3, 2),
                &buf[..len]
            ),
            ACCEPT
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv6, Some(exit.ip()), 443, 3, 2),
                &buf[..len]
            ),
            ACCEPT
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv6, Some(entry.ip()), 443, 3, 2),
                &buf[..len]
            ),
            0
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv6, None, 443, 3, 1),
                &buf[..len]
            ),
            0
        );
        assert_eq!(
            run_bpf(
                &exit_filter(OuterFamily::Ipv6, None, 444, 3, 2),
                &buf[..len]
            ),
            0
        );
    }
}
