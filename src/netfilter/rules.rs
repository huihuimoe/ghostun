//! Ghostun's fixed rules, compiled directly into nf_tables expressions.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{DefaultNla, NLM_F_APPEND, NLM_F_CREATE};
use netlink_packet_netfilter::nftables::{
    Bitwise, ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions,
    Hook, Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator,
    Payload, Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict,
    VerdictAttribute,
};

use super::batch::Batch;
use super::NftSpec;
use crate::config::{Mode, Transport};
use crate::net::{Cidr, OuterFamily};
use crate::sys::raw::SOCKET_MARK;

const REGISTER: Register = Register::Reg1;
const NETWORK_HEADER: u32 = 1;
const TRANSPORT_HEADER: u32 = 2;
// Missing typed expressions in netlink-packet-netfilter 0.4; Linux nf_tables.h UAPI.
const NFTA_RT_DREG: u16 = 1;
const NFTA_RT_KEY: u16 = 2;
const NFT_RT_TCPMSS: u32 = 3;
const NFTA_BYTEORDER_SREG: u16 = 1;
const NFTA_BYTEORDER_DREG: u16 = 2;
const NFTA_BYTEORDER_OP: u16 = 3;
const NFTA_BYTEORDER_LEN: u16 = 4;
const NFTA_BYTEORDER_SIZE: u16 = 5;
const NFT_BYTEORDER_HTON: u32 = 1;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;

pub(super) fn table(table: &str) -> TableMessage {
    TableMessage {
        attributes: vec![TableAttribute::Name(table.into())],
    }
}

fn chain(
    batch: &mut Batch,
    table: &str,
    name: &str,
    hook: InetHookNumber,
    priority: i32,
    kind: &str,
) {
    batch.push(
        NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(table.into()),
                ChainAttribute::Name(name.into()),
                ChainAttribute::Type(kind.into()),
                ChainAttribute::Hook(vec![
                    Hook::Number(hook.into()),
                    Hook::Priority(priority as u32),
                ]),
                ChainAttribute::Policy(libc::NF_ACCEPT as u32),
            ],
        }),
        NLM_F_CREATE,
    );
}

#[derive(Default)]
struct Rule(Vec<ListAttribute<ExpressionAttribute>>);

impl Rule {
    fn expression(&mut self, expression: Expressions) {
        self.0.push(expression.into());
    }

    fn compare(&mut self, op: Operator, value: Vec<u8>) {
        self.expression(Expressions::Cmp(vec![
            Cmp::SourceRegister(REGISTER),
            Cmp::Op(op),
            Cmp::Data(DataAttribute::Value(value)),
        ]));
    }

    fn meta(&mut self, key: MetaKey, op: Operator, value: Vec<u8>) {
        self.expression(Expressions::Meta(vec![
            Meta::Key(key),
            Meta::DestinationRegister(REGISTER),
        ]));
        self.compare(op, value);
    }

    fn interface(&mut self, key: MetaKey, op: Operator, name: &str) {
        let mut value = vec![0; libc::IFNAMSIZ];
        value[..name.len()].copy_from_slice(name.as_bytes());
        self.meta(key, op, value);
    }

    fn family(&mut self, family: OuterFamily) {
        let value = match family {
            OuterFamily::Ipv4 => libc::NFPROTO_IPV4,
            OuterFamily::Ipv6 => libc::NFPROTO_IPV6,
        };
        self.meta(MetaKey::Nfproto, Operator::Equal, vec![value as u8]);
    }

    fn tcp(&mut self) {
        self.meta(
            MetaKey::L4Proto,
            Operator::Equal,
            vec![libc::IPPROTO_TCP as u8],
        );
    }

    fn payload(&mut self, base: u32, offset: u32, length: u32) {
        self.expression(Expressions::Payload(vec![
            Payload::DestinationRegister(REGISTER),
            Payload::Base(base),
            Payload::Offset(offset),
            Payload::Len(length),
        ]));
    }

    fn mask(&mut self, mask: Vec<u8>) {
        self.expression(Expressions::Bitwise(vec![
            Bitwise::SourceRegister(REGISTER),
            Bitwise::DestinationRegister(REGISTER),
            Bitwise::Length(mask.len() as u32),
            Bitwise::Xor(DataAttribute::Value(vec![0; mask.len()])),
            Bitwise::Mask(DataAttribute::Value(mask)),
        ]));
    }

    fn address(&mut self, address: IpAddr, source: bool) {
        let (offset, value) = match address {
            IpAddr::V4(ip) => (if source { 12 } else { 16 }, ip.octets().to_vec()),
            IpAddr::V6(ip) => (if source { 8 } else { 24 }, ip.octets().to_vec()),
        };
        self.payload(NETWORK_HEADER, offset, value.len() as u32);
        self.compare(Operator::Equal, value);
    }

    fn port(&mut self, source: bool, op: Operator, port: u16) {
        self.payload(TRANSPORT_HEADER, if source { 0 } else { 2 }, 2);
        self.compare(op, port.to_be_bytes().to_vec());
    }

    fn flags(&mut self, flag: u8) {
        self.payload(TRANSPORT_HEADER, 13, 1);
        self.mask(vec![flag]);
        self.compare(Operator::NotEqual, vec![0]);
    }

    fn verdict(&mut self, verdict: u32) {
        self.expression(Expressions::Immediate(vec![
            Immediate::DestinationRegister(Register::Verdict),
            Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                Verdict::Other(verdict),
            )])),
        ]));
    }

    fn untyped_expression(&mut self, name: &str, attributes: Vec<DefaultNla>) {
        self.expression(Expressions::Other {
            expression_type: name.into(),
            attributes,
        });
    }

    fn append(self, batch: &mut Batch, table: &str, chain: &str) {
        batch.push(
            NfTablesMessage::NewRule(RuleMessage {
                attributes: vec![
                    RuleAttribute::Table(table.into()),
                    RuleAttribute::Chain(chain.into()),
                    RuleAttribute::Expressions(self.0),
                ],
            }),
            NLM_F_CREATE | NLM_F_APPEND,
        );
    }
}

fn u32_attribute(kind: u16, value: u32) -> DefaultNla {
    DefaultNla::new(kind, value.to_be_bytes().to_vec())
}

fn outer(spec: &NftSpec, incoming: bool) -> Rule {
    let mut rule = Rule::default();
    rule.family(spec.outer_family);
    match spec.mode {
        Mode::Entry => {
            let remote = spec.remote.expect("entry netfilter spec requires remote");
            rule.address(remote.ip(), incoming);
            rule.tcp();
            rule.port(incoming, Operator::Equal, remote.port());
            rule.port(!incoming, Operator::GreatherThanEqual, spec.base_port);
            if incoming {
                rule.interface(MetaKey::Iifname, Operator::NotEqual, &spec.tun_name);
            }
        }
        Mode::Exit => {
            if let Some(ip) = spec.listen_ip {
                rule.address(ip, !incoming);
            }
            rule.tcp();
            rule.port(!incoming, Operator::Equal, spec.listen_port);
            if incoming {
                match &spec.iface {
                    Some(iface) => rule.interface(MetaKey::Iifname, Operator::Equal, iface),
                    None => rule.interface(MetaKey::Iifname, Operator::NotEqual, &spec.tun_name),
                }
            } else if let Some(iface) = &spec.iface {
                rule.interface(MetaKey::Oifname, Operator::Equal, iface);
            }
        }
    }
    rule
}

fn clamp(batch: &mut Batch, table: &str, chain: &str, key: MetaKey, tun: &str) {
    let mut rule = Rule::default();
    rule.interface(key, Operator::Equal, tun);
    rule.tcp();
    rule.flags(0x02); // SYN, including SYN+ACK.
    rule.untyped_expression(
        "rt",
        vec![
            u32_attribute(NFTA_RT_DREG, REGISTER.into()),
            u32_attribute(NFTA_RT_KEY, NFT_RT_TCPMSS),
        ],
    );
    // rt tcpmss is host-endian, whereas the TCP option is network-endian.
    rule.untyped_expression(
        "byteorder",
        vec![
            u32_attribute(NFTA_BYTEORDER_SREG, REGISTER.into()),
            u32_attribute(NFTA_BYTEORDER_DREG, REGISTER.into()),
            u32_attribute(NFTA_BYTEORDER_OP, NFT_BYTEORDER_HTON),
            u32_attribute(NFTA_BYTEORDER_LEN, 2),
            u32_attribute(NFTA_BYTEORDER_SIZE, 2),
        ],
    );
    rule.untyped_expression(
        "exthdr",
        vec![
            DefaultNla::new(NFTA_EXTHDR_TYPE, vec![2]), // TCPOPT_MAXSEG.
            u32_attribute(NFTA_EXTHDR_OFFSET, 2),
            u32_attribute(NFTA_EXTHDR_LEN, 2),
            u32_attribute(NFTA_EXTHDR_OP, NFT_EXTHDR_OP_TCPOPT),
            u32_attribute(NFTA_EXTHDR_SREG, REGISTER.into()),
        ],
    );
    rule.append(batch, table, chain);
}

fn masquerade(
    batch: &mut Batch,
    table: &str,
    spec: &NftSpec,
    family: OuterFamily,
    network: Vec<u8>,
    mask: Vec<u8>,
) {
    let mut rule = Rule::default();
    rule.family(family);
    rule.payload(
        NETWORK_HEADER,
        if family == OuterFamily::Ipv4 { 12 } else { 8 },
        network.len() as u32,
    );
    if mask.iter().any(|byte| *byte != 0xff) {
        rule.mask(mask);
    }
    rule.compare(Operator::Equal, network);
    rule.interface(MetaKey::Oifname, Operator::NotEqual, &spec.tun_name);
    if let Some(iface) = &spec.iface {
        rule.interface(MetaKey::Oifname, Operator::Equal, iface);
    }
    rule.untyped_expression("masq", vec![]);
    rule.append(batch, table, "postrouting");
}

pub(super) fn build(spec: &NftSpec, table_name: &str) -> io::Result<Batch> {
    // Interface comparisons load exactly IFNAMSIZ bytes, including the terminator.
    for name in std::iter::once(spec.tun_name.as_str()).chain(spec.iface.as_deref()) {
        if name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid interface name {name:?}"),
            ));
        }
    }
    let mut batch = Batch::new();
    // Ensure deletion works on first start as well as with a stale table, within the same transaction.
    batch.push(NfTablesMessage::NewTable(table(table_name)), NLM_F_CREATE);
    batch.push(NfTablesMessage::DeleteTable(table(table_name)), 0);
    batch.push(NfTablesMessage::NewTable(table(table_name)), NLM_F_CREATE);
    if spec.transport == Transport::Faketcp {
        chain(
            &mut batch,
            table_name,
            "prerouting",
            InetHookNumber::PreRouting,
            -300,
            "filter",
        );
        let mut incoming = outer(spec, true);
        incoming.untyped_expression("notrack", vec![]);
        incoming.expression(Expressions::Immediate(vec![
            Immediate::DestinationRegister(REGISTER),
            Immediate::Data(DataAttribute::Value(vec![libc::PACKET_OTHERHOST])),
        ]));
        incoming.expression(Expressions::Meta(vec![
            Meta::Key(MetaKey::PacketType),
            Meta::SourceRegister(REGISTER),
        ]));
        incoming.append(&mut batch, table_name, "prerouting");
        chain(
            &mut batch,
            table_name,
            "output",
            InetHookNumber::LocalOut,
            -300,
            "filter",
        );
        let mut rst = outer(spec, false);
        rst.flags(0x04);
        rst.meta(
            MetaKey::Mark,
            Operator::NotEqual,
            SOCKET_MARK.to_ne_bytes().to_vec(),
        );
        rst.verdict(libc::NF_DROP as u32);
        rst.append(&mut batch, table_name, "output");
        let mut outgoing = outer(spec, false);
        outgoing.untyped_expression("notrack", vec![]);
        outgoing.verdict(libc::NF_ACCEPT as u32);
        outgoing.append(&mut batch, table_name, "output");
    } else {
        chain(
            &mut batch,
            table_name,
            "output",
            InetHookNumber::LocalOut,
            0,
            "filter",
        );
    }
    clamp(
        &mut batch,
        table_name,
        "output",
        MetaKey::Oifname,
        &spec.tun_name,
    );
    chain(
        &mut batch,
        table_name,
        "forward",
        InetHookNumber::Forward,
        0,
        "filter",
    );
    clamp(
        &mut batch,
        table_name,
        "forward",
        MetaKey::Oifname,
        &spec.tun_name,
    );
    clamp(
        &mut batch,
        table_name,
        "forward",
        MetaKey::Iifname,
        &spec.tun_name,
    );
    if spec.mode == Mode::Exit && spec.masq {
        chain(
            &mut batch,
            table_name,
            "postrouting",
            InetHookNumber::PostRouting,
            100,
            "nat",
        );
        let v4 = spec.inner_v4.network();
        let v4_mask = Cidr {
            addr: Ipv4Addr::BROADCAST,
            prefix: v4.prefix,
        }
        .network();
        masquerade(
            &mut batch,
            table_name,
            spec,
            OuterFamily::Ipv4,
            v4.addr.octets().to_vec(),
            v4_mask.addr.octets().to_vec(),
        );
        if let Some(v6) = spec.inner_v6 {
            let v6 = v6.network();
            let v6_mask = Cidr {
                addr: Ipv6Addr::from(u128::MAX),
                prefix: v6.prefix,
            }
            .network();
            masquerade(
                &mut batch,
                table_name,
                spec,
                OuterFamily::Ipv6,
                v6.addr.octets().to_vec(),
                v6_mask.addr.octets().to_vec(),
            );
        }
    }
    Ok(batch)
}
