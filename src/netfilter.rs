//! Dedicated per-instance nftables table: conntrack/TCP-input bypass, RST suppression, MSS clamping, exit masquerade.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{Cidr, Mode, OuterFamily, Transport};
use crate::sys::{self, SOCKET_MARK};

use crate::config::Config;

#[derive(Clone, Debug)]
pub struct NftSpec {
    pub mode: Mode,
    pub transport: Transport,
    pub outer_family: OuterFamily,
    pub tun_name: String,
    /// Entry: exit node outer address.
    pub remote: Option<SocketAddr>,
    pub base_port: u16,
    pub listen_ip: Option<IpAddr>,
    pub listen_port: u16,
    pub inner_v4: Cidr<Ipv4Addr>,
    pub inner_v6: Option<Cidr<Ipv6Addr>>,
    /// Exit: restrict outer rules and masquerade to this interface.
    pub iface: Option<String>,
    /// Exit: masquerade inner subnets on non-TUN egress.
    pub masq: bool,
}

impl NftSpec {
    pub fn from_config(cfg: &Config, listen_port: u16) -> Self {
        Self {
            mode: cfg.mode,
            transport: cfg.transport,
            outer_family: cfg.outer_family,
            tun_name: cfg.tun_name.clone(),
            remote: cfg.remote,
            base_port: cfg.base_port,
            listen_ip: cfg.listen_ip,
            listen_port,
            inner_v4: cfg.tun_ipv4,
            inner_v6: cfg.tun_ipv6,
            iface: cfg.iface.clone(),
            masq: cfg.masq,
        }
    }
}

pub fn table_name(tun_name: &str) -> String {
    let safe: String = tun_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("ghostun_{safe}")
}

pub fn render(spec: &NftSpec) -> String {
    let table = table_name(&spec.tun_name);
    let tun = &spec.tun_name;
    let (proto, addr) = match spec.outer_family {
        OuterFamily::Ipv4 => ("ipv4", "ip"),
        OuterFamily::Ipv6 => ("ipv6", "ip6"),
    };
    let oif = spec
        .iface
        .as_ref()
        .map(|i| format!(r#" oifname "{i}""#))
        .unwrap_or_default();
    // Non-TUN outer frames bypass conntrack and local TCP input (tcp_v4/v6_rcv discard pkt_type != PACKET_HOST).
    let (outer_in, outer_out, in_iif) = match spec.mode {
        Mode::Entry => {
            let r = spec.remote.expect("entry netfilter spec requires remote");
            (
                format!(
                    "{addr} saddr {} tcp sport {} tcp dport >= {}",
                    r.ip(),
                    r.port(),
                    spec.base_port
                ),
                format!(
                    "{addr} daddr {} tcp dport {} tcp sport >= {}",
                    r.ip(),
                    r.port(),
                    spec.base_port
                ),
                format!(r#"iifname != "{tun}""#),
            )
        }
        Mode::Exit => {
            let (in_ip, out_ip) = match spec.listen_ip {
                Some(ip) => (format!("{addr} daddr {ip}"), format!("{addr} saddr {ip}")),
                None => (
                    format!("meta nfproto {proto}"),
                    format!("meta nfproto {proto}"),
                ),
            };
            let iif = match &spec.iface {
                Some(dev) => format!(r#"iifname "{dev}""#),
                None => format!(r#"iifname != "{tun}""#),
            };
            (
                format!("{in_ip} tcp dport {}", spec.listen_port),
                format!("{out_ip} tcp sport {}{oif}", spec.listen_port),
                iif,
            )
        }
    };
    let clamp = "tcp flags syn tcp option maxseg size set rt mtu";
    let mark = format!("{SOCKET_MARK:#x}");
    let postrouting = if spec.mode == Mode::Exit && spec.masq {
        let v4 = spec.inner_v4.network();
        let v6 = spec
            .inner_v6
            .map(|v6| {
                format!(
                    r#"ip6 saddr {} oifname != "{tun}"{oif} masquerade"#,
                    v6.network()
                )
            })
            .unwrap_or_default();
        format!(
            r#"
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {v4} oifname != "{tun}"{oif} masquerade
        {v6}
    }}"#
        )
    } else {
        String::new()
    };
    let outer_rules = if spec.transport == Transport::Faketcp {
        format!(
            r#"chain prerouting {{
        type filter hook prerouting priority raw; policy accept;
        {outer_in} {in_iif} notrack meta pkttype set other
    }}
    chain output {{
        type filter hook output priority raw; policy accept;
        {outer_out} tcp flags rst meta mark != {mark} drop
        {outer_out} notrack accept
        oifname "{tun}" {clamp}
    }}"#
        )
    } else {
        format!(
            r#"chain output {{
        type filter hook output priority filter; policy accept;
        oifname "{tun}" {clamp}
    }}"#
        )
    };
    // Declaring the table first makes the delete succeed when it does not exist yet.
    format!(
        r#"table inet {table} {{}}
delete table inet {table}
table inet {table} {{
    {outer_rules}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        oifname "{tun}" {clamp}
        iifname "{tun}" {clamp}
    }}{postrouting}
}}
"#
    )
}

/// Owns the installed table; removing it on drop covers early-return error paths too.
pub struct Guard {
    table: String,
    armed: bool,
}

impl Guard {
    pub fn remove(mut self) -> io::Result<()> {
        self.armed = false;
        delete_table(&self.table)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = delete_table(&self.table) {
                log::error!("removing nftables table {}: {e}", self.table);
            }
        }
    }
}

fn delete_table(table: &str) -> io::Result<()> {
    sys::run("nft", &["delete", "table", "inet", table], None).map(drop)
}

pub fn install(spec: &NftSpec) -> io::Result<Guard> {
    if spec.mode == Mode::Exit {
        sys::sysctl_set("net.ipv4.ip_forward", "1")?;
        if spec.inner_v6.is_some() {
            sys::sysctl_set("net.ipv6.conf.all.forwarding", "1")?;
        }
    }
    sys::run("nft", &["-f", "-"], Some(&render(spec)))?;
    let table = table_name(&spec.tun_name);
    log::info!("installed nftables table inet {table}");
    Ok(Guard { table, armed: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_rules_and_optional_masquerade() {
        assert_eq!(table_name("ghostun0"), "ghostun_ghostun0");
        assert_eq!(table_name("wan.1-a"), "ghostun_wan_1_a");
        let mut spec = NftSpec {
            mode: Mode::Exit,
            transport: Transport::Faketcp,
            outer_family: OuterFamily::Ipv4,
            tun_name: "ghostun0".into(),
            remote: None,
            base_port: 30000,
            listen_ip: None,
            listen_port: 443,
            inner_v4: "10.200.0.2/30".parse().unwrap(),
            inner_v6: Some("fd00:200::2/126".parse().unwrap()),
            iface: Some("eth0".into()),
            masq: true,
        };
        let rules = render(&spec);
        assert!(
            rules.contains(
                r#"meta nfproto ipv4 tcp dport 443 iifname "eth0" notrack meta pkttype set other"#
            ),
            "{rules}"
        );
        assert!(
            rules.contains(r#"meta nfproto ipv4 tcp sport 443 oifname "eth0" notrack accept"#),
            "{rules}"
        );
        assert!(
            rules.contains(
                r#"ip saddr 10.200.0.0/30 oifname != "ghostun0" oifname "eth0" masquerade"#
            ),
            "{rules}"
        );

        spec.listen_ip = Some("198.51.100.20".parse().unwrap());
        spec.iface = None;
        let ip_rules = render(&spec);
        assert!(
            ip_rules.contains(
                r#"ip daddr 198.51.100.20 tcp dport 443 iifname != "ghostun0" notrack meta pkttype set other"#
            ),
            "{ip_rules}"
        );
        assert!(
            ip_rules.contains("ip saddr 198.51.100.20 tcp sport 443 notrack accept"),
            "{ip_rules}"
        );
        spec.masq = false;
        for transport in [Transport::Faketcp, Transport::Tcp] {
            spec.transport = transport;
            let no_masq = render(&spec);
            assert!(!no_masq.contains("postrouting"), "{no_masq}");
            assert!(!no_masq.contains("masquerade"), "{no_masq}");
            assert!(
                no_masq.contains(
                    r#"oifname "ghostun0" tcp flags syn tcp option maxseg size set rt mtu"#
                ),
                "{no_masq}"
            );
            assert!(
                no_masq.contains(
                    r#"iifname "ghostun0" tcp flags syn tcp option maxseg size set rt mtu"#
                ),
                "{no_masq}"
            );
        }
    }
}
