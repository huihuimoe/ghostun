//! Dedicated per-instance nftables table: kernel RST suppression, MSS clamping, exit masquerade.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{Cidr, Mode, OuterFamily};
use crate::sys::{self, SOCKET_MARK};

#[derive(Clone, Debug)]
pub struct NftSpec {
    pub mode: Mode,
    pub outer_family: OuterFamily,
    pub tun_name: String,
    /// Entry: exit node outer address.
    pub remote: Option<SocketAddr>,
    pub base_port: u16,
    pub listen_port: u16,
    pub inner_v4: Cidr<Ipv4Addr>,
    pub inner_v6: Option<Cidr<Ipv6Addr>>,
    /// Exit: restrict masquerade to this egress interface.
    pub out_iface: Option<String>,
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
    // Outer tunnel frames sent by this host; the kernel answers our raw-socket peers with RSTs.
    let outer_out = match spec.mode {
        Mode::Entry => {
            let r = spec.remote.expect("entry netfilter spec requires remote");
            format!(
                "{addr} daddr {} tcp dport {} tcp sport >= {}",
                r.ip(),
                r.port(),
                spec.base_port
            )
        }
        Mode::Exit => format!("meta nfproto {proto} tcp sport {}", spec.listen_port),
    };
    let clamp = "tcp flags syn tcp option maxseg size set rt mtu";
    let mark = format!("{SOCKET_MARK:#x}");
    let postrouting = match spec.mode {
        Mode::Entry => String::new(),
        Mode::Exit => {
            let oif = spec
                .out_iface
                .as_ref()
                .map(|i| format!(r#" oifname "{i}""#))
                .unwrap_or_default();
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
        }
    };
    // Declaring the table first makes the delete succeed when it does not exist yet.
    format!(
        r#"table inet {table} {{}}
delete table inet {table}
table inet {table} {{
    chain output {{
        type filter hook output priority filter; policy accept;
        {outer_out} tcp flags rst meta mark != {mark} drop
        oifname "{tun}" {clamp}
    }}
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
    fn table_name_is_sanitized() {
        assert_eq!(table_name("ghostun0"), "ghostun_ghostun0");
        assert_eq!(table_name("wan.1-a"), "ghostun_wan_1_a");
    }
}
