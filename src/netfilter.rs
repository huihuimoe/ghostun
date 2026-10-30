//! Dedicated per-instance nftables table: conntrack/TCP-input bypass, RST suppression, MSS clamping, exit masquerade.

mod batch;
mod rules;

#[cfg(test)]
mod tests;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use netlink_packet_netfilter::nftables::NfTablesMessage;

use crate::config::{Config, Mode, Transport};
use crate::net::{Cidr, OuterFamily};
use crate::sys;

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
    let mut batch = batch::Batch::new();
    batch.push(NfTablesMessage::DeleteTable(rules::table(table)), 0);
    batch.commit()
}

pub fn install(spec: &NftSpec) -> io::Result<Guard> {
    if spec.mode == Mode::Exit {
        sys::sysctl_set("net.ipv4.ip_forward", "1")?;
        if spec.inner_v6.is_some() {
            sys::sysctl_set("net.ipv6.conf.all.forwarding", "1")?;
        }
    }
    let table = table_name(&spec.tun_name);
    rules::build(spec, &table)?.commit()?;
    log::info!("installed nftables table inet {table}");
    Ok(Guard { table, armed: true })
}
