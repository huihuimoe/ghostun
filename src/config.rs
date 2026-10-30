//! CLI flags + TOML file merged into a validated runtime configuration (CLI > TOML > defaults).

use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use argh::{FromArgValue, FromArgs};
use serde::Deserialize;

use crate::net::{ipv4, ipv6, Cidr, OuterFamily};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, FromArgValue)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Entry,
    Exit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, FromArgValue)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Faketcp,
    Tcp,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey(pub [u8; 32]);

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey([REDACTED])")
    }
}

impl FromStr for AuthKey {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || "`auth_key` must contain exactly 64 hexadecimal characters".to_owned();
        if text.len() != 64 {
            return Err(invalid());
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let digit = |ch: u8| match ch {
                b'0'..=b'9' => Some(ch - b'0'),
                b'a'..=b'f' => Some(ch - b'a' + 10),
                b'A'..=b'F' => Some(ch - b'A' + 10),
                _ => None,
            };
            *byte =
                (digit(pair[0]).ok_or_else(invalid)? << 4) | digit(pair[1]).ok_or_else(invalid)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ListenSpec {
    ip: Option<IpAddr>,
    port: u16,
    family: Option<OuterFamily>,
}

impl FromStr for ListenSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(port) = s.parse::<u16>() {
            return Ok(Self {
                ip: None,
                port,
                family: None,
            });
        }
        let sa = s
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid `listen` value {s:?}: expected PORT or IP:PORT"))?;
        let ip = sa.ip();
        Ok(Self {
            ip: (!ip.is_unspecified()).then_some(ip),
            port: sa.port(),
            family: Some(OuterFamily::of(ip)),
        })
    }
}

impl<'de> Deserialize<'de> for ListenSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ListenSpec;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a port number or \"[IP:]PORT\" string")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                self.visit_u64(u64::try_from(v).map_err(|_| E::custom("listen port out of range"))?)
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                u16::try_from(v)
                    .map(|port| ListenSpec {
                        ip: None,
                        port,
                        family: None,
                    })
                    .map_err(|_| E::custom("listen port out of range"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// Settings that running workers apply on reload; changing any other `Config` field requires a restart.
#[derive(Clone, Debug, PartialEq)]
pub struct Tunables {
    pub auth_key: AuthKey,
    pub cpus: Option<Vec<usize>>,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub transport: Transport,
    /// TCP unsent low watermark and write batch limit, in bytes.
    pub tcp_notsent: u32,
    pub base_port_explicit: bool,
    pub mode: Mode,
    pub tunables: Tunables,
    pub tun_name: String,
    pub tun_ipv4: Cidr<Ipv4Addr>,
    pub tun_ipv6: Option<Cidr<Ipv6Addr>>,
    pub conns: u16,
    pub outer_mtu: Option<u32>,
    pub tun_mtu: Option<u32>,
    pub iface: Option<String>,
    pub base_port: u16,
    pub netfilter: bool,
    pub masq: bool,
    /// Exit node outer address; `Some` exactly in entry mode.
    pub remote: Option<SocketAddr>,
    /// Outer listen port; `Some` exactly in exit mode.
    pub listen: Option<u16>,
    /// Optional specific outer listen IP in exit mode (`None` means wildcard).
    pub listen_ip: Option<IpAddr>,
    pub outer_family: OuterFamily,
    cli: Cli,
}

impl Config {
    /// Validates explicit and detected MTUs before any network resources are changed.
    #[inline(always)]
    const fn inner_min_mtu(&self) -> u32 {
        if self.tun_ipv6.is_some() {
            ipv6::MIN_MTU
        } else {
            ipv4::MIN_MTU
        }
    }

    /// Bound exit listen IP, or the outer family's unspecified wildcard address.
    pub fn exit_ip(&self) -> IpAddr {
        self.listen_ip
            .unwrap_or_else(|| self.outer_family.unspecified())
    }

    pub fn resolve_tun_mtu(&self, outer_mtu: u32) -> Result<u32, String> {
        let overhead = self.outer_family.overhead() as u32;
        let min_outer = self.outer_family.min_mtu();
        if !(min_outer..=65535).contains(&outer_mtu) {
            return Err(format!("outer MTU must be within {min_outer}..=65535"));
        }
        let available = outer_mtu - overhead;
        let mtu = self.tun_mtu.unwrap_or(available);
        let minimum = self.inner_min_mtu();
        if mtu < minimum || mtu > available {
            return Err(format!("TUN MTU {mtu} must be within {minimum}..={available} for outer MTU {outer_mtu} and {overhead}-byte encapsulation"));
        }
        Ok(mtu)
    }

    /// Records that the kernel has no inner IPv6 support so subsequent reloads stay consistent.
    pub fn disable_inner_ipv6(&mut self) {
        self.tun_ipv6 = None;
        self.cli.no_ipv6 = true;
    }

    /// Re-reads the `--config` TOML file, re-applies startup CLI overrides, and rejects
    /// changes to any topology- or socket-bound field.
    pub fn reload(&self) -> Result<Config, String> {
        if self.cli.config.is_none() {
            return Err("reload requires `--config`".into());
        }
        let next = build_config(self.cli.clone(), Some(self.conns))?;
        ensure_reload_compatible(self, &next)?;
        Ok(next)
    }
}

#[derive(Clone, Debug, Default, PartialEq, FromArgs)]
#[argh(
    name = "ghostun",
    description = "L3 tunnel over FakeTCP or relay-compatible TCP.",
    help_triggers("-h", "--help", "help")
)]
struct Cli {
    /// print version information and exit
    #[argh(switch, short = 'V')]
    version: bool,
    /// TOML configuration file; CLI flags override its values
    #[argh(option, arg_name = "PATH")]
    config: Option<PathBuf>,
    /// outer transport: faketcp or tcp [default: faketcp]
    #[argh(option)]
    transport: Option<Transport>,
    /// TCP unsent low watermark and write batch in KiB; restart to change [default: 64]
    #[argh(option, arg_name = "KIB")]
    tcp_notsent: Option<u32>,
    /// node role: entry or exit
    #[argh(positional)]
    role: Option<Mode>,
    /// exit node outer address (entry only)
    #[argh(option, arg_name = "IP:PORT")]
    remote: Option<SocketAddr>,
    /// outer listen port or IP:PORT (exit only)
    #[argh(option, arg_name = "[IP:]PORT")]
    listen: Option<ListenSpec>,
    /// outer address family; entry derives it from --remote [default: ipv4]
    #[argh(option)]
    outer_family: Option<OuterFamily>,
    /// inner TUN interface name [default: ghostun0]
    #[argh(option, long = "tun", arg_name = "NAME")]
    tun_name: Option<String>,
    /// inner IPv4 address [default: entry 10.200.0.1/30, exit 10.200.0.2/30]
    #[argh(option, arg_name = "CIDR")]
    tun_ipv4: Option<String>,
    /// inner IPv6 address [default: entry fd00:200::1/126, exit fd00:200::2/126]
    #[argh(option, arg_name = "CIDR")]
    tun_ipv6: Option<String>,
    /// outer connections = worker threads; must match on both ends [default: CPU count]
    #[argh(option, arg_name = "N")]
    conns: Option<u16>,
    /// worker CPU list or ranges, e.g. 0,1 or 2-3 [default: all usable CPUs]
    #[argh(option, arg_name = "LIST")]
    cpus: Option<String>,
    /// outer path MTU [default: egress interface MTU, fallback 1500]
    #[argh(option, arg_name = "MTU")]
    outer_mtu: Option<u32>,
    /// inner TUN MTU [default: outer MTU - 40 for IPv4, - 60 for IPv6]
    #[argh(option, arg_name = "MTU")]
    tun_mtu: Option<u32>,
    /// outer egress interface [default: from routing table]
    #[argh(option, arg_name = "IFACE")]
    iface: Option<String>,
    /// first outer source port of the entry port pool [default: 32768]
    #[argh(option, arg_name = "PORT")]
    base_port: Option<u16>,
    /// health ping interval in seconds [default: 5]
    #[argh(option, arg_name = "SECS")]
    ping_interval: Option<u64>,
    /// reconnect after this many seconds without traffic from the peer [default: 15]
    #[argh(option, arg_name = "SECS")]
    dead_timeout: Option<u64>,
    /// do not configure inner IPv6
    #[argh(switch)]
    no_ipv6: bool,
    /// do not touch nftables or sysctl
    #[argh(switch)]
    no_netfilter: bool,
    /// do not add exit nftables masquerade rules (exit only)
    #[argh(switch)]
    no_masq: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct File {
    transport: Option<Transport>,
    tcp_notsent: Option<u32>,
    mode: Option<Mode>,
    auth_key: Option<String>,
    tun_name: Option<String>,
    tun_ipv4: Option<String>,
    tun_ipv6: Option<String>,
    conns: Option<u16>,
    cpus: Option<String>,
    outer_mtu: Option<u32>,
    tun_mtu: Option<u32>,
    iface: Option<String>,
    base_port: Option<u16>,
    ping_interval: Option<u64>,
    dead_timeout: Option<u64>,
    #[serde(default)]
    no_ipv6: bool,
    #[serde(default)]
    no_netfilter: bool,
    #[serde(default)]
    no_masq: bool,
    remote: Option<SocketAddr>,
    listen: Option<ListenSpec>,
    outer_family: Option<OuterFamily>,
}

pub fn load() -> Result<Config, String> {
    parse_from(std::env::args_os())
}

/// `--help`/`--version` and usage errors exit the process, like any CLI.
pub fn parse_from<I, T>(args: I) -> Result<Config, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let owned: Vec<String> = args
        .into_iter()
        .map(|arg| {
            arg.into()
                .into_string()
                .map_err(|_| "CLI arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let strs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (cmd, rest) = strs.split_first().unwrap_or((&"ghostun", &[]));
    let cli = Cli::from_args(&[cmd], rest).unwrap_or_else(|early_exit| match early_exit.status {
        Ok(()) => {
            println!("{}", early_exit.output);
            std::process::exit(0);
        }
        Err(()) => {
            eprintln!("{}", early_exit.output);
            std::process::exit(1);
        }
    });
    if cli.version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    build_config(cli, None)
}

fn build_config(cli: Cli, running_conns: Option<u16>) -> Result<Config, String> {
    let file = match &cli.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            // TOML's display output includes source lines, which can contain the key.
            toml::from_str::<File>(&text)
                .map_err(|_| format!("parsing {}: invalid TOML configuration", path.display()))?
        }
        None => File::default(),
    };
    let mode = cli
        .role
        .or(file.mode)
        .ok_or("missing role: use `entry`/`exit` or set `mode` in the config file")?;
    if cli.role.is_some() && file.mode.is_some_and(|m| m != mode) {
        return Err(format!(
            "role {mode:?} conflicts with `mode` in the config file"
        ));
    }
    let remote = cli.remote.or(file.remote);
    let listen_spec = cli.listen.or(file.listen);
    let listen = listen_spec.map(|l| l.port);
    let listen_ip = listen_spec.and_then(|l| l.ip);
    let listen_family = listen_spec.and_then(|l| l.family);
    let outer_family = cli.outer_family.or(file.outer_family);
    if mode == Mode::Entry && outer_family.is_some() {
        return Err(
            "`outer_family` is only valid in exit mode; entry uses the remote address family"
                .into(),
        );
    }
    if let (Some(explicit), Some(inferred)) = (outer_family, listen_family) {
        if explicit != inferred {
            return Err("`outer_family` conflicts with `listen` address family".into());
        }
    }
    let outer_family = remote
        .map(|r| OuterFamily::of(r.ip()))
        .or(listen_family)
        .or(outer_family)
        .unwrap_or_default();
    let no_masq = cli.no_masq || file.no_masq;
    match mode {
        Mode::Entry if listen.is_some() => return Err("`listen` is only valid in exit mode".into()),
        Mode::Entry if no_masq => return Err("`no_masq` is only valid in exit mode".into()),
        Mode::Exit if remote.is_some() => return Err("`remote` is only valid in entry mode".into()),
        _ => {}
    }
    let (v4_default, v6_default) = match mode {
        Mode::Entry => ("10.200.0.1/30", "fd00:200::1/126"),
        Mode::Exit => ("10.200.0.2/30", "fd00:200::2/126"),
    };
    let tun_ipv4 = cli
        .tun_ipv4
        .as_deref()
        .or(file.tun_ipv4.as_deref())
        .unwrap_or(v4_default)
        .parse()?;
    let tun_ipv6 = if cli.no_ipv6 || file.no_ipv6 {
        None
    } else {
        Some(
            cli.tun_ipv6
                .as_deref()
                .or(file.tun_ipv6.as_deref())
                .unwrap_or(v6_default)
                .parse()?,
        )
    };
    let cpus = cli
        .cpus
        .as_deref()
        .or(file.cpus.as_deref())
        .map(parse_cpus)
        .transpose()?;
    let default_conns = running_conns.unwrap_or_else(|| {
        cpus.as_ref().map_or_else(
            || std::thread::available_parallelism().map_or(1, |n| n.get().min(256) as u16),
            |c| c.len().min(256) as u16,
        )
    });
    let cfg = Config {
        transport: cli.transport.or(file.transport).unwrap_or_default(),
        tcp_notsent: cli
            .tcp_notsent
            .or(file.tcp_notsent)
            .unwrap_or(crate::transport::budget::TCP_NOTSENT / 1024)
            .checked_mul(1024)
            .filter(|&bytes| bytes != 0)
            .ok_or("`tcp_notsent` must be within 1..=4194303 KiB")?,
        base_port_explicit: cli.base_port.is_some() || file.base_port.is_some(),
        mode,
        tunables: Tunables {
            auth_key: file
                .auth_key
                .as_deref()
                .ok_or("missing TOML `auth_key`")?
                .parse()?,
            cpus,
            ping_interval: Duration::from_secs(
                cli.ping_interval.or(file.ping_interval).unwrap_or(5),
            ),
            dead_timeout: Duration::from_secs(cli.dead_timeout.or(file.dead_timeout).unwrap_or(15)),
        },
        tun_name: cli
            .tun_name
            .clone()
            .or(file.tun_name)
            .unwrap_or_else(|| "ghostun0".into()),
        tun_ipv4,
        tun_ipv6,
        conns: cli.conns.or(file.conns).unwrap_or(default_conns),
        outer_mtu: cli.outer_mtu.or(file.outer_mtu),
        tun_mtu: cli.tun_mtu.or(file.tun_mtu),
        iface: cli.iface.clone().or(file.iface),
        base_port: cli.base_port.or(file.base_port).unwrap_or(32768),
        netfilter: !(cli.no_netfilter || file.no_netfilter),
        masq: !no_masq,
        remote,
        listen,
        listen_ip,
        outer_family,
        cli,
    };
    validate(&cfg)?;
    Ok(cfg)
}

fn ensure_reload_compatible(old: &Config, new: &Config) -> Result<(), String> {
    for (changed, field) in [
        (old.mode != new.mode, "mode"),
        (old.transport != new.transport, "transport"),
        (old.tcp_notsent != new.tcp_notsent, "tcp_notsent"),
        (old.outer_family != new.outer_family, "outer_family"),
        (old.tun_name != new.tun_name, "tun_name"),
        (old.tun_ipv4 != new.tun_ipv4, "tun_ipv4"),
        (old.tun_ipv6 != new.tun_ipv6, "tun_ipv6"),
        (old.conns != new.conns, "conns"),
        (old.outer_mtu != new.outer_mtu, "outer_mtu"),
        (old.tun_mtu != new.tun_mtu, "tun_mtu"),
        (old.iface != new.iface, "iface"),
        (old.netfilter != new.netfilter, "no_netfilter"),
        (old.masq != new.masq, "no_masq"),
        (old.remote != new.remote, "remote"),
        (
            old.listen != new.listen || old.listen_ip != new.listen_ip,
            "listen",
        ),
        (old.base_port != new.base_port, "base_port"),
    ] {
        if changed {
            return Err(format!("cannot reload `{field}` without restarting"));
        }
    }
    // The list above only names fields for errors; this keeps unlisted fields restart-only.
    let mut pinned = new.clone();
    pinned.tunables = old.tunables.clone();
    pinned.base_port_explicit = old.base_port_explicit;
    if pinned != *old {
        return Err("cannot reload this change without restarting".into());
    }
    Ok(())
}

fn parse_cpus(spec: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("invalid CPU list {spec:?}"));
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: usize = a
                .parse()
                .map_err(|_| format!("invalid CPU range {part:?} in {spec:?}"))?;
            let end: usize = b
                .parse()
                .map_err(|_| format!("invalid CPU range {part:?} in {spec:?}"))?;
            if start > end || end >= libc::CPU_SETSIZE as usize {
                return Err(format!("invalid CPU range {part:?} in {spec:?}"));
            }
            out.extend(start..=end);
        } else {
            let cpu: usize = part
                .parse()
                .map_err(|_| format!("invalid CPU ID {part:?} in {spec:?}"))?;
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(format!("invalid CPU ID {part:?} in {spec:?}"));
            }
            out.push(cpu);
        }
    }
    Ok(out)
}

fn validate(c: &Config) -> Result<(), String> {
    let name = &c.tun_name;
    if name.is_empty()
        || name.len() > 15
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_.-".contains(ch))
    {
        return Err(format!(
            "invalid TUN name {name:?}: 1-15 characters of [A-Za-z0-9_.-]"
        ));
    }
    if !(1..=256).contains(&c.conns) {
        return Err("`conns` must be within 1..=256".into());
    }
    if let Some(m) = c.outer_mtu {
        c.resolve_tun_mtu(m)?;
    } else if let Some(m) = c.tun_mtu {
        let min = c.inner_min_mtu();
        let max = 65535 - c.outer_family.overhead() as u32;
        if m < min || m > max {
            return Err(format!("`tun_mtu` must be within {min}..={max}"));
        }
    }
    let t = &c.tunables;
    if t.ping_interval.is_zero() {
        return Err("`ping_interval` must be positive".into());
    }
    if t.dead_timeout <= t.ping_interval {
        return Err("`dead_timeout` must be greater than `ping_interval`".into());
    }
    match c.mode {
        Mode::Entry => {
            let remote = c.remote.ok_or("entry mode requires `remote` (IP:PORT)")?;
            if remote.port() == 0 {
                return Err("`remote` port must not be 0".into());
            }
            if c.transport == Transport::Faketcp
                && (c.base_port < 1024 || u32::from(c.base_port) + u32::from(c.conns) > 65535)
            {
                return Err(
                    "`base_port` must be >= 1024 and leave room for `conns` ports below 65536"
                        .into(),
                );
            }
        }
        Mode::Exit => {
            if c.listen.is_none_or(|p| p == 0) {
                return Err("exit mode requires a non-zero `listen` port".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
