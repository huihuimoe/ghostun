//! CLI flags + TOML file merged into a validated runtime configuration (CLI > TOML > defaults).

use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use crate::faketcp::pkt::{ipv4, ipv6, tcp};
use argh::{FromArgValue, FromArgs};
use serde::Deserialize;

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
        if ip.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }

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

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub transport: Transport,
    pub base_port_explicit: bool,
    pub mode: Mode,
    pub auth_key: AuthKey,
    pub tun_name: String,
    pub tun_ipv4: Cidr<Ipv4Addr>,
    pub tun_ipv6: Option<Cidr<Ipv6Addr>>,
    pub conns: u16,
    pub cpus: Option<Vec<usize>>,
    pub outer_mtu: Option<u32>,
    pub tun_mtu: Option<u32>,
    pub iface: Option<String>,
    pub base_port: u16,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
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
        base_port_explicit: cli.base_port.is_some() || file.base_port.is_some(),
        mode,
        auth_key: file
            .auth_key
            .as_deref()
            .ok_or("missing TOML `auth_key`")?
            .parse()?,
        tun_name: cli
            .tun_name
            .clone()
            .or(file.tun_name)
            .unwrap_or_else(|| "ghostun0".into()),
        tun_ipv4,
        tun_ipv6,
        conns: cli.conns.or(file.conns).unwrap_or(default_conns),
        cpus,
        outer_mtu: cli.outer_mtu.or(file.outer_mtu),
        tun_mtu: cli.tun_mtu.or(file.tun_mtu),
        iface: cli.iface.clone().or(file.iface),
        base_port: cli.base_port.or(file.base_port).unwrap_or(32768),
        ping_interval: Duration::from_secs(cli.ping_interval.or(file.ping_interval).unwrap_or(5)),
        dead_timeout: Duration::from_secs(cli.dead_timeout.or(file.dead_timeout).unwrap_or(15)),
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
    // Interpolated into nft scripts, so keep to a conservative charset.
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
    if c.ping_interval.is_zero() {
        return Err("`ping_interval` must be positive".into());
    }
    if c.dead_timeout <= c.ping_interval {
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
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        with_file(&format!("cli-{:?}", std::thread::current().id()), "", args)
    }

    fn entry(extra: &[&str]) -> Result<Config, String> {
        let mut args = vec!["entry", "--remote", "203.0.113.9:443"];
        args.extend_from_slice(extra);
        parse(&args)
    }

    fn with_file(name: &str, toml: &str, args: &[&str]) -> Result<Config, String> {
        with_raw_file(
            name,
            &format!("auth_key = '{}'\n{toml}", "a7".repeat(32)),
            args,
        )
    }

    fn with_raw_file(name: &str, toml: &str, args: &[&str]) -> Result<Config, String> {
        let path =
            std::env::temp_dir().join(format!("ghostun-test-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();
        let mut all = vec!["--config", path.to_str().unwrap()];
        all.extend_from_slice(args);
        let r = parse_from(std::iter::once("ghostun").chain(all.iter().copied()));
        std::fs::remove_file(&path).unwrap();
        r
    }

    #[test]
    fn transport_defaults_precedence_and_validation() {
        assert_eq!(entry(&[]).unwrap().transport, Transport::Faketcp);
        let tcp = with_file(
            "tcp",
            "transport = 'tcp'\nbase_port = 1",
            &["entry", "--remote", "192.0.2.1:443"],
        )
        .unwrap();
        assert_eq!(tcp.transport, Transport::Tcp);
        assert!(tcp.base_port_explicit);
        assert_eq!(
            with_file(
                "override-transport",
                "transport = 'tcp'",
                &[
                    "entry",
                    "--remote",
                    "192.0.2.1:443",
                    "--transport",
                    "faketcp"
                ]
            )
            .unwrap()
            .transport,
            Transport::Faketcp
        );
        assert!(with_file(
            "bad-transport",
            "transport = 'udp'",
            &["entry", "--remote", "192.0.2.1:443"]
        )
        .is_err());
    }

    #[test]
    fn both_roles_require_an_auth_key() {
        for args in [
            vec!["ghostun", "entry", "--remote", "203.0.113.9:443"],
            vec!["ghostun", "exit", "--listen", "443"],
        ] {
            assert!(parse_from(args).is_err(), "a missing key must fail closed");
        }
    }

    #[test]
    fn key_validation_never_discloses_secret_material() {
        let key = "a7B9".repeat(16);
        for role in [
            "mode = 'entry'\nremote = '192.0.2.1:443'",
            "mode = 'exit'\nlisten = 443",
        ] {
            let config =
                with_raw_file("valid-key", &format!("auth_key = '{key}'\n{role}"), &[]).unwrap();
            assert!(!format!("{config:?}").contains(&key));
            for bad in [
                String::new(),
                "password".into(),
                "a".repeat(63),
                "a".repeat(65),
                "g".repeat(64),
                "é".repeat(32),
            ] {
                let error =
                    with_raw_file("invalid-key", &format!("auth_key = '{bad}'\n{role}"), &[])
                        .unwrap_err();
                if !bad.is_empty() {
                    assert!(!error.contains(&bad));
                }
            }
            for invalid in [
                format!("auth_key = '{key}'\n{role}\nbroken = ["),
                format!("auth_key = ['{key}']\n{role}"),
            ] {
                let error = with_raw_file("invalid-toml", &invalid, &[]).unwrap_err();
                assert!(!error.contains(&key));
            }
        }
    }

    #[test]
    fn entry_defaults() {
        let c = entry(&[]).unwrap();
        assert_eq!(c.mode, Mode::Entry);
        assert_eq!(c.tun_name, "ghostun0");
        assert_eq!(c.tun_ipv4.to_string(), "10.200.0.1/30");
        assert_eq!(c.tun_ipv6.unwrap().to_string(), "fd00:200::1/126");
        assert_eq!(
            usize::from(c.conns),
            std::thread::available_parallelism().unwrap().get().min(256)
        );
        assert_eq!(c.cpus, None);
        assert_eq!(
            (c.outer_mtu, c.tun_mtu, c.iface.as_deref()),
            (None, None, None)
        );
        assert_eq!(c.base_port, 32768);
        assert_eq!(
            (c.ping_interval, c.dead_timeout),
            (Duration::from_secs(5), Duration::from_secs(15))
        );
        assert!(c.netfilter);
        assert_eq!(c.remote, Some("203.0.113.9:443".parse().unwrap()));
        assert_eq!(c.listen, None);
    }

    #[test]
    fn exit_defaults() {
        let c = parse(&["exit", "--listen", "443"]).unwrap();
        assert_eq!(c.mode, Mode::Exit);
        assert_eq!(c.tun_ipv4.to_string(), "10.200.0.2/30");
        assert_eq!(c.tun_ipv6.unwrap().to_string(), "fd00:200::2/126");
        assert!(c.netfilter && c.masq);
        assert_eq!((c.listen, c.remote), (Some(443), None));
        let c = with_file(
            "exit-no-masq",
            "mode = 'exit'\nlisten = 443\nno_masq = true\n",
            &["--no-netfilter", "--iface", "eth0"],
        )
        .unwrap();
        assert!(!c.netfilter && !c.masq);
        assert_eq!(c.iface.as_deref(), Some("eth0"));
        assert!(
            !parse(&["exit", "--listen", "443", "--no-masq"])
                .unwrap()
                .masq
        );
    }

    #[test]
    fn all_flags_apply() {
        let c = entry(&[
            "--tun",
            "wan7",
            "--tun-ipv4",
            "10.9.0.1/24",
            "--tun-ipv6",
            "fd00:9::1/64",
            "--conns",
            "3",
            "--cpus",
            "2-3,0",
            "--outer-mtu",
            "1492",
            "--tun-mtu",
            "1400",
            "--iface",
            "eth1",
            "--base-port",
            "40000",
            "--ping-interval",
            "2",
            "--dead-timeout",
            "7",
            "--no-netfilter",
        ])
        .unwrap();
        assert_eq!(c.tun_name, "wan7");
        assert_eq!(c.tun_ipv4.to_string(), "10.9.0.1/24");
        assert_eq!(c.tun_ipv6.unwrap().to_string(), "fd00:9::1/64");
        assert_eq!(
            (c.conns, c.outer_mtu, c.tun_mtu),
            (3, Some(1492), Some(1400))
        );
        assert_eq!(c.cpus.as_deref(), Some(&[2, 3, 0][..]));
        assert_eq!(c.iface.as_deref(), Some("eth1"));
        assert_eq!(c.base_port, 40000);
        assert_eq!(
            (c.ping_interval, c.dead_timeout),
            (Duration::from_secs(2), Duration::from_secs(7))
        );
        assert!(!c.netfilter);
    }

    #[test]
    fn no_ipv6_disables_inner_v6() {
        assert_eq!(entry(&["--no-ipv6"]).unwrap().tun_ipv6, None);
        // 1280 floor only applies with IPv6.
        assert_eq!(
            entry(&["--no-ipv6", "--tun-mtu", "1000"]).unwrap().tun_mtu,
            Some(1000)
        );
        assert!(entry(&["--tun-mtu", "1000"]).is_err());
    }

    #[test]
    fn toml_alone_selects_role() {
        let c = with_file(
            "role",
            "mode = \"exit\"\nlisten = 8443\nconns = 2\ntun_name = \"gx\"\nno_ipv6 = true\n",
            &[],
        )
        .unwrap();
        assert_eq!(
            (c.mode, c.listen, c.conns, c.tun_name.as_str(), c.tun_ipv6),
            (Mode::Exit, Some(8443), 2, "gx", None)
        );
    }

    #[test]
    fn cli_overrides_toml() {
        let toml =
            "remote = \"203.0.113.1:80\"\nconns = 2\ndead_timeout = 30\ntun_name = \"fromfile\"\n";
        let c = with_file(
            "override",
            toml,
            &["entry", "--conns", "5", "--tun", "fromcli"],
        )
        .unwrap();
        assert_eq!(c.conns, 5);
        assert_eq!(c.tun_name, "fromcli");
        assert_eq!(c.dead_timeout, Duration::from_secs(30));
        assert_eq!(c.remote, Some("203.0.113.1:80".parse().unwrap()));
        let c = with_file(
            "override-file-mode",
            &format!("mode = \"entry\"\n{toml}"),
            &["--conns", "7"],
        )
        .unwrap();
        assert_eq!(
            (c.mode, c.conns, c.tun_name.as_str()),
            (Mode::Entry, 7, "fromfile")
        );
    }

    #[test]
    fn file_errors() {
        assert!(with_file(
            "conflict",
            "mode = \"exit\"\nlisten = 1\n",
            &["entry", "--remote", "1.2.3.4:5"]
        )
        .unwrap_err()
        .contains("conflicts"));
        assert!(with_file("unknown", "mode = \"exit\"\nlisten = 1\nbogus = 1\n", &[]).is_err());
        assert!(with_file("norole", "conns = 1\n", &[])
            .unwrap_err()
            .contains("missing role"));
        assert!(with_file(
            "wrongrole",
            "mode = \"exit\"\nlisten = 1\nremote = \"1.2.3.4:5\"\n",
            &[]
        )
        .unwrap_err()
        .contains("entry mode"));
        assert!(with_file(
            "entry-no-masq",
            "mode = \"entry\"\nremote = \"1.2.3.4:5\"\nno_masq = true\n",
            &[]
        )
        .unwrap_err()
        .contains("exit mode"));
    }

    #[test]
    fn validation_errors() {
        assert!(parse(&["entry"]).unwrap_err().contains("remote"));
        assert!(parse(&["exit"]).unwrap_err().contains("listen"));
        assert!(parse(&["exit", "--listen", "0"]).is_err());
        assert!(entry(&["--no-masq"]).unwrap_err().contains("exit mode"));
        assert!(entry(&["--ping-interval", "5", "--dead-timeout", "5"])
            .unwrap_err()
            .contains("dead_timeout"));
        assert!(entry(&["--ping-interval", "0"]).is_err());
        assert!(entry(&["--base-port", "65530", "--conns", "8"]).is_err());
        assert!(entry(&["--base-port", "80"]).is_err());
        assert!(entry(&["--conns", "0"]).is_err());
        assert!(entry(&["--conns", "257"]).is_err());
        assert!(entry(&["--outer-mtu", "100"]).is_err());
        assert!(entry(&["--tun", "a-very-long-name0"])
            .unwrap_err()
            .contains("TUN name"));
        assert!(entry(&["--tun", "a/b"]).is_err());
        assert!(entry(&["--tun", "a\"b"]).is_err());
        assert!(entry(&["--tun", ""]).is_err());
        assert!(entry(&["--tun-ipv4", "10.0.0.1/33"])
            .unwrap_err()
            .contains("prefix"));
        assert!(entry(&["--tun-ipv4", "10.0.0.1"]).is_err());
        assert!(entry(&["--tun-ipv6", "fd00::1/129"]).is_err());
        assert!(entry(&["--cpus", ""]).is_err());
        assert!(entry(&["--cpus", "3-1"]).is_err());
        assert!(entry(&["--cpus", "1024"]).is_err());
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

    #[test]
    fn outer_family_is_independent_of_inner_ipv6() {
        let c = parse(&["entry", "--remote", "[2001:db8::1]:443", "--no-ipv6"]).unwrap();
        assert_eq!(c.outer_family, OuterFamily::Ipv6);
        assert_eq!(c.tun_ipv6, None);
        let c = with_file(
            "v6-family",
            "mode = 'exit'\nlisten = 443\nouter_family = 'ipv6'\n",
            &[],
        )
        .unwrap();
        assert_eq!(c.outer_family, OuterFamily::Ipv6);
        let c = with_file(
            "v6-override",
            "mode = 'exit'\nlisten = 443\nouter_family = 'ipv6'\n",
            &["exit", "--outer-family", "ipv4"],
        )
        .unwrap();
        assert_eq!(c.outer_family, OuterFamily::Ipv4);
        assert!(with_file(
            "entry-family",
            "mode = 'entry'\nremote = '[2001:db8::1]:443'\nouter_family = 'ipv6'\n",
            &[]
        )
        .is_err());
        let v6_listen = parse(&["exit", "--listen", "[2001:db8::1]:443"]).unwrap();
        assert_eq!(v6_listen.outer_family, OuterFamily::Ipv6);
        assert_eq!(v6_listen.listen, Some(443));
        assert_eq!(v6_listen.listen_ip, Some("2001:db8::1".parse().unwrap()));
        let v6_wild = with_file("v6-wild", "mode = 'exit'\nlisten = '[::]:8443'\n", &[]).unwrap();
        assert_eq!(v6_wild.outer_family, OuterFamily::Ipv6);
        assert_eq!(v6_wild.listen, Some(8443));
        assert_eq!(v6_wild.listen_ip, None);
        let v4_wild = parse(&["exit", "--listen", "0.0.0.0:443"]).unwrap();
        assert_eq!(v4_wild.outer_family, OuterFamily::Ipv4);
        assert_eq!(v4_wild.listen_ip, None);
        assert!(parse(&[
            "exit",
            "--listen",
            "192.0.2.1:443",
            "--outer-family",
            "ipv6"
        ])
        .unwrap_err()
        .contains("conflicts"));
    }

    #[test]
    fn mtu_validation_uses_outer_family_and_detected_mtu() {
        for (family, overhead) in [("ipv4", 40), ("ipv6", 60)] {
            let mut c = parse(&["exit", "--listen", "443", "--outer-family", family]).unwrap();
            assert_eq!(c.resolve_tun_mtu(1500).unwrap(), 1500 - overhead);
            assert_eq!(c.resolve_tun_mtu(1280 + overhead).unwrap(), 1280);
            assert!(c.resolve_tun_mtu(1279 + overhead).is_err());
            c.tun_mtu = Some(1441);
            assert!(c.resolve_tun_mtu(1440 + overhead).is_err());
        }
        assert!(parse(&[
            "exit",
            "--listen",
            "443",
            "--outer-family",
            "ipv6",
            "--outer-mtu",
            "1280"
        ])
        .is_err());
        let c = parse(&[
            "exit",
            "--listen",
            "443",
            "--outer-family",
            "ipv6",
            "--outer-mtu",
            "1280",
            "--no-ipv6",
        ])
        .unwrap();
        assert_eq!(c.resolve_tun_mtu(1280).unwrap(), 1220);
        assert!(c.resolve_tun_mtu(1279).is_err());
    }

    #[test]
    fn reload_updates_mutable_fields_and_rejects_immutable_or_invalid_changes() {
        let path = std::env::temp_dir().join(format!("ghostun-reload-{}.toml", std::process::id()));
        let key1 = "a7".repeat(32);
        let key2 = "b8".repeat(32);
        std::fs::write(
            &path,
            format!(
                "mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key1}'\nconns = 2\nping_interval = 5\ndead_timeout = 15\n"
            ),
        )
        .unwrap();
        let cfg = parse_from([
            "ghostun",
            "--config",
            path.to_str().unwrap(),
            "--base-port",
            "40000",
        ])
        .unwrap();

        // Updating all four mutable fields (auth_key, ping_interval, dead_timeout, cpus) succeeds
        // while preserving startup CLI overrides (--base-port 40000).
        std::fs::write(
            &path,
            format!(
                "mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\ncpus = '0,1'\nping_interval = 3\ndead_timeout = 12\n"
            ),
        )
        .unwrap();
        let reloaded = cfg.reload().unwrap();
        assert_eq!(reloaded.auth_key, key2.parse().unwrap());
        assert_eq!(reloaded.ping_interval, Duration::from_secs(3));
        assert_eq!(reloaded.dead_timeout, Duration::from_secs(12));
        assert_eq!(reloaded.cpus, Some(vec![0, 1]));
        assert_eq!(reloaded.base_port, 40000);

        // Changing cpus when conns was omitted in TOML/CLI keeps the running conns.
        std::fs::write(
            &path,
            format!(
                "mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\ncpus = '0,1,2,3'\nping_interval = 3\ndead_timeout = 12\n"
            ),
        )
        .unwrap();
        let reloaded_cpus = reloaded.reload().unwrap();
        assert_eq!(reloaded_cpus.conns, 2);
        assert_eq!(reloaded_cpus.cpus, Some(vec![0, 1, 2, 3]));

        // Invalid TOML syntax or invalid key is rejected without disclosing secret material.
        let secret = "c9D0".repeat(16);
        std::fs::write(&path, format!("auth_key = ['{secret}']\n")).unwrap();
        let err = reloaded.reload().unwrap_err();
        assert!(!err.contains(&secret));

        // Changing any immutable field is rejected.
        for bad_toml in [
            format!("mode = 'entry'\ntransport = 'tcp'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\n"),
            format!("mode = 'exit'\nlisten = 443\nauth_key = '{key2}'\nconns = 2\n"),
            format!("mode = 'entry'\nremote = '203.0.113.10:443'\nauth_key = '{key2}'\nconns = 2\n"),
            format!("mode = 'entry'\nremote = '[2001:db8::1]:443'\nauth_key = '{key2}'\nconns = 2\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 4\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\ntun_name = 'gtun1'\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\ntun_ipv4 = '10.200.1.1/30'\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\ntun_ipv6 = 'fd00:201::1/126'\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\nouter_mtu = 1420\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\ntun_mtu = 1360\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\niface = 'eth9'\n"),
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key2}'\nconns = 2\nno_netfilter = true\n"),
        ] {
            std::fs::write(&path, &bad_toml).unwrap();
            assert!(reloaded.reload().is_err(), "expected immutable change to fail: {bad_toml}");
        }

        std::fs::write(
            &path,
            format!("mode = 'exit'\nlisten = 443\nauth_key = '{key1}'\nconns = 2\n"),
        )
        .unwrap();
        let exit_cfg = parse_from(["ghostun", "--config", path.to_str().unwrap()]).unwrap();
        std::fs::write(
            &path,
            format!(
                "mode = 'exit'\nlisten = 443\nauth_key = '{key1}'\nconns = 2\nno_masq = true\n"
            ),
        )
        .unwrap();
        assert!(exit_cfg.reload().unwrap_err().contains("no_masq"));
        std::fs::write(
            &path,
            format!("mode = 'exit'\nlisten = '192.0.2.1:443'\nauth_key = '{key1}'\nconns = 2\n"),
        )
        .unwrap();
        assert!(exit_cfg.reload().unwrap_err().contains("listen"));

        // When inner IPv6 was disabled at startup, reload remains compatible without false mismatch.
        std::fs::write(
            &path,
            format!("mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{key1}'\nconns = 2\n"),
        )
        .unwrap();
        let mut no_v6_cfg = reloaded.clone();
        no_v6_cfg.disable_inner_ipv6();
        let after_no_v6 = no_v6_cfg.reload().unwrap();
        assert_eq!(after_no_v6.tun_ipv6, None);
        assert_eq!(after_no_v6.auth_key, key1.parse().unwrap());

        std::fs::remove_file(&path).unwrap();
    }
}
