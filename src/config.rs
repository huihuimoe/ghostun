//! CLI flags + TOML file merged into a validated runtime configuration (CLI > TOML > defaults).

use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Entry,
    Exit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OuterFamily {
    #[default]
    Ipv4,
    Ipv6,
}

impl OuterFamily {
    pub fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }

    pub fn overhead(self) -> usize {
        match self {
            Self::Ipv4 => 40,
            Self::Ipv6 => 60,
        }
    }

    pub fn ip_flag(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
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

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub mode: Mode,
    pub tun_name: String,
    pub tun_ipv4: Cidr<Ipv4Addr>,
    pub tun_ipv6: Option<Cidr<Ipv6Addr>>,
    pub conns: u16,
    pub outer_mtu: Option<u32>,
    pub tun_mtu: Option<u32>,
    pub iface: Option<String>,
    pub base_port: u16,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
    pub netfilter: bool,
    /// Exit node outer address; `Some` exactly in entry mode.
    pub remote: Option<SocketAddr>,
    /// Outer listen port; `Some` exactly in exit mode.
    pub listen: Option<u16>,
    pub outer_family: OuterFamily,
}

impl Config {
    /// Validates explicit and detected MTUs before any network resources are changed.
    pub fn resolve_tun_mtu(&self, outer_mtu: u32) -> Result<u32, String> {
        let overhead = self.outer_family.overhead() as u32;
        let min_outer = if self.outer_family == OuterFamily::Ipv6 {
            1280
        } else {
            576
        };
        if !(min_outer..=65535).contains(&outer_mtu) {
            return Err(format!("outer MTU must be within {min_outer}..=65535"));
        }
        let available = outer_mtu - overhead;
        let mtu = self.tun_mtu.unwrap_or(available);
        let minimum = if self.tun_ipv6.is_some() { 1280 } else { 576 };
        if mtu < minimum || mtu > available {
            return Err(format!("TUN MTU {mtu} must be within {minimum}..={available} for outer MTU {outer_mtu} and {overhead}-byte encapsulation"));
        }
        Ok(mtu)
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "ghostun",
    version,
    about = "L3-over-FakeTCP tunnel with per-core BPF steering"
)]
struct Cli {
    /// TOML configuration file; CLI flags override its values.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    role: Option<Role>,
}

#[derive(Subcommand, Debug)]
enum Role {
    /// Entry node: dials the exit node.
    Entry {
        /// Exit node outer address.
        #[arg(long, value_name = "IP:PORT")]
        remote: Option<SocketAddr>,
        #[command(flatten)]
        common: Common,
    },
    /// Exit node: accepts entry connections and NATs inner traffic.
    Exit {
        /// Outer FakeTCP listen port.
        #[arg(long, value_name = "PORT")]
        listen: Option<u16>,
        /// Outer address family; entry derives it from --remote [default: ipv4].
        #[arg(long, value_enum)]
        outer_family: Option<OuterFamily>,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(Args, Debug, Default)]
struct Common {
    /// Inner TUN interface name [default: ghostun0].
    #[arg(long = "tun", visible_alias = "tun-name", value_name = "NAME")]
    tun_name: Option<String>,
    /// Inner IPv4 address [default: entry 10.200.0.1/30, exit 10.200.0.2/30].
    #[arg(long, value_name = "CIDR")]
    tun_ipv4: Option<String>,
    /// Inner IPv6 address [default: entry fd00:200::1/126, exit fd00:200::2/126].
    #[arg(long, value_name = "CIDR")]
    tun_ipv6: Option<String>,
    /// Outer connections = worker threads; must match on both ends [default: CPU count].
    #[arg(long, value_name = "N")]
    conns: Option<u16>,
    /// Outer path MTU [default: egress interface MTU, fallback 1500].
    #[arg(long, value_name = "MTU")]
    outer_mtu: Option<u32>,
    /// Inner TUN MTU [default: outer MTU - 40 for IPv4, - 60 for IPv6].
    #[arg(long, value_name = "MTU")]
    tun_mtu: Option<u32>,
    /// Outer egress interface [default: from routing table].
    #[arg(long, value_name = "IFACE")]
    iface: Option<String>,
    /// First outer source port of the entry port pool [default: 32768].
    #[arg(long, value_name = "PORT")]
    base_port: Option<u16>,
    /// Health ping interval in seconds [default: 5].
    #[arg(long, value_name = "SECS")]
    ping_interval: Option<u64>,
    /// Reconnect after this many seconds without traffic from the peer [default: 15].
    #[arg(long, value_name = "SECS")]
    dead_timeout: Option<u64>,
    /// Do not configure inner IPv6.
    #[arg(long)]
    no_ipv6: bool,
    /// Do not touch nftables or sysctl.
    #[arg(long)]
    no_netfilter: bool,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct File {
    mode: Option<Mode>,
    tun_name: Option<String>,
    tun_ipv4: Option<String>,
    tun_ipv6: Option<String>,
    conns: Option<u16>,
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
    remote: Option<SocketAddr>,
    listen: Option<u16>,
    outer_family: Option<OuterFamily>,
}

pub fn load() -> Result<Config, String> {
    parse_from(std::env::args_os())
}

/// `--help`/`--version` and usage errors exit the process through clap, like any CLI.
pub fn parse_from<I, T>(args: I) -> Result<Config, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::try_parse_from(args).unwrap_or_else(|e| e.exit());
    let file = match &cli.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            toml::from_str::<File>(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?
        }
        None => File::default(),
    };
    let (mode, common, remote, listen, outer_family) = match cli.role {
        Some(Role::Entry { remote, common }) => (Mode::Entry, common, remote, None, None),
        Some(Role::Exit {
            listen,
            outer_family,
            common,
        }) => (Mode::Exit, common, None, listen, outer_family),
        None => (
            file.mode
                .ok_or("missing role: use `entry`/`exit` or set `mode` in the config file")?,
            Common::default(),
            None,
            None,
            None,
        ),
    };
    if file.mode.is_some_and(|m| m != mode) {
        return Err(format!(
            "role {mode:?} conflicts with `mode` in the config file"
        ));
    }
    let remote = remote.or(file.remote);
    let listen = listen.or(file.listen);
    let outer_family = outer_family.or(file.outer_family);
    if mode == Mode::Entry && outer_family.is_some() {
        return Err(
            "`outer_family` is only valid in exit mode; entry uses the remote address family"
                .into(),
        );
    }
    let outer_family = remote
        .map(|r| OuterFamily::of(r.ip()))
        .unwrap_or(outer_family.unwrap_or_default());
    match mode {
        Mode::Entry if listen.is_some() => return Err("`listen` is only valid in exit mode".into()),
        Mode::Exit if remote.is_some() => return Err("`remote` is only valid in entry mode".into()),
        _ => {}
    }
    let (v4_default, v6_default) = match mode {
        Mode::Entry => ("10.200.0.1/30", "fd00:200::1/126"),
        Mode::Exit => ("10.200.0.2/30", "fd00:200::2/126"),
    };
    let tun_ipv4 = common
        .tun_ipv4
        .or(file.tun_ipv4)
        .as_deref()
        .unwrap_or(v4_default)
        .parse()?;
    let tun_ipv6 = if common.no_ipv6 || file.no_ipv6 {
        None
    } else {
        Some(
            common
                .tun_ipv6
                .or(file.tun_ipv6)
                .as_deref()
                .unwrap_or(v6_default)
                .parse()?,
        )
    };
    let default_conns = std::thread::available_parallelism().map_or(1, |n| n.get().min(256) as u16);
    let cfg = Config {
        mode,
        tun_name: common
            .tun_name
            .or(file.tun_name)
            .unwrap_or_else(|| "ghostun0".into()),
        tun_ipv4,
        tun_ipv6,
        conns: common.conns.or(file.conns).unwrap_or(default_conns),
        outer_mtu: common.outer_mtu.or(file.outer_mtu),
        tun_mtu: common.tun_mtu.or(file.tun_mtu),
        iface: common.iface.or(file.iface),
        base_port: common.base_port.or(file.base_port).unwrap_or(32768),
        ping_interval: Duration::from_secs(
            common.ping_interval.or(file.ping_interval).unwrap_or(5),
        ),
        dead_timeout: Duration::from_secs(common.dead_timeout.or(file.dead_timeout).unwrap_or(15)),
        netfilter: !(common.no_netfilter || file.no_netfilter),
        remote,
        listen,
        outer_family,
    };
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(c: &Config) -> Result<(), String> {
    let name = &c.tun_name;
    // Interpolated into nft scripts and `ip` arguments, so keep to a conservative charset.
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
        let min = if c.tun_ipv6.is_some() { 1280 } else { 576 };
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
            if c.base_port < 1024 || u32::from(c.base_port) + u32::from(c.conns) > 65535 {
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
        parse_from(std::iter::once("ghostun").chain(args.iter().copied()))
    }

    fn entry(extra: &[&str]) -> Result<Config, String> {
        let mut args = vec!["entry", "--remote", "203.0.113.9:443"];
        args.extend_from_slice(extra);
        parse(&args)
    }

    fn with_file(name: &str, toml: &str, args: &[&str]) -> Result<Config, String> {
        let path =
            std::env::temp_dir().join(format!("ghostun-test-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();
        let mut all = vec!["--config", path.to_str().unwrap()];
        all.extend_from_slice(args);
        let r = parse(&all);
        std::fs::remove_file(&path).unwrap();
        r
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
        assert_eq!((c.listen, c.remote), (Some(443), None));
    }

    #[test]
    fn all_flags_apply() {
        let c = entry(&[
            "--tun-name",
            "wan7",
            "--tun-ipv4",
            "10.9.0.1/24",
            "--tun-ipv6",
            "fd00:9::1/64",
            "--conns",
            "3",
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
        assert_eq!(c.iface.as_deref(), Some("eth1"));
        assert_eq!(c.base_port, 40000);
        assert_eq!(
            (c.ping_interval, c.dead_timeout),
            (Duration::from_secs(2), Duration::from_secs(7))
        );
        assert!(!c.netfilter);
        assert_eq!(entry(&["--tun", "t1"]).unwrap().tun_name, "t1");
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
        assert!(
            with_file("unknown", "mode = \"exit\"\nlisten = 1\nbogus = 1\n", &[])
                .unwrap_err()
                .contains("bogus")
        );
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
    }

    #[test]
    fn validation_errors() {
        assert!(parse(&["entry"]).unwrap_err().contains("remote"));
        assert!(parse(&["exit"]).unwrap_err().contains("listen"));
        assert!(parse(&["exit", "--listen", "0"]).is_err());
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
}
