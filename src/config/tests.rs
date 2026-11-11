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
        &format!("[global]\nauth_key = '{}'\n{toml}", "a7".repeat(32)),
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
    for (name, expected) in [("tcp", Transport::Tcp), ("udp", Transport::Udp)] {
        let cfg = with_file(
            name,
            &format!("transport = '{name}'\n[entry]\nbase_port = 1"),
            &["entry", "--remote", "192.0.2.1:443"],
        )
        .unwrap();
        assert_eq!(cfg.transport, expected);
        assert!(cfg.base_port_explicit);
    }
    assert_eq!(
        with_file(
            "override-transport",
            "transport = 'tcp'",
            &["entry", "--remote", "192.0.2.1:443", "--transport", "udp"]
        )
        .unwrap()
        .transport,
        Transport::Udp
    );
    assert!(
        with_file(
            "bad-transport",
            "transport = 'quic'",
            &["entry", "--remote", "192.0.2.1:443"]
        )
        .is_err()
    );
}

#[test]
fn tcp_notsent_defaults_precedence_validation_and_reload() {
    assert_eq!(entry(&[]).unwrap().tcp_notsent, 64 * 1024);
    for (role, address) in [("entry", "--remote"), ("exit", "--listen")] {
        let endpoint = if role == "entry" {
            "192.0.2.1:443"
        } else {
            "443"
        };
        let args = [role, address, endpoint, "--transport", "tcp"];
        let cfg = with_file("notsent-file", "tcp_notsent = 128", &args).unwrap();
        assert_eq!(cfg.tcp_notsent, 128 * 1024);
        let mut override_args = args.to_vec();
        override_args.extend(["--tcp-notsent", "32"]);
        let overridden = with_file("notsent-cli", "tcp_notsent = 128", &override_args).unwrap();
        assert_eq!(overridden.tcp_notsent, 32 * 1024);
        assert!(
            ensure_reload_compatible(&cfg, &overridden)
                .unwrap_err()
                .contains("tcp_notsent")
        );
        assert!(ensure_reload_compatible(&cfg, &cfg).is_ok());
        for value in ["0", "-1", "4194304", "4294967295"] {
            assert!(
                with_file("notsent-invalid", &format!("tcp_notsent = {value}"), &args).is_err()
            );
        }
        assert!(Cli::from_args(&["ghostun"], &["--tcp-notsent", "-1"]).is_err());
        for value in ["0", "4194304", "4294967295"] {
            let mut invalid_args = args.to_vec();
            invalid_args.extend(["--tcp-notsent", value]);
            assert!(with_file("notsent-invalid-cli", "", &invalid_args).is_err());
        }
    }
    assert_eq!(entry(&["--tcp-notsent", "1"]).unwrap().tcp_notsent, 1024);
    assert_eq!(
        entry(&["--tcp-notsent", "4194303"]).unwrap().tcp_notsent,
        4194303 * 1024
    );
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
        "mode = 'entry'\n[entry]\nremote = [{ address = '192.0.2.1:443', conns = 1 }]",
        "mode = 'exit'\n[exit]\nlisten = 443",
    ] {
        let config = with_raw_file(
            "valid-key",
            &format!("[global]\nauth_key = '{key}'\n{role}"),
            &[],
        )
        .unwrap();
        assert!(!format!("{config:?}").contains(&key));
        for bad in [
            String::new(),
            "password".into(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            let error = with_raw_file(
                "invalid-key",
                &format!("[global]\nauth_key = '{bad}'\n{role}"),
                &[],
            )
            .unwrap_err();
            if !bad.is_empty() {
                assert!(!error.contains(&bad));
            }
        }
        for invalid in [
            format!("[global]\nauth_key = '{key}'\n{role}\nbroken = ["),
            format!("[global]\nauth_key = ['{key}']\n{role}"),
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
        std::thread::available_parallelism()
            .unwrap()
            .get()
            .min(MAX_CONNS)
    );
    assert_eq!(c.tunables.cpus, None);
    assert_eq!(
        (c.outer_mtu, c.tun_mtu, c.iface.as_deref()),
        (None, None, None)
    );
    assert_eq!(c.base_port, 32768);
    assert_eq!(
        (c.tunables.ping_interval, c.tunables.dead_timeout),
        (Duration::from_secs(5), Duration::from_secs(15))
    );
    assert!(c.netfilter);
    assert_eq!(
        c.remote,
        vec![RemoteConfig {
            address: "203.0.113.9:443".parse().unwrap(),
            conns: c.conns,
        }]
    );
    assert_eq!(c.listen, None);
}

#[test]
fn exit_defaults() {
    let c = parse(&["exit", "--listen", "443"]).unwrap();
    assert_eq!(c.mode, Mode::Exit);
    assert_eq!(c.tun_ipv4.to_string(), "10.200.0.2/30");
    assert_eq!(c.tun_ipv6.unwrap().to_string(), "fd00:200::2/126");
    assert!(c.netfilter && c.masq);
    assert_eq!((c.listen, c.remote.as_slice()), (Some(443), &[][..]));
    let c = with_file(
        "exit-no-masq",
        "mode = 'exit'\n[exit]\nlisten = 443\nno_masq = true\n",
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
    assert_eq!(c.tunables.cpus.as_deref(), Some(&[2, 3, 0][..]));
    assert_eq!(c.iface.as_deref(), Some("eth1"));
    assert_eq!(c.base_port, 40000);
    assert_eq!(
        (c.tunables.ping_interval, c.tunables.dead_timeout),
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
        "mode = \"exit\"\ntun_name = \"gx\"\nno_ipv6 = true\n[exit]\nlisten = 8443\n",
        &[],
    )
    .unwrap();
    assert_eq!(
        (c.mode, c.listen, c.conns, c.tun_name.as_str(), c.tun_ipv6),
        (Mode::Exit, Some(8443), 0, "gx", None)
    );
}

#[test]
fn cli_overrides_toml() {
    let toml = "dead_timeout = 30\ntun_name = \"fromfile\"\n[entry]\nremote = [{ address = \"203.0.113.1:80\", conns = 2 }]\n";
    let c = with_file(
        "override",
        toml,
        &[
            "entry",
            "--remote",
            "203.0.113.2:80",
            "--conns",
            "5",
            "--tun",
            "fromcli",
        ],
    )
    .unwrap();
    assert_eq!(c.conns, 5);
    assert_eq!(c.tun_name, "fromcli");
    assert_eq!(c.tunables.dead_timeout, Duration::from_secs(30));
    assert_eq!(
        c.remote,
        vec![RemoteConfig {
            address: "203.0.113.2:80".parse().unwrap(),
            conns: 5,
        }]
    );
    let c = with_file(
        "override-file-mode",
        &format!("mode = \"entry\"\n{toml}"),
        &["--remote", "203.0.113.3:80", "--conns", "7"],
    )
    .unwrap();
    assert_eq!(
        (c.mode, c.conns, c.tun_name.as_str()),
        (Mode::Entry, 7, "fromfile")
    );
    assert!(
        with_file(
            "conns-without-cli-remote",
            &format!("mode = \"entry\"\n{toml}"),
            &["--conns", "7"]
        )
        .is_err()
    );
}

#[test]
fn file_errors() {
    assert!(
        with_file(
            "conflict",
            "mode = \"exit\"\n[exit]\nlisten = 1\n",
            &["entry", "--remote", "1.2.3.4:5"]
        )
        .unwrap_err()
        .contains("conflicts")
    );
    assert!(
        with_file(
            "unknown-global",
            "mode = \"exit\"\nbogus = 1\n[exit]\nlisten = 1\n",
            &[]
        )
        .is_err()
    );
    assert!(
        with_raw_file(
            "flat-root-rejected",
            &format!(
                "auth_key = '{}'\nmode = 'exit'\nlisten = 443\n",
                "a7".repeat(32)
            ),
            &[]
        )
        .is_err()
    );
    assert!(
        with_file(
            "norole",
            "[entry]\nremote = [{ address = '1.2.3.4:5', conns = 1 }]\n",
            &[]
        )
        .unwrap_err()
        .contains("missing role")
    );
    assert!(
        with_file(
            "wrong-section-remote",
            "mode = \"exit\"\n[exit]\nlisten = 1\nremote = \"1.2.3.4:5\"\n",
            &[]
        )
        .is_err()
    );
    assert!(
        with_file(
            "wrong-section-conns",
            "mode = \"exit\"\n[exit]\nlisten = 1\nconns = 2\n",
            &[]
        )
        .is_err()
    );
    assert!(with_file(
        "entry-top-level-conns-rejected",
        "mode = \"entry\"\n[entry]\nremote = [{ address = \"1.2.3.4:5\", conns = 1 }]\nconns = 2\n",
        &[]
    )
    .is_err());
    assert!(
        with_file(
            "entry-scalar-remote-rejected",
            "mode = \"entry\"\n[entry]\nremote = \"1.2.3.4:5\"\n",
            &[]
        )
        .is_err()
    );
    assert!(with_file(
        "wrong-section-no-masq",
        "mode = \"entry\"\n[entry]\nremote = [{ address = \"1.2.3.4:5\", conns = 1 }]\nno_masq = true\n",
        &[]
    )
    .is_err());
    // Inactive section still validates field names and types so typos fail closed.
    assert!(
        with_file(
            "inactive-exit-typo",
            "[entry]\nremote = [{ address = \"1.2.3.4:5\", conns = 1 }]\n[exit]\nlitsen = 443\n",
            &["entry"]
        )
        .is_err()
    );
    assert!(with_file(
        "inactive-exit-bad-type",
        "[entry]\nremote = [{ address = \"1.2.3.4:5\", conns = 1 }]\n[exit]\nlisten = \"not-a-port\"\n",
        &["entry"]
    )
    .is_err());
    assert!(
        with_file(
            "inactive-entry-typo",
            "[entry]\nbogus = 1\n[exit]\nlisten = 443\n",
            &["exit"]
        )
        .is_err()
    );
}

#[test]
fn shared_file_reads_only_global_and_active_role_section() {
    let shared = "\
transport = 'tcp'
tun_name = 'shared0'
[entry]
remote = [
    { address = '198.51.100.10:443', conns = 1 },
    { address = '198.51.100.11:443', conns = 2 },
]
base_port = 41000
tun_ipv4 = '10.210.0.1/30'
tun_ipv6 = 'fd00:210::1/126'
outer_mtu = 1492
iface = 'eth-entry'
cpus = '0,1'
[exit]
listen = 8443
outer_family = 'ipv6'
no_masq = true
tun_ipv4 = '10.210.0.2/30'
tun_ipv6 = 'fd00:210::2/126'
outer_mtu = 1420
iface = 'eth-exit'
cpus = '2,3'
";
    let entry_cfg = with_file("shared-entry", shared, &["entry"]).unwrap();
    assert_eq!(entry_cfg.mode, Mode::Entry);
    assert_eq!(entry_cfg.transport, Transport::Tcp);
    assert_eq!(entry_cfg.tun_name, "shared0");
    assert_eq!(
        entry_cfg.remote,
        vec![
            RemoteConfig {
                address: "198.51.100.10:443".parse().unwrap(),
                conns: 1,
            },
            RemoteConfig {
                address: "198.51.100.11:443".parse().unwrap(),
                conns: 2,
            },
        ]
    );
    assert_eq!(entry_cfg.listen, None);
    assert_eq!(entry_cfg.conns, 3);
    assert_eq!(entry_cfg.base_port, 41000);
    assert_eq!(entry_cfg.outer_family, OuterMode::Ipv4);
    assert!(entry_cfg.masq);
    assert_eq!(entry_cfg.tun_ipv4.to_string(), "10.210.0.1/30");
    assert_eq!(entry_cfg.tun_ipv6.unwrap().to_string(), "fd00:210::1/126");
    assert_eq!(entry_cfg.outer_mtu, Some(1492));
    assert_eq!(entry_cfg.iface.as_deref(), Some("eth-entry"));
    assert_eq!(entry_cfg.tunables.cpus, Some(vec![0, 1]));

    let exit_cfg = with_file("shared-exit", shared, &["exit"]).unwrap();
    assert_eq!(exit_cfg.mode, Mode::Exit);
    assert_eq!(exit_cfg.transport, Transport::Tcp);
    assert_eq!(exit_cfg.tun_name, "shared0");
    assert_eq!(exit_cfg.listen, Some(8443));
    assert!(exit_cfg.remote.is_empty());
    assert_eq!(exit_cfg.conns, 0);
    assert_eq!(exit_cfg.outer_family, OuterMode::Ipv6);
    assert!(!exit_cfg.masq);
    assert_eq!(exit_cfg.tun_ipv4.to_string(), "10.210.0.2/30");
    assert_eq!(exit_cfg.tun_ipv6.unwrap().to_string(), "fd00:210::2/126");
    assert_eq!(exit_cfg.outer_mtu, Some(1420));
    assert_eq!(exit_cfg.iface.as_deref(), Some("eth-exit"));
    assert_eq!(exit_cfg.tunables.cpus, Some(vec![2, 3]));

    let example = std::fs::read_to_string("deploy/config.example.toml")
        .unwrap()
        .replace(
            "# auth_key = \"<64 hexadecimal characters>\"",
            &format!("auth_key = '{}'", "a7".repeat(32)),
        );
    assert_eq!(
        with_raw_file("example-entry", &example, &[]).unwrap().mode,
        Mode::Entry
    );
    let exit_example = example.replace("mode = \"entry\"", "mode = \"exit\"");
    assert_eq!(
        with_raw_file("example-exit", &exit_example, &[])
            .unwrap()
            .mode,
        Mode::Exit
    );
}

#[test]
fn validation_errors() {
    assert!(parse(&["entry"]).unwrap_err().contains("remote"));
    assert!(parse(&["exit"]).unwrap_err().contains("listen"));
    assert!(parse(&["exit", "--listen", "0"]).is_err());
    assert!(entry(&["--no-masq"]).unwrap_err().contains("exit mode"));
    assert!(
        parse(&["exit", "--listen", "443", "--conns", "2"])
            .unwrap_err()
            .contains("entry mode")
    );
    assert!(
        entry(&["--ping-interval", "5", "--dead-timeout", "5"])
            .unwrap_err()
            .contains("dead_timeout")
    );
    assert!(entry(&["--ping-interval", "0"]).is_err());
    assert!(entry(&["--base-port", "65530", "--conns", "8"]).is_err());
    assert!(entry(&["--base-port", "80"]).is_err());
    assert!(entry(&["--conns", "0"]).is_err());
    assert!(entry(&["--conns", "255"]).is_ok());
    assert!(entry(&["--conns", "256"]).is_err());
    assert!(
        with_file(
            "empty-remote",
            "mode = 'entry'\n[entry]\nremote = []\n",
            &[]
        )
        .is_err()
    );
    assert!(
        with_file(
            "zero-remote-conns",
            "mode = 'entry'\n[entry]\nremote = [{ address = '1.2.3.4:443', conns = 0 }]\n",
            &[]
        )
        .is_err()
    );
    assert!(with_file(
        "duplicate-remote-address",
        "mode = 'entry'\n[entry]\nremote = [{ address = '1.2.3.4:443', conns = 1 }, { address = '1.2.3.4:443', conns = 1 }]\n",
        &[]
    )
    .is_err());
    assert!(with_file(
        "sum-conns-overflow",
        "mode = 'entry'\n[entry]\nremote = [{ address = '1.2.3.4:443', conns = 200 }, { address = '1.2.3.5:443', conns = 56 }]\n",
        &[]
    )
    .is_err());
    assert!(entry(&["--outer-mtu", "100"]).is_err());
    assert!(
        entry(&["--tun", "a-very-long-name0"])
            .unwrap_err()
            .contains("TUN name")
    );
    assert!(entry(&["--tun", "a/b"]).is_err());
    assert!(entry(&["--tun", "a\"b"]).is_err());
    assert!(entry(&["--tun", ""]).is_err());
    assert!(
        entry(&["--tun-ipv4", "10.0.0.1/33"])
            .unwrap_err()
            .contains("prefix")
    );
    assert!(entry(&["--tun-ipv4", "10.0.0.1"]).is_err());
    assert!(entry(&["--tun-ipv6", "fd00::1/129"]).is_err());
    assert!(entry(&["--cpus", ""]).is_err());
    assert!(entry(&["--cpus", "3-1"]).is_err());
    assert!(entry(&["--cpus", "1024"]).is_err());
}

#[test]
fn outer_family_is_independent_of_inner_ipv6() {
    let c = parse(&["entry", "--remote", "[2001:db8::1]:443", "--no-ipv6"]).unwrap();
    assert_eq!(c.outer_family, OuterMode::Ipv6);
    assert_eq!(c.tun_ipv6, None);
    let c = with_file(
        "v6-family",
        "mode = 'exit'\n[exit]\nlisten = 443\nouter_family = 'ipv6'\n",
        &[],
    )
    .unwrap();
    assert_eq!(c.outer_family, OuterMode::Ipv6);
    let c = with_file(
        "v6-override",
        "mode = 'exit'\n[exit]\nlisten = 443\nouter_family = 'ipv6'\n",
        &["exit", "--outer-family", "ipv4"],
    )
    .unwrap();
    assert_eq!(c.outer_family, OuterMode::Ipv4);
    assert!(with_file(
        "entry-family",
        "mode = 'entry'\n[entry]\nremote = [{ address = '[2001:db8::1]:443', conns = 1 }]\nouter_family = 'ipv6'\n",
        &[]
    )
    .is_err());
    let v6_listen = parse(&["exit", "--listen", "[2001:db8::1]:443"]).unwrap();
    assert_eq!(v6_listen.outer_family, OuterMode::Ipv6);
    assert_eq!(v6_listen.listen, Some(443));
    assert_eq!(v6_listen.listen_ip, Some("2001:db8::1".parse().unwrap()));
    let v6_wild = with_file(
        "v6-wild",
        "mode = 'exit'\n[exit]\nlisten = '[::]:8443'\n",
        &[],
    )
    .unwrap();
    assert_eq!(v6_wild.outer_family, OuterMode::Ipv6);
    assert_eq!(v6_wild.listen, Some(8443));
    assert_eq!(v6_wild.listen_ip, None);
    let v4_wild = parse(&["exit", "--listen", "0.0.0.0:443"]).unwrap();
    assert_eq!(v4_wild.outer_family, OuterMode::Ipv4);
    assert_eq!(v4_wild.listen_ip, None);
    assert!(
        parse(&[
            "exit",
            "--listen",
            "192.0.2.1:443",
            "--outer-family",
            "ipv6"
        ])
        .unwrap_err()
        .contains("conflicts")
    );
}

#[test]
fn mixed_preserves_policy_but_entry_opens_only_the_remote_family() {
    for (remote, family) in [
        ("192.0.2.1:443", OuterFamily::Ipv4),
        ("[2001:db8::1]:443", OuterFamily::Ipv6),
    ] {
        let c = parse(&["entry", "--remote", remote, "--outer-family", "mixed"]).unwrap();
        assert_eq!(c.outer_family, OuterMode::Mixed);
        assert_eq!(c.socket_families(), &[family]);
        assert_eq!(c.resolve_tun_mtu(1500).unwrap(), 1440);
        assert_eq!(c.resolve_tun_mtu(1420).unwrap(), 1360);
        #[cfg(target_os = "linux")]
        assert_eq!(
            crate::netfilter::NftSpec::from_config(&c, 0).remotes,
            vec![remote.parse().unwrap()]
        );
    }
    let dual = with_file(
        "mixed-entry-remotes",
        "mode = 'entry'\n[entry]\nremote = [{ address = '192.0.2.1:443', conns = 2 }, { address = '[2001:db8::1]:443', conns = 2 }]\n",
        &[],
    )
    .unwrap();
    assert_eq!(dual.outer_family, OuterMode::Mixed);
    assert_eq!(
        dual.socket_families(),
        &[OuterFamily::Ipv4, OuterFamily::Ipv6]
    );
    assert_eq!(dual.resolve_tun_mtu(1500).unwrap(), 1440);
    let c = with_file(
        "mixed-exit",
        "mode = 'exit'\n[exit]\nlisten = 443\nouter_family = 'mixed'\n",
        &[],
    )
    .unwrap();
    assert_eq!(c.outer_family, OuterMode::Mixed);
    assert_eq!(c.socket_families(), &[OuterFamily::Ipv4, OuterFamily::Ipv6]);
    #[cfg(target_os = "linux")]
    assert_eq!(
        crate::netfilter::NftSpec::from_config(&c, 443).outer_family,
        None
    );
    for listen in [
        "192.0.2.1:443",
        "[2001:db8::1]:443",
        "0.0.0.0:443",
        "[::]:443",
    ] {
        assert!(
            parse(&["exit", "--listen", listen, "--outer-family", "mixed"])
                .unwrap_err()
                .contains("bare listen port")
        );
    }
    let c = with_file(
        "mixed-override",
        "mode = 'exit'\n[exit]\nlisten = 443\nouter_family = 'mixed'\n",
        &["--outer-family", "ipv4"],
    )
    .unwrap();
    assert_eq!(c.outer_family, OuterMode::Ipv4);
}

#[test]
fn mtu_validation_uses_outer_family_and_detected_mtu() {
    for (family, tcp_overhead, udp_overhead) in
        [("ipv4", 40, 28), ("ipv6", 60, 48), ("mixed", 60, 48)]
    {
        for (transport, overhead) in [
            ("faketcp", tcp_overhead),
            ("tcp", tcp_overhead),
            ("udp", udp_overhead),
        ] {
            let mut c = parse(&[
                "exit",
                "--listen",
                "443",
                "--outer-family",
                family,
                "--transport",
                transport,
            ])
            .unwrap();
            assert_eq!(c.resolve_tun_mtu(1500).unwrap(), 1500 - overhead);
            assert_eq!(c.resolve_tun_mtu(1280 + overhead).unwrap(), 1280);
            assert!(c.resolve_tun_mtu(1279 + overhead).is_err());
            c.tun_mtu = Some(1441);
            assert!(c.resolve_tun_mtu(1440 + overhead).is_err());
        }
    }
    assert!(
        parse(&[
            "exit",
            "--listen",
            "443",
            "--outer-family",
            "ipv6",
            "--outer-mtu",
            "1280"
        ])
        .is_err()
    );
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
            "[global]\nmode = 'entry'\nauth_key = '{key1}'\nping_interval = 5\ndead_timeout = 15\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"
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

    // Updating all four mutable fields (auth_key, ping_interval, dead_timeout, cpus) AND
    // editing the inactive [exit] section succeeds while preserving startup CLI overrides.
    std::fs::write(
        &path,
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\nping_interval = 3\ndead_timeout = 12\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\ncpus = '0,1'\n[exit]\nlisten = 8443\nno_masq = true\n"
        ),
    )
    .unwrap();
    let reloaded = cfg.reload().unwrap();
    assert_eq!(reloaded.tunables.auth_key, key2.parse().unwrap());
    assert_eq!(reloaded.tunables.ping_interval, Duration::from_secs(3));
    assert_eq!(reloaded.tunables.dead_timeout, Duration::from_secs(12));
    assert_eq!(reloaded.tunables.cpus, Some(vec![0, 1]));
    assert_eq!(reloaded.base_port, 40000);

    // Changing cpus when --remote was given on the CLI without --conns keeps the running conns.
    let cli_cfg = parse_from([
        "ghostun",
        "--config",
        path.to_str().unwrap(),
        "--remote",
        "203.0.113.9:443",
    ])
    .unwrap();
    assert_eq!(cli_cfg.conns, 2);
    std::fs::write(
        &path,
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\nping_interval = 3\ndead_timeout = 12\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\ncpus = '0,1,2,3'\n"
        ),
    )
    .unwrap();
    let reloaded_cpus = cli_cfg.reload().unwrap();
    assert_eq!(reloaded_cpus.conns, 2);
    assert_eq!(reloaded_cpus.tunables.cpus, Some(vec![0, 1, 2, 3]));

    // Invalid TOML syntax or invalid key is rejected without disclosing secret material.
    let secret = "c9D0".repeat(16);
    std::fs::write(&path, format!("[global]\nauth_key = ['{secret}']\n")).unwrap();
    let err = reloaded.reload().unwrap_err();
    assert!(!err.contains(&secret));

    // Changing any immutable field is rejected.
    for bad_toml in [
        format!(
            "[global]\nmode = 'entry'\ntransport = 'tcp'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"
        ),
        format!("[global]\nmode = 'exit'\nauth_key = '{key2}'\n[exit]\nlisten = 443\n"),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.10:443', conns = 2 }}]\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '[2001:db8::1]:443', conns = 2 }}]\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 4 }}]\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\ntun_name = 'gtun1'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\ntun_ipv4 = '10.200.1.1/30'\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\ntun_ipv6 = 'fd00:201::1/126'\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\nouter_mtu = 1420\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\ntun_mtu = 1360\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\niface = 'eth9'\n"
        ),
        format!(
            "[global]\nmode = 'entry'\nauth_key = '{key2}'\nno_netfilter = true\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"
        ),
    ] {
        std::fs::write(&path, &bad_toml).unwrap();
        assert!(
            reloaded.reload().is_err(),
            "expected immutable change to fail: {bad_toml}"
        );
    }

    std::fs::write(
        &path,
        format!("[global]\nmode = 'exit'\nauth_key = '{key1}'\n[exit]\nlisten = 443\n"),
    )
    .unwrap();
    let exit_cfg = parse_from(["ghostun", "--config", path.to_str().unwrap()]).unwrap();
    std::fs::write(
        &path,
        format!(
            "[global]\nmode = 'exit'\nauth_key = '{key1}'\n[exit]\nlisten = 443\ncpus = '0,1'\n"
        ),
    )
    .unwrap();
    assert_eq!(exit_cfg.reload().unwrap().tunables.cpus, Some(vec![0, 1]));
    std::fs::write(
        &path,
        format!(
            "[global]\nmode = 'exit'\nauth_key = '{key1}'\n[exit]\nlisten = 443\nno_masq = true\n"
        ),
    )
    .unwrap();
    assert!(exit_cfg.reload().unwrap_err().contains("no_masq"));
    std::fs::write(
        &path,
        format!("[global]\nmode = 'exit'\nauth_key = '{key1}'\n[exit]\nlisten = '192.0.2.1:443'\n"),
    )
    .unwrap();
    assert!(exit_cfg.reload().unwrap_err().contains("listen"));

    // When inner IPv6 was disabled at startup, reload remains compatible without false mismatch.
    std::fs::write(
        &path,
        format!("[global]\nmode = 'entry'\nauth_key = '{key1}'\n[entry]\nremote = [{{ address = '203.0.113.9:443', conns = 2 }}]\n"),
    )
    .unwrap();
    let mut no_v6_cfg = reloaded.clone();
    no_v6_cfg.disable_inner_ipv6();
    let after_no_v6 = no_v6_cfg.reload().unwrap();
    assert_eq!(after_no_v6.tun_ipv6, None);
    assert_eq!(after_no_v6.tunables.auth_key, key1.parse().unwrap());
    std::fs::remove_file(&path).unwrap();
}
