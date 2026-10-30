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
        assert!(ensure_reload_compatible(&cfg, &overridden)
            .unwrap_err()
            .contains("tcp_notsent"));
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
            let error = with_raw_file("invalid-key", &format!("auth_key = '{bad}'\n{role}"), &[])
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
    assert_eq!(c.tunables.dead_timeout, Duration::from_secs(30));
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
    assert_eq!(reloaded.tunables.auth_key, key2.parse().unwrap());
    assert_eq!(reloaded.tunables.ping_interval, Duration::from_secs(3));
    assert_eq!(reloaded.tunables.dead_timeout, Duration::from_secs(12));
    assert_eq!(reloaded.tunables.cpus, Some(vec![0, 1]));
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
    assert_eq!(reloaded_cpus.tunables.cpus, Some(vec![0, 1, 2, 3]));

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
        format!("mode = 'exit'\nlisten = 443\nauth_key = '{key1}'\nconns = 2\nno_masq = true\n"),
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
    assert_eq!(after_no_v6.tunables.auth_key, key1.parse().unwrap());

    std::fs::remove_file(&path).unwrap();
}
