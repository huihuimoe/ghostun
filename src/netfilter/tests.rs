use std::process::{Command, Output};

use netlink_packet_core::NLM_F_CREATE;
use netlink_packet_netfilter::nftables::{
    ChainAttribute, ChainMessage, Expressions, NfTablesMessage, RuleAttribute, RuleMessage,
};

use super::*;

fn spec() -> NftSpec {
    NftSpec {
        mode: Mode::Exit,
        transport: Transport::Tcp,
        outer_family: OuterFamily::Ipv4,
        tun_name: "nft_atomic".into(),
        remote: None,
        base_port: 30000,
        listen_ip: None,
        listen_port: 443,
        inner_v4: "10.200.0.2/30".parse().unwrap(),
        inner_v6: Some("fd00:200::2/126".parse().unwrap()),
        iface: None,
        masq: true,
    }
}

#[test]
fn invalid_interface_names_are_rejected_without_truncation() {
    let mut spec = spec();
    for name in ["1234567890123456", "eth0\0sibling"] {
        spec.iface = Some(name.into());
        let error = rules::build(&spec, "ghostun_invalid_iface")
            .err()
            .expect("invalid name accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

fn nft(args: &[&str]) -> Output {
    Command::new("nft")
        .args(args)
        .output()
        .expect("nft observer required")
}

fn malformed_replacement(spec: &NftSpec, table: &str) -> netlink::Batch {
    let mut batch = rules::build(spec, table).unwrap();
    // A real kernel validation error after all preceding table/chain/rule mutations.
    batch.push(
        NfTablesMessage::NewRule(RuleMessage {
            attributes: vec![
                RuleAttribute::Table(table.into()),
                RuleAttribute::Chain("output".into()),
                RuleAttribute::Expressions(vec![Expressions::Other {
                    expression_type: "rt".into(),
                    attributes: vec![],
                }
                .into()]),
            ],
        }),
        NLM_F_CREATE,
    );
    batch
}

#[test]
#[ignore = "privileged disposable Docker container only; requires nft observer"]
fn atomic_table_replacement() {
    let spec = spec();
    let table = table_name(&spec.tun_name);
    assert!(
        !nft(&["list", "table", "inet", &table]).status.success(),
        "fixture table already exists"
    );
    let error = malformed_replacement(&spec, &table).commit().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(
        !nft(&["list", "table", "inet", &table]).status.success(),
        "failed first install leaked a table"
    );

    let mut original = netlink::Batch::new();
    original.push(
        NfTablesMessage::NewTable(rules::table(&table)),
        NLM_F_CREATE,
    );
    original.push(
        NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(table.clone()),
                ChainAttribute::Name("canary".into()),
            ],
        }),
        NLM_F_CREATE,
    );
    original.commit().unwrap();
    let guard = Guard {
        table: table.clone(),
        armed: true,
    };
    let before = nft(&["--json", "list", "table", "inet", &table]);
    assert!(before.status.success());
    let error = malformed_replacement(&spec, &table).commit().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let after = nft(&["--json", "list", "table", "inet", &table]);
    assert!(after.status.success());
    assert_eq!(
        after.stdout, before.stdout,
        "failed replacement changed the original kernel table"
    );

    rules::build(&spec, &table).unwrap().commit().unwrap();
    assert!(
        !nft(&["list", "chain", "inet", &table, "canary"])
            .status
            .success(),
        "stale chain survived replacement"
    );
    assert!(
        nft(&["list", "chain", "inet", &table, "forward"])
            .status
            .success(),
        "new rules missing after successful replacement"
    );
    guard.remove().unwrap();
    assert!(
        !nft(&["list", "table", "inet", &table]).status.success(),
        "owned table survived removal"
    );
}
