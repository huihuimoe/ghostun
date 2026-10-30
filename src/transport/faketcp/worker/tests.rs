use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::config::{self, AuthKey};
use crate::transport::control::RollingReload;

#[derive(Default)]
struct Wire(Vec<Vec<u8>>);

impl Sink for Wire {
    fn send(&mut self, frame: &[u8], _dst: IpAddr) {
        self.0.push(frame.to_vec());
    }
}

fn test_cfg(key_byte: u8, cpus: Option<&str>) -> Config {
    let path = std::env::temp_dir().join(format!(
        "ghostun-worker-test-{}-{key_byte}.toml",
        std::process::id()
    ));
    let hex = format!("{key_byte:02x}").repeat(32);
    let cpus_line = cpus.map_or_else(String::new, |c| format!("cpus = '{c}'\n"));
    std::fs::write(
        &path,
        format!(
            "mode = 'entry'\nremote = '203.0.113.9:443'\nauth_key = '{hex}'\nconns = 2\n{cpus_line}"
        ),
    )
    .unwrap();
    let cfg = config::parse_from(["ghostun", "--config", path.to_str().unwrap()]).unwrap();
    std::fs::remove_file(&path).unwrap();
    cfg
}

fn make_session(mode: Mode, worker: u16, key_byte: u8, now: Instant) -> Session {
    let entry_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let exit = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    Session::new(
        SessionConfig {
            mode,
            auth_key: AuthKey([key_byte; 32]),
            local_ip: if mode == Mode::Entry {
                entry_ip
            } else {
                exit.ip()
            },
            remote: (mode == Mode::Entry).then_some(exit),
            listen_port: exit.port(),
            worker,
            conns: 2,
            base_port: 32768,
            mss: 1460,
            ping_interval: Duration::from_secs(5),
            dead_timeout: Duration::from_secs(15),
        },
        now,
        u64::from(worker) + 1,
    )
    .unwrap()
}

fn exchange(entry: &mut Session, exit: &mut Session, now: Instant, mut to_exit: Vec<Vec<u8>>) {
    while !to_exit.is_empty() {
        let mut back = Wire::default();
        for f in &to_exit {
            exit.on_outer(now, f, &mut back);
        }
        let mut fwd = Wire::default();
        for f in std::mem::take(&mut back.0) {
            entry.on_outer(now, &f, &mut fwd);
        }
        to_exit = fwd.0;
    }
}

fn sync_reload(
    ctrl: &Control,
    id: usize,
    cpu: &mut Option<usize>,
    applied_gen: &mut u64,
    now: Instant,
    session: &mut Session,
    out: &mut impl Sink,
) {
    let wait = apply_reload(ctrl, id, cpu, applied_gen, now, session, out);
    ctrl.report(*applied_gen, session.is_established(), wait);
}

#[test]
fn rolling_reload_rotates_established_workers_sequentially_and_rolls_back_without_resetting_sibling(
) {
    let now = Instant::now();
    let default_cpus = vec![0, 1];
    let controls = vec![
        Arc::new(Control::new(Some(0), -1)),
        Arc::new(Control::new(Some(1), -1)),
    ];
    let mut entries = [
        make_session(Mode::Entry, 0, 0xa7, now),
        make_session(Mode::Entry, 1, 0xa7, now),
    ];
    let mut exits = [
        make_session(Mode::Exit, 0, 0xa7, now),
        make_session(Mode::Exit, 1, 0xa7, now),
    ];
    let mut cpus = [Some(0), Some(1)];
    let mut gens = [0u64, 0u64];

    for i in 0..2 {
        let mut w = Wire::default();
        entries[i].start(now, &mut w);
        exchange(
            &mut entries[i],
            &mut exits[i],
            now,
            std::mem::take(&mut w.0),
        );
        assert!(entries[i].is_established());
        sync_reload(
            &controls[i],
            i,
            &mut cpus[i],
            &mut gens[i],
            now,
            &mut entries[i],
            &mut w,
        );
    }

    // Start reload to a wrong key (0xb8) while exits still use 0xa7: worker 0 rotates and
    // waits for Established; worker 1 is not touched and keeps forwarding inner packets.
    let mut rolling = RollingReload::start(&controls, &default_cpus, 1, test_cfg(0xb8, Some("1")));
    let mut w0 = Wire::default();
    sync_reload(
        &controls[0],
        0,
        &mut cpus[0],
        &mut gens[0],
        now,
        &mut entries[0],
        &mut w0,
    );
    assert_eq!(cpus[0], Some(1));
    exchange(&mut entries[0], &mut exits[0], now, w0.0);
    assert!(!entries[0].is_established());
    RollingReload::advance(&controls, &default_cpus, &mut rolling);
    assert_eq!(rolling.as_ref().unwrap().next_worker, 0);
    assert!(entries[1].is_established());

    // Rollback SIGHUP (generation 2) restores key 0xa7 and removes explicit cpus override:
    // worker 0 restores default CPU 0 and re-establishes; worker 1 sees unchanged key 0xa7
    // and completes without emitting any RST or SYN frames.
    rolling = RollingReload::start(&controls, &default_cpus, 2, test_cfg(0xa7, None));
    let mut w0 = Wire::default();
    sync_reload(
        &controls[0],
        0,
        &mut cpus[0],
        &mut gens[0],
        now,
        &mut entries[0],
        &mut w0,
    );
    assert_eq!(cpus[0], Some(0));
    exchange(&mut entries[0], &mut exits[0], now, w0.0);
    assert!(entries[0].is_established());
    sync_reload(
        &controls[0],
        0,
        &mut cpus[0],
        &mut gens[0],
        now,
        &mut entries[0],
        &mut Wire::default(),
    );
    RollingReload::advance(&controls, &default_cpus, &mut rolling);
    assert_eq!(rolling.as_ref().unwrap().next_worker, 1);

    let mut w1 = Wire::default();
    sync_reload(
        &controls[1],
        1,
        &mut cpus[1],
        &mut gens[1],
        now,
        &mut entries[1],
        &mut w1,
    );
    assert!(
        w1.0.is_empty(),
        "unchanged key on worker 1 must not reset its session"
    );
    assert!(entries[1].is_established());
    RollingReload::advance(&controls, &default_cpus, &mut rolling);
    assert!(rolling.is_none());
}

#[test]
fn rolling_reload_fast_forwards_unestablished_workers() {
    let now = Instant::now();
    let default_cpus = vec![0, 1];
    let controls = vec![
        Arc::new(Control::new(Some(0), -1)),
        Arc::new(Control::new(Some(1), -1)),
    ];
    let mut exits = [
        make_session(Mode::Exit, 0, 0xa7, now),
        make_session(Mode::Exit, 1, 0xa7, now),
    ];
    let mut cpus = [Some(0), Some(1)];
    let mut gens = [0u64, 0u64];

    let mut rolling = RollingReload::start(&controls, &default_cpus, 1, test_cfg(0xc9, None));
    sync_reload(
        &controls[0],
        0,
        &mut cpus[0],
        &mut gens[0],
        now,
        &mut exits[0],
        &mut Wire::default(),
    );
    RollingReload::advance(&controls, &default_cpus, &mut rolling);
    assert_eq!(rolling.as_ref().unwrap().next_worker, 1);
    sync_reload(
        &controls[1],
        1,
        &mut cpus[1],
        &mut gens[1],
        now,
        &mut exits[1],
        &mut Wire::default(),
    );
    RollingReload::advance(&controls, &default_cpus, &mut rolling);
    assert!(rolling.is_none());
}
