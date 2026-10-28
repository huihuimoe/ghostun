mod config;
mod faketcp;
mod netfilter;
mod sys;
mod tcp;
mod worker;

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use config::{Config, Mode, Transport};
use faketcp::{Session, SessionConfig};
use sys::netlink;
use worker::RollingReload;

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static MAIN_WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::Relaxed);
    } else {
        STOP.store(true, Ordering::Relaxed);
    }
    sys::eventfd_notify(MAIN_WAKE.load(Ordering::Relaxed));
}

/// Outer addressing derived from config plus the routing table.
struct Outer {
    /// Entry source address. The exit learns its address from each incoming SYN instead.
    local_ip: IpAddr,
    dev: Option<String>,
    mtu: u32,
}

fn resolve_outer(cfg: &Config) -> Result<Outer, String> {
    let (local_ip, dev) = match (cfg.mode, cfg.remote) {
        (Mode::Entry, Some(remote)) => {
            let route = netlink::route_to(remote.ip(), cfg.iface.as_deref())
                .map_err(|e| format!("route to {remote}: {e}"))?;
            (route.src, Some(route.dev))
        }
        _ => (
            cfg.exit_ip(),
            cfg.iface
                .clone()
                .or_else(|| netlink::default_route_dev(cfg.outer_family).ok()),
        ),
    };
    let mtu = match (cfg.outer_mtu, &dev) {
        (Some(mtu), _) => mtu,
        (None, Some(dev)) => sys::iface_mtu(dev).unwrap_or_else(|e| {
            log::warn!("cannot read MTU of {dev} ({e}), assuming 1500");
            1500
        }),
        (None, None) => {
            log::warn!("no egress interface found, assuming outer MTU 1500");
            1500
        }
    };
    Ok(Outer { local_ip, dev, mtu })
}

fn run(mut cfg: Config) -> Result<(), String> {
    let main_wake = sys::eventfd().map_err(|e| format!("eventfd: {e}"))?;
    let main_wake_fd = main_wake.as_raw_fd();
    MAIN_WAKE.store(main_wake_fd, Ordering::Relaxed);
    sys::install_signal_handlers(on_signal).map_err(|e| format!("signal handlers: {e}"))?;
    let outer = resolve_outer(&cfg)?;
    let tun_mtu = cfg.resolve_tun_mtu(outer.mtu)?;
    let mss = (outer.mtu - cfg.outer_family.overhead() as u32) as u16;
    let listen_port = cfg.listen.unwrap_or(0);
    if cfg.transport == Transport::Tcp && cfg.base_port_explicit {
        log::warn!("tcp transport: explicitly configured base_port is ignored; kernel assigns source ports");
    }
    let n = usize::from(cfg.conns);
    let tuns = sys::create_tun(&cfg.tun_name, n)
        .map_err(|e| format!("creating TUN {}: {e}", cfg.tun_name))?;
    let ipv6 = netlink::configure_tun(&cfg.tun_name, tun_mtu, cfg.tun_ipv4, cfg.tun_ipv6)
        .map_err(|e| format!("configuring {}: {e}", cfg.tun_name))?;
    if !ipv6 {
        cfg.disable_inner_ipv6();
    }
    let outer_endpoint = match cfg.mode {
        Mode::Entry => format!(
            "outer {} -> {}",
            outer.local_ip,
            cfg.remote.expect("validated")
        ),
        Mode::Exit => format!("listen {}", SocketAddr::new(outer.local_ip, listen_port)),
    };
    let tun_addrs = match cfg.tun_ipv6 {
        Some(v6) => format!("{}, {v6}", cfg.tun_ipv4),
        None => cfg.tun_ipv4.to_string(),
    };
    log::info!(
        "{:?} {:?} mode: {} via {} (mtu {}), tun {} {} (mtu {}), {} conns",
        cfg.transport,
        cfg.mode,
        outer_endpoint,
        outer.dev.as_deref().unwrap_or("?"),
        outer.mtu,
        cfg.tun_name,
        tun_addrs,
        tun_mtu,
        cfg.conns
    );
    // Rules go in before sockets exist so the kernel never RSTs our first handshake.
    let guard = if cfg.netfilter {
        let spec = netfilter::NftSpec::from_config(&cfg, listen_port);
        Some(netfilter::install(&spec).map_err(|e| format!("netfilter: {e}"))?)
    } else {
        None
    };

    enum Start {
        Fake(Box<Session>, std::os::fd::OwnedFd, std::os::fd::OwnedFd),
        Tcp(Box<tcp::Worker>),
    }
    let listener = if cfg.transport == Transport::Tcp && cfg.mode == Mode::Exit {
        Some(tcp::Listener::bind(&cfg, tun_mtu as u16).map_err(|e| format!("tcp listener: {e}"))?)
    } else {
        None
    };
    let mut slots = Vec::with_capacity(n);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    for (i, tun) in tuns.into_iter().enumerate() {
        if cfg.transport == Transport::Tcp {
            slots.push(Start::Tcp(Box::new(tcp::Worker::new(
                i,
                cfg.clone(),
                tun_mtu as u16,
                tun,
                listener.as_ref(),
            ))));
            continue;
        }
        let id = i as u16;
        let filter = match cfg.mode {
            Mode::Entry => {
                faketcp::entry_filter(cfg.remote.expect("validated"), cfg.base_port, cfg.conns, id)
            }
            Mode::Exit => {
                faketcp::exit_filter(cfg.outer_family, cfg.listen_ip, listen_port, cfg.conns, id)
            }
        };
        let bind_dev = match cfg.mode {
            Mode::Entry => outer.dev.as_deref(),
            Mode::Exit => cfg.iface.as_deref(),
        };
        let entry_addresses = (cfg.mode == Mode::Entry)
            .then(|| (outer.local_ip, cfg.remote.expect("validated").ip()));
        let raw = sys::raw_socket(cfg.outer_family, bind_dev, &filter, entry_addresses)
            .map_err(|e| format!("raw socket: {e}"))?;
        let scfg = SessionConfig::from_config(&cfg, outer.local_ip, listen_port, id, mss);
        let session = Session::new(scfg, std::time::Instant::now(), seed ^ ((id as u64) << 48))
            .map_err(|e| format!("initializing worker {id} authentication: {e}"))?;
        slots.push(Start::Fake(Box::new(session), tun, raw));
    }
    let family = cfg.outer_family;
    let tun_io_uring = cfg.tun_io_uring;
    let default_cpus = sys::usable_cpus();
    let mut controls = Vec::with_capacity(n);
    let mut workers = Vec::with_capacity(n);
    for (i, start) in slots.into_iter().enumerate() {
        let cpu = worker::cpu_for(&cfg, &default_cpus, i);
        let ctrl = Arc::new(worker::Control::new(cpu, main_wake_fd));
        let worker_ctrl = Arc::clone(&ctrl);
        controls.push(ctrl);
        workers.push(
            std::thread::Builder::new()
                .name(format!("ghostun-w{i}"))
                .spawn(move || {
                    let _guard = worker::StopOnDrop(&STOP, main_wake_fd);
                    match start {
                        Start::Fake(session, tun, raw) => faketcp::run(
                            i,
                            family,
                            *session,
                            tun,
                            raw,
                            &STOP,
                            &worker_ctrl,
                            tun_io_uring,
                        ),
                        Start::Tcp(tcp) => tcp.run(&STOP, &worker_ctrl),
                    }
                })
                .expect("spawning worker thread"),
        );
    }

    let listener_wake = listener.as_ref().map(tcp::Listener::wake_fd);
    if let Some(listener) = listener {
        workers.push(
            listener
                .spawn(&STOP, main_wake_fd)
                .expect("spawning TCP accept thread"),
        );
    }
    let mut poll_fd = [sys::pollfd(main_wake_fd, libc::POLLIN)];
    let mut generation = 0u64;
    let mut rolling = None;
    while !STOP.load(Ordering::Relaxed) {
        sys::eventfd_drain(main_wake.as_fd());
        if RELOAD.swap(false, Ordering::Relaxed) {
            match cfg.reload() {
                Ok(next) if next == cfg && rolling.is_none() => {
                    log::info!("configuration reload: no changes");
                }
                Ok(next) => {
                    generation += 1;
                    log::info!("reloading configuration (generation {generation})");
                    cfg = next;
                    rolling =
                        RollingReload::start(&controls, &default_cpus, generation, cfg.clone());
                }
                Err(e) => log::error!("reload rejected: {e}"),
            }
        }
        RollingReload::advance(&controls, &default_cpus, &mut rolling);
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        if let Err(e) = sys::poll(&mut poll_fd, -1) {
            log::error!("main poll: {e}");
            break;
        }
    }
    STOP.store(true, Ordering::Relaxed);
    for ctrl in &controls {
        ctrl.wake();
    }
    if let Some(fd) = listener_wake {
        sys::eventfd_notify(fd);
    }
    for w in workers {
        if w.join().is_err() {
            log::error!("worker panicked");
        }
    }
    log::info!("shutting down");
    if let Some(guard) = guard {
        guard
            .remove()
            .map_err(|e| format!("removing netfilter table: {e}"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match config::load().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthKey;
    use crate::faketcp::Sink;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct Wire(Vec<Vec<u8>>);

    impl Sink for Wire {
        fn send(&mut self, frame: &[u8], _dst: IpAddr) {
            self.0.push(frame.to_vec());
        }
    }

    fn test_cfg(key_byte: u8, cpus: Option<&str>) -> Config {
        let path = std::env::temp_dir().join(format!(
            "ghostun-main-test-{}-{key_byte}.toml",
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

    #[test]
    fn rolling_reload_rotates_established_workers_sequentially_and_rolls_back_without_resetting_sibling(
    ) {
        let now = Instant::now();
        let default_cpus = vec![0, 1];
        let controls = vec![
            Arc::new(worker::Control::new(Some(0), -1)),
            Arc::new(worker::Control::new(Some(1), -1)),
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
            faketcp::sync_reload(
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
        let mut rolling =
            RollingReload::start(&controls, &default_cpus, 1, test_cfg(0xb8, Some("1")));
        let mut w0 = Wire::default();
        faketcp::sync_reload(
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
        faketcp::sync_reload(
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
        faketcp::sync_reload(
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
        faketcp::sync_reload(
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
            Arc::new(worker::Control::new(Some(0), -1)),
            Arc::new(worker::Control::new(Some(1), -1)),
        ];
        let mut exits = [
            make_session(Mode::Exit, 0, 0xa7, now),
            make_session(Mode::Exit, 1, 0xa7, now),
        ];
        let mut cpus = [Some(0), Some(1)];
        let mut gens = [0u64, 0u64];

        let mut rolling = RollingReload::start(&controls, &default_cpus, 1, test_cfg(0xc9, None));
        faketcp::sync_reload(
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
        faketcp::sync_reload(
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
}
