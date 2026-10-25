mod auth;
mod config;
mod faketcp;
mod netfilter;
mod pkt;
mod sys;
mod tcp;
mod worker;

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use config::{Config, Mode, Transport};
use faketcp::{Session, SessionConfig};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::Relaxed);
    } else {
        STOP.store(true, Ordering::Relaxed);
    }
}

fn install_signal_handlers() -> std::io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
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
            let route = sys::route_to(remote.ip(), cfg.iface.as_deref())
                .map_err(|e| format!("route to {remote}: {e}"))?;
            (route.src, Some(route.dev))
        }
        _ => (
            cfg.outer_family.unspecified(),
            cfg.iface
                .clone()
                .or_else(|| sys::default_route_dev(cfg.outer_family).ok()),
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
    install_signal_handlers().map_err(|e| format!("signal handlers: {e}"))?;
    let outer = resolve_outer(&cfg)?;
    let tun_mtu = cfg.resolve_tun_mtu(outer.mtu)?;
    let mss = (outer.mtu - cfg.outer_family.overhead() as u32) as u16;
    let listen_port = cfg.listen.unwrap_or(0);
    log::info!(
        "{:?} {:?} mode: outer {} via {} (mtu {}), tun {} mtu {}, {} conns",
        cfg.transport,
        cfg.mode,
        outer.local_ip,
        outer.dev.as_deref().unwrap_or("?"),
        outer.mtu,
        cfg.tun_name,
        tun_mtu,
        cfg.conns
    );

    if cfg.transport == Transport::Tcp && cfg.base_port_explicit {
        log::warn!("tcp transport: explicitly configured base_port is ignored; kernel assigns source ports");
    }
    let n = usize::from(cfg.conns);
    let tuns = sys::create_tun(&cfg.tun_name, n)
        .map_err(|e| format!("creating TUN {}: {e}", cfg.tun_name))?;
    let v6 = cfg.tun_ipv6.map(|c| c.to_string());
    let ipv6 = sys::configure_tun(
        &cfg.tun_name,
        tun_mtu,
        &cfg.tun_ipv4.to_string(),
        v6.as_deref(),
    )
    .map_err(|e| format!("configuring {}: {e}", cfg.tun_name))?;
    if !ipv6 {
        cfg.disable_inner_ipv6();
    }

    // Rules go in before sockets exist so the kernel never RSTs our first handshake.
    let guard = if cfg.netfilter {
        let spec = netfilter::NftSpec {
            mode: cfg.mode,
            transport: cfg.transport,
            outer_family: cfg.outer_family,
            tun_name: cfg.tun_name.clone(),
            remote: cfg.remote,
            base_port: cfg.base_port,
            listen_port,
            inner_v4: cfg.tun_ipv4,
            inner_v6: cfg.tun_ipv6,
            out_iface: cfg.iface.clone(),
            masq: cfg.masq,
        };
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
                pkt::entry_filter(cfg.remote.expect("validated"), cfg.base_port, cfg.conns, id)
            }
            Mode::Exit => pkt::exit_filter(cfg.outer_family, listen_port, cfg.conns, id),
        };
        let bind_dev = (cfg.mode == Mode::Entry)
            .then_some(outer.dev.as_deref())
            .flatten();
        let raw = sys::raw_socket(cfg.outer_family, bind_dev, &filter)
            .map_err(|e| format!("raw socket: {e}"))?;
        let scfg = SessionConfig {
            mode: cfg.mode,
            auth_key: cfg.auth_key.clone(),
            local_ip: outer.local_ip,
            remote: cfg.remote,
            listen_port,
            worker: id,
            conns: cfg.conns,
            base_port: cfg.base_port,
            mss,
            ping_interval: cfg.ping_interval,
            dead_timeout: cfg.dead_timeout,
        };
        let session = Session::new(scfg, std::time::Instant::now(), seed ^ ((id as u64) << 48))
            .map_err(|e| format!("initializing worker {id} authentication: {e}"))?;
        slots.push(Start::Fake(Box::new(session), tun, raw));
    }
    let family = cfg.outer_family;
    let default_cpus = sys::usable_cpus();
    let mut controls = Vec::with_capacity(n);
    let mut workers = Vec::with_capacity(n);
    for (i, start) in slots.into_iter().enumerate() {
        let cpu = cpu_for(&cfg, &default_cpus, i);
        let ctrl = Arc::new(worker::Control::new(cpu));
        let worker_ctrl = Arc::clone(&ctrl);
        controls.push(ctrl);
        workers.push(
            std::thread::Builder::new()
                .name(format!("ghostun-w{i}"))
                .spawn(move || match start {
                    Start::Fake(session, tun, raw) => {
                        worker::run(i, family, *session, tun, raw, &STOP, &worker_ctrl)
                    }
                    Start::Tcp(tcp) => tcp.run(&STOP, &worker_ctrl),
                })
                .expect("spawning worker thread"),
        );
    }

    if let Some(listener) = listener {
        workers.push(listener.spawn(&STOP).expect("spawning TCP accept thread"));
    }
    let mut generation = 0u64;
    let mut rolling = None;
    while !STOP.load(Ordering::Relaxed) {
        if RELOAD.swap(false, Ordering::Relaxed) {
            match cfg.reload() {
                Ok(next) if next == cfg && rolling.is_none() => {
                    log::info!("configuration reload: no changes");
                }
                Ok(next) => {
                    generation += 1;
                    log::info!("reloading configuration (generation {generation})");
                    cfg = next;
                    rolling = start_reload(&controls, &default_cpus, generation, cfg.clone());
                }
                Err(e) => log::error!("reload rejected: {e}"),
            }
        }
        advance_reload(&controls, &default_cpus, &mut rolling);
        if workers.iter().any(|w| w.is_finished()) {
            STOP.store(true, Ordering::Relaxed);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
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

struct RollingReload {
    generation: u64,
    next_worker: usize,
    target: Config,
}

fn cpu_for(cfg: &Config, default_cpus: &[usize], id: usize) -> Option<usize> {
    let list = cfg.cpus.as_deref().unwrap_or(default_cpus);
    (!list.is_empty()).then(|| list[id % list.len()])
}

fn reload_for(cfg: &Config, default_cpus: &[usize], id: usize) -> worker::Reload {
    worker::Reload {
        auth_key: cfg.auth_key.clone(),
        ping_interval: cfg.ping_interval,
        dead_timeout: cfg.dead_timeout,
        cpu: cpu_for(cfg, default_cpus, id),
    }
}

fn start_reload(
    controls: &[Arc<worker::Control>],
    default_cpus: &[usize],
    generation: u64,
    target: Config,
) -> Option<RollingReload> {
    let first = controls.first()?;
    first.publish(generation, reload_for(&target, default_cpus, 0));
    Some(RollingReload {
        generation,
        next_worker: 0,
        target,
    })
}

fn advance_reload(
    controls: &[Arc<worker::Control>],
    default_cpus: &[usize],
    rolling: &mut Option<RollingReload>,
) {
    while let Some(state) = rolling.as_mut() {
        if !controls[state.next_worker].is_step_complete(state.generation) {
            break;
        }
        state.next_worker += 1;
        if state.next_worker < controls.len() {
            controls[state.next_worker].publish(
                state.generation,
                reload_for(&state.target, default_cpus, state.next_worker),
            );
        } else {
            log::info!(
                "configuration reload complete (generation {})",
                state.generation
            );
            *rolling = None;
        }
    }
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
    use std::time::Instant;

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
            Arc::new(worker::Control::new(Some(0))),
            Arc::new(worker::Control::new(Some(1))),
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
            controls[i].sync(i, &mut cpus[i], &mut gens[i], now, &mut entries[i], &mut w);
        }

        // Start reload to a wrong key (0xb8) while exits still use 0xa7: worker 0 rotates and
        // waits for Established; worker 1 is not touched and keeps forwarding inner packets.
        let mut rolling = start_reload(&controls, &default_cpus, 1, test_cfg(0xb8, Some("1")));
        let mut w0 = Wire::default();
        controls[0].sync(0, &mut cpus[0], &mut gens[0], now, &mut entries[0], &mut w0);
        assert_eq!(cpus[0], Some(1));
        exchange(&mut entries[0], &mut exits[0], now, w0.0);
        assert!(!entries[0].is_established());
        advance_reload(&controls, &default_cpus, &mut rolling);
        assert_eq!(rolling.as_ref().unwrap().next_worker, 0);
        assert!(entries[1].is_established());

        // Rollback SIGHUP (generation 2) restores key 0xa7 and removes explicit cpus override:
        // worker 0 restores default CPU 0 and re-establishes; worker 1 sees unchanged key 0xa7
        // and completes without emitting any RST or SYN frames.
        rolling = start_reload(&controls, &default_cpus, 2, test_cfg(0xa7, None));
        let mut w0 = Wire::default();
        controls[0].sync(0, &mut cpus[0], &mut gens[0], now, &mut entries[0], &mut w0);
        assert_eq!(cpus[0], Some(0));
        exchange(&mut entries[0], &mut exits[0], now, w0.0);
        assert!(entries[0].is_established());
        controls[0].sync(
            0,
            &mut cpus[0],
            &mut gens[0],
            now,
            &mut entries[0],
            &mut Wire::default(),
        );
        advance_reload(&controls, &default_cpus, &mut rolling);
        assert_eq!(rolling.as_ref().unwrap().next_worker, 1);

        let mut w1 = Wire::default();
        controls[1].sync(1, &mut cpus[1], &mut gens[1], now, &mut entries[1], &mut w1);
        assert!(
            w1.0.is_empty(),
            "unchanged key on worker 1 must not reset its session"
        );
        assert!(entries[1].is_established());
        advance_reload(&controls, &default_cpus, &mut rolling);
        assert!(rolling.is_none());
    }

    #[test]
    fn rolling_reload_fast_forwards_unestablished_workers() {
        let now = Instant::now();
        let default_cpus = vec![0, 1];
        let controls = vec![
            Arc::new(worker::Control::new(Some(0))),
            Arc::new(worker::Control::new(Some(1))),
        ];
        let mut exits = [
            make_session(Mode::Exit, 0, 0xa7, now),
            make_session(Mode::Exit, 1, 0xa7, now),
        ];
        let mut cpus = [Some(0), Some(1)];
        let mut gens = [0u64, 0u64];

        let mut rolling = start_reload(&controls, &default_cpus, 1, test_cfg(0xc9, None));
        controls[0].sync(
            0,
            &mut cpus[0],
            &mut gens[0],
            now,
            &mut exits[0],
            &mut Wire::default(),
        );
        advance_reload(&controls, &default_cpus, &mut rolling);
        assert_eq!(rolling.as_ref().unwrap().next_worker, 1);
        controls[1].sync(
            1,
            &mut cpus[1],
            &mut gens[1],
            now,
            &mut exits[1],
            &mut Wire::default(),
        );
        advance_reload(&controls, &default_cpus, &mut rolling);
        assert!(rolling.is_none());
    }
}
