mod auth;
mod config;
mod netfilter;
mod pkt;
mod session;
mod sys;
mod worker;

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use config::{Config, Mode};
use session::{Session, SessionConfig};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() -> std::io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
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
        "{:?} mode: outer {} via {} (mtu {}), tun {} mtu {}, {} conns",
        cfg.mode,
        outer.local_ip,
        outer.dev.as_deref().unwrap_or("?"),
        outer.mtu,
        cfg.tun_name,
        tun_mtu,
        cfg.conns
    );

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
        cfg.tun_ipv6 = None;
    }

    // Rules go in before sockets exist so the kernel never RSTs our first handshake.
    let guard = if cfg.netfilter {
        let spec = netfilter::NftSpec {
            mode: cfg.mode,
            outer_family: cfg.outer_family,
            tun_name: cfg.tun_name.clone(),
            remote: cfg.remote,
            base_port: cfg.base_port,
            listen_port,
            inner_v4: cfg.tun_ipv4,
            inner_v6: cfg.tun_ipv6,
            out_iface: cfg.iface.clone(),
        };
        Some(netfilter::install(&spec).map_err(|e| format!("netfilter: {e}"))?)
    } else {
        None
    };

    let mut slots = Vec::with_capacity(n);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    for (i, tun) in tuns.into_iter().enumerate() {
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
        slots.push((session, tun, raw));
    }
    let family = cfg.outer_family;
    let cpus = cfg.cpus.as_deref();
    let workers: Vec<_> = slots
        .into_iter()
        .enumerate()
        .map(|(i, (session, tun, raw))| {
            let cpu = cpus.map(|list| list[i % list.len()]);
            std::thread::Builder::new()
                .name(format!("ghostun-w{i}"))
                .spawn(move || worker::run(i, cpu, family, session, tun, raw, &STOP))
                .expect("spawning worker thread")
        })
        .collect();

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
