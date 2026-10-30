//! Process runtime: TUN and netfilter setup, signals, and the reload/shutdown loop around the transport.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::config::{Config, Mode};
use crate::netfilter;
use crate::sys::{self, route};
use crate::transport::{self, budget, Outer};

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

fn resolve_outer(cfg: &Config) -> Result<Outer, String> {
    let (local_ip, dev) = match (cfg.mode, cfg.remote) {
        (Mode::Entry, Some(remote)) => {
            let route = route::route_to(remote.ip(), cfg.iface.as_deref())
                .map_err(|e| format!("route to {remote}: {e}"))?;
            (route.src, Some(route.dev))
        }
        _ => (
            cfg.exit_ip(),
            cfg.iface
                .clone()
                .or_else(|| route::default_route_dev(cfg.outer_family).ok()),
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

pub fn run(mut cfg: Config) -> Result<(), String> {
    let main_wake = sys::eventfd().map_err(|e| format!("eventfd: {e}"))?;
    let main_wake_fd = main_wake.as_raw_fd();
    MAIN_WAKE.store(main_wake_fd, Ordering::Relaxed);
    sys::install_signal_handlers(on_signal).map_err(|e| format!("signal handlers: {e}"))?;
    let outer = resolve_outer(&cfg)?;
    let tun_mtu = cfg.resolve_tun_mtu(outer.mtu)?;
    let listen_port = cfg.listen.unwrap_or(0);
    let n = usize::from(cfg.conns);
    let tuns = sys::tun::create(&cfg.tun_name, n)
        .map_err(|e| format!("creating TUN {}: {e}", cfg.tun_name))?;
    let ipv6 = route::configure_tun(
        &cfg.tun_name,
        tun_mtu,
        budget::tun_packets(tun_mtu),
        cfg.tun_ipv4,
        cfg.tun_ipv6,
    )
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

    let mut running = transport::start(&cfg, &outer, tun_mtu, tuns, &STOP, main_wake_fd)?;
    let mut poll_fd = [sys::pollfd(main_wake_fd, libc::POLLIN)];
    while !STOP.load(Ordering::Relaxed) {
        sys::eventfd_drain(main_wake.as_fd());
        if RELOAD.swap(false, Ordering::Relaxed) {
            match cfg.reload() {
                Ok(next) if next == cfg && !running.is_reloading() => {
                    log::info!("configuration reload: no changes");
                }
                Ok(next) => {
                    cfg = next;
                    running.reload(cfg.clone());
                }
                Err(e) => log::error!("reload rejected: {e}"),
            }
        }
        running.advance();
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        if let Err(e) = sys::poll(&mut poll_fd, -1) {
            log::error!("main poll: {e}");
            break;
        }
    }
    STOP.store(true, Ordering::Relaxed);
    running.join();
    log::info!("shutting down");
    if let Some(guard) = guard {
        guard
            .remove()
            .map_err(|e| format!("removing netfilter table: {e}"))?;
    }
    Ok(())
}
