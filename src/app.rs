//! Process runtime: TUN and netfilter setup, signals, and the reload/shutdown loop around the transport.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::config::{Config, Mode};
use crate::netfilter;
use crate::platform::{self, route};
use crate::transport::{self, EntryRoute, Outer, budget};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static MAIN_WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::Relaxed);
    } else {
        STOP.store(true, Ordering::Relaxed);
    }
    platform::eventfd_notify(MAIN_WAKE.load(Ordering::Relaxed));
}

fn interface_mtu(dev: &str) -> u32 {
    platform::iface_mtu(dev).unwrap_or_else(|e| {
        log::warn!("cannot read MTU of {dev} ({e}), assuming 1500");
        1500
    })
}

fn resolve_outer(cfg: &Config) -> Result<Outer, String> {
    let mut entry = Vec::with_capacity(cfg.remote.len());
    let mut devs = Vec::new();
    if cfg.mode == Mode::Entry {
        for r in &cfg.remote {
            let route = route::route_to(r.address.ip(), cfg.iface.as_deref())
                .map_err(|e| format!("route to {}: {e}", r.address))?;
            if !devs.contains(&route.dev) {
                devs.push(route.dev.clone());
            }
            entry.push(EntryRoute {
                remote: r.address,
                local_ip: route.src,
                dev: route.dev,
                conns: r.conns,
            });
        }
    } else {
        for &family in cfg.socket_families() {
            if let Some(dev) = cfg
                .iface
                .clone()
                .or_else(|| route::default_route_dev(family).ok())
                && !devs.contains(&dev)
            {
                devs.push(dev);
            }
        }
    }
    let mtu = cfg.outer_mtu.unwrap_or_else(|| {
        devs.iter()
            .map(|dev| interface_mtu(dev))
            .min()
            .unwrap_or_else(|| {
                log::warn!("no egress interface found, assuming outer MTU 1500");
                1500
            })
    });
    Ok(Outer {
        entry,
        dev: (!devs.is_empty()).then(|| devs.join(",")),
        mtu,
    })
}

pub fn run(mut cfg: Config) -> Result<(), String> {
    let main_wake = platform::eventfd().map_err(|e| format!("eventfd: {e}"))?;
    let main_wake_fd = main_wake.as_raw_fd();
    MAIN_WAKE.store(main_wake_fd, Ordering::Relaxed);
    platform::install_signal_handlers(on_signal).map_err(|e| format!("signal handlers: {e}"))?;
    let outer = resolve_outer(&cfg)?;
    let tun_mtu = cfg.resolve_tun_mtu(outer.mtu)?;
    let listen_port = cfg.listen.unwrap_or(0);
    let queues = match cfg.mode {
        Mode::Entry => usize::from(cfg.conns),
        Mode::Exit => 1,
    };
    let tuns = platform::tun::create(&cfg.tun_name, queues)
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
            "outer {}",
            outer
                .entry
                .iter()
                .map(|e| format!("{} -> {} ({})", e.local_ip, e.remote, e.conns))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Mode::Exit => format!(
            "listen {}",
            cfg.socket_families()
                .iter()
                .map(|family| {
                    SocketAddr::new(
                        cfg.listen_ip.unwrap_or_else(|| family.unspecified()),
                        listen_port,
                    )
                    .to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let tun_addrs = match cfg.tun_ipv6 {
        Some(v6) => format!("{}, {v6}", cfg.tun_ipv4),
        None => cfg.tun_ipv4.to_string(),
    };
    let conns_suffix = match cfg.mode {
        Mode::Entry => format!(", {} conns", cfg.conns),
        Mode::Exit => String::new(),
    };
    log::info!(
        "{:?} {:?} mode: {outer_endpoint} via {} (mtu {}), tun {} {tun_addrs} (mtu {tun_mtu}){conns_suffix}",
        cfg.transport,
        cfg.mode,
        outer.dev.as_deref().unwrap_or("?"),
        outer.mtu,
        cfg.tun_name,
    );
    // Rules go in before sockets exist so the kernel never RSTs our first handshake.
    let guard = if cfg.netfilter {
        let spec = netfilter::NftSpec::from_config(&cfg, listen_port);
        Some(netfilter::install(&spec).map_err(|e| format!("netfilter: {e}"))?)
    } else {
        None
    };

    let mut running = transport::start(&cfg, &outer, tun_mtu, tuns, &STOP, main_wake_fd)?;
    let mut poll_fd = [platform::pollfd(main_wake_fd, libc::POLLIN)];
    while !STOP.load(Ordering::Relaxed) {
        platform::eventfd_drain(main_wake.as_fd());
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
        if let Err(e) = platform::poll(&mut poll_fd, -1) {
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
