//! Outer transports and the per-worker runtime they share: worker threads, rolling reload, shutdown.

pub mod budget;
mod control;
mod faketcp;
mod keepalive;
mod tcp;

use std::net::IpAddr;
use std::os::fd::{OwnedFd, RawFd};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::config::{Config, Mode, Transport};
use crate::sys;
use control::{Control, RollingReload, StopOnDrop};

/// Outer addressing derived from config plus the routing table.
pub struct Outer {
    /// Entry source address. The exit learns its address from each incoming SYN instead.
    pub local_ip: IpAddr,
    pub dev: Option<String>,
    pub mtu: u32,
}

enum Start {
    Fake(Box<faketcp::Worker>),
    Tcp(Box<tcp::Worker>),
}

/// Running worker threads, one per TUN queue, plus the exit TCP accept thread.
pub struct Running {
    controls: Vec<Arc<Control>>,
    threads: Vec<JoinHandle<()>>,
    listener_wake: Option<RawFd>,
    default_cpus: Vec<usize>,
    generation: u64,
    rolling: Option<RollingReload>,
}

/// Opens every outer socket before spawning any thread, so a setup error leaves nothing running.
/// Any thread that exits sets `stop` and notifies `main_wake`.
pub fn start(
    cfg: &Config,
    outer: &Outer,
    tun_mtu: u32,
    tuns: Vec<OwnedFd>,
    stop: &'static AtomicBool,
    main_wake: RawFd,
) -> Result<Running, String> {
    if cfg.transport == Transport::Tcp && cfg.base_port_explicit {
        log::warn!("tcp transport: explicitly configured base_port is ignored; kernel assigns source ports");
    }
    let listener = if cfg.transport == Transport::Tcp && cfg.mode == Mode::Exit {
        Some(tcp::Listener::bind(cfg, tun_mtu as u16).map_err(|e| format!("tcp listener: {e}"))?)
    } else {
        None
    };
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut starts = Vec::with_capacity(tuns.len());
    for (i, tun) in tuns.into_iter().enumerate() {
        starts.push(match cfg.transport {
            Transport::Tcp => Start::Tcp(Box::new(tcp::Worker::new(
                i,
                cfg.clone(),
                tun_mtu as u16,
                tun,
                listener.as_ref(),
            ))),
            Transport::Faketcp => Start::Fake(Box::new(faketcp::Worker::new(
                i,
                cfg,
                outer.local_ip,
                outer.dev.as_deref(),
                outer.mtu,
                tun,
                seed,
            )?)),
        });
    }
    let default_cpus = sys::usable_cpus();
    let mut controls = Vec::with_capacity(starts.len());
    let mut threads = Vec::with_capacity(starts.len() + 1);
    for (i, start) in starts.into_iter().enumerate() {
        let cpu = control::cpu_for(cfg, &default_cpus, i);
        let ctrl = Arc::new(Control::new(cpu, main_wake));
        let worker_ctrl = Arc::clone(&ctrl);
        controls.push(ctrl);
        threads.push(
            std::thread::Builder::new()
                .name(format!("ghostun-w{i}"))
                .spawn(move || {
                    let _guard = StopOnDrop(stop, main_wake);
                    match start {
                        Start::Fake(worker) => worker.run(stop, &worker_ctrl),
                        Start::Tcp(worker) => worker.run(stop, &worker_ctrl),
                    }
                })
                .expect("spawning worker thread"),
        );
    }
    let listener_wake = listener.as_ref().map(tcp::Listener::wake_fd);
    if let Some(listener) = listener {
        threads.push(
            listener
                .spawn(stop, main_wake)
                .expect("spawning TCP accept thread"),
        );
    }
    Ok(Running {
        controls,
        threads,
        listener_wake,
        default_cpus,
        generation: 0,
        rolling: None,
    })
}

impl Running {
    pub fn is_reloading(&self) -> bool {
        self.rolling.is_some()
    }

    /// Starts a rolling reload to `cfg`, superseding any reload still in progress.
    pub fn reload(&mut self, cfg: Config) {
        self.generation += 1;
        log::info!("reloading configuration (generation {})", self.generation);
        self.rolling =
            RollingReload::start(&self.controls, &self.default_cpus, self.generation, cfg);
    }

    /// Moves the rolling reload to the next worker once the current one has applied it.
    pub fn advance(&mut self) {
        RollingReload::advance(&self.controls, &self.default_cpus, &mut self.rolling);
    }

    /// Wakes every thread to observe `stop`, which the caller has set, and joins them.
    pub fn join(self) {
        for ctrl in &self.controls {
            ctrl.wake();
        }
        if let Some(fd) = self.listener_wake {
            sys::eventfd_notify(fd);
        }
        for thread in self.threads {
            if thread.join().is_err() {
                log::error!("worker panicked");
            }
        }
    }
}
