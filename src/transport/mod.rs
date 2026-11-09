//! Outer transports and the per-worker runtime they share: worker threads, rolling reload, shutdown.

pub mod budget;
mod control;
mod faketcp;
mod keepalive;
mod queue;
mod tcp;
mod tun_driver;
mod udp;

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

use crate::config::{Config, MAX_CONNS, Mode, OuterMode, Transport};
use crate::sys;
use control::{
    Control, CoreTable, ExitWorkerGuard, Reload, RollingReload, StopOnDrop, candidate_cpus,
};

/// Bytes reserved before an inner packet, including the concrete outer protocol header.
pub const fn overhead(transport: Transport, family: OuterMode) -> usize {
    let ip = match family {
        OuterMode::Ipv4 => crate::net::ipv4::HDR_LEN,
        OuterMode::Ipv6 | OuterMode::Mixed => crate::net::ipv6::HDR_LEN,
    };
    ip + match transport {
        Transport::Udp => udp::OVERHEAD,
        Transport::Faketcp | Transport::Tcp => crate::net::tcp::HDR_LEN,
    }
}

/// Per-remote outer route and connection count on Entry.
pub struct EntryRoute {
    pub remote: SocketAddr,
    pub local_ip: IpAddr,
    pub dev: String,
    pub conns: u16,
}

/// Outer addressing derived from config plus the routing table.
pub struct Outer {
    pub entry: Vec<EntryRoute>,
    pub dev: Option<String>,
    pub mtu: u32,
}

enum Start {
    Fake(Box<faketcp::Worker>),
    Tcp(Box<tcp::Worker>),
    Udp(Box<udp::Worker>),
}

impl Start {
    fn run(self, stop: &AtomicBool, ctrl: &Control) {
        match self {
            Self::Fake(worker) => worker.run(stop, ctrl),
            Self::Tcp(worker) => worker.run(stop, ctrl),
            Self::Udp(worker) => worker.run(stop, ctrl),
        }
    }
}

enum ExitDispatcher {
    Fake(faketcp::SharedExitState),
    Tcp(tcp::SharedExitState),
    Udp(udp::SharedExitState),
}

struct ExitSlot {
    ctrl: Arc<Control>,
    thread: JoinHandle<()>,
    cpu: Option<usize>,
    tuple: Option<(SocketAddr, SocketAddr)>,
    peer_label: String,
}

/// Manager state owning persistent Entry workers or dynamic Exit workers and the CPU binding table.
pub struct Running {
    cfg: Config,
    outer_mtu: u32,
    tun_mtu: u32,
    seed: u64,
    stop: &'static AtomicBool,
    main_wake: RawFd,
    default_cpus: Vec<usize>,
    core_table: CoreTable,
    entry_controls: Vec<Arc<Control>>,
    entry_cpus: Vec<Option<usize>>,
    entry_threads: Vec<JoinHandle<()>>,
    rolling: Option<RollingReload>,
    _anchor_tun: Option<OwnedFd>,
    exit_dispatcher: Option<ExitDispatcher>,
    listener_wake: Option<RawFd>,
    listener_thread: Option<JoinHandle<()>>,
    exit_workers: Vec<Option<ExitSlot>>,
    exit_reload_gen: Option<u64>,
    generation: u64,
}

/// Opens outer listener/entry sockets before spawning any thread, so a setup error leaves nothing running.
pub fn start(
    cfg: &Config,
    outer: &Outer,
    tun_mtu: u32,
    tuns: Vec<OwnedFd>,
    stop: &'static AtomicBool,
    main_wake: RawFd,
) -> Result<Running, String> {
    if cfg.transport != Transport::Faketcp && cfg.base_port_explicit {
        log::warn!(
            "{:?} transport: explicitly configured base_port is ignored; kernel assigns source ports",
            cfg.transport
        );
    }
    let default_cpus = sys::usable_cpus();
    let mut core_table = CoreTable::new(candidate_cpus(cfg, &default_cpus));
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    if cfg.mode == Mode::Entry {
        let mut starts = Vec::with_capacity(tuns.len());
        let mut tuns = tuns.into_iter();
        for route in &outer.entry {
            for _ in 0..route.conns {
                let i = starts.len();
                let tun = tuns.next().expect("TUN queue per entry connection");
                starts.push(match cfg.transport {
                    Transport::Udp => Start::Udp(Box::new(udp::Worker::new_entry(
                        i,
                        cfg,
                        route,
                        tun_mtu as u16,
                        tun,
                        seed,
                    )?)),
                    Transport::Tcp => Start::Tcp(Box::new(tcp::Worker::new_entry(
                        i,
                        cfg.clone(),
                        route.remote,
                        tun_mtu as u16,
                        tun,
                    ))),
                    Transport::Faketcp => Start::Fake(Box::new(faketcp::Worker::new_entry(
                        i, cfg, route, outer.mtu, tun, seed,
                    )?)),
                });
            }
        }
        let mut entry_controls = Vec::with_capacity(starts.len());
        let mut entry_cpus = Vec::with_capacity(starts.len());
        let mut entry_threads = Vec::with_capacity(starts.len());
        for (i, start) in starts.into_iter().enumerate() {
            let cpu = core_table.acquire();
            let ctrl = Arc::new(Control::new(cpu, main_wake));
            let worker_ctrl = Arc::clone(&ctrl);
            entry_cpus.push(cpu);
            entry_controls.push(ctrl);
            entry_threads.push(
                std::thread::Builder::new()
                    .name(format!("ghostun-w{i}"))
                    .spawn(move || {
                        let _guard = StopOnDrop(stop, main_wake);
                        start.run(stop, &worker_ctrl);
                    })
                    .expect("spawning worker thread"),
            );
        }
        return Ok(Running {
            cfg: cfg.clone(),
            outer_mtu: outer.mtu,
            tun_mtu,
            seed,
            stop,
            main_wake,
            default_cpus,
            core_table,
            entry_controls,
            entry_cpus,
            entry_threads,
            rolling: None,
            _anchor_tun: None,
            exit_dispatcher: None,
            listener_wake: None,
            listener_thread: None,
            exit_workers: Vec::new(),
            exit_reload_gen: None,
            generation: 0,
        });
    }

    let anchor_tun = tuns.into_iter().next();
    let (exit_dispatcher, listener_wake, listener_thread) = match cfg.transport {
        Transport::Udp => {
            let listener = udp::Listener::bind(cfg, tun_mtu as u16, main_wake)?;
            let wake = listener.wake_fd();
            let state = Arc::clone(&listener.state);
            let thread = listener
                .spawn(stop, main_wake)
                .expect("spawning UDP accept thread");
            (ExitDispatcher::Udp(state), wake, thread)
        }
        Transport::Tcp => {
            let listener = tcp::Listener::bind(cfg, tun_mtu as u16, main_wake)
                .map_err(|e| format!("tcp listener: {e}"))?;
            let wake = listener.wake_fd();
            let state = Arc::clone(&listener.state);
            let thread = listener
                .spawn(stop, main_wake)
                .expect("spawning TCP accept thread");
            (ExitDispatcher::Tcp(state), wake, thread)
        }
        Transport::Faketcp => {
            let listener = faketcp::Listener::bind(cfg, outer.mtu, seed, main_wake)?;
            let wake = listener.wake_fd();
            let state = Arc::clone(&listener.state);
            let thread = listener
                .spawn(stop, main_wake)
                .expect("spawning FakeTCP accept thread");
            (ExitDispatcher::Fake(state), wake, thread)
        }
    };
    Ok(Running {
        cfg: cfg.clone(),
        outer_mtu: outer.mtu,
        tun_mtu,
        seed,
        stop,
        main_wake,
        default_cpus,
        core_table,
        entry_controls: Vec::new(),
        entry_cpus: Vec::new(),
        entry_threads: Vec::new(),
        rolling: None,
        _anchor_tun: anchor_tun,
        exit_dispatcher: Some(exit_dispatcher),
        listener_wake: Some(listener_wake),
        listener_thread: Some(listener_thread),
        exit_workers: (0..MAX_CONNS).map(|_| None).collect(),
        exit_reload_gen: None,
        generation: 0,
    })
}

impl Running {
    pub fn is_reloading(&self) -> bool {
        self.rolling.is_some() || self.exit_reload_gen.is_some()
    }

    fn reap_exited_workers(&mut self) {
        for slot in &mut self.exit_workers {
            if slot.as_ref().is_some_and(|s| s.ctrl.is_exited()) {
                let finished = slot.take().unwrap();
                let _ = finished.thread.join();
                self.core_table.release(finished.cpu);
            }
        }
    }

    fn replace_exit_slot(&mut self, id: usize, new_tuple: Option<(SocketAddr, SocketAddr)>) {
        if let Some(old) = self.exit_workers[id].take() {
            let send_rst = match (old.tuple, new_tuple) {
                (Some(old_t), Some(new_t)) => old_t != new_t,
                _ => true,
            };
            if !old.ctrl.is_exited() {
                log::info!(
                    "worker {id}: authenticated takeover, closing {}",
                    old.peer_label
                );
            }
            old.ctrl.stop(send_rst);
            let _ = old.thread.join();
            self.core_table.release(old.cpu);
        }
    }

    fn spawn_exit_slot(
        &mut self,
        id: usize,
        tuple: Option<(SocketAddr, SocketAddr)>,
        peer_label: String,
        build: impl FnOnce(&Self, OwnedFd) -> Result<Start, String>,
    ) {
        self.replace_exit_slot(id, tuple);
        let tun = match sys::tun::open_queue(&self.cfg.tun_name) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!("worker {id}: opening TUN queue {}: {e}", self.cfg.tun_name);
                return;
            }
        };
        let start = match build(self, tun) {
            Ok(start) => start,
            Err(e) => {
                log::error!("worker {id}: {e}");
                return;
            }
        };
        let cpu = self.core_table.acquire();
        let ctrl = Arc::new(Control::new(cpu, self.main_wake));
        let worker_ctrl = Arc::clone(&ctrl);
        let stop = self.stop;
        let main_wake = self.main_wake;
        let thread = std::thread::Builder::new()
            .name(format!("ghostun-w{id}"))
            .spawn(move || {
                let _guard = ExitWorkerGuard {
                    stop,
                    ctrl: Arc::clone(&worker_ctrl),
                    main_wake,
                };
                start.run(stop, &worker_ctrl);
            })
            .expect("spawning exit worker thread");
        self.exit_workers[id] = Some(ExitSlot {
            ctrl,
            thread,
            cpu,
            tuple,
            peer_label,
        });
    }

    /// Starts a reload to `cfg`, superseding any reload still in progress.
    pub fn reload(&mut self, cfg: Config) {
        self.generation += 1;
        log::info!("reloading configuration (generation {})", self.generation);
        if self.cfg.mode == Mode::Entry {
            if cfg.tunables.cpus != self.cfg.tunables.cpus {
                self.core_table = CoreTable::new(candidate_cpus(&cfg, &self.default_cpus));
                self.entry_cpus = (0..self.entry_controls.len())
                    .map(|_| self.core_table.acquire())
                    .collect();
            }
            self.cfg = cfg.clone();
            self.rolling = RollingReload::start(
                &self.entry_controls,
                self.entry_cpus.clone(),
                self.generation,
                cfg.tunables,
            );
            return;
        }

        let key_changed = self.cfg.tunables.auth_key != cfg.tunables.auth_key;
        let cpus_changed = self.cfg.tunables.cpus != cfg.tunables.cpus;
        self.cfg = cfg.clone();
        match &self.exit_dispatcher {
            Some(ExitDispatcher::Udp(state)) => {
                let mut s = state.lock().unwrap();
                if key_changed {
                    s.key = cfg.tunables.auth_key.clone();
                    s.epoch += 1;
                    s.admitted.clear();
                }
                s.timeout = cfg.tunables.dead_timeout;
            }
            Some(ExitDispatcher::Tcp(state)) => {
                let mut s = state.lock().unwrap();
                if key_changed {
                    s.key = cfg.tunables.auth_key.clone();
                    s.epoch += 1;
                    s.admitted.clear();
                }
                s.timeout = cfg.tunables.dead_timeout;
            }
            Some(ExitDispatcher::Fake(state)) => {
                let mut s = state.lock().unwrap();
                if key_changed {
                    s.key = cfg.tunables.auth_key.clone();
                    s.epoch += 1;
                    s.admitted.clear();
                }
                s.timeout = cfg.tunables.dead_timeout;
            }
            None => {}
        }
        if let Some(fd) = self.listener_wake {
            sys::eventfd_notify(fd);
        }
        self.reap_exited_workers();
        if key_changed {
            for slot in &mut self.exit_workers {
                if let Some(old) = slot.take() {
                    old.ctrl.stop(true);
                    let _ = old.thread.join();
                    self.core_table.release(old.cpu);
                }
            }
            if cpus_changed {
                self.core_table = CoreTable::new(candidate_cpus(&self.cfg, &self.default_cpus));
            }
            self.exit_reload_gen = None;
            log::info!(
                "configuration reload complete (generation {})",
                self.generation
            );
        } else {
            if cpus_changed {
                self.core_table = CoreTable::new(candidate_cpus(&self.cfg, &self.default_cpus));
                for slot in self.exit_workers.iter_mut().flatten() {
                    slot.cpu = self.core_table.acquire();
                }
            }
            for slot in self.exit_workers.iter().flatten() {
                slot.ctrl.publish(
                    self.generation,
                    Reload {
                        tunables: self.cfg.tunables.clone(),
                        cpu: slot.cpu,
                    },
                );
            }
            self.exit_reload_gen = Some(self.generation);
            self.advance();
        }
    }

    /// Reaps exited workers, spawns newly admitted Exit workers, and advances active reloads.
    pub fn advance(&mut self) {
        if self.cfg.mode == Mode::Entry {
            RollingReload::advance(&self.entry_controls, &mut self.rolling);
            return;
        }
        self.reap_exited_workers();
        match self.exit_dispatcher.as_ref() {
            Some(ExitDispatcher::Udp(state)) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admitted.pop_front();
                    let Some(promo) = next else { break };
                    let id = promo.worker;
                    let tuple = Some((promo.local, promo.peer));
                    let peer_label = format!("{} <-> {}", promo.local, promo.peer);
                    let worker_state = Arc::clone(&state);
                    self.spawn_exit_slot(id, tuple, peer_label, |this, tun| {
                        udp::Worker::new_exit(
                            id,
                            &this.cfg,
                            this.tun_mtu as u16,
                            tun,
                            promo,
                            worker_state,
                            this.seed,
                        )
                        .map(|w| Start::Udp(Box::new(w)))
                    });
                }
            }
            Some(ExitDispatcher::Tcp(state)) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admitted.pop_front();
                    let Some((id, conn)) = next else { break };
                    let peer_label = conn.to_string();
                    self.spawn_exit_slot(id, None, peer_label, |this, tun| {
                        Ok(Start::Tcp(Box::new(tcp::Worker::new_exit(
                            id,
                            this.cfg.clone(),
                            this.tun_mtu as u16,
                            tun,
                            conn,
                        ))))
                    });
                }
            }
            Some(ExitDispatcher::Fake(state)) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admitted.pop_front();
                    let Some(promo) = next else { break };
                    let id = promo.worker;
                    let tuple = Some((promo.local, promo.peer));
                    let peer_label = format!("{} <-> {}", promo.local, promo.peer);
                    let worker_state = Arc::clone(&state);
                    self.spawn_exit_slot(id, tuple, peer_label, |this, tun| {
                        faketcp::Worker::new_exit(
                            id,
                            &this.cfg,
                            this.outer_mtu,
                            tun,
                            promo,
                            worker_state,
                            this.seed,
                        )
                        .map(|w| Start::Fake(Box::new(w)))
                    });
                }
            }
            None => {}
        }
        if let Some(generation) = self.exit_reload_gen
            && self
                .exit_workers
                .iter()
                .flatten()
                .all(|s| s.ctrl.is_step_complete(generation))
        {
            log::info!("configuration reload complete (generation {generation})");
            self.exit_reload_gen = None;
        }
    }

    /// Wakes every thread to observe `stop`, which the caller has set, and joins them.
    pub fn join(self) {
        for ctrl in &self.entry_controls {
            ctrl.wake();
        }
        for slot in self.exit_workers.iter().flatten() {
            slot.ctrl.stop(true);
        }
        if let Some(fd) = self.listener_wake {
            sys::eventfd_notify(fd);
        }
        for thread in self.entry_threads {
            if thread.join().is_err() {
                log::error!("worker panicked");
            }
        }
        for slot in self.exit_workers.into_iter().flatten() {
            if slot.thread.join().is_err() {
                log::error!("worker panicked");
            }
        }
        if let Some(thread) = self.listener_thread
            && thread.join().is_err()
        {
            log::error!("listener panicked");
        }
    }
}
