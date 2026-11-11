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

use crate::config::{Config, MAX_CONNS, Mode, OuterMode, Transport, Tunables};
use crate::platform;
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

impl ExitDispatcher {
    fn reload(&self, tunables: &Tunables, key_changed: bool) {
        match self {
            Self::Fake(state) => state
                .lock()
                .unwrap()
                .admission
                .reload(tunables, key_changed),
            Self::Tcp(state) => state.lock().unwrap().reload(tunables, key_changed),
            Self::Udp(state) => state
                .lock()
                .unwrap()
                .admission
                .reload(tunables, key_changed),
        }
    }
}

struct ExitSlot {
    ctrl: Arc<Control>,
    thread: JoinHandle<()>,
    cpu: Option<usize>,
    tuple: Option<(SocketAddr, SocketAddr)>,
    peer_label: String,
}

/// Manager state both modes need to spawn and reload workers.
struct Shared {
    cfg: Config,
    outer_mtu: u32,
    tun_mtu: u32,
    seed: u64,
    stop: &'static AtomicBool,
    main_wake: RawFd,
    default_cpus: Vec<usize>,
    core_table: CoreTable,
    generation: u64,
}

impl Shared {
    fn reset_core_table(&mut self) {
        self.core_table = CoreTable::new(candidate_cpus(&self.cfg, &self.default_cpus));
    }
}

/// Persistent Entry workers, one per configured connection.
struct Entry {
    controls: Vec<Arc<Control>>,
    cpus: Vec<Option<usize>>,
    threads: Vec<JoinHandle<()>>,
    rolling: Option<RollingReload>,
}

/// The Exit listener and the workers it admits, indexed by the peer's worker id.
struct Exit {
    _anchor_tun: Option<OwnedFd>,
    dispatcher: ExitDispatcher,
    listener_wake: RawFd,
    listener_thread: JoinHandle<()>,
    workers: Vec<Option<ExitSlot>>,
    reload_gen: Option<u64>,
}

enum Role {
    Entry(Entry),
    Exit(Exit),
}

/// Manager state owning persistent Entry workers or dynamic Exit workers and the CPU binding table.
pub struct Running {
    shared: Shared,
    role: Role,
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
    let default_cpus = platform::usable_cpus();
    let mut shared = Shared {
        cfg: cfg.clone(),
        outer_mtu: outer.mtu,
        tun_mtu,
        seed: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64),
        stop,
        main_wake,
        core_table: CoreTable::new(candidate_cpus(cfg, &default_cpus)),
        default_cpus,
        generation: 0,
    };
    let seed = shared.seed;
    let role = if cfg.mode == Mode::Entry {
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
        let mut entry = Entry {
            controls: Vec::with_capacity(starts.len()),
            cpus: Vec::with_capacity(starts.len()),
            threads: Vec::with_capacity(starts.len()),
            rolling: None,
        };
        for (i, start) in starts.into_iter().enumerate() {
            let cpu = shared.core_table.acquire();
            let ctrl = Arc::new(Control::new(cpu, main_wake));
            let worker_ctrl = Arc::clone(&ctrl);
            entry.cpus.push(cpu);
            entry.controls.push(ctrl);
            entry.threads.push(
                std::thread::Builder::new()
                    .name(format!("ghostun-w{i}"))
                    .spawn(move || {
                        let _guard = StopOnDrop(stop, main_wake);
                        start.run(stop, &worker_ctrl);
                    })
                    .expect("spawning worker thread"),
            );
        }
        Role::Entry(entry)
    } else {
        let anchor_tun = tuns.into_iter().next();
        let (dispatcher, listener_wake, listener_thread) = match cfg.transport {
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
        Role::Exit(Exit {
            _anchor_tun: anchor_tun,
            dispatcher,
            listener_wake,
            listener_thread,
            workers: (0..MAX_CONNS).map(|_| None).collect(),
            reload_gen: None,
        })
    };
    Ok(Running { shared, role })
}

impl Exit {
    fn reap_exited_workers(&mut self, cores: &mut CoreTable) {
        for slot in &mut self.workers {
            if slot.as_ref().is_some_and(|s| s.ctrl.is_exited()) {
                let finished = slot.take().unwrap();
                let _ = finished.thread.join();
                cores.release(finished.cpu);
            }
        }
    }

    fn replace_slot(
        &mut self,
        cores: &mut CoreTable,
        id: usize,
        new_tuple: Option<(SocketAddr, SocketAddr)>,
    ) {
        if let Some(old) = self.workers[id].take() {
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
            cores.release(old.cpu);
        }
    }

    fn spawn_slot(
        &mut self,
        shared: &mut Shared,
        id: usize,
        tuple: Option<(SocketAddr, SocketAddr)>,
        peer_label: String,
        build: impl FnOnce(&Shared, OwnedFd) -> Result<Start, String>,
    ) {
        self.replace_slot(&mut shared.core_table, id, tuple);
        let tun = match platform::tun::open_queue(&shared.cfg.tun_name) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(
                    "worker {id}: opening TUN queue {}: {e}",
                    shared.cfg.tun_name
                );
                return;
            }
        };
        let start = match build(shared, tun) {
            Ok(start) => start,
            Err(e) => {
                log::error!("worker {id}: {e}");
                return;
            }
        };
        let cpu = shared.core_table.acquire();
        let ctrl = Arc::new(Control::new(cpu, shared.main_wake));
        let worker_ctrl = Arc::clone(&ctrl);
        let stop = shared.stop;
        let main_wake = shared.main_wake;
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
        self.workers[id] = Some(ExitSlot {
            ctrl,
            thread,
            cpu,
            tuple,
            peer_label,
        });
    }

    fn reload(&mut self, shared: &mut Shared, key_changed: bool, cpus_changed: bool) {
        self.dispatcher.reload(&shared.cfg.tunables, key_changed);
        platform::eventfd_notify(self.listener_wake);
        self.reap_exited_workers(&mut shared.core_table);
        if key_changed {
            for slot in &mut self.workers {
                if let Some(old) = slot.take() {
                    old.ctrl.stop(true);
                    let _ = old.thread.join();
                    shared.core_table.release(old.cpu);
                }
            }
            if cpus_changed {
                shared.reset_core_table();
            }
            self.reload_gen = None;
            log::info!(
                "configuration reload complete (generation {})",
                shared.generation
            );
        } else {
            if cpus_changed {
                shared.reset_core_table();
                for slot in self.workers.iter_mut().flatten() {
                    slot.cpu = shared.core_table.acquire();
                }
            }
            for slot in self.workers.iter().flatten() {
                slot.ctrl.publish(
                    shared.generation,
                    Reload {
                        tunables: shared.cfg.tunables.clone(),
                        cpu: slot.cpu,
                    },
                );
            }
            self.reload_gen = Some(shared.generation);
            self.advance(shared);
        }
    }

    fn advance(&mut self, shared: &mut Shared) {
        self.reap_exited_workers(&mut shared.core_table);
        match &self.dispatcher {
            ExitDispatcher::Udp(state) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admission.admitted.pop_front();
                    let Some(promo) = next else { break };
                    let id = promo.worker;
                    let tuple = Some((promo.local, promo.peer));
                    let peer_label = format!("{} <-> {}", promo.local, promo.peer);
                    let worker_state = Arc::clone(&state);
                    self.spawn_slot(shared, id, tuple, peer_label, |shared, tun| {
                        udp::Worker::new_exit(
                            id,
                            &shared.cfg,
                            shared.tun_mtu as u16,
                            tun,
                            promo,
                            worker_state,
                            shared.seed,
                        )
                        .map(|w| Start::Udp(Box::new(w)))
                    });
                }
            }
            ExitDispatcher::Tcp(state) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admitted.pop_front();
                    let Some((id, conn)) = next else { break };
                    let peer_label = conn.to_string();
                    self.spawn_slot(shared, id, None, peer_label, |shared, tun| {
                        Ok(Start::Tcp(Box::new(tcp::Worker::new_exit(
                            id,
                            shared.cfg.clone(),
                            shared.tun_mtu as u16,
                            tun,
                            conn,
                        ))))
                    });
                }
            }
            ExitDispatcher::Fake(state) => {
                let state = Arc::clone(state);
                loop {
                    let next = state.lock().unwrap().admission.admitted.pop_front();
                    let Some(promo) = next else { break };
                    let id = promo.worker;
                    let tuple = Some((promo.local, promo.peer));
                    let peer_label = format!("{} <-> {}", promo.local, promo.peer);
                    let worker_state = Arc::clone(&state);
                    self.spawn_slot(shared, id, tuple, peer_label, |shared, tun| {
                        faketcp::Worker::new_exit(
                            id,
                            &shared.cfg,
                            shared.outer_mtu,
                            tun,
                            promo,
                            worker_state,
                            shared.seed,
                        )
                        .map(|w| Start::Fake(Box::new(w)))
                    });
                }
            }
        }
        if let Some(generation) = self.reload_gen
            && self
                .workers
                .iter()
                .flatten()
                .all(|s| s.ctrl.is_step_complete(generation))
        {
            log::info!("configuration reload complete (generation {generation})");
            self.reload_gen = None;
        }
    }
}

impl Running {
    pub fn is_reloading(&self) -> bool {
        match &self.role {
            Role::Entry(entry) => entry.rolling.is_some(),
            Role::Exit(exit) => exit.reload_gen.is_some(),
        }
    }

    /// Starts a reload to `cfg`, superseding any reload still in progress.
    pub fn reload(&mut self, cfg: Config) {
        let shared = &mut self.shared;
        shared.generation += 1;
        log::info!("reloading configuration (generation {})", shared.generation);
        let key_changed = shared.cfg.tunables.auth_key != cfg.tunables.auth_key;
        let cpus_changed = shared.cfg.tunables.cpus != cfg.tunables.cpus;
        shared.cfg = cfg;
        match &mut self.role {
            Role::Entry(entry) => {
                if cpus_changed {
                    shared.reset_core_table();
                    entry.cpus = (0..entry.controls.len())
                        .map(|_| shared.core_table.acquire())
                        .collect();
                }
                entry.rolling = RollingReload::start(
                    &entry.controls,
                    entry.cpus.clone(),
                    shared.generation,
                    shared.cfg.tunables.clone(),
                );
            }
            Role::Exit(exit) => exit.reload(shared, key_changed, cpus_changed),
        }
    }

    /// Reaps exited workers, spawns newly admitted Exit workers, and advances active reloads.
    pub fn advance(&mut self) {
        match &mut self.role {
            Role::Entry(entry) => RollingReload::advance(&entry.controls, &mut entry.rolling),
            Role::Exit(exit) => exit.advance(&mut self.shared),
        }
    }

    /// Wakes every thread to observe `stop`, which the caller has set, and joins them.
    pub fn join(self) {
        let (threads, listener) = match self.role {
            Role::Entry(entry) => {
                for ctrl in &entry.controls {
                    ctrl.wake();
                }
                (entry.threads, None)
            }
            Role::Exit(exit) => {
                for slot in exit.workers.iter().flatten() {
                    slot.ctrl.stop(true);
                }
                platform::eventfd_notify(exit.listener_wake);
                let threads = exit.workers.into_iter().flatten().map(|slot| slot.thread);
                (threads.collect(), Some(exit.listener_thread))
            }
        };
        for thread in threads {
            if thread.join().is_err() {
                log::error!("worker panicked");
            }
        }
        if let Some(thread) = listener
            && thread.join().is_err()
        {
            log::error!("listener panicked");
        }
    }
}
