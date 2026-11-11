//! Per-core event loop pumping one TUN queue and connected UDP socket through a UDP [`Session`],
//! plus the Exit handshake listener that authenticates incoming peers before workers are spawned.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::auth::{self, Auth, ExitStep, PROOF_LEN, Promoted};
use super::session::{Session, SessionConfig, Sink};
use crate::config::{Config, Mode};
use crate::net::OuterFamily;
use crate::platform::{self, Interest, Poller, TunDriver, TunQueue, Waker, udp};
use crate::transport::control::{self, Admission, Control};
use crate::transport::queue::Pending;

const ROUNDS: usize = 4;
const MIN_STRIDE: usize = 2048;

struct EntryBind {
    local_ip: IpAddr,
    remote: SocketAddr,
    dev: String,
}

#[derive(Clone, Copy)]
struct UnconnectedDst {
    index: usize,
    local: SocketAddr,
    peer: SocketAddr,
}

struct UdpSink {
    socket: UdpSocket,
    local: SocketAddr,
    entry_bind: Option<EntryBind>,
    reuse_initial: bool,
    pending: Pending<()>,
}

impl UdpSink {
    fn new(socket: UdpSocket, local: SocketAddr, entry_bind: Option<EntryBind>) -> Self {
        Self {
            socket,
            local,
            entry_bind,
            reuse_initial: true,
            pending: Pending::default(),
        }
    }

    fn room(&self, driver: &TunDriver<'_>, bytes: usize, count: usize) -> bool {
        let (reserved_bytes, reserved_slots) = driver.read_budget();
        self.pending
            .room_for(bytes + reserved_bytes, count + reserved_slots)
    }

    fn flush(&mut self, sender: &mut udp::Sender) {
        if self.pending.packets.is_empty() {
            return;
        }
        let count = self.pending.packets.len().min(platform::BATCH);
        let frames = self
            .pending
            .packets
            .iter()
            .take(count)
            .map(|p| p.bytes.as_slice());
        let completed = sender.send(&self.socket, frames);
        for _ in 0..completed {
            self.pending.pop();
        }
    }

    fn data<'a>(
        &mut self,
        sender: &mut udp::Sender,
        frames: impl ExactSizeIterator<Item = &'a [u8]> + Clone,
    ) {
        let completed = if self.pending.packets.is_empty() {
            sender.send(&self.socket, frames.clone())
        } else {
            0
        };
        for bytes in frames.skip(completed) {
            let accepted = self.pending.push(bytes, (), false);
            debug_assert!(accepted, "TUN reads reserve pending queue capacity");
        }
    }
}

impl Sink for UdpSink {
    fn send(&mut self, frame: &[u8]) {
        if self.pending.packets.is_empty() {
            loop {
                match udp::send(&self.socket, frame) {
                    Ok(()) => return,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!("udp send: {e}");
                        return;
                    }
                }
            }
        }
        if !self.pending.push(frame, (), true) {
            log::debug!("udp control queue full; dropping new control packet");
        }
    }

    fn reset(&mut self) {
        self.pending.clear();
    }

    fn rebind(&mut self, default_local: SocketAddr) -> io::Result<SocketAddr> {
        self.pending.clear();
        if self.reuse_initial {
            self.reuse_initial = false;
            return Ok(self.local);
        }
        if let Some(bind) = &self.entry_bind {
            let (fd, local) = udp::connect_entry(bind.local_ip, bind.remote, Some(&bind.dev))?;
            self.socket = fd;
            self.local = local;
            return Ok(local);
        }
        Ok(default_local)
    }
}

pub struct ExitState {
    pub(crate) admission: Admission<Promoted>,
    applied_epoch: u64,
    auth: Auth,
}

impl ExitState {
    fn sync(&mut self) -> bool {
        self.auth
            .reload(&self.admission.key, self.admission.timeout);
        if self.applied_epoch != self.admission.epoch {
            self.auth.reset();
            self.applied_epoch = self.admission.epoch;
            return true;
        }
        false
    }

    fn on_request(
        &mut self,
        now: Instant,
        local: SocketAddr,
        peer: SocketAddr,
        payload: &[u8],
    ) -> io::Result<ExitStep> {
        self.sync();
        self.auth.on_exit_request(now, local, peer, payload)
    }
}

pub type SharedExitState = Arc<Mutex<ExitState>>;

pub struct Listener {
    sockets: Vec<(OuterFamily, UdpSocket)>,
    wake: Arc<Waker>,
    pub(crate) state: SharedExitState,
    listen_ip: Option<IpAddr>,
    listen_port: u16,
}

impl Listener {
    pub fn bind(cfg: &Config, tun_mtu: u16, main_wake: Arc<Waker>) -> Result<Self, String> {
        let listen_port = cfg.listen.expect("validated exit listen port");
        let mut sockets = Vec::new();
        for &family in cfg.socket_families() {
            let fd = udp::listener(family, cfg.listen_ip, listen_port, cfg.iface.as_deref())
                .map_err(|e| format!("{family:?} UDP listener: {e}"))?;
            sockets.push((family, fd));
        }
        let wake = Waker::new()
            .map(Arc::new)
            .map_err(|e| format!("listener eventfd: {e}"))?;
        let auth = Auth::new(
            &cfg.tunables.auth_key,
            tun_mtu,
            Instant::now(),
            cfg.tunables.dead_timeout,
        );
        let state = Arc::new(Mutex::new(ExitState {
            admission: Admission::new(
                cfg.tunables.auth_key.clone(),
                cfg.tunables.dead_timeout,
                main_wake,
            ),
            applied_epoch: 0,
            auth,
        }));
        Ok(Self {
            sockets,
            wake,
            state,
            listen_ip: cfg.listen_ip,
            listen_port,
        })
    }

    pub fn waker(&self) -> Arc<Waker> {
        self.wake.clone()
    }

    pub fn spawn(
        self,
        stop: &'static AtomicBool,
        main_wake: Arc<Waker>,
    ) -> io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name("ghostun-udp-accept".into())
            .spawn(move || {
                let _guard = control::StopOnDrop(stop, main_wake);
                self.run(stop);
            })
    }

    fn run(self, stop: &AtomicBool) {
        let Self {
            sockets,
            wake,
            state,
            listen_ip,
            listen_port,
        } = self;
        let mut pending: Pending<UnconnectedDst> = Pending::default();
        let mut poller = Poller::default();
        let wake_slot = poller.add(&wake, Interest::READ);
        for (_, socket) in &sockets {
            poller.add(socket, Interest::READ);
        }
        let mut buf = [0u8; PROOF_LEN + 64];
        while !stop.load(Ordering::Relaxed) {
            for index in 0..sockets.len() {
                let blocked = pending
                    .packets
                    .front()
                    .is_some_and(|p| p.metadata.index == index);
                poller.set(index + 1, Interest::READ | Interest::WRITE.when(blocked));
            }
            match poller.wait(None) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    log::error!("udp listener poll: {e}");
                    return;
                }
            }
            if poller.woken(wake_slot, &wake) && state.lock().unwrap().sync() {
                pending.clear();
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if (1..=sockets.len()).any(|slot| poller.write_ready(slot)) {
                flush_unconnected(&sockets, &mut pending);
            }
            let now = Instant::now();
            for (index, (family, fd)) in sockets.iter().enumerate() {
                if !poller.readable(index + 1) {
                    continue;
                }
                for _ in 0..ROUNDS * platform::BATCH {
                    let (n, local, peer) =
                        match udp::recv_unconnected(fd, *family, listen_port, &mut buf) {
                            Ok(res) => res,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => break,
                        };
                    if n == 0
                        || buf[0] != auth::CONTROL
                        || listen_ip.is_some_and(|ip| local.ip() != ip)
                    {
                        continue;
                    }
                    let dst = UnconnectedDst { index, local, peer };
                    let step = state
                        .lock()
                        .unwrap()
                        .on_request(now, local, peer, &buf[..n]);
                    match step {
                        Ok(ExitStep::Ignore) => {}
                        Ok(ExitStep::Challenge(c)) => {
                            send_or_queue(&sockets, &mut pending, dst, &c);
                        }
                        Ok(ExitStep::Finished(f)) => {
                            send_or_queue(&sockets, &mut pending, dst, &f);
                        }
                        Ok(ExitStep::Promote(promo)) => {
                            state.lock().unwrap().admission.admit(promo);
                        }
                        Err(e) => log::error!("authentication randomness: {e}"),
                    }
                }
            }
        }
    }
}

fn send_or_queue(
    sockets: &[(OuterFamily, UdpSocket)],
    pending: &mut Pending<UnconnectedDst>,
    dst: UnconnectedDst,
    frame: &[u8],
) {
    if pending.packets.is_empty() {
        loop {
            match udp::send_unconnected(&sockets[dst.index].1, dst.local, dst.peer, frame) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::debug!("udp listener send to {}: {e}", dst.peer);
                    return;
                }
            }
        }
    }
    if !pending.push(frame, dst, true) {
        log::debug!("udp listener control queue full; dropping reply");
    }
}

fn flush_unconnected(sockets: &[(OuterFamily, UdpSocket)], pending: &mut Pending<UnconnectedDst>) {
    while let Some(front) = pending.packets.front() {
        let dst = front.metadata;
        match udp::send_unconnected(&sockets[dst.index].1, dst.local, dst.peer, &front.bytes) {
            Ok(()) => pending.pop(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                log::debug!("udp listener send to {}: {e}; dropping reply", dst.peer);
                pending.pop();
            }
        }
    }
}

#[inline]
fn apply_reload(
    ctrl: &Control,
    id: usize,
    cpu: &mut Option<usize>,
    applied_gen: &mut u64,
    now: Instant,
    session: &mut Session,
    out: &mut impl Sink,
) -> bool {
    let mut wait = ctrl.wait_for_established();
    if let Some((generation, reload)) = ctrl.take_reload(*applied_gen) {
        if reload.cpu != *cpu {
            *cpu = reload.cpu;
            control::pin(id, *cpu);
        }
        let prior_wait = wait && !session.is_established();
        wait = session.reload(
            now,
            reload.tunables.auth_key,
            reload.tunables.ping_interval,
            reload.tunables.dead_timeout,
            out,
        ) || prior_wait;
        *applied_gen = generation;
    }
    wait
}

pub struct Worker {
    id: usize,
    mode: Mode,
    session: Session,
    tun: TunQueue,
    out: UdpSink,
    exit_state: Option<SharedExitState>,
}

impl Worker {
    pub fn new_entry(
        id: usize,
        cfg: &Config,
        route: &crate::transport::EntryRoute,
        tun_mtu: u16,
        tun: TunQueue,
        seed: u64,
    ) -> Result<Self, String> {
        let worker = id as u16;
        let (socket, local) = udp::connect_entry(route.local_ip, route.remote, Some(&route.dev))
            .map_err(|e| format!("UDP entry socket ({}): {e}", route.remote))?;
        let scfg =
            SessionConfig::from_config(cfg, route.local_ip, Some(route.remote), 0, worker, tun_mtu);
        let session = Session::new(scfg, Instant::now(), seed ^ (u64::from(worker) << 48));
        Ok(Self {
            id,
            mode: Mode::Entry,
            session,
            tun,
            out: UdpSink::new(
                socket,
                local,
                Some(EntryBind {
                    local_ip: route.local_ip,
                    remote: route.remote,
                    dev: route.dev.clone(),
                }),
            ),
            exit_state: None,
        })
    }

    pub fn new_exit(
        id: usize,
        cfg: &Config,
        tun_mtu: u16,
        tun: TunQueue,
        promo: Promoted,
        state: SharedExitState,
        seed: u64,
    ) -> Result<Self, String> {
        let worker = id as u16;
        let socket =
            udp::connect_exit(promo.local, promo.peer, cfg.iface.as_deref()).map_err(|e| {
                format!(
                    "UDP exit worker socket ({} <-> {}): {e}",
                    promo.local, promo.peer
                )
            })?;
        let scfg = SessionConfig::from_config(
            cfg,
            promo.local.ip(),
            None,
            promo.local.port(),
            worker,
            tun_mtu,
        );
        let mut attached = false;
        control::sync_tun_queue(id, &tun, &mut attached, true);
        let mut out = UdpSink::new(socket, promo.local, None);
        let session = Session::new_exit_established(
            scfg,
            &promo,
            Instant::now(),
            seed ^ (u64::from(worker) << 48),
            &mut out,
        );
        Ok(Self {
            id,
            mode: Mode::Exit,
            session,
            tun,
            out,
            exit_state: Some(state),
        })
    }

    pub fn run(self, stop: &AtomicBool, ctrl: &Control) {
        let Self {
            id,
            mode,
            mut session,
            tun,
            mut out,
            exit_state,
        } = self;
        let mut cpu = ctrl.initial_cpu();
        control::pin(id, cpu);
        let stride = usize::from(session.mtu()).max(MIN_STRIDE);
        session.start(Instant::now(), &mut out);
        let mut generation = session.generation();
        let mut driver = TunDriver::new(&tun, usize::from(session.mtu()), 0);
        let mut attached = mode == Mode::Exit;
        let mut sender = udp::Sender::new();
        let mut rx = udp::Receiver::new(stride);
        let mut poller = Poller::default();
        let tun_slot = poller.add(&tun, Interest::READ);
        let wake_slot = poller.add(ctrl.waker(), Interest::READ);
        let ring_slot = poller.reserve();
        let socket_slot = poller.add(&out.socket, Interest::READ);
        let mut busy = false;
        let mut applied_gen = 0;
        let mut handoff: Option<Promoted> = None;
        while !stop.load(Ordering::Relaxed) && !ctrl.is_stopped() {
            let polled = driver.bind_ring(&mut poller, ring_slot);
            poller.set(
                tun_slot,
                Interest::READ.when(polled && out.room(&driver, stride, 1))
                    | Interest::WRITE.when(driver.wants_write()),
            );
            // The session may have rebound to a fresh socket.
            poller.bind(
                socket_slot,
                &out.socket,
                Interest::READ | Interest::WRITE.when(!out.pending.packets.is_empty()),
            );
            let timeout = if busy || (driver.has_reads() && out.room(&driver, stride, 1)) {
                Duration::ZERO
            } else {
                session
                    .next_deadline()
                    .saturating_duration_since(Instant::now())
            };
            match poller.wait(Some(timeout)) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    log::error!("worker {id}: poll: {e}");
                    break;
                }
            }
            poller.woken(wake_slot, ctrl.waker());
            if stop.load(Ordering::Relaxed) || ctrl.is_stopped() {
                break;
            }
            let now = Instant::now();
            let read_allowed = out.room(&driver, stride, 1);
            driver.service(attached, read_allowed);
            if poller.write_ready(socket_slot) {
                out.flush(&mut sender);
            }
            if poller.write_ready(tun_slot) {
                driver.flush();
            }
            let mut tun_ready =
                (poller.readable(tun_slot) || driver.has_reads()) && out.room(&driver, stride, 1);
            let mut udp_ready = poller.readable(socket_slot);
            for _ in 0..ROUNDS {
                if udp_ready {
                    udp_ready = match rx.receive(&out.socket) {
                        Ok(m) => {
                            for k in 0..m {
                                let n = rx.lens[k];
                                if n == 0 {
                                    continue;
                                }
                                let frame = &rx.buffers()[k * stride..k * stride + n];
                                if mode == Mode::Exit
                                    && frame.first() == Some(&auth::CONTROL)
                                    && let Some(state) = &exit_state
                                {
                                    let local = session.local();
                                    let peer = session.peer().expect("exit worker has peer");
                                    let step =
                                        state.lock().unwrap().on_request(now, local, peer, frame);
                                    match step {
                                        Ok(ExitStep::Ignore) => {}
                                        Ok(ExitStep::Challenge(challenge)) => {
                                            out.send(&challenge);
                                        }
                                        Ok(ExitStep::Finished(finished)) => {
                                            out.send(&finished);
                                        }
                                        Ok(ExitStep::Promote(promo)) => {
                                            if promo.worker == id {
                                                session.accept_in_place(
                                                    now,
                                                    &promo.finished,
                                                    &mut out,
                                                );
                                                driver.reset();
                                                generation = session.generation();
                                            } else {
                                                handoff = Some(promo);
                                                session.close(&mut out);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "worker {id}: authentication randomness: {e}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let inner = session.on_outer(now, frame, &mut out);
                                if generation != session.generation() {
                                    driver.reset();
                                    generation = session.generation();
                                }
                                if let Some(inner) = inner
                                    && !driver.write(inner)
                                {
                                    log::debug!(
                                        "worker {id}: TUN queue full; dropping new data packet"
                                    );
                                }
                            }
                            m == platform::BATCH && handoff.is_none()
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                log::debug!("worker {id}: udp receive: {e}");
                            }
                            false
                        }
                    };
                }
                if handoff.is_some() {
                    break;
                }
                if tun_ready && out.room(&driver, stride, 1) {
                    let established = session.is_established();
                    let (reserved_bytes, reserved_slots) = driver.read_budget();
                    let (reads, frames) = driver.read_batch(
                        rx.buffers_mut(),
                        stride,
                        |bytes, count| {
                            out.pending
                                .room_for(bytes + reserved_bytes, count + reserved_slots)
                        },
                        |_, _| established,
                    );
                    if frames.len() > 0 {
                        out.data(&mut sender, frames);
                    }
                    tun_ready = reads == platform::BATCH && out.room(&driver, stride, 1);
                } else {
                    tun_ready = false;
                }
                if !udp_ready && !tun_ready {
                    break;
                }
                let read_allowed = out.room(&driver, stride, 1);
                driver.service(attached, read_allowed);
                tun_ready = (tun_ready || driver.has_reads()) && read_allowed;
            }
            if handoff.is_some() {
                break;
            }
            busy = udp_ready || tun_ready;
            if now >= session.next_deadline() {
                session.on_tick(now, &mut out);
            }
            let wait = apply_reload(
                ctrl,
                id,
                &mut cpu,
                &mut applied_gen,
                now,
                &mut session,
                &mut out,
            );
            if generation != session.generation() {
                driver.reset();
                generation = session.generation();
            }
            let established = session.is_established();
            if mode == Mode::Exit && !established {
                break;
            }
            control::sync_tun_queue(id, &tun, &mut attached, established);
            let read_allowed = out.room(&driver, stride, 1);
            driver.service(attached, read_allowed);
            ctrl.report(applied_gen, established, wait);
        }
        out.flush(&mut sender);
        // Close the connected socket before handing off the 4-tuple to another worker slot.
        drop(out);
        if let (Some(promo), Some(state)) = (handoff, exit_state) {
            state.lock().unwrap().admission.admit(promo);
        }
    }
}
