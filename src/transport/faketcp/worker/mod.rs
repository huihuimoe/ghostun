//! Per-core event loop pumping one TUN queue and steered raw socket through a FakeTCP [`Session`],
//! plus the Exit handshake listener that authenticates incoming peers before workers are spawned.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::auth::{self, Auth, ExitStep, PROOF_LEN};
use super::filter::{entry_filter, exit_listener_filter, exit_worker_filter};
use super::frame::{self, MAX_OVERHEAD, TcpMeta, flags};
use super::session::{Promoted, Session, SessionConfig, Sink, WINDOW, emit};
use crate::config::{Config, MAX_CONNS, Mode};
use crate::net::OuterFamily;
use crate::platform::{self, Interest, Poller, Waker, raw};
use crate::transport::control::{self, Admission, Control};
use crate::transport::queue::Pending;
use crate::transport::tun_driver::TunDriver;
#[cfg(test)]
mod tests;

const ROUNDS: usize = 4;
/// Extra slot space beyond `overhead + mss` so incoming frames with IP/TCP options never truncate.
const OPT_HEADROOM: usize = 80;
const MIN_STRIDE: usize = 2048;

struct RawSink<'a> {
    sockets: &'a [(OuterFamily, OwnedFd)],
    sender: raw::Sender,
    pending: Pending<IpAddr>,
}

impl RawSink<'_> {
    fn room(&self, driver: &TunDriver<'_>, bytes: usize, count: usize) -> bool {
        let (reserved_bytes, reserved_slots) = driver.read_budget();
        self.pending
            .room_for(bytes + reserved_bytes, count + reserved_slots)
    }

    fn socket_index(&self, family: OuterFamily) -> usize {
        self.sockets
            .iter()
            .position(|(f, _)| *f == family)
            .expect("socket for session family")
    }

    fn flush(&mut self) {
        let Some(packet) = self.pending.packets.front() else {
            return;
        };
        let family = OuterFamily::of(packet.metadata);
        let index = self.socket_index(family);
        // All frames in a syscall must use the socket's concrete family.
        let count = self
            .pending
            .packets
            .iter()
            .take(platform::BATCH)
            .take_while(|p| OuterFamily::of(p.metadata) == family)
            .count();
        let frames = self
            .pending
            .packets
            .iter()
            .take(count)
            .map(|p| (p.bytes.as_slice(), p.metadata));
        let completed = self.sender.send(self.sockets[index].1.as_fd(), frames);
        for _ in 0..completed {
            self.pending.pop();
        }
    }

    fn data<'a>(&mut self, frames: impl ExactSizeIterator<Item = (&'a [u8], IpAddr)> + Clone) {
        let completed = if self.pending.packets.is_empty() {
            self.sender.send(self.sockets[0].1.as_fd(), frames.clone())
        } else {
            0
        };
        for (bytes, dst) in frames.skip(completed) {
            let accepted = self.pending.push(bytes, dst, false);
            debug_assert!(accepted, "TUN reads reserve pending queue capacity");
        }
    }
}

impl Sink for RawSink<'_> {
    fn send(&mut self, frame: &[u8], dst: IpAddr) {
        if self.pending.packets.is_empty() {
            loop {
                let index = self.socket_index(OuterFamily::of(dst));
                match raw::send(self.sockets[index].1.as_fd(), frame, dst) {
                    Ok(()) => return,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::debug!("send to {dst}: {e}");
                        return;
                    }
                }
            }
        }
        if !self.pending.push(frame, dst, true) {
            log::debug!("raw control queue full; dropping new control packet");
        }
    }

    fn reset(&mut self) {
        self.pending.clear();
    }
}

#[derive(Clone, Copy)]
pub struct ActivePeer {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub irs: u32,
    pub iss: u32,
}

pub struct ExitState {
    pub(crate) admission: Admission<Promoted>,
    pub(crate) active: Box<[Option<ActivePeer>; MAX_CONNS]>,
}

pub type SharedExitState = Arc<Mutex<ExitState>>;

pub struct Listener {
    sockets: Vec<(OuterFamily, OwnedFd)>,
    wake: Arc<Waker>,
    pub(crate) state: SharedExitState,
    auth: Auth,
    listen_ip: Option<IpAddr>,
    listen_port: u16,
    mss: u16,
    ip_id: u16,
}

impl Listener {
    pub fn bind(
        cfg: &Config,
        outer_mtu: u32,
        seed: u64,
        main_wake: Arc<Waker>,
    ) -> Result<Self, String> {
        let listen_port = cfg.listen.expect("validated exit listen port");
        let mut sockets = Vec::new();
        for &family in cfg.socket_families() {
            let filter = exit_listener_filter(family, cfg.listen_ip, listen_port);
            let fd = raw::socket(family, cfg.iface.as_deref(), &filter, None)
                .map_err(|e| format!("{family:?} raw socket: {e}"))?;
            sockets.push((family, fd));
        }
        let wake = Waker::new()
            .map(Arc::new)
            .map_err(|e| format!("listener eventfd: {e}"))?;
        let auth = Auth::new(
            &cfg.tunables.auth_key,
            Mode::Exit,
            Instant::now(),
            cfg.tunables.dead_timeout,
        )
        .map_err(|e| format!("initializing exit authentication: {e}"))?;
        let state = Arc::new(Mutex::new(ExitState {
            admission: Admission::new(
                cfg.tunables.auth_key.clone(),
                cfg.tunables.dead_timeout,
                main_wake,
            ),
            active: Box::new([None; MAX_CONNS]),
        }));
        Ok(Self {
            sockets,
            wake,
            state,
            auth,
            listen_ip: cfg.listen_ip,
            listen_port,
            mss: (outer_mtu - cfg.outer_family.overhead() as u32) as u16,
            ip_id: seed as u16,
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
            .name("ghostun-fk-accept".into())
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
            mut auth,
            listen_ip,
            listen_port,
            mss,
            mut ip_id,
        } = self;
        let mut out = RawSink {
            sockets: &sockets,
            sender: raw::Sender::new(sockets[0].0),
            pending: Pending::default(),
        };
        let mut receivers: Vec<_> = sockets
            .iter()
            .map(|(f, _)| raw::Receiver::new(*f, MIN_STRIDE))
            .collect();
        let mut poller = Poller::default();
        let wake_slot = poller.add(&*wake, Interest::READ);
        for (_, fd) in &sockets {
            poller.add(fd, Interest::READ);
        }
        let mut scratch = [0u8; MAX_OVERHEAD + PROOF_LEN];
        let mut applied_epoch = 0;
        while !stop.load(Ordering::Relaxed) {
            for (index, _) in sockets.iter().enumerate() {
                let blocked = out
                    .pending
                    .packets
                    .front()
                    .is_some_and(|p| OuterFamily::of(p.metadata) == sockets[index].0);
                poller.set(index + 1, Interest::READ | Interest::WRITE.when(blocked));
            }
            match poller.wait(None) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    log::error!("faketcp listener poll: {e}");
                    return;
                }
            }
            if poller.woken(wake_slot, &wake) {
                let s = state.lock().unwrap();
                auth.reload(&s.admission.key, s.admission.timeout);
                if s.admission.epoch != applied_epoch {
                    auth.reset();
                    applied_epoch = s.admission.epoch;
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if (1..=sockets.len()).any(|slot| poller.write_ready(slot)) {
                out.flush();
            }
            let now = Instant::now();
            for (index, (family, fd)) in sockets.iter().enumerate() {
                if !poller.readable(index + 1) {
                    continue;
                }
                let rx = &mut receivers[index];
                for _ in 0..ROUNDS {
                    let Ok(m) = rx.receive(fd.as_fd()) else {
                        break;
                    };
                    for k in 0..m {
                        let n = rx.lens[k];
                        if n == 0 {
                            continue;
                        }
                        let frame = &rx.buffers()[k * MIN_STRIDE..k * MIN_STRIDE + n];
                        let Some(p) = frame::parse(frame) else {
                            continue;
                        };
                        let meta = &p.meta;
                        if meta.dst.port() != listen_port
                            || OuterFamily::of(meta.dst.ip()) != *family
                            || listen_ip.is_some_and(|ip| meta.dst.ip() != ip)
                        {
                            continue;
                        }
                        if meta.flags & flags::SYN != 0 {
                            if meta.flags & (flags::ACK | flags::RST) == 0 && p.payload.is_empty() {
                                let seq = state
                                    .lock()
                                    .unwrap()
                                    .active
                                    .iter()
                                    .flatten()
                                    .find(|a| {
                                        a.local == meta.dst
                                            && a.peer == meta.src
                                            && a.irs == meta.seq
                                    })
                                    .map_or_else(|| auth.syn_cookie(now, meta), |a| a.iss);
                                let reply = TcpMeta {
                                    src: meta.dst,
                                    dst: meta.src,
                                    seq,
                                    ack: meta.seq.wrapping_add(1),
                                    flags: flags::SYN | flags::ACK,
                                    window: WINDOW,
                                };
                                ip_id = ip_id.wrapping_add(1);
                                let len = frame::write_syn(&mut scratch, &reply, mss, ip_id);
                                out.send(&scratch[..len], reply.dst.ip());
                            }
                            continue;
                        }
                        if meta.flags & (flags::ACK | flags::RST) != flags::ACK {
                            continue;
                        }
                        if p.payload.first() == Some(&auth::CONTROL) {
                            match auth.on_exit_request(now, true, meta, p.payload) {
                                Ok(ExitStep::Ignore) => {}
                                Ok(ExitStep::Challenge(challenge)) => {
                                    let reply = TcpMeta {
                                        src: meta.dst,
                                        dst: meta.src,
                                        seq: meta.ack,
                                        ack: meta.seq.wrapping_add(p.payload.len() as u32),
                                        flags: flags::PSH | flags::ACK,
                                        window: WINDOW,
                                    };
                                    ip_id = ip_id.wrapping_add(1);
                                    emit(&mut scratch, &reply, &challenge, ip_id, &mut out);
                                }
                                Ok(ExitStep::Finished(finished)) => {
                                    let reply = TcpMeta {
                                        src: meta.dst,
                                        dst: meta.src,
                                        seq: meta.ack,
                                        ack: meta.seq.wrapping_add(p.payload.len() as u32),
                                        flags: flags::PSH | flags::ACK,
                                        window: WINDOW,
                                    };
                                    ip_id = ip_id.wrapping_add(1);
                                    emit(&mut scratch, &reply, &finished, ip_id, &mut out);
                                }
                                Ok(ExitStep::Promote(promo)) => {
                                    state.lock().unwrap().admission.admit(Promoted {
                                        worker: promo.worker,
                                        local: meta.dst,
                                        peer: meta.src,
                                        req_seq: meta.seq,
                                        req_ack: meta.ack,
                                        req_len: p.payload.len(),
                                        iss: promo.iss,
                                        irs: promo.irs,
                                        snd_nxt: promo.snd_nxt,
                                        rcv_nxt: promo.rcv_nxt,
                                        finished: promo.finished,
                                    });
                                }
                                Err(e) => log::error!("authentication randomness: {e}"),
                            }
                        } else if !p.payload.is_empty() {
                            let is_active = state
                                .lock()
                                .unwrap()
                                .active
                                .iter()
                                .flatten()
                                .any(|a| a.local == meta.dst && a.peer == meta.src);
                            if !is_active {
                                let rst = TcpMeta {
                                    src: meta.dst,
                                    dst: meta.src,
                                    seq: meta.ack,
                                    ack: 0,
                                    flags: flags::RST,
                                    window: 0,
                                };
                                ip_id = ip_id.wrapping_add(1);
                                let len = frame::write_headers(&mut scratch, &rst, 0, ip_id);
                                out.send(&scratch[..len], rst.dst.ip());
                            }
                        }
                    }
                    if m < platform::BATCH {
                        break;
                    }
                }
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
    tun: OwnedFd,
    socket: (OuterFamily, OwnedFd),
    pending_out: Pending<IpAddr>,
    exit_cleanup: Option<(SharedExitState, SocketAddr, SocketAddr)>,
}

impl Worker {
    pub fn new_entry(
        id: usize,
        cfg: &Config,
        route: &crate::transport::EntryRoute,
        outer_mtu: u32,
        tun: OwnedFd,
        seed: u64,
    ) -> Result<Self, String> {
        let worker = id as u16;
        let family = OuterFamily::of(route.remote.ip());
        let filter = entry_filter(route.remote, cfg.base_port, cfg.conns, worker);
        let fd = raw::socket(
            family,
            Some(&route.dev),
            &filter,
            Some((route.local_ip, route.remote.ip())),
        )
        .map_err(|e| format!("{family:?} raw socket: {e}"))?;
        let mss = (outer_mtu - cfg.outer_family.overhead() as u32) as u16;
        let scfg =
            SessionConfig::from_config(cfg, route.local_ip, Some(route.remote), 0, worker, mss);
        let session = Session::new(scfg, Instant::now(), seed ^ (u64::from(worker) << 48))
            .map_err(|e| format!("initializing worker {worker} authentication: {e}"))?;
        Ok(Self {
            id,
            mode: Mode::Entry,
            session,
            tun,
            socket: (family, fd),
            pending_out: Pending::default(),
            exit_cleanup: None,
        })
    }

    pub fn new_exit(
        id: usize,
        cfg: &Config,
        outer_mtu: u32,
        tun: OwnedFd,
        promo: Promoted,
        state: SharedExitState,
        seed: u64,
    ) -> Result<Self, String> {
        let worker = id as u16;
        let family = OuterFamily::of(promo.local.ip());
        let filter = exit_worker_filter(promo.local, promo.peer);
        let fd = raw::socket(family, cfg.iface.as_deref(), &filter, None)
            .map_err(|e| format!("{family:?} raw socket: {e}"))?;
        let socket = (family, fd);
        let mss = (outer_mtu - cfg.outer_family.overhead() as u32) as u16;
        let scfg = SessionConfig::from_config(
            cfg,
            promo.local.ip(),
            None,
            promo.local.port(),
            worker,
            mss,
        );
        state.lock().unwrap().active[id] = Some(ActivePeer {
            local: promo.local,
            peer: promo.peer,
            irs: promo.irs,
            iss: promo.iss,
        });
        let mut attached = false;
        control::sync_tun_queue(id, tun.as_fd(), &mut attached, true);
        let mut out = RawSink {
            sockets: std::slice::from_ref(&socket),
            sender: raw::Sender::new(family),
            pending: Pending::default(),
        };
        let session = Session::new_exit_established(
            scfg,
            &promo,
            Instant::now(),
            seed ^ (u64::from(worker) << 48),
            &mut out,
        )
        .map_err(|e| format!("initializing exit worker {worker}: {e}"))?;
        let pending_out = out.pending;
        Ok(Self {
            id,
            mode: Mode::Exit,
            session,
            tun,
            socket,
            pending_out,
            exit_cleanup: Some((state, promo.local, promo.peer)),
        })
    }

    /// Runs until `stop` is set (or the session closes on Exit).
    pub fn run(self, stop: &AtomicBool, ctrl: &Control) {
        let Self {
            id,
            mode,
            mut session,
            tun,
            socket,
            pending_out,
            exit_cleanup,
        } = self;
        let mut cpu = ctrl.initial_cpu();
        control::pin(id, cpu);
        let family = socket.0;
        let overhead = family.overhead();
        let stride = (overhead + usize::from(session.mss()) + OPT_HEADROOM).max(MIN_STRIDE);
        let sockets = std::slice::from_ref(&socket);
        let mut out = RawSink {
            sockets,
            sender: raw::Sender::new(family),
            pending: pending_out,
        };
        session.start(Instant::now(), &mut out);
        let mut generation = session.generation();
        let mut driver = TunDriver::new(tun.as_fd(), stride, overhead);
        let mut attached = mode == Mode::Exit;
        let mut rx = raw::Receiver::new(family, stride);
        let mut poller = Poller::default();
        let tun_slot = poller.add(&tun, Interest::READ);
        let wake_slot = poller.add(ctrl.waker(), Interest::READ);
        let ring_slot = poller.reserve();
        let socket_slot = poller.add(&socket.1, Interest::READ);
        let mut busy = false;
        let mut applied_gen = 0;
        while !stop.load(Ordering::Relaxed) && !ctrl.is_stopped() {
            let polled = driver.read_fd() == tun.as_raw_fd();
            if polled {
                poller.unbind(ring_slot);
            } else {
                poller.bind(ring_slot, &driver.read_fd(), Interest::READ);
            }
            poller.set(
                tun_slot,
                Interest::READ.when(polled && out.room(&driver, stride, 1))
                    | Interest::WRITE.when(driver.wants_write()),
            );
            poller.set(
                socket_slot,
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
                out.flush();
            }
            if poller.write_ready(tun_slot) {
                driver.flush();
            }
            let mut tun_ready =
                (poller.readable(tun_slot) || driver.has_reads()) && out.room(&driver, stride, 1);
            let mut raw_ready = poller.readable(socket_slot);
            for _ in 0..ROUNDS {
                if raw_ready {
                    raw_ready = match rx.receive(socket.1.as_fd()) {
                        Ok(m) => {
                            for k in 0..m {
                                let n = rx.lens[k];
                                if n == 0 {
                                    continue;
                                }
                                let frame = &rx.buffers()[k * stride..k * stride + n];
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
                            m == platform::BATCH
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                log::debug!("worker {id}: raw receive: {e}");
                            }
                            false
                        }
                    };
                }
                if tun_ready && out.room(&driver, stride, 1) {
                    let mut batch_dst = None;
                    let (reserved_bytes, reserved_slots) = driver.read_budget();
                    let (reads, frames) = driver.read_batch(
                        rx.buffers_mut(),
                        stride,
                        |bytes, count| {
                            out.pending
                                .room_for(bytes + reserved_bytes, count + reserved_slots)
                        },
                        |slot, n| {
                            if let Some((_, dst)) = session.encap(slot, n) {
                                batch_dst = Some(dst);
                                true
                            } else {
                                false
                            }
                        },
                    );
                    if let Some(dst) = batch_dst {
                        out.data(frames.map(|frame| (frame, dst)));
                    }
                    tun_ready = reads == platform::BATCH && out.room(&driver, stride, 1);
                } else {
                    tun_ready = false;
                }
                if !raw_ready && !tun_ready {
                    break;
                }
                let read_allowed = out.room(&driver, stride, 1);
                driver.service(attached, read_allowed);
                tun_ready = (tun_ready || driver.has_reads()) && read_allowed;
            }
            busy = raw_ready || tun_ready;
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
            control::sync_tun_queue(id, tun.as_fd(), &mut attached, established);
            let read_allowed = out.room(&driver, stride, 1);
            driver.service(attached, read_allowed);
            ctrl.report(applied_gen, established, wait);
        }
        if mode == Mode::Entry || stop.load(Ordering::Relaxed) || ctrl.should_send_rst() {
            session.shutdown(&mut out);
        }
        out.flush();
        if let Some((state, local, peer)) = exit_cleanup {
            let mut s = state.lock().unwrap();
            if s.active[id].is_some_and(|a| a.local == local && a.peer == peer) {
                s.active[id] = None;
            }
        }
    }
}
