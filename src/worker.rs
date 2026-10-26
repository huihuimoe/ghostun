//! Worker thread control, CPU affinity, TUN queue synchronization, and rolling reload coordination.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{AuthKey, Config};
use crate::sys;

pub struct Reload {
    pub auth_key: AuthKey,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
    pub cpu: Option<usize>,
}

pub struct Control {
    initial_cpu: Option<usize>,
    wake: OwnedFd,
    main_wake: RawFd,
    target_gen: AtomicU64,
    applied_gen: AtomicU64,
    wait_for_established: AtomicBool,
    established: AtomicBool,
    pending: Mutex<Option<(u64, Reload)>>,
}

impl Control {
    pub fn new(initial_cpu: Option<usize>, main_wake: RawFd) -> Self {
        Self {
            initial_cpu,
            wake: sys::eventfd().expect("creating worker eventfd"),
            main_wake,
            target_gen: AtomicU64::new(0),
            applied_gen: AtomicU64::new(0),
            wait_for_established: AtomicBool::new(false),
            established: AtomicBool::new(false),
            pending: Mutex::new(None),
        }
    }

    #[inline(always)]
    pub fn wake_fd(&self) -> BorrowedFd<'_> {
        self.wake.as_fd()
    }

    #[inline]
    pub fn wake(&self) {
        sys::eventfd_notify(self.wake.as_raw_fd());
    }

    pub fn publish(&self, generation: u64, reload: Reload) {
        *self.pending.lock().expect("reload lock") = Some((generation, reload));
        self.target_gen.store(generation, Ordering::Release);
        self.wake();
    }

    pub fn is_step_complete(&self, generation: u64) -> bool {
        self.applied_gen.load(Ordering::Acquire) == generation
            && (!self.wait_for_established.load(Ordering::Acquire)
                || self.established.load(Ordering::Acquire))
    }

    #[inline(always)]
    pub fn initial_cpu(&self) -> Option<usize> {
        self.initial_cpu
    }

    #[inline]
    pub fn take_reload(&self, applied: u64) -> Option<(u64, Reload)> {
        if self.target_gen.load(Ordering::Acquire) == applied {
            return None;
        }
        self.pending.lock().expect("reload lock").take()
    }

    #[inline]
    pub fn report(&self, generation: u64, established: bool, wait: bool) {
        let prev = (
            self.applied_gen.load(Ordering::Relaxed),
            self.established.load(Ordering::Relaxed),
            self.wait_for_established.load(Ordering::Relaxed),
        );
        if prev != (generation, established, wait) {
            let was_complete = prev.0 == generation && (!prev.2 || prev.1);
            self.wait_for_established.store(wait, Ordering::Release);
            self.established.store(established, Ordering::Release);
            self.applied_gen.store(generation, Ordering::Release);
            if generation > 0 && !was_complete && (!wait || established) {
                sys::eventfd_notify(self.main_wake);
            }
        }
    }

    #[inline(always)]
    pub fn wait_for_established(&self) -> bool {
        self.wait_for_established.load(Ordering::Relaxed)
    }
}

pub fn cpu_for(cfg: &Config, default_cpus: &[usize], id: usize) -> Option<usize> {
    let list = cfg.cpus.as_deref().unwrap_or(default_cpus);
    (!list.is_empty()).then(|| list[id % list.len()])
}

pub fn reload_for(cfg: &Config, default_cpus: &[usize], id: usize) -> Reload {
    Reload {
        auth_key: cfg.auth_key.clone(),
        ping_interval: cfg.ping_interval,
        dead_timeout: cfg.dead_timeout,
        cpu: cpu_for(cfg, default_cpus, id),
    }
}

pub struct RollingReload {
    pub generation: u64,
    pub next_worker: usize,
    pub target: Config,
}

impl RollingReload {
    pub fn start(
        controls: &[Arc<Control>],
        default_cpus: &[usize],
        generation: u64,
        target: Config,
    ) -> Option<Self> {
        let first = controls.first()?;
        first.publish(generation, reload_for(&target, default_cpus, 0));
        Some(Self {
            generation,
            next_worker: 0,
            target,
        })
    }

    pub fn advance(controls: &[Arc<Control>], default_cpus: &[usize], rolling: &mut Option<Self>) {
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
}

pub fn pin(id: usize, cpu: Option<usize>) {
    if let Some(target) = cpu {
        if let Err(e) = sys::pin_to_cpu(target) {
            log::warn!("worker {id}: cannot pin to CPU: {e}");
        }
    }
}

#[inline]
pub fn sync_tun_queue(id: usize, tun: BorrowedFd<'_>, attached: &mut bool, established: bool) {
    if *attached != established {
        match sys::set_tun_queue(tun, established) {
            Ok(()) => *attached = established,
            Err(e) => log::warn!("worker {id}: TUN queue attach={established}: {e}"),
        }
    }
}

pub struct StopOnDrop(pub &'static AtomicBool, pub RawFd);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
        sys::eventfd_notify(self.1);
    }
}
