//! Worker thread control, CPU affinity, and TUN queue synchronization.

use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::config::AuthKey;
use crate::sys;

pub struct Reload {
    pub auth_key: AuthKey,
    pub ping_interval: Duration,
    pub dead_timeout: Duration,
    pub cpu: Option<usize>,
}

pub struct Control {
    initial_cpu: Option<usize>,
    target_gen: AtomicU64,
    applied_gen: AtomicU64,
    wait_for_established: AtomicBool,
    established: AtomicBool,
    pending: Mutex<Option<(u64, Reload)>>,
}

impl Control {
    pub fn new(initial_cpu: Option<usize>) -> Self {
        Self {
            initial_cpu,
            target_gen: AtomicU64::new(0),
            applied_gen: AtomicU64::new(0),
            wait_for_established: AtomicBool::new(false),
            established: AtomicBool::new(false),
            pending: Mutex::new(None),
        }
    }

    pub fn publish(&self, generation: u64, reload: Reload) {
        *self.pending.lock().expect("reload lock") = Some((generation, reload));
        self.target_gen.store(generation, Ordering::Release);
    }

    pub fn is_step_complete(&self, generation: u64) -> bool {
        self.applied_gen.load(Ordering::Acquire) == generation
            && (!self.wait_for_established.load(Ordering::Acquire)
                || self.established.load(Ordering::Acquire))
    }

    pub fn initial_cpu(&self) -> Option<usize> {
        self.initial_cpu
    }

    pub fn take_reload(&self, applied: u64) -> Option<(u64, Reload)> {
        if self.target_gen.load(Ordering::Acquire) == applied {
            return None;
        }
        self.pending.lock().expect("reload lock").take()
    }

    pub fn report(&self, generation: u64, established: bool, wait: bool) {
        self.wait_for_established.store(wait, Ordering::Release);
        self.established.store(established, Ordering::Release);
        self.applied_gen.store(generation, Ordering::Release);
    }

    pub fn wait_for_established(&self) -> bool {
        self.wait_for_established.load(Ordering::Relaxed)
    }
}

pub fn pin(id: usize, cpu: Option<usize>) {
    if let Some(target) = cpu {
        if let Err(e) = sys::pin_to_cpu(target) {
            log::warn!("worker {id}: cannot pin to CPU: {e}");
        }
    }
}

pub fn sync_tun_queue(id: usize, tun: BorrowedFd<'_>, attached: &mut bool, established: bool) {
    if *attached != established {
        match sys::set_tun_queue(tun, established) {
            Ok(()) => *attached = established,
            Err(e) => log::warn!("worker {id}: TUN queue attach={established}: {e}"),
        }
    }
}
