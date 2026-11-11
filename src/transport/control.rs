//! Worker thread control, CPU affinity, TUN queue synchronization, and rolling reload coordination.

use std::collections::VecDeque;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use std::time::Duration;

use crate::config::{AuthKey, Config, Tunables};
use crate::platform::{self, Waker};

pub struct Reload {
    pub tunables: Tunables,
    pub cpu: Option<usize>,
}

/// Bounded exponential retry backoff with uniform `[base / 2, base]` jitter (`0.5s..=30s`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Backoff {
    pub failures: u32,
}

impl Backoff {
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    pub fn delay(&mut self, sample: u32, reset: bool) -> std::time::Duration {
        if reset {
            self.failures = 0;
        }
        let base = [1, 2, 4, 8, 15, 30][self.failures.min(5) as usize];
        self.failures = self.failures.saturating_add(1);
        std::time::Duration::from_millis(base * 500 + u64::from(sample) % (base * 500 + 1))
    }
}

pub struct CoreTable {
    cores: Vec<(usize, usize)>,
}

impl CoreTable {
    pub fn new(cpus: &[usize]) -> Self {
        let mut cores = Vec::with_capacity(cpus.len());
        for &cpu in cpus {
            if !cores.iter().any(|&(c, _)| c == cpu) {
                cores.push((cpu, 0));
            }
        }
        Self { cores }
    }

    /// Selects the candidate core with the fewest bound workers (ties broken by list order)
    /// and increments its active count. When all cores have `count >= 1`, cores are reused.
    pub fn acquire(&mut self) -> Option<usize> {
        let (cpu, count) = self.cores.iter_mut().min_by_key(|(_, count)| *count)?;
        *count += 1;
        Some(*cpu)
    }

    pub fn release(&mut self, cpu: Option<usize>) {
        if let Some(target) = cpu
            && let Some((_, count)) = self.cores.iter_mut().find(|(c, _)| *c == target)
        {
            *count = count.saturating_sub(1);
        }
    }
}

pub fn candidate_cpus<'a>(cfg: &'a Config, default_cpus: &'a [usize]) -> &'a [usize] {
    cfg.tunables.cpus.as_deref().unwrap_or(default_cpus)
}

pub struct Control {
    initial_cpu: Option<usize>,
    wake: Waker,
    main_wake: Arc<Waker>,
    target_gen: AtomicU64,
    applied_gen: AtomicU64,
    wait_for_established: AtomicBool,
    established: AtomicBool,
    stopped: AtomicBool,
    send_rst: AtomicBool,
    exited: AtomicBool,
    pending: Mutex<Option<(u64, Reload)>>,
}

impl Control {
    pub fn new(initial_cpu: Option<usize>, main_wake: Arc<Waker>) -> Self {
        Self {
            initial_cpu,
            wake: Waker::new().expect("creating worker eventfd"),
            main_wake,
            target_gen: AtomicU64::new(0),
            applied_gen: AtomicU64::new(0),
            wait_for_established: AtomicBool::new(false),
            established: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            send_rst: AtomicBool::new(true),
            exited: AtomicBool::new(false),
            pending: Mutex::new(None),
        }
    }

    #[inline(always)]
    pub fn waker(&self) -> &Waker {
        &self.wake
    }

    #[inline]
    pub fn wake(&self) {
        self.wake.notify();
    }

    pub fn stop(&self, send_rst: bool) {
        self.send_rst.store(send_rst, Ordering::Relaxed);
        self.stopped.store(true, Ordering::Release);
        self.wake();
    }

    #[inline(always)]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn should_send_rst(&self) -> bool {
        self.send_rst.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn mark_exited(&self) {
        self.exited.store(true, Ordering::Release);
    }

    #[inline(always)]
    pub fn is_exited(&self) -> bool {
        self.exited.load(Ordering::Acquire)
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
                self.main_wake.notify();
            }
        }
    }

    #[inline(always)]
    pub fn wait_for_established(&self) -> bool {
        self.wait_for_established.load(Ordering::Relaxed)
    }
}

pub struct RollingReload {
    pub generation: u64,
    pub next_worker: usize,
    pub target: Tunables,
    pub cpus: Vec<Option<usize>>,
}

impl RollingReload {
    pub fn start(
        controls: &[Arc<Control>],
        cpus: Vec<Option<usize>>,
        generation: u64,
        target: Tunables,
    ) -> Option<Self> {
        let first = controls.first()?;
        first.publish(
            generation,
            Reload {
                tunables: target.clone(),
                cpu: cpus.first().copied().flatten(),
            },
        );
        Some(Self {
            generation,
            next_worker: 0,
            target,
            cpus,
        })
    }

    pub fn advance(controls: &[Arc<Control>], rolling: &mut Option<Self>) {
        while let Some(state) = rolling.as_mut() {
            if !controls[state.next_worker].is_step_complete(state.generation) {
                break;
            }
            state.next_worker += 1;
            if state.next_worker < controls.len() {
                controls[state.next_worker].publish(
                    state.generation,
                    Reload {
                        tunables: state.target.clone(),
                        cpu: state.cpus.get(state.next_worker).copied().flatten(),
                    },
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
    if let Some(target) = cpu
        && let Err(e) = platform::pin_to_cpu(target)
    {
        log::warn!("worker {id}: cannot pin to CPU: {e}");
    }
}

#[inline]
pub fn sync_tun_queue(id: usize, tun: BorrowedFd<'_>, attached: &mut bool, established: bool) {
    if *attached != established {
        match platform::tun::set_queue(tun, established) {
            Ok(()) => *attached = established,
            Err(e) => log::warn!("worker {id}: TUN queue attach={established}: {e}"),
        }
    }
}

/// Exit admission state shared by the listener, its workers, and the manager.
pub struct Admission<P> {
    pub key: AuthKey,
    /// Bumped on every key change, so a handshake begun under the old key is never admitted.
    pub epoch: u64,
    pub timeout: Duration,
    /// Authenticated peers waiting for the manager to spawn their worker.
    pub admitted: VecDeque<P>,
    main_wake: Arc<Waker>,
}

impl<P> Admission<P> {
    pub fn new(key: AuthKey, timeout: Duration, main_wake: Arc<Waker>) -> Self {
        Self {
            key,
            epoch: 0,
            timeout,
            admitted: VecDeque::new(),
            main_wake,
        }
    }

    pub fn reload(&mut self, tunables: &Tunables, key_changed: bool) {
        if key_changed {
            self.key = tunables.auth_key.clone();
            self.epoch += 1;
            self.admitted.clear();
        }
        self.timeout = tunables.dead_timeout;
    }

    pub fn admit(&mut self, peer: P) {
        self.admitted.push_back(peer);
        self.main_wake.notify();
    }
}

pub struct StopOnDrop(pub &'static AtomicBool, pub Arc<Waker>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
        self.1.notify();
    }
}

pub struct ExitWorkerGuard {
    pub stop: &'static AtomicBool,
    pub ctrl: Arc<Control>,
    pub main_wake: Arc<Waker>,
}

impl Drop for ExitWorkerGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.stop.store(true, Ordering::Relaxed);
        }
        self.ctrl.mark_exited();
        self.main_wake.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_table_picks_least_used_core_and_reuses_when_saturated() {
        let mut table = CoreTable::new(&[2, 4, 2, 6]);
        assert_eq!(table.acquire(), Some(2));
        assert_eq!(table.acquire(), Some(4));
        assert_eq!(table.acquire(), Some(6));
        // All cores have >= 1 worker bound; reuse starts from the least-used in order.
        assert_eq!(table.acquire(), Some(2));
        assert_eq!(table.acquire(), Some(4));
        // Releasing core 6 makes it the least-used (count 0 vs 2, 2).
        table.release(Some(6));
        assert_eq!(table.acquire(), Some(6));
        // Releasing core 4 once makes it count 1 vs core 2 (count 2) and core 6 (count 1);
        // tie breaks by candidate order (core 4 before core 6).
        table.release(Some(4));
        assert_eq!(table.acquire(), Some(4));
    }
}
