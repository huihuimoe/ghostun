//! Process signals: SIGINT/SIGTERM request shutdown, SIGHUP requests a configuration reload.

use std::io;
use std::mem::zeroed;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use super::{Waker, cvt, notify};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::Relaxed);
    } else {
        STOP.store(true, Ordering::Relaxed);
    }
    notify(WAKE.load(Ordering::Relaxed));
}

pub struct Signals {
    waker: Arc<Waker>,
}

/// Installs the handlers; every signal also notifies the returned [`Signals::waker`].
pub fn install() -> io::Result<Signals> {
    let waker = Arc::new(Waker::new()?);
    WAKE.store(waker.as_raw_fd(), Ordering::Relaxed);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `sigaction` is zero-initialized and populated with a valid C signal handler.
        unsafe {
            let mut sa: libc::sigaction = zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            cvt(libc::sigaction(sig, &sa, std::ptr::null_mut()))?;
        }
    }
    Ok(Signals { waker })
}

impl Signals {
    /// Set by SIGINT/SIGTERM; workers also set it to bring the whole process down.
    pub fn stop(&self) -> &'static AtomicBool {
        &STOP
    }

    pub fn take_reload(&self) -> bool {
        RELOAD.swap(false, Ordering::Relaxed)
    }

    pub fn waker(&self) -> &Arc<Waker> {
        &self.waker
    }
}
