//! Readiness polling over a small, index-addressed set of sources.

use std::io;
use std::ops::BitOr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::{READ_READY, WRITE_READY, Waker};

#[derive(Clone, Copy)]
pub struct Interest(i16);

impl Interest {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(libc::POLLIN);
    pub const WRITE: Self = Self(libc::POLLOUT);

    #[inline(always)]
    pub const fn when(self, wanted: bool) -> Self {
        if wanted { self } else { Self::NONE }
    }
}

impl BitOr for Interest {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Slots are addressed by the index [`Poller::add`] returned. An unbound slot is skipped by
/// [`Poller::wait`] and reports no readiness.
#[derive(Default)]
pub struct Poller {
    fds: Vec<libc::pollfd>,
}

impl Poller {
    pub fn add(&mut self, source: &impl AsRawFd, interest: Interest) -> usize {
        self.fds.push(super::pollfd(source.as_raw_fd(), interest.0));
        self.fds.len() - 1
    }

    /// Appends an unbound slot for a source that comes and goes.
    pub fn reserve(&mut self) -> usize {
        self.fds.push(super::pollfd(-1, 0));
        self.fds.len() - 1
    }

    #[inline]
    pub fn bind(&mut self, slot: usize, source: &impl AsRawFd, interest: Interest) {
        self.fds[slot].fd = source.as_raw_fd();
        self.fds[slot].events = interest.0;
    }

    /// Also forgets the readiness last reported for the slot.
    #[inline]
    pub fn unbind(&mut self, slot: usize) {
        self.fds[slot] = super::pollfd(-1, 0);
    }

    #[inline]
    pub fn set(&mut self, slot: usize, interest: Interest) {
        self.fds[slot].events = interest.0;
    }

    pub fn truncate(&mut self, len: usize) {
        self.fds.truncate(len);
    }

    pub fn swap_remove(&mut self, slot: usize) {
        self.fds.swap_remove(slot);
    }

    /// `None` waits indefinitely. Sub-millisecond waits round up so callers never wake just before
    /// a deadline and spin. Returns `false`, with no readiness reported, when a signal interrupted.
    #[inline]
    pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        let polled = super::poll(&mut self.fds, timeout.map_or(-1, super::poll_ms))?;
        if !polled {
            self.fds.iter_mut().for_each(|fd| fd.revents = 0);
        }
        Ok(polled)
    }

    #[inline(always)]
    pub fn is_bound(&self, slot: usize) -> bool {
        self.fds[slot].fd >= 0
    }

    /// Any readiness at all, including errors and hangup.
    #[inline(always)]
    pub fn fired(&self, slot: usize) -> bool {
        self.fds[slot].revents != 0
    }

    /// Data is waiting; unlike [`Self::read_ready`], an error or hangup alone does not count.
    #[inline(always)]
    pub fn readable(&self, slot: usize) -> bool {
        self.fds[slot].revents & libc::POLLIN != 0
    }

    #[inline(always)]
    pub fn read_ready(&self, slot: usize) -> bool {
        self.fds[slot].revents & READ_READY != 0
    }

    #[inline(always)]
    pub fn write_ready(&self, slot: usize) -> bool {
        self.fds[slot].revents & WRITE_READY != 0
    }

    /// Whether a read is worth attempting: the slot reported [`Self::read_ready`], or reads were
    /// not asked about and so must be tried.
    #[inline(always)]
    pub fn can_read(&self, slot: usize) -> bool {
        self.fds[slot].events & libc::POLLIN == 0 || self.read_ready(slot)
    }

    #[inline(always)]
    pub fn can_write(&self, slot: usize) -> bool {
        self.fds[slot].events & libc::POLLOUT == 0 || self.write_ready(slot)
    }

    /// Drains `waker` when its slot is readable.
    #[inline]
    pub fn woken(&self, slot: usize, waker: &Waker) -> bool {
        let ready = self.readable(slot);
        if ready {
            waker.drain();
        }
        ready
    }
}
