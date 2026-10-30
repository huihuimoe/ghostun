//! Kernel TCP transport: relay-compatible framed connections, one per worker.
//! Exit dispatches authenticated candidates to workers; there is no raw-socket or port steering.

mod auth;
mod connection;
mod frame;
mod listener;
mod queue;
#[cfg(test)]
mod tests;
mod worker;

use std::io;

use connection::Connection;

pub use listener::Listener;
pub use worker::Worker;

const ROUNDS: usize = 4;
const BATCH: usize = 64;

#[inline(always)]
const fn can_io(pfd: libc::pollfd, event: i16, ready: i16) -> bool {
    pfd.events & event == 0 || pfd.revents & ready != 0
}

#[inline]
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
