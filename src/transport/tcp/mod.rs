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

pub use connection::Connection;
pub use listener::{Listener, SharedExitState};
pub use worker::Worker;

const ROUNDS: usize = 4;
const BATCH: usize = 64;

#[inline]
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
