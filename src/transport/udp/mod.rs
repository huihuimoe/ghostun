//! Kernel UDP transport: 0-byte data framing, stateless-cookie mutual authentication,
//! and per-worker connected UDP sockets steered by the kernel.

mod auth;
mod session;
mod worker;

#[cfg(test)]
mod tests;

/// Outer UDP header length in bytes; inner IP packets carry no additional framing header.
pub const OVERHEAD: usize = 8;

pub use worker::{Listener, SharedExitState, Worker};
