//! FakeTCP transport: per-worker raw-socket sessions that look like TCP to stateful firewalls.

mod auth;
mod filter;
mod frame;
mod session;
mod worker;

pub use worker::{Listener, SharedExitState, Worker};
