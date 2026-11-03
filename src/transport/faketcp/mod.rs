//! FakeTCP transport: per-worker raw-socket sessions that look like TCP to stateful firewalls.

mod auth;
mod filter;
mod frame;
mod queue;
mod session;
mod tun_driver;
mod worker;

pub use session::Promoted;
pub use worker::{Listener, SharedExitState, Worker};
