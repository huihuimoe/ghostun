// Off Linux only the placeholder platform exists, so FakeTCP-only helpers are unused there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod app;
mod config;
mod net;
#[cfg(target_os = "linux")]
mod netfilter;
mod platform;
mod transport;

use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match config::load().and_then(app::run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}
