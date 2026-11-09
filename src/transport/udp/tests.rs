use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::auth::{self, CHALLENGE_LEN, FINISHED_LEN, HELLO_LEN, PROOF_LEN};
use super::session::{CTRL_PING, CTRL_PONG, RETRANSMIT_BASE, Session, SessionConfig, Sink, State};
use crate::config::{AuthKey, Mode};
use crate::net::{ipv4, ipv6};
use crate::transport::keepalive;

const ENTRY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 51000);
const EXIT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
const MTU: u16 = 1392;

#[derive(Default)]
struct Wire {
    frames: Vec<Vec<u8>>,
    rebinds: usize,
    next_port: u16,
}

impl Wire {
    fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.frames)
    }
}

impl Sink for Wire {
    fn send(&mut self, frame: &[u8]) {
        self.frames.push(frame.to_vec());
    }

    fn reset(&mut self) {
        self.frames.clear();
    }

    fn rebind(&mut self, default_local: SocketAddr) -> std::io::Result<SocketAddr> {
        self.reset();
        self.rebinds += 1;
        let port = if self.next_port == 0 {
            ENTRY_ADDR.port()
        } else {
            let p = self.next_port;
            self.next_port += 1;
            p
        };
        Ok(SocketAddr::new(default_local.ip(), port))
    }
}

fn key(byte: u8) -> AuthKey {
    AuthKey([byte; 32])
}

fn cfg(mode: Mode, auth_key: AuthKey, worker: u16, mtu: u16) -> SessionConfig {
    SessionConfig {
        mode,
        auth_key,
        local_ip: match mode {
            Mode::Entry => ENTRY_ADDR.ip(),
            Mode::Exit => EXIT_ADDR.ip(),
        },
        remote: (mode == Mode::Entry).then_some(EXIT_ADDR),
        listen_port: if mode == Mode::Exit {
            EXIT_ADDR.port()
        } else {
            0
        },
        worker,
        mtu,
        ping_interval: Duration::from_secs(5),
        dead_timeout: Duration::from_secs(15),
    }
}

fn inner_v4(payload: &[u8]) -> Vec<u8> {
    let total = ipv4::HDR_LEN + payload.len();
    let mut pkt = vec![0u8; total];
    ipv4::write_header(
        &mut pkt,
        total as u16,
        1,
        Ipv4Addr::new(10, 200, 0, 1),
        Ipv4Addr::new(10, 200, 0, 2),
    );
    pkt[ipv4::HDR_LEN..].copy_from_slice(payload);
    pkt
}

fn inner_v6(payload: &[u8]) -> Vec<u8> {
    let total = ipv6::HDR_LEN + payload.len();
    let mut pkt = vec![0u8; total];
    ipv6::write_header(
        &mut pkt,
        payload.len() as u16,
        Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2),
    );
    pkt[ipv6::HDR_LEN..].copy_from_slice(payload);
    pkt
}

fn pair(now: Instant) -> (Session, Session, Wire, Wire) {
    let mut entry = Session::new(cfg(Mode::Entry, key(7), 0, MTU), now, 1);
    let mut exit = Session::new(cfg(Mode::Exit, key(7), 0, MTU), now, 2);
    let mut entry_out = Wire::default();
    let mut exit_out = Wire::default();

    entry.start(now, &mut entry_out);
    assert_eq!(entry.state(), State::Authenticating);
    let hello = entry_out.take();
    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0].len(), HELLO_LEN);

    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &hello[0], &mut exit_out);
    assert_eq!(exit.state(), State::Closed);
    let challenge = exit_out.take();
    assert_eq!(challenge.len(), 1);
    assert_eq!(challenge[0].len(), CHALLENGE_LEN);

    assert!(entry.on_outer(now, &challenge[0], &mut entry_out).is_none());
    assert_eq!(entry.state(), State::Authenticating);
    let proof = entry_out.take();
    assert_eq!(proof.len(), 1);
    assert_eq!(proof[0].len(), PROOF_LEN);

    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &proof[0], &mut exit_out);
    assert_eq!(exit.state(), State::Established);
    let finished = exit_out.take();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].len(), FINISHED_LEN);

    assert!(entry.on_outer(now, &finished[0], &mut entry_out).is_none());
    assert_eq!(entry.state(), State::Established);
    assert!(entry_out.take().is_empty());
    (entry, exit, entry_out, exit_out)
}

#[test]
fn handshake_forwards_valid_dual_stack_packets_and_rejects_malformed_data() {
    let now = Instant::now();
    let (mut entry, mut exit, mut entry_out, mut exit_out) = pair(now);

    let v4 = inner_v4(b"hello over udp v4");
    let v6 = inner_v6(b"hello over udp v6");
    assert_eq!(
        exit.on_outer(now, &v4, &mut exit_out).unwrap(),
        v4.as_slice()
    );
    assert_eq!(
        entry.on_outer(now, &v6, &mut entry_out).unwrap(),
        v6.as_slice()
    );

    // Oversized or truncated inner IP packets are dropped without tearing down the session.
    let oversized = inner_v4(&vec![b'x'; usize::from(MTU)]);
    assert!(exit.on_outer(now, &oversized, &mut exit_out).is_none());
    assert!(
        exit.on_outer(now, &[0x45, 0, 0, 40], &mut exit_out)
            .is_none()
    );
    assert!(exit.is_established());
}

#[test]
fn wrong_key_mismatched_mtu_and_replayed_proof_are_rejected_and_preserve_active_session() {
    let now = Instant::now();
    let (mut entry, mut exit, mut entry_out, mut exit_out) = pair(now);

    // Wrong key cannot pass challenge verification or disturb the active Exit session.
    let mut bad_key = Session::new(cfg(Mode::Entry, key(9), 0, MTU), now, 3);
    let mut bad_out = Wire::default();
    bad_key.start(now, &mut bad_out);
    let bad_hello = bad_out.take().pop().unwrap();
    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &bad_hello, &mut exit_out);
    let challenge = exit_out.take().pop().unwrap();
    assert!(bad_key.on_outer(now, &challenge, &mut bad_out).is_none());
    assert!(bad_out.take().is_empty());
    assert_eq!(bad_key.state(), State::Authenticating);

    // Mismatched MTU is rejected at Hello without even issuing a Challenge.
    let mut bad_mtu = Session::new(cfg(Mode::Entry, key(7), 0, MTU - 20), now, 4);
    bad_mtu.start(now, &mut bad_out);
    let mtu_hello = bad_out.take().pop().unwrap();
    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &mtu_hello, &mut exit_out);
    assert!(exit_out.take().is_empty());

    // Active session still forwards data and responds to keepalive probes.
    let pkt = inner_v4(b"still alive");
    assert_eq!(
        exit.on_outer(now, &pkt, &mut exit_out).unwrap(),
        pkt.as_slice()
    );
    entry.on_tick(now + Duration::from_secs(5), &mut entry_out);
    let ping = entry_out.take().pop().unwrap();
    assert_eq!(ping[0], CTRL_PING);
    assert_eq!(ping.len(), keepalive::LEN);
    assert!(
        exit.on_outer(now + Duration::from_secs(5), &ping, &mut exit_out)
            .is_none()
    );
    let pong = exit_out.take().pop().unwrap();
    assert_eq!(pong[0], CTRL_PONG);
    assert!(
        entry
            .on_outer(now + Duration::from_secs(5), &pong, &mut entry_out)
            .is_none()
    );
}

#[test]
fn lost_finished_retransmits_cleanly_and_same_tuple_reconnect_recovers_in_place() {
    let now = Instant::now();
    let mut entry = Session::new(cfg(Mode::Entry, key(7), 0, MTU), now, 10);
    let mut exit = Session::new(cfg(Mode::Exit, key(7), 0, MTU), now, 20);
    let mut entry_out = Wire::default();
    let mut exit_out = Wire::default();

    entry.start(now, &mut entry_out);
    let hello = entry_out.take().pop().unwrap();
    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &hello, &mut exit_out);
    let challenge = exit_out.take().pop().unwrap();
    entry.on_outer(now, &challenge, &mut entry_out);
    let proof = entry_out.take().pop().unwrap();

    // Exit promotes and emits Finished, but Finished is lost on the wire.
    exit.on_auth_request(now, EXIT_ADDR, ENTRY_ADDR, &proof, &mut exit_out);
    assert_eq!(exit.state(), State::Established);
    let lost_finished = exit_out.take().pop().unwrap();

    // Entry retransmits Proof after RETRANSMIT_BASE; Exit re-emits the identical Finished.
    entry.on_tick(now + RETRANSMIT_BASE, &mut entry_out);
    let retried_proof = entry_out.take().pop().unwrap();
    assert_eq!(retried_proof, proof);
    exit.on_auth_request(
        now + RETRANSMIT_BASE,
        EXIT_ADDR,
        ENTRY_ADDR,
        &retried_proof,
        &mut exit_out,
    );
    let resent_finished = exit_out.take().pop().unwrap();
    assert_eq!(resent_finished, lost_finished);
    entry.on_outer(now + RETRANSMIT_BASE, &resent_finished, &mut entry_out);
    assert_eq!(entry.state(), State::Established);

    // Relay/NAT scenario: Entry restarts on the exact same 4-tuple while Exit is still Established.
    let mut restarted = Session::new(cfg(Mode::Entry, key(7), 0, MTU), now, 30);
    restarted.start(now + Duration::from_secs(2), &mut entry_out);
    let new_hello = entry_out.take().pop().unwrap();
    exit.on_auth_request(
        now + Duration::from_secs(2),
        EXIT_ADDR,
        ENTRY_ADDR,
        &new_hello,
        &mut exit_out,
    );
    assert_eq!(exit.state(), State::Established);
    let new_challenge = exit_out.take().pop().unwrap();
    restarted.on_outer(now + Duration::from_secs(2), &new_challenge, &mut entry_out);
    let new_proof = entry_out.take().pop().unwrap();

    // Spoofed/corrupted proof from same tuple must not tear down Exit.
    let mut bad_proof = new_proof.clone();
    *bad_proof.last_mut().unwrap() ^= 1;
    exit.on_auth_request(
        now + Duration::from_secs(2),
        EXIT_ADDR,
        ENTRY_ADDR,
        &bad_proof,
        &mut exit_out,
    );
    assert!(exit_out.take().is_empty());
    assert_eq!(exit.state(), State::Established);

    // Valid proof completes takeover in place.
    exit.on_auth_request(
        now + Duration::from_secs(2),
        EXIT_ADDR,
        ENTRY_ADDR,
        &new_proof,
        &mut exit_out,
    );
    let new_finished = exit_out.take().pop().unwrap();
    restarted.on_outer(now + Duration::from_secs(2), &new_finished, &mut entry_out);
    assert_eq!(restarted.state(), State::Established);
}

#[test]
fn timeout_and_key_reload_rebind_entry_port_and_reauthenticate() {
    let now = Instant::now();
    let (mut entry, mut exit, mut entry_out, mut exit_out) = pair(now);
    entry_out.next_port = 52000;

    // Silence past dead_timeout triggers immediate reconnect on a new ephemeral port.
    let t = now + Duration::from_secs(15);
    entry.on_tick(t, &mut entry_out);
    assert_eq!(entry.state(), State::Authenticating);
    assert_eq!(entry.local().port(), 52000);
    assert_eq!(entry_out.take().len(), 1);

    // If that attempt times out without a reply, Entry backs off and closes until retry_at.
    let t2 = t + Duration::from_secs(15);
    entry.on_tick(t2, &mut entry_out);
    assert_eq!(entry.state(), State::Closed);

    // Key reload resets backoff and starts a fresh handshake with the new key.
    assert!(!entry.reload(
        t2,
        key(42),
        Duration::from_secs(5),
        Duration::from_secs(15),
        &mut entry_out,
    ));
    assert!(exit.reload(
        t2,
        key(42),
        Duration::from_secs(5),
        Duration::from_secs(15),
        &mut exit_out,
    ));
    assert_eq!(exit.state(), State::Closed);
    let hello = entry_out.take().pop().unwrap();
    assert_eq!(hello[0], auth::CONTROL);
}
