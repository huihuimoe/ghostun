use super::pkt::Parsed;
use super::*;
use std::net::Ipv4Addr;

const ENTRY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const EXIT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
const MS: Duration = Duration::from_millis(1);

#[derive(Default)]
struct Wire(Vec<Vec<u8>>, usize);

impl Sink for Wire {
    fn reset(&mut self) {
        self.1 += 1;
    }
    fn send(&mut self, frame: &[u8], _dst: IpAddr) {
        assert!(
            (frame[0] >> 4 == 6 || pkt::ipv4_header_checksum_ok(frame))
                && pkt::tcp_checksum_ok(frame)
        );
        self.0.push(frame.to_vec());
    }
}

impl Wire {
    fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0)
    }
}

fn parsed(f: &[u8]) -> Parsed<'_> {
    pkt::parse(f).unwrap()
}

fn cfg(mode: Mode, worker: u16, conns: u16) -> SessionConfig {
    SessionConfig {
        mode,
        auth_key: AuthKey([0xa7; 32]),
        local_ip: if mode == Mode::Entry {
            ENTRY_IP
        } else {
            EXIT.ip()
        },
        remote: (mode == Mode::Entry).then_some(EXIT),
        listen_port: EXIT.port(),
        worker,
        conns,
        base_port: 32768,
        mss: 1460,
        ping_interval: Duration::from_secs(5),
        dead_timeout: Duration::from_secs(15),
    }
}

/// Entry + exit connected through an in-memory wire.
struct Pair {
    t: Instant,
    entry: Session,
    exit: Session,
}

impl Pair {
    fn new(worker: u16, conns: u16, seed: u64) -> Self {
        let t = Instant::now();
        Pair {
            t,
            entry: Session::new(cfg(Mode::Entry, worker, conns), t, seed).unwrap(),
            exit: Session::new(cfg(Mode::Exit, worker, conns), t, seed + 1).unwrap(),
        }
    }

    /// Delivers frames back and forth until quiet; returns inner packets seen as (to_exit, to_entry).
    fn pump(&mut self, mut to_exit: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut at_exit, mut at_entry) = (Vec::new(), Vec::new());
        while !to_exit.is_empty() {
            let mut back = Wire::default();
            for f in &to_exit {
                if let Some(inner) = self.exit.on_outer(self.t, f, &mut back) {
                    at_exit.push(inner.to_vec());
                }
            }
            let mut fwd = Wire::default();
            for f in back.take() {
                if let Some(inner) = self.entry.on_outer(self.t, &f, &mut fwd) {
                    at_entry.push(inner.to_vec());
                }
            }
            to_exit = fwd.take();
        }
        (at_exit, at_entry)
    }

    fn connect(&mut self) -> TcpMeta {
        let mut w = Wire::default();
        self.entry.start(self.t, &mut w);
        let syn = parsed(&w.0[0]).meta;
        self.pump(w.take());
        assert_eq!(self.entry.state(), State::Established);
        assert_eq!(self.exit.state(), State::Established);
        syn
    }
}

fn encap(s: &mut Session, inner: &[u8], overhead: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; overhead + inner.len()];
    buf[overhead..].copy_from_slice(inner);
    s.encap(&mut buf, inner.len())
        .map(|(len, _)| buf[..len].to_vec())
}

struct AuthExchange {
    syn: Vec<u8>,
    ack: Vec<u8>,
    hello: Vec<u8>,
    challenge: Vec<u8>,
}

fn start_auth(entry: &mut Session, exit: &mut Session, now: Instant) -> AuthExchange {
    let mut wire = Wire::default();
    entry.start(now, &mut wire);
    let syn = wire.take().remove(0);
    exit.on_outer(now, &syn, &mut wire);
    let syn_ack = wire.take().remove(0);
    entry.on_outer(now, &syn_ack, &mut wire);
    let mut frames = wire.take();
    let ack = frames.remove(0);
    let hello = frames.remove(0);
    exit.on_outer(now, &ack, &mut wire);
    exit.on_outer(now, &hello, &mut wire);
    let challenge = wire.take().remove(0);
    AuthExchange {
        syn,
        ack,
        hello,
        challenge,
    }
}

fn frame(meta: TcpMeta, payload: &[u8]) -> Vec<u8> {
    let overhead = OuterFamily::of(meta.src.ip()).overhead();
    let mut buf = vec![0; overhead + payload.len()];
    buf[overhead..].copy_from_slice(payload);
    pkt::write_headers(&mut buf, &meta, payload.len(), 0);
    buf
}

#[test]
fn old_proofs_fail_against_a_fresh_handshake_and_challenge() {
    let mut pair = Pair::new(0, 1, 91);
    let first = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let mut wire = Wire::default();
    pair.entry.on_outer(pair.t, &first.challenge, &mut wire);
    let old_proof = wire.take().remove(0);
    pair.t += Duration::from_secs(1);
    pair.entry = Session::new(cfg(Mode::Entry, 0, 1), pair.t, 92).unwrap();
    let second = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let stale_reply = frame(
        parsed(&second.challenge).meta,
        parsed(&first.challenge).payload,
    );
    pair.entry.on_outer(pair.t, &stale_reply, &mut wire);
    assert!(wire.take().is_empty());
    pair.entry.on_outer(pair.t, &second.challenge, &mut wire);
    let proof = wire.take().remove(0);
    let replay = frame(parsed(&proof).meta, parsed(&old_proof).payload);
    pair.exit.on_outer(pair.t, &replay, &mut wire);
    assert!(wire.take().is_empty());
    assert!(encap(&mut pair.exit, &[0x45; 20], 40).is_none());
    let mut body = parsed(&proof).payload.to_vec();
    body[147..].copy_from_slice(&parsed(&old_proof).payload[147..]);
    pair.exit
        .on_outer(pair.t, &frame(parsed(&proof).meta, &body), &mut wire);
    assert!(wire.take().is_empty());
    pair.pump(vec![proof]);
    let data = encap(&mut pair.entry, &[0x45; 20], 40).unwrap();
    assert_eq!(
        pair.exit.on_outer(pair.t, &data, &mut wire),
        Some(&[0x45; 20][..])
    );
}

#[test]
fn finished_received_at_or_after_the_attempt_deadline_cannot_authorize() {
    for delay in [
        Duration::from_secs(15) - MS,
        Duration::from_secs(15),
        Duration::from_secs(16),
    ] {
        let mut pair = Pair::new(0, 1, 111);
        let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
        let mut wire = Wire::default();
        pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
        let proof = wire.take().remove(0);
        pair.exit.on_outer(pair.t, &proof, &mut wire);
        let finished = wire.take().remove(0);
        pair.entry.on_outer(pair.t + delay, &finished, &mut wire);
        let data = encap(&mut pair.entry, &[0x45; 20], 40);
        if delay < Duration::from_secs(15) {
            assert!(data.is_some());
        } else {
            assert!(
                data.is_none(),
                "receive processing must enforce the deadline before on_tick"
            );
            let outgoing = wire.take();
            let syn = outgoing
                .iter()
                .find(|f| parsed(f).meta.flags == flags::SYN)
                .unwrap();
            assert_ne!(parsed(syn).meta.src.port(), parsed(&proof).meta.src.port());
        }
    }
}

#[test]
fn authentication_timeout_rotates_the_port_and_expired_cookies_cannot_admit() {
    let mut pair = Pair::new(0, 1, 101);
    let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let mut wire = Wire::default();
    pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
    let proof = wire.take().remove(0);
    let old = parsed(&proof).meta;
    pair.entry.on_outer(
        pair.t + Duration::from_secs(14),
        &exchange.challenge,
        &mut wire,
    );
    assert!(wire.take().is_empty());
    pair.entry
        .on_tick(pair.t + Duration::from_secs(15), &mut wire);
    let retry = wire.take();
    let syn = retry
        .iter()
        .find(|f| parsed(f).meta.flags == flags::SYN)
        .unwrap();
    assert_ne!(parsed(syn).meta.src.port(), old.src.port());
    assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
    pair.exit
        .on_outer(pair.t + Duration::from_secs(30) + MS, &proof, &mut wire);
    assert!(wire.take().is_empty());
    assert!(encap(&mut pair.exit, &[0x45; 20], 40).is_none());
    pair.t += Duration::from_secs(31);
    pair.entry = Session::new(cfg(Mode::Entry, 0, 1), pair.t, 102).unwrap();
    pair.connect();
    let data = encap(&mut pair.entry, &[0x45; 20], 40).unwrap();
    assert_eq!(
        pair.exit.on_outer(pair.t, &data, &mut wire),
        Some(&[0x45; 20][..])
    );
}

#[test]
fn each_lost_authentication_message_recovers_without_reconsuming_sequence_space() {
    use std::collections::{BTreeMap, VecDeque};
    for lost_kind in [auth::HELLO, auth::CHALLENGE, auth::PROOF, auth::FINISHED] {
        let mut pair = Pair::new(0, 1, 81);
        let mut wire = Wire::default();
        pair.entry.start(pair.t, &mut wire);
        let syn = wire.take().remove(0);
        let entry_isn = parsed(&syn).meta.seq;
        let mut exit_isn = None;
        let mut queue = VecDeque::from([(true, syn)]);
        let mut dropped = false;
        let mut requests = BTreeMap::new();
        let mut proof = None;
        for round in 0..3 {
            let now = pair.t + Duration::from_secs(round);
            let mut count = 0;
            while let Some((to_exit, packet)) = queue.pop_front() {
                count += 1;
                assert!(count < 100, "authentication must not form a response loop");
                let p = parsed(&packet);
                if p.meta.flags == flags::SYN | flags::ACK {
                    exit_isn = Some(p.meta.seq);
                }
                if p.payload.first() == Some(&auth::CONTROL) {
                    let kind = p.payload[2];
                    if to_exit {
                        let value = (p.meta, p.payload.to_vec());
                        if let Some(previous) = requests.insert(kind, value.clone()) {
                            assert_eq!(previous, value);
                        }
                        if kind == auth::PROOF {
                            proof = Some(packet.clone());
                        }
                    }
                    if kind == lost_kind && !dropped {
                        dropped = true;
                        continue;
                    }
                }
                if to_exit {
                    pair.exit.on_outer(now, &packet, &mut wire);
                } else {
                    pair.entry.on_outer(now, &packet, &mut wire);
                }
                queue.extend(wire.take().into_iter().map(|f| (!to_exit, f)));
            }
            pair.entry.on_tick(now + SYN_RETRY, &mut wire);
            queue.extend(wire.take().into_iter().map(|f| (true, f)));
        }
        assert!(dropped);
        pair.t += Duration::from_secs(3);
        let first = encap(&mut pair.entry, &[0x45; 100], 40).unwrap();
        let back = encap(&mut pair.exit, &[0x60; 80], 40).unwrap();
        assert_eq!(parsed(&first).meta.seq, entry_isn.wrapping_add(215));
        assert_eq!(parsed(&back).meta.seq, exit_isn.unwrap().wrapping_add(191));
        assert_eq!(
            pair.exit.on_outer(pair.t, &first, &mut wire),
            Some(&[0x45; 100][..])
        );
        assert_eq!(
            pair.entry.on_outer(pair.t, &back, &mut wire),
            Some(&[0x60; 80][..])
        );
        pair.exit.on_outer(pair.t, &proof.unwrap(), &mut wire);
        for duplicate in wire.take() {
            pair.entry.on_outer(pair.t, &duplicate, &mut wire);
        }
        let after = encap(&mut pair.entry, &[0x45; 1], 40).unwrap();
        assert_eq!(
            parsed(&after).meta.seq,
            parsed(&first).meta.seq.wrapping_add(100)
        );
        assert_eq!(
            parsed(&after).meta.ack,
            parsed(&back).meta.seq.wrapping_add(80)
        );
    }
}

#[test]
fn legitimate_replacement_survives_unrelated_attempts_and_old_proof_replays() {
    let mut pair = Pair::new(0, 1, 71);
    let original = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let mut wire = Wire::default();
    pair.entry.on_outer(pair.t, &original.challenge, &mut wire);
    let old_proof = wire.take().remove(0);
    pair.pump(vec![old_proof.clone()]);
    let mut config = cfg(Mode::Entry, 0, 1);
    config.local_ip = "203.0.113.7".parse().unwrap();
    let mut replacement = Session::new(config, pair.t, 72).unwrap();
    let now = pair.t + Duration::from_secs(1);
    let exchange = start_auth(&mut replacement, &mut pair.exit, now);
    replacement.on_outer(now, &exchange.challenge, &mut wire);
    let proof = wire.take().remove(0);
    for i in 0..128 {
        let mut wrong = cfg(Mode::Entry, 0, 1);
        wrong.local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20 + i));
        wrong.auth_key = AuthKey([0xb8; 32]);
        let mut wrong = Session::new(wrong, now, u64::from(i) + 100).unwrap();
        let attempt = start_auth(&mut wrong, &mut pair.exit, now);
        wrong.on_outer(now, &attempt.challenge, &mut wire);
        assert!(wire.take().is_empty());
        let data = encap(&mut pair.exit, &[0x45; 20], 40).unwrap();
        assert_eq!(
            pair.entry.on_outer(now, &data, &mut wire),
            Some(&[0x45; 20][..])
        );
    }
    let old_generation = pair.exit.generation();
    let old_resets = wire.1;
    pair.exit.on_outer(now, &proof, &mut wire);
    assert!(pair.exit.is_established());
    assert_ne!(pair.exit.generation(), old_generation);
    assert_eq!(wire.1, old_resets + 1);
    let mut promoted = wire.take();
    let resets: Vec<_> = promoted
        .iter()
        .filter(|f| parsed(f).meta.flags & flags::RST != 0)
        .collect();
    assert_eq!(
        resets.len(),
        2,
        "verified replacement must release the old firewall tuple"
    );
    assert!(resets
        .iter()
        .all(|f| parsed(f).meta.dst == parsed(&original.syn).meta.src));
    let finished = promoted.pop().unwrap();
    replacement.on_outer(now, &finished, &mut wire);
    wire.take();
    let inner = [0x60; 40];
    let data = encap(&mut replacement, &inner, 40).unwrap();
    assert_eq!(pair.exit.on_outer(now, &data, &mut wire), Some(&inner[..]));
    pair.exit.on_outer(now, &old_proof, &mut wire);
    pair.exit.on_outer(now, &original.hello, &mut wire);
    wire.take();
    let reply = encap(&mut pair.exit, &inner, 40).unwrap();
    assert_eq!(parsed(&reply).meta.dst, parsed(&proof).meta.src);
    assert_eq!(
        replacement.on_outer(now, &reply, &mut wire),
        Some(&inner[..])
    );
}

#[test]
fn unauthenticated_candidates_cannot_replace_or_keep_an_active_peer_alive() {
    let mut pair = Pair::new(0, 1, 61);
    let original = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let mut wire = Wire::default();
    pair.entry.on_outer(pair.t, &original.challenge, &mut wire);
    let proof = wire.take().remove(0);
    pair.pump(vec![proof.clone()]);
    let before = parsed(&encap(&mut pair.exit, &[0x45; 7], 40).unwrap()).meta;
    let mut candidate = cfg(Mode::Entry, 0, 1);
    candidate.local_ip = "192.0.2.77".parse().unwrap();
    candidate.auth_key = AuthKey([0xb8; 32]);
    let mut candidate = Session::new(candidate, pair.t, 62).unwrap();
    let now = pair.t + Duration::from_secs(14);
    let exchange = start_auth(&mut candidate, &mut pair.exit, now);
    candidate.on_outer(now, &exchange.challenge, &mut wire);
    assert!(wire.take().is_empty());
    for packet in [
        &original.syn,
        &original.ack,
        &original.hello,
        &proof,
        &exchange.hello,
    ] {
        assert!(pair.exit.on_outer(now, packet, &mut wire).is_none());
        wire.take();
    }
    let mut invalid = parsed(&proof).payload.to_vec();
    invalid[178] ^= 1;
    assert!(pair
        .exit
        .on_outer(now, &frame(parsed(&proof).meta, &invalid), &mut wire)
        .is_none());
    assert!(pair
        .exit
        .on_outer(
            now,
            &frame(parsed(&exchange.hello).meta, &[0x45; 20]),
            &mut wire
        )
        .is_none());
    let after = encap(&mut pair.exit, &[0x60; 40], 40).unwrap();
    assert_eq!(parsed(&after).meta.dst, before.dst);
    assert_eq!(parsed(&after).meta.seq, before.seq.wrapping_add(7));
    assert_eq!(
        pair.entry.on_outer(now, &after, &mut wire),
        Some(&[0x60; 40][..])
    );
    pair.exit
        .on_tick(pair.t + Duration::from_secs(15), &mut wire);
    assert!(
        encap(&mut pair.exit, &[0x45; 20], 40).is_none(),
        "candidate traffic must not postpone active expiry"
    );
    pair.exit
        .on_outer(pair.t + Duration::from_secs(16), &proof, &mut wire);
    assert!(
        encap(&mut pair.exit, &[0x45; 20], 40).is_none(),
        "a completed proof must not resurrect an expired peer"
    );
}

#[test]
fn invalid_or_reflected_proofs_cannot_authorize_either_role() {
    let mut pair = Pair::new(0, 1, 51);
    let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let challenge = parsed(&exchange.challenge);
    let mut malformed = Vec::new();
    for index in [1, 2, 19, 146] {
        let mut body = challenge.payload.to_vec();
        body[index] ^= 0xff;
        malformed.push(body);
    }
    malformed.push(challenge.payload[..146].to_vec());
    malformed.push([challenge.payload, &[0]].concat());
    let mut wire = Wire::default();
    for body in malformed {
        pair.entry
            .on_outer(pair.t, &frame(challenge.meta, &body), &mut wire);
        assert!(wire.take().is_empty());
        assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
    }
    pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
    let proof = wire.take().remove(0);
    let request = parsed(&proof);
    let mut reflected = request.payload.to_vec();
    reflected[147..179].copy_from_slice(&request.payload[115..147]);
    let mut malformed = vec![
        reflected,
        request.payload[..178].to_vec(),
        [request.payload, &[0]].concat(),
    ];
    for index in [1, 2, 3, 11, 51, 83, 178] {
        let mut body = request.payload.to_vec();
        body[index] ^= 0xff;
        malformed.push(body);
    }
    for body in malformed {
        assert!(pair
            .exit
            .on_outer(pair.t, &frame(request.meta, &body), &mut wire)
            .is_none());
        assert!(wire.take().is_empty());
        assert!(encap(&mut pair.exit, &[0x60; 40], 40).is_none());
    }
    assert!(pair
        .exit
        .on_outer(pair.t, &frame(request.meta, &[0x45; 20]), &mut wire)
        .is_none());
    wire.take();
    pair.exit.on_outer(pair.t, &proof, &mut wire);
    let finished = wire.take().remove(0);
    let parsed_finished = parsed(&finished);
    let mut bad = parsed_finished.payload.to_vec();
    bad[11..].copy_from_slice(&request.payload[147..]);
    pair.entry
        .on_outer(pair.t, &frame(parsed_finished.meta, &bad), &mut wire);
    assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
    pair.entry.on_outer(pair.t, &finished, &mut wire);
    let inner = [0x45; 20];
    let packet = encap(&mut pair.entry, &inner, 40).unwrap();
    assert_eq!(
        pair.exit.on_outer(pair.t, &packet, &mut wire),
        Some(&inner[..])
    );
}

#[test]
fn mismatched_keys_deny_forwarding_in_both_directions() {
    let mut pair = Pair::new(0, 1, 41);
    let mut wrong = cfg(Mode::Entry, 0, 1);
    wrong.auth_key = AuthKey([0xb8; 32]);
    pair.entry = Session::new(wrong, pair.t, 41).unwrap();
    let exchange = start_auth(&mut pair.entry, &mut pair.exit, pair.t);
    let mut wire = Wire::default();
    pair.entry.on_outer(pair.t, &exchange.challenge, &mut wire);
    assert!(
        wire.take().is_empty(),
        "Entry must not prove itself to an untrusted Exit"
    );
    assert!(encap(&mut pair.entry, &[0x45; 20], 40).is_none());
    assert!(encap(&mut pair.exit, &[0x60; 40], 40).is_none());
    pair.entry
        .on_tick(pair.t + Duration::from_secs(15), &mut wire);
    assert!(wire
        .take()
        .iter()
        .any(|f| parsed(f).meta.flags == flags::SYN));
}

#[test]
fn entry_source_port_stays_in_worker_residue_class() {
    for seed in 0..50 {
        let t = Instant::now();
        let mut s = Session::new(cfg(Mode::Entry, 3, 4), t, seed * 7919).unwrap();
        let mut w = Wire::default();
        s.start(t, &mut w);
        let port = parsed(&w.take()[0]).meta.src.port();
        assert_eq!(port % 4, 3);
        assert!(port >= 32768);
    }
}

#[test]
fn handshake_options_are_preserved_but_forwarding_requires_mutual_authentication() {
    let mut p = Pair::new(1, 4, 42);
    let mut w = Wire::default();
    p.entry.start(p.t, &mut w);
    let syn = w.take();
    let s = parsed(&syn[0]);
    assert_eq!(s.meta.flags, flags::SYN);
    assert_eq!(s.meta.dst, EXIT);
    assert_eq!(syn[0].len(), pkt::SYN_FRAME_LEN);
    assert_eq!(p.entry.state(), State::SynSent);

    let mut w = Wire::default();
    assert!(p.exit.on_outer(p.t, &syn[0], &mut w).is_none());
    assert!(encap(&mut p.exit, &[0x45; 20], 40).is_none());
    let synack = w.take();
    let sa = parsed(&synack[0]);
    assert_eq!(sa.meta.flags, flags::SYN | flags::ACK);
    assert_eq!(sa.meta.ack, s.meta.seq.wrapping_add(1));
    assert_eq!(sa.meta.dst, s.meta.src);

    let mut w = Wire::default();
    p.entry.on_outer(p.t, &synack[0], &mut w);
    assert!(encap(&mut p.entry, &[0x45; 20], 40).is_none());
    let ack = w.take();
    assert_eq!(parsed(&ack[0]).meta.flags, flags::ACK);
    p.pump(ack);
    assert_eq!(p.entry.state(), State::Established);
    assert_eq!(p.exit.state(), State::Established);
    let reply = encap(&mut p.exit, &[0x45; 20], 40).unwrap();
    assert_eq!(parsed(&reply).meta.dst, s.meta.src);
    assert_eq!(
        p.entry.on_outer(p.t, &reply, &mut Wire::default()),
        Some(&[0x45; 20][..])
    );
}

#[test]
fn inner_dual_stack_flows_over_both_outer_families_without_extra_control() {
    for ipv6 in [false, true] {
        let mut p = Pair::new(0, 2, 7);
        if ipv6 {
            let mut entry = cfg(Mode::Entry, 0, 2);
            entry.local_ip = "2001:db8:1::1".parse().unwrap();
            entry.remote = Some("[2001:db8:2::1]:443".parse().unwrap());
            let mut exit = cfg(Mode::Exit, 0, 2);
            exit.local_ip = "::".parse().unwrap();
            p.entry = Session::new(entry, p.t, 7).unwrap();
            p.exit = Session::new(exit, p.t, 8).unwrap();
        }
        p.connect();
        let overhead = if ipv6 { 60 } else { 40 };
        let v4 = [0x45, 0, 0, 20, 1, 2, 3];
        let v6 = [0x60, 0, 0, 0, 9];
        let f4 = encap(&mut p.entry, &v4, overhead).unwrap();
        assert_eq!(f4.len(), v4.len() + overhead);
        let f6 = encap(&mut p.entry, &v6, overhead).unwrap();
        let (at_exit, _) = p.pump(vec![f4, f6]);
        assert_eq!(at_exit, vec![v4.to_vec(), v6.to_vec()]);
        let back = encap(&mut p.exit, &v6, overhead).unwrap();
        let mut w = Wire::default();
        assert_eq!(p.entry.on_outer(p.t, &back, &mut w), Some(&v6[..]));
        assert!(w.0.is_empty(), "no reply below ACK threshold");
    }
}

#[test]
fn sequence_numbers_advance_by_payload_and_ack_tracks_peer() {
    let mut p = Pair::new(0, 1, 3);
    p.connect();
    let a = parsed(&encap(&mut p.entry, &[0x45; 100], 40).unwrap()).meta;
    let b = parsed(&encap(&mut p.entry, &[0x45; 10], 40).unwrap()).meta;
    assert_eq!(b.seq, a.seq.wrapping_add(100));
    let from_exit = encap(&mut p.exit, &[0x60; 30], 40).unwrap();
    let exit_seq = parsed(&from_exit).meta.seq;
    p.entry.on_outer(p.t, &from_exit, &mut Wire::default());
    let c = parsed(&encap(&mut p.entry, &[0x45; 1], 40).unwrap()).meta;
    assert_eq!(c.ack, exit_seq.wrapping_add(30));
    assert_eq!(c.flags, flags::PSH | flags::ACK);
}

#[test]
fn encap_drops_until_established() {
    let mut s = Session::new(cfg(Mode::Entry, 0, 1), Instant::now(), 1).unwrap();
    assert!(encap(&mut s, &[0x45; 20], 40).is_none());
    s.start(Instant::now(), &mut Wire::default());
    assert!(encap(&mut s, &[0x45; 20], 40).is_none());
}

#[test]
fn ping_is_answered_with_pong_echoing_nonce() {
    let mut p = Pair::new(0, 1, 9);
    p.connect();
    let mut w = Wire::default();
    p.entry.on_tick(p.t + Duration::from_secs(5), &mut w);
    let ping = w.take();
    assert_eq!(ping.len(), 1);
    let payload = parsed(&ping[0]).payload.to_vec();
    assert_eq!((payload[0], payload.len()), (CTRL_PING, CTRL_LEN));

    let mut w = Wire::default();
    assert!(p.exit.on_outer(p.t, &ping[0], &mut w).is_none());
    let pong = w.take();
    let pong_payload = parsed(&pong[0]).payload;
    assert_eq!(pong_payload[0], CTRL_PONG);
    assert_eq!(pong_payload[1..], payload[1..]);
    assert!(p
        .entry
        .on_outer(p.t, &pong[0], &mut Wire::default())
        .is_none());
}

#[test]
fn traffic_from_peer_defers_dead_timeout() {
    let mut p = Pair::new(0, 1, 11);
    let original = p.connect().src;
    for _ in 0..5 {
        p.t += Duration::from_secs(5);
        let mut w = Wire::default();
        p.entry.on_tick(p.t, &mut w);
        let frames = w.take();
        assert!(frames.iter().all(|f| parsed(f).meta.src == original));
        p.pump(frames);
    }
    assert_eq!(p.entry.state(), State::Established);
    assert!(p.entry.next_deadline() <= p.t + Duration::from_secs(5));
}

#[test]
fn bulk_receive_triggers_bare_ack_at_threshold() {
    let mut p = Pair::new(0, 1, 5);
    p.connect();
    let chunk = vec![0x45u8; 60000];
    let mut acks = Vec::new();
    let mut received = 0u32;
    for _ in 0..20 {
        let f = encap(&mut p.exit, &chunk, 40).unwrap();
        let end = parsed(&f).meta.seq.wrapping_add(chunk.len() as u32);
        let mut w = Wire::default();
        p.entry.on_outer(p.t, &f, &mut w);
        received += chunk.len() as u32;
        for a in w.take() {
            acks.push((received, end, parsed(&a).meta));
        }
    }
    assert_eq!(acks.len(), 1);
    let (at, end, meta) = acks[0];
    assert!(at >= ACK_THRESHOLD && at - (chunk.len() as u32) < ACK_THRESHOLD);
    assert_eq!(meta.flags, flags::ACK);
    assert_eq!(meta.ack, end, "acks everything received so far");
}

#[test]
fn dead_entry_sends_two_rsts_then_resyncs_on_rotated_port() {
    let mut p = Pair::new(2, 4, 13);
    let old = p.connect().src.port();
    let mut w = Wire::default();
    p.entry.on_tick(p.t + Duration::from_secs(15) - MS, &mut w);
    assert!(
        w.0.iter().all(|f| parsed(f).meta.flags & flags::RST == 0),
        "not dead yet"
    );
    w.take();

    p.entry.on_tick(p.t + Duration::from_secs(15), &mut w);
    let frames = w.take();
    let metas: Vec<_> = frames.iter().map(|f| parsed(f).meta).collect();
    assert_eq!(metas.len(), 3);
    for rst in &metas[..2] {
        assert_eq!(rst.flags, flags::RST | flags::ACK);
        assert_eq!(rst.src.port(), old);
    }
    assert_eq!(metas[2].flags, flags::SYN);
    assert_eq!(metas[2].src.port(), old + 4);
    assert_eq!(metas[2].src.port() % 4, 2);
    assert_eq!(p.entry.state(), State::SynSent);

    // Exit side accepts the new tuple and replaces its stale peer.
    p.pump(vec![frames[2].clone()]);
    let reply = encap(&mut p.exit, &[0x45; 20], 40).unwrap();
    assert_eq!(parsed(&reply).meta.dst, metas[2].src);
    assert_eq!(
        p.entry.on_outer(p.t, &reply, &mut Wire::default()),
        Some(&[0x45; 20][..])
    );
    assert_eq!(p.entry.state(), State::Established);
}

#[test]
fn source_port_rotation_wraps_to_start_of_pool() {
    let mut c = cfg(Mode::Entry, 1, 2);
    c.base_port = 65530;
    let t = Instant::now();
    let mut s = Session::new(c, t, 2).unwrap(); // pool: 65531, 65533, 65535
    let mut w = Wire::default();
    s.start(t, &mut w);
    assert_eq!(parsed(&w.take()[0]).meta.src.port(), 65535);
    s.on_tick(t + Duration::from_secs(15), &mut w);
    let frames = w.take();
    assert_eq!(parsed(frames.last().unwrap()).meta.src.port(), 65531);
}

#[test]
fn syn_is_retried_then_port_rotates_after_dead_timeout() {
    let t = Instant::now();
    let mut s = Session::new(cfg(Mode::Entry, 0, 1), t, 1).unwrap();
    let mut w = Wire::default();
    s.start(t, &mut w);
    let first = parsed(&w.take()[0]).meta;
    assert_eq!(s.next_deadline(), t + SYN_RETRY);
    let rst = frame(
        TcpMeta {
            src: first.dst,
            dst: first.src,
            seq: 0,
            ack: first.seq.wrapping_add(1),
            flags: flags::RST | flags::ACK,
            window: 0,
        },
        &[],
    );
    assert!(s.on_outer(t, &rst, &mut w).is_none());
    assert!(
        w.take().is_empty(),
        "SynSent RST must not spin immediate reconnect"
    );
    s.on_tick(t + SYN_RETRY, &mut w);
    let retry = parsed(&w.take()[0]).meta;
    assert_eq!(
        (retry.flags, retry.seq, retry.src),
        (flags::SYN, first.seq, first.src)
    );
    s.on_tick(t + Duration::from_secs(15), &mut w);
    let reconnect = w.take();
    assert_ne!(
        parsed(reconnect.last().unwrap()).meta.src.port(),
        first.src.port()
    );
    assert_eq!(s.state(), State::SynSent);
}

#[test]
fn exit_resets_unknown_peers_and_entry_reconnects_on_rst() {
    let mut p = Pair::new(0, 1, 17);
    p.connect();
    // Exit lost its state (e.g. restarted).
    p.exit = Session::new(cfg(Mode::Exit, 0, 1), p.t, 99).unwrap();
    let data = encap(&mut p.entry, &[0x45; 20], 40).unwrap();
    let mut w = Wire::default();
    assert!(p.exit.on_outer(p.t, &data, &mut w).is_none());
    let rst = w.take();
    let r = parsed(&rst[0]).meta;
    assert_eq!(r.flags, flags::RST);
    assert_eq!(r.seq, parsed(&data).meta.ack);

    let old = parsed(&data).meta.src.port();
    let mut w = Wire::default();
    p.entry.on_outer(p.t, &rst[0], &mut w);
    let syn = w.take();
    assert_eq!(syn.len(), 1, "peer already reset: no RST of our own");
    assert_eq!(parsed(&syn[0]).meta.flags, flags::SYN);
    assert_ne!(parsed(&syn[0]).meta.src.port(), old);
    p.pump(syn);
    assert_eq!(p.exit.state(), State::Established);
}

#[test]
fn exit_times_out_silently() {
    let mut p = Pair::new(0, 1, 19);
    p.connect();
    let mut w = Wire::default();
    p.exit.on_tick(p.t + Duration::from_secs(15), &mut w);
    assert!(w.0.is_empty());
    assert_eq!(p.exit.state(), State::Closed);
    assert!(encap(&mut p.exit, &[0x45; 20], 40).is_none());
}

#[test]
fn frames_for_other_tuples_are_ignored() {
    let mut p = Pair::new(0, 1, 23);
    p.connect();
    let mut stray = encap(&mut p.exit, &[0x45; 8], 40).unwrap();
    let port = parsed(&stray).meta.dst.port();
    stray[22..24].copy_from_slice(&(port + 1).to_be_bytes()); // dport
    let mut w = Wire::default();
    assert!(p.entry.on_outer(p.t, &stray, &mut w).is_none());
    let mut w2 = Wire::default();
    p.entry.on_tick(p.t + Duration::from_secs(15), &mut w2);
    assert!(
        w2.take()
            .iter()
            .any(|f| parsed(f).meta.flags & flags::RST != 0),
        "stray frame did not refresh liveness"
    );
}

#[test]
fn duplicate_syn_gets_identical_synack() {
    let t = Instant::now();
    let mut entry = Session::new(cfg(Mode::Entry, 0, 1), t, 1).unwrap();
    let mut exit = Session::new(cfg(Mode::Exit, 0, 1), t, 2).unwrap();
    let mut w = Wire::default();
    entry.start(t, &mut w);
    let syn = w.take().remove(0);
    exit.on_outer(t, &syn, &mut w);
    exit.on_outer(t, &syn, &mut w);
    let sa = w.take();
    assert_eq!(parsed(&sa[0]).meta.seq, parsed(&sa[1]).meta.seq);
}

#[test]
fn delayed_duplicate_syn_preserves_established_sequence_space() {
    for (entry_ip, remote, overhead) in [
        (ENTRY_IP, EXIT, 40),
        (
            "2001:db8:1::1".parse().unwrap(),
            "[2001:db8:2::1]:443".parse().unwrap(),
            60,
        ),
    ] {
        for data_first in [false, true] {
            let mut entry = cfg(Mode::Entry, 0, 1);
            entry.local_ip = entry_ip;
            entry.remote = Some(remote);
            let mut exit = cfg(Mode::Exit, 0, 1);
            exit.local_ip = remote.ip();
            let t = Instant::now();
            let mut p = Pair {
                t,
                entry: Session::new(entry, t, 31).unwrap(),
                exit: Session::new(exit, t, 32).unwrap(),
            };
            let mut w = Wire::default();
            p.entry.start(p.t, &mut w);
            let syn = w.take().remove(0);
            p.exit.on_outer(p.t, &syn, &mut w);
            let synack = w.take().remove(0);
            let original = parsed(&synack).meta;
            p.entry.on_outer(p.t, &synack, &mut w);
            p.pump(w.take());

            if data_first {
                let inner = [0x45; 100];
                let data = encap(&mut p.entry, &inner, overhead).unwrap();
                assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
                let reply = encap(&mut p.exit, &inner, overhead).unwrap();
                assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
            }
            p.t += Duration::from_secs(2);
            p.exit.on_outer(p.t, &syn, &mut w);
            let duplicate = w.take().remove(0);
            assert_eq!(parsed(&duplicate).meta, original);
            p.entry.on_outer(p.t, &duplicate, &mut w);
            let ack = w.take().remove(0);
            p.exit.on_outer(p.t, &ack, &mut w);

            let inner = [0x45; 20];
            let data = encap(&mut p.entry, &inner, overhead).unwrap();
            assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
            let reply = encap(&mut p.exit, &inner, overhead).unwrap();
            assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
            let expected = original
                .seq
                .wrapping_add(1 + auth::EXIT_BYTES + if data_first { 100 } else { 0 });
            assert_eq!(parsed(&data).meta.ack, expected);
            assert_eq!(parsed(&reply).meta.seq, expected);
        }
    }
}

#[test]
fn new_syn_on_same_tuple_can_replace_established_peer() {
    let mut p = Pair::new(0, 1, 31);
    let original = p.connect();
    p.t += Duration::from_secs(2);
    p.entry = Session::new(cfg(Mode::Entry, 0, 1), p.t, 31 + 32768).unwrap();
    let mut w = Wire::default();
    p.entry.start(p.t, &mut w);
    let frames = w.take();
    let replacement = parsed(&frames[0]).meta;
    assert_eq!(replacement.src, original.src);
    assert_ne!(replacement.seq, original.seq);
    p.pump(frames);
    let inner = [0x45; 20];
    let data = encap(&mut p.entry, &inner, 40).unwrap();
    assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
    let reply = encap(&mut p.exit, &inner, 40).unwrap();
    assert_eq!(p.entry.on_outer(p.t, &reply, &mut w), Some(&inner[..]));
}

#[test]
fn shutdown_resets_live_session() {
    let mut p = Pair::new(0, 1, 29);
    p.connect();
    let mut w = Wire::default();
    p.entry.shutdown(&mut w);
    let f = w.take();
    assert_eq!(f.len(), 2);
    assert!(f.iter().all(|f| parsed(f).meta.flags & flags::RST != 0));
    assert_eq!(p.entry.state(), State::Closed);
    p.entry.shutdown(&mut w);
    assert!(w.0.is_empty());
}

#[test]
fn reload_updates_timers_in_place_and_rotates_session_on_key_change() {
    let mut p = Pair::new(0, 2, 41);
    let first_tuple = p.connect();
    let original_generation = p.entry.generation();
    let key1 = AuthKey([0xa7; 32]);
    let key2 = AuthKey([0xb8; 32]);

    // 1. In-place timer update with unchanged key emits no frames and keeps the session live.
    let mut w = Wire::default();
    assert!(!p.entry.reload(
        p.t,
        key1.clone(),
        Duration::from_secs(2),
        Duration::from_secs(9),
        &mut w,
    ));
    assert!(w.0.is_empty());
    assert_eq!(w.1, 0);
    assert_eq!(p.entry.generation(), original_generation);
    assert!(p.entry.is_established());
    assert_eq!(p.entry.next_deadline(), p.t + Duration::from_secs(2));

    let inner = [0x45; 20];
    let data = encap(&mut p.entry, &inner, 40).unwrap();
    assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));

    // 2. Entry key rotation emits RSTs on the old tuple + SYN on the next port in its pool.
    p.t += Duration::from_secs(1);
    assert!(p.entry.reload(
        p.t,
        key2.clone(),
        Duration::from_secs(2),
        Duration::from_secs(9),
        &mut w,
    ));
    assert!(!p.entry.is_established());
    assert!(w.1 > 0);
    assert_ne!(p.entry.generation(), original_generation);
    let frames = w.take();
    assert!(frames.iter().any(|f| {
        let m = parsed(f).meta;
        m.src == first_tuple.src && m.flags & flags::RST != 0
    }));
    let syn = frames
        .iter()
        .find(|f| parsed(f).meta.flags == flags::SYN)
        .expect("entry reload must initiate a new SYN");
    assert_eq!(parsed(syn).meta.src.port(), first_tuple.src.port() + 2);

    // Before Exit reloads its key, handshake cannot complete.
    p.pump(frames);
    assert!(!p.entry.is_established());
    assert!(!p.exit.is_established());

    // Once Exit reloads to key2 (while Closed, so no RST emitted), the next retry establishes.
    assert!(!p.exit.reload(
        p.t,
        key2.clone(),
        Duration::from_secs(2),
        Duration::from_secs(9),
        &mut w,
    ));
    assert!(w.0.is_empty());
    p.t += SYN_RETRY;
    p.entry.on_tick(p.t, &mut w);
    let retry = w.take();
    p.pump(retry);
    assert!(p.entry.is_established());
    assert!(p.exit.is_established());

    // 3. Exit-first key rotation on an Established session emits RST, prompting Entry to
    // immediately reconnect; once Entry also reloads key1, session re-establishes immediately.
    p.t += Duration::from_secs(1);
    assert!(p.exit.reload(
        p.t,
        key1.clone(),
        Duration::from_secs(2),
        Duration::from_secs(9),
        &mut w,
    ));
    assert!(!p.exit.is_established());
    let exit_rst = w.take();
    assert!(exit_rst
        .iter()
        .all(|f| parsed(f).meta.flags & flags::RST != 0));
    for f in &exit_rst {
        p.entry.on_outer(p.t, f, &mut w);
    }
    p.pump(w.take());
    assert!(!p.entry.is_established());

    assert!(!p.entry.reload(
        p.t,
        key1,
        Duration::from_secs(2),
        Duration::from_secs(9),
        &mut w,
    ));
    let entry_reconn = w.take();
    p.pump(entry_reconn);
    assert!(p.entry.is_established());
    assert!(p.exit.is_established());

    let data = encap(&mut p.entry, &inner, 40).unwrap();
    assert_eq!(p.exit.on_outer(p.t, &data, &mut w), Some(&inner[..]));
}

#[test]
fn exit_bound_ip_ignores_other_local_addresses_while_wildcard_accepts_any() {
    let t = Instant::now();
    let other_exit: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let mut entry_cfg = cfg(Mode::Entry, 0, 1);
    entry_cfg.remote = Some(other_exit);
    let mut entry = Session::new(entry_cfg, t, 1).unwrap();
    let mut bound_exit = Session::new(cfg(Mode::Exit, 0, 1), t, 2).unwrap();

    let mut w = Wire::default();
    entry.start(t, &mut w);
    let syn = w.take().pop().unwrap();

    // Bound exit (198.51.100.20) ignores SYN targeting 198.51.100.21:443.
    assert!(bound_exit.on_outer(t, &syn, &mut w).is_none());
    assert!(w.take().is_empty());

    // Wildcard exit (0.0.0.0) accepts SYN targeting 198.51.100.21:443.
    let mut wild_cfg = cfg(Mode::Exit, 0, 1);
    wild_cfg.local_ip = Ipv4Addr::UNSPECIFIED.into();
    let mut wild_exit = Session::new(wild_cfg, t, 2).unwrap();
    assert!(wild_exit.on_outer(t, &syn, &mut w).is_none());
    assert_eq!(w.take().len(), 1);
}

#[test]
fn shutdown_discards_old_backlog_before_queueing_closing_controls() {
    struct Queued(super::queue::Pending<IpAddr>);
    impl Sink for Queued {
        fn send(&mut self, frame: &[u8], dst: IpAddr) {
            assert!(self.0.push(frame, dst, true));
        }
        fn reset(&mut self) {
            self.0.clear();
        }
    }
    let mut pair = Pair::new(0, 1, 101);
    pair.connect();
    let mut out = Queued(Default::default());
    assert!(out.0.push(b"old data", EXIT.ip(), false));
    pair.entry.shutdown(&mut out);
    assert_eq!(out.0.packets.len(), 2);
    for packet in &out.0.packets {
        assert_ne!(parsed(&packet.bytes).meta.flags & flags::RST, 0);
    }
}
