use super::*;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixDatagram;
use wire::TX_LIMIT;

fn params() -> Params {
    Params {
        worker: 1,
        conns: 2,
        mtu: 1380,
    }
}
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let b = listener.accept().unwrap().0;
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    (a, b)
}
fn packet(tag: u8) -> Vec<u8> {
    let mut p = vec![tag; 64];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&64u16.to_be_bytes());
    p
}

#[test]
fn mutual_authentication_rejects_wrong_keys_reflection_replay_and_parameters() {
    let key = AuthKey([7; 32]);
    let (mut entry, hello) = Handshake::entry(&key, params()).unwrap();
    let (mut exit, challenge) = Handshake::exit(&key, params(), &hello).unwrap();
    assert!(!entry.done());
    assert!(!exit.done());
    let proof = entry.receive(&challenge).unwrap().unwrap();
    let mut reflected = vec![3];
    reflected.extend_from_slice(&challenge[33..]);
    assert!(exit.receive(&reflected).is_err(), "reflected Exit proof");
    let finished = exit.receive(&proof).unwrap().unwrap();
    assert!(!exit.done(), "Exit must wait for explicit Ready");
    let ready = entry.receive(&finished).unwrap().unwrap();
    exit.receive(&ready).unwrap();
    assert!(entry.done() && exit.done());
    let (mut fresh, _) = Handshake::exit(&key, params(), &hello).unwrap();
    assert!(
        fresh.receive(&proof).is_err(),
        "fresh Exit nonce rejects replay"
    );
    let (mut fresh_entry, _) = Handshake::entry(&key, params()).unwrap();
    assert!(
        fresh_entry.receive(&challenge).is_err(),
        "fresh Entry nonce rejects replay"
    );
    let (mut wrong, wrong_hello) = Handshake::entry(&AuthKey([8; 32]), params()).unwrap();
    let (_, wrong_challenge) = Handshake::exit(&key, params(), &wrong_hello).unwrap();
    assert!(wrong.receive(&wrong_challenge).is_err());
    for p in [
        Params {
            worker: 2,
            ..params()
        },
        Params {
            conns: 3,
            ..params()
        },
        Params {
            mtu: 1400,
            ..params()
        },
    ] {
        let (_, hello) = Handshake::entry(&key, p).unwrap();
        assert!(Handshake::exit(&key, params(), &hello).is_err());
    }
    let mut unsupported = hello.clone();
    unsupported[5] = 2;
    assert!(wire::hello_params(&unsupported).is_err());
}

/// A deterministic short-I/O peer: each successful byte is followed by WouldBlock.
struct SplitIo {
    bytes: std::collections::VecDeque<u8>,
    block: bool,
}
impl Read for SplitIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.block = !self.block;
        if self.block {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Some(byte) = self.bytes.pop_front() {
            buf[0] = byte;
            Ok(1)
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}
impl Write for SplitIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.block = !self.block;
        if self.block {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.bytes.push_back(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn split_prefix_payload_coalescing_and_partial_writes_preserve_packets_and_cap() {
    let packets = [packet(10), packet(20), vec![PING; 9]];
    let mut tx = SendQueue::default();
    for p in &packets {
        assert!(tx.push(p));
    }
    let mut stream = SplitIo {
        bytes: Default::default(),
        block: false,
    };
    while tx.bytes > 0 {
        tx.flush(&mut stream).unwrap();
    }
    let mut reader = Receive::new(1380);
    for p in &packets {
        while !reader.read(&mut stream).unwrap() {}
        assert_eq!(reader.payload(), p);
        reader.clear();
    }
    assert!(stream.bytes.is_empty());
    let payload = packet(30);
    while tx.push(&payload) {}
    assert!(tx.bytes <= TX_LIMIT);
    assert!(!tx.room(1380));
    let mut sink = Vec::new();
    tx.flush(&mut sink).unwrap();
    assert_eq!(tx.bytes, 0);
    let mut input = &sink[..];
    while !input.is_empty() {
        assert!(reader.read(&mut input).unwrap());
        assert_eq!(reader.payload(), payload);
        reader.clear();
    }
}

#[test]
fn malformed_lengths_and_packets_fail_without_resynchronizing() {
    for bytes in [&[0, 0][..], &[255, 255][..], &[0, 3, 1][..]] {
        let mut input = bytes;
        assert!(Receive::new(1380).read(&mut input).is_err());
    }
    let mut p = packet(1);
    wire::validate_packet(&p, 1380).unwrap();
    assert!(wire::validate_packet(&p, 63).is_err());
    p[2..4].copy_from_slice(&63u16.to_be_bytes());
    assert!(wire::validate_packet(&p, 1380).is_err());
    p[0] = 0x44;
    assert!(wire::validate_packet(&p, 1380).is_err());
    for p in [vec![], vec![1; 9], vec![3; 33], vec![0x60; 39]] {
        assert!(wire::validate_packet(&p, 1380).is_err());
    }
}

#[test]
fn attempt_deadline_is_absolute_and_jitter_backoff_resets_only_after_stability() {
    let key = AuthKey([7; 32]);
    let (a, _b) = pair();
    let start = Instant::now();
    let mut c = Connection::new(a, start).unwrap();
    c.auth = Some(Handshake::entry(&key, params()).unwrap().0);
    assert!(c
        .authenticate(start + Duration::from_secs(4), Duration::from_secs(4))
        .is_err());
    let mut b = Backoff { failures: 0 };
    for base in [1, 2, 4, 8, 15, 15, 15] {
        let d = b.delay(0, false);
        assert_eq!(d, Duration::from_millis(base * 500));
    }
    assert!(b.delay(u32::MAX, false).as_millis() <= 15000);
    assert_eq!(b.delay(0, true), Duration::from_millis(500));
    assert_eq!(b.delay(0, false), Duration::from_secs(1));
}

fn candidates(key: &AuthKey) -> Slots {
    Arc::new(
        (0..2)
            .map(|_| {
                Mutex::new(Slot {
                    key: key.clone(),
                    epoch: 0,
                    timeout: Duration::from_secs(4),
                    pending: None,
                })
            })
            .collect(),
    )
}

fn admit(slots: &Slots, key: &AuthKey) -> Connection {
    let (client, server) = pair();
    let now = Instant::now();
    let mut client = Connection::new(client, now).unwrap();
    let (auth, hello) = Handshake::entry(key, params()).unwrap();
    client.auth = Some(auth);
    client.tx.push(&hello);
    let mut candidate = Candidate {
        conn: Connection::new(server, now).unwrap(),
        identity: None,
        timeout: Duration::from_secs(4),
    };
    for _ in 0..1000 {
        let done = client
            .authenticate(Instant::now(), Duration::from_secs(4))
            .unwrap();
        if candidate.advance(slots, 1380).unwrap() {
            assert!(
                done || client
                    .authenticate(Instant::now(), Duration::from_secs(4))
                    .unwrap()
            );
            client.establish(1380);
            candidate.admit(slots, 1380).unwrap();
            return client;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("authentication did not finish")
}

#[test]
fn authenticated_admission_and_takeover_preserve_exact_data_and_ignore_incomplete_candidates() {
    let key = AuthKey([7; 32]);
    let slots = candidates(&key);
    let mut entry = admit(&slots, &key);
    assert!(slots[0].lock().unwrap().pending.is_none());
    let mut exit = slots[1].lock().unwrap().pending.take().unwrap();
    let (tun, consumer) = UnixDatagram::pair().unwrap();
    tun.set_nonblocking(true).unwrap();
    consumer.set_nonblocking(true).unwrap();
    let tun = OwnedFd::from(tun);
    let p = packet(9);
    entry.tx.push(&p);
    entry.tx.flush(&mut entry.socket).unwrap();
    let mut delivered = false;
    for _ in 0..100 {
        exit.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(1),
            Duration::from_secs(4),
        )
        .unwrap();
        let mut data = [0; 2048];
        if let Ok(n) = consumer.recv(&mut data) {
            assert_eq!(&data[..n], p);
            delivered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        delivered,
        "authenticated packet must reach the TUN consumer"
    );
    let (bad_socket, _bad_peer) = pair();
    let mut incomplete = Candidate {
        conn: Connection::new(bad_socket, Instant::now()).unwrap(),
        identity: None,
        timeout: Duration::from_secs(4),
    };
    let prior = exit.last_rx;
    assert!(!incomplete.advance(&slots, 1380).unwrap());
    assert_eq!(exit.last_rx, prior);
    let _new_entry = admit(&slots, &key);
    let replacement = slots[1].lock().unwrap().pending.take().unwrap();
    drop(exit);
    drop(replacement);
    let mut buf = [0; 1];
    for _ in 0..100 {
        match entry.socket.read(&mut buf) {
            Ok(0) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            result => panic!("old connection: {result:?}"),
        }
    }
    panic!("old socket did not close");
}

#[test]
fn blocked_tun_retains_one_frame_then_delivers_in_order_after_resume() {
    let (mut sender, receiver) = pair();
    let mut c = Connection::new(receiver, Instant::now()).unwrap();
    c.establish(1380);
    let (tun, consumer) = UnixDatagram::pair().unwrap();
    tun.set_nonblocking(true).unwrap();
    consumer.set_nonblocking(true).unwrap();
    let filler = vec![99; 64];
    while tun.send(&filler).is_ok() {}
    let tun = OwnedFd::from(tun);
    let packets = [packet(10), packet(20)];
    let mut tx = SendQueue::default();
    for p in &packets {
        tx.push(p);
    }
    tx.flush(&mut sender).unwrap();
    for _ in 0..100 {
        c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(5),
            Duration::from_secs(15),
        )
        .unwrap();
        if c.tun_pending {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(c.tun_pending);
    assert_eq!(c.rx.payload(), packets[0]);
    let mut buf = [0; 2048];
    while consumer.recv(&mut buf).is_ok() {}
    c.pump(
        &tun,
        &mut [0; 1381],
        Duration::from_secs(5),
        Duration::from_secs(15),
    )
    .unwrap();
    for p in &packets {
        let n = consumer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], p);
    }
    assert!(!c.tun_pending);
}

#[test]
fn eof_and_illegal_established_control_close_the_stream() {
    let (mut sender, receiver) = pair();
    let mut c = Connection::new(receiver, Instant::now()).unwrap();
    c.establish(1380);
    let (tun, _consumer) = UnixDatagram::pair().unwrap();
    tun.set_nonblocking(true).unwrap();
    let tun = OwnedFd::from(tun);
    sender.write_all(&[0, 1, 3]).unwrap();
    for _ in 0..100 {
        if c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(5),
            Duration::from_secs(15),
        )
        .is_err()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    sender.shutdown(Shutdown::Both).unwrap();
    panic!("illegal control accepted")
}

#[test]
fn key_reload_invalidates_pending_authentication_before_admission() {
    let key = AuthKey([7; 32]);
    let slots = candidates(&key);
    let (a, b) = pair();
    let now = Instant::now();
    let mut client = Connection::new(a, now).unwrap();
    let (auth, hello) = Handshake::entry(&key, params()).unwrap();
    client.auth = Some(auth);
    client.tx.push(&hello);
    let mut candidate = Candidate {
        conn: Connection::new(b, now).unwrap(),
        identity: None,
        timeout: Duration::from_secs(4),
    };
    client.tx.flush(&mut client.socket).unwrap();
    for _ in 0..100 {
        candidate.advance(&slots, 1380).unwrap();
        if candidate.identity.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(candidate.identity.is_some());
    slots[1].lock().unwrap().epoch += 1;
    for _ in 0..100 {
        client
            .authenticate(Instant::now(), Duration::from_secs(4))
            .unwrap();
        if candidate.advance(&slots, 1380).unwrap() {
            assert!(candidate.admit(&slots, 1380).is_err());
            assert!(slots[1].lock().unwrap().pending.is_none());
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("old-key candidate admitted after reload")
}

#[test]
fn partial_bytes_do_not_refresh_end_to_end_liveness() {
    let (mut peer, receiver) = pair();
    let mut c = Connection::new(receiver, Instant::now()).unwrap();
    c.establish(1380);
    let (tun, _consumer) = UnixDatagram::pair().unwrap();
    tun.set_nonblocking(true).unwrap();
    let tun = OwnedFd::from(tun);
    let prior = c.last_rx;
    peer.write_all(&[0, 9, PING, 0]).unwrap();
    for _ in 0..10 {
        c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(1),
            Duration::from_secs(4),
        )
        .unwrap();
        assert_eq!(c.last_rx, prior);
        std::thread::sleep(Duration::from_millis(1));
    }
    peer.write_all(&[0; 7]).unwrap();
    for _ in 0..100 {
        c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(1),
            Duration::from_secs(4),
        )
        .unwrap();
        if c.last_rx > prior {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("valid complete health message did not refresh liveness")
}

#[test]
fn slow_tcp_receiver_backpressures_tun_at_the_transmit_bound_then_delivers_exact_data() {
    let (mut peer, receiver) = pair();
    let small = 4096i32;
    // SAFETY: valid socket and option pointer with matching c_int size.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&small as *const i32).cast(),
                4,
            )
        },
        0
    );
    let mut c = Connection::new(receiver, Instant::now()).unwrap();
    c.establish(1380);
    let (tun, producer) = UnixDatagram::pair().unwrap();
    tun.set_nonblocking(true).unwrap();
    producer.set_nonblocking(true).unwrap();
    let tun = OwnedFd::from(tun);
    let p = packet(23);
    let mut sent = 0;
    for _ in 0..1000 {
        for _ in 0..128 {
            if producer.send(&p).is_ok() {
                sent += 1;
            } else {
                break;
            }
        }
        c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(c.tx.bytes <= TX_LIMIT);
        if !c.tx.room(1380) {
            break;
        }
    }
    assert!(
        !c.tx.room(1380),
        "blocked TCP peer must fill the bounded queue and stop TUN reads"
    );
    let mut received = 0;
    let mut rx = Receive::new(1380);
    let deadline = Instant::now() + Duration::from_secs(5);
    while received < sent && Instant::now() < deadline {
        c.pump(
            &tun,
            &mut [0; 1381],
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .unwrap();
        while rx.read(&mut peer).unwrap() {
            assert_eq!(rx.payload(), p);
            received += 1;
            rx.clear();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        received, sent,
        "all accepted packets retain order and payload after backpressure"
    );
}
