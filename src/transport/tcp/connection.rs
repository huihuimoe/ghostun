use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use std::{fmt, io};

use super::auth::{AUTH_MAX, Handshake};
use super::frame::{self, FRAME_PREFIX_LEN, PING, PONG, Receive, TX_LIMIT};
use super::queue::SendQueue;
use super::{BATCH, ROUNDS};
use crate::platform;
use crate::platform::TunDriver;
use crate::transport::keepalive::{self, Keepalive};

/// TUN-side state owned by a worker and lent to its current connection.
pub struct TunIo<'a> {
    pub driver: TunDriver<'a>,
    /// Poll-fallback read buffer: `platform::BATCH` slots of `stride` bytes.
    pub scratch: Vec<u8>,
    pub stride: usize,
    pub attached: bool,
}

/// What the last poll reported; `false` skips the matching system call this round.
#[derive(Clone, Copy)]
pub(super) struct Ready {
    pub tun: bool,
    pub socket_read: bool,
    pub socket_write: bool,
}

pub struct Connection {
    pub(super) socket: TcpStream,
    pub(super) local: SocketAddr,
    pub(super) peer: SocketAddr,
    pub(super) rx: Receive,
    pub(super) tx: SendQueue,
    pub(super) auth: Option<Handshake>,
    pub(super) since: Instant,
    pub(super) last_rx: Instant,
    pub(super) last_ping: Instant,
    pub(super) tun_pending: bool,
}

impl fmt::Display for Connection {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <-> {}", self.local, self.peer)
    }
}

impl Connection {
    pub(super) fn new(
        socket: TcpStream,
        peer: SocketAddr,
        now: Instant,
        tcp_notsent: u32,
    ) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        platform::tcp::set_notsent_lowat(&socket, tcp_notsent)?;
        let local = socket.local_addr()?;
        Ok(Self {
            socket,
            local,
            peer,
            rx: Receive::new(AUTH_MAX),
            tx: SendQueue::new(tcp_notsent as usize),
            auth: None,
            since: now,
            last_rx: now,
            last_ping: now,
            tun_pending: false,
        })
    }

    pub(super) fn authenticate(&mut self, now: Instant, timeout: Duration) -> io::Result<bool> {
        if now.duration_since(self.since) >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "authentication/connection attempt timeout",
            ));
        }
        self.tx.flush(&mut self.socket)?;
        let auth = self.auth.as_mut().expect("handshake initialized");
        if auth.done() {
            return Ok(self.tx.bytes() == 0);
        }
        if self.rx.read(&mut self.socket)? {
            if let Some(reply) = auth.receive(self.rx.payload())? {
                self.tx.push(&reply);
            }
            self.rx.clear();
        }
        self.tx.flush(&mut self.socket)?;
        Ok(auth.done() && self.tx.bytes() == 0)
    }

    pub(super) fn establish(&mut self, mtu: u16) {
        self.auth = None;
        self.rx.grow(mtu as usize);
        self.tx.grow();
        self.since = Instant::now();
        self.last_rx = self.since;
        self.last_ping = self.since;
    }

    #[inline]
    pub(super) fn next_deadline(&self, ping: Duration, dead: Duration) -> Instant {
        if self.auth.is_some() {
            return self.since + dead;
        }
        let mut next = self.last_rx + dead;
        if self.tx.room(keepalive::LEN) {
            next = next.min(self.last_ping + ping);
        }
        next
    }

    #[inline]
    pub(super) fn flush_tx(&mut self, sock_w: &mut bool) -> io::Result<()> {
        if self.tx.bytes() > 0 && *sock_w {
            self.tx.flush(&mut self.socket)?;
            *sock_w = self.tx.bytes() == 0;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn pump(
        &mut self,
        tun: &mut TunIo<'_>,
        mtu: u16,
        ping: Duration,
        dead: Duration,
    ) -> io::Result<()> {
        // Poll-mode tests have no real readiness events, so report everything as ready.
        let ready = Ready {
            tun: true,
            socket_read: true,
            socket_write: true,
        };
        self.pump_io(tun, mtu, Instant::now(), ping, dead, ready)
            .map(drop)
    }

    #[inline]
    pub(super) fn pump_io(
        &mut self,
        tun: &mut TunIo<'_>,
        mtu: u16,
        now: Instant,
        ping: Duration,
        dead: Duration,
        ready: Ready,
    ) -> io::Result<bool> {
        let mtu = mtu as usize;
        if now.duration_since(self.last_rx) >= dead {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer liveness timeout",
            ));
        }
        let mut tun_r = tun.driver.has_reads() || ready.tun;
        let mut tun_w = true;
        let mut sock_r = ready.socket_read;
        let mut sock_w = ready.socket_write;
        self.flush_tx(&mut sock_w)?;
        let mut busy = false;
        for _ in 0..ROUNDS {
            let mut rx_count = 0;
            while rx_count < BATCH {
                if !self.tun_pending {
                    if !self.rx.ready() && !sock_r {
                        break;
                    }
                    if !self.rx.read(&mut self.socket)? {
                        sock_r = false;
                        break;
                    }
                    let p = self.rx.payload();
                    if let Some(ka) = Keepalive::decode(p).filter(|k| matches!(k.kind, PING | PONG))
                    {
                        if ka.kind == PING {
                            if !self.tx.room(keepalive::LEN) {
                                break;
                            }
                            let pong = Keepalive::new(PONG, ka.nonce).encode();
                            self.tx.push(&pong);
                        }
                        self.rx.clear();
                        self.last_rx = now;
                        rx_count += 1;
                        continue;
                    }
                    frame::validate_packet(p, mtu)?;
                    self.tun_pending = true;
                    self.last_rx = now;
                }
                if !tun_w {
                    break;
                }
                if !tun.driver.write(self.rx.payload()) {
                    tun_w = false;
                    break;
                }
                self.rx.clear();
                self.tun_pending = false;
                rx_count += 1;
            }
            if tun_r && self.tx.room(mtu) {
                // TX_LIMIT alone bounds TCP reads: unlike udp/faketcp, completed ring reads that
                // do not fit simply wait in the driver, so no in-flight reservation is needed.
                let queued = self.tx.bytes();
                let mut malformed = None;
                let (reads, frames) = tun.driver.read_batch(
                    &mut tun.scratch,
                    tun.stride,
                    |bytes, count| queued + bytes + count * FRAME_PREFIX_LEN <= TX_LIMIT,
                    |slot, n| match frame::validate_packet(&slot[..n], mtu) {
                        Ok(()) => true,
                        Err(e) => {
                            malformed = Some(e);
                            false
                        }
                    },
                );
                for packet in frames {
                    let accepted = self.tx.push(packet);
                    debug_assert!(accepted, "read_batch room check reserves TX capacity");
                }
                if let Some(e) = malformed {
                    return Err(e);
                }
                tun_r = reads == platform::BATCH;
            }
            self.flush_tx(&mut sock_w)?;
            tun.driver.service(tun.attached, self.tx.room(mtu));
            tun_r |= tun.driver.has_reads();
            let rx_blocked_on_pong = self.rx.ready() && !self.tx.room(keepalive::LEN);
            let more_rx = !self.tun_pending && !rx_blocked_on_pong && (sock_r || self.rx.ready());
            let more_tx = tun_r && self.tx.room(mtu);
            busy = more_rx || more_tx;
            if !busy {
                break;
            }
        }
        if now.duration_since(self.last_ping) >= ping && self.tx.room(keepalive::LEN) {
            let mut nonce = [0u8; 8];
            platform::random(&mut nonce)?;
            let msg = Keepalive::new(PING, nonce).encode();
            self.tx.push(&msg);
            self.last_ping = now;
            self.flush_tx(&mut sock_w)?;
        }
        Ok(busy)
    }
}
