use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};
use std::{fmt, io};

use super::auth::{Handshake, AUTH_MAX};
use super::frame::{self, Receive, PING, PONG};
use super::queue::SendQueue;
use super::{can_io, BATCH, ROUNDS};
use crate::sys::{self, READ_READY, WRITE_READY};
use crate::transport::keepalive::{self, Keepalive};

pub(super) struct Connection {
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
        sys::tcp::set_notsent_lowat(&socket, tcp_notsent)?;
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
        tun: &OwnedFd,
        mtu: u16,
        ping: Duration,
        dead: Duration,
    ) -> io::Result<()> {
        self.pump_io(
            tun,
            mtu,
            Instant::now(),
            ping,
            dead,
            &[sys::pollfd(-1, 0), sys::pollfd(-1, 0)],
        )
        .map(drop)
    }

    #[inline]
    pub(super) fn pump_io(
        &mut self,
        tun: &OwnedFd,
        mtu: u16,
        now: Instant,
        ping: Duration,
        dead: Duration,
        fds: &[libc::pollfd],
    ) -> io::Result<bool> {
        let mtu = mtu as usize;
        if now.duration_since(self.last_rx) >= dead {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer liveness timeout",
            ));
        }
        let mut tun_r = can_io(fds[0], libc::POLLIN, READ_READY);
        let mut tun_w = can_io(fds[0], libc::POLLOUT, WRITE_READY);
        let mut sock_r = can_io(fds[1], libc::POLLIN, READ_READY);
        let mut sock_w = can_io(fds[1], libc::POLLOUT, WRITE_READY);
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
                if !sys::tun::write(tun.as_fd(), self.rx.payload())? {
                    tun_w = false;
                    break;
                }
                self.rx.clear();
                self.tun_pending = false;
                rx_count += 1;
            }
            if tun_r {
                for _ in 0..BATCH {
                    let pushed = self.tx.push_in_place(mtu, |buf| {
                        let Some(n) = sys::tun::read(tun.as_fd(), buf)? else {
                            return Ok(None);
                        };
                        frame::validate_packet(&buf[..n], mtu)?;
                        Ok(Some(n))
                    })?;
                    if !pushed {
                        if self.tx.room(mtu) {
                            tun_r = false;
                        }
                        break;
                    }
                }
            }
            self.flush_tx(&mut sock_w)?;
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
            sys::random(&mut nonce)?;
            let msg = Keepalive::new(PING, nonce).encode();
            self.tx.push(&msg);
            self.last_ping = now;
            self.flush_tx(&mut sock_w)?;
        }
        Ok(busy)
    }
}
