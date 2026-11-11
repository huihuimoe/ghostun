//! Placeholder for targets without a platform implementation.
//!
//! It mirrors the interface the portable layers use, so they type-check everywhere; porting to
//! a new operating system means replacing every `todo!()` here with a real implementation.
#![allow(unused_variables)]

use std::io;
use std::ops::BitOr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub const BATCH: usize = 64;
pub const MAX_CPUS: usize = 1024;

pub struct Waker;

impl Waker {
    pub fn new() -> io::Result<Self> {
        todo!()
    }

    pub fn notify(&self) {
        todo!()
    }

    pub fn drain(&self) {
        todo!()
    }

    pub fn wait(&self) -> io::Result<()> {
        todo!()
    }
}

#[derive(Clone, Copy)]
pub struct Interest;

impl Interest {
    pub const NONE: Self = Self;
    pub const READ: Self = Self;
    pub const WRITE: Self = Self;

    pub const fn when(self, wanted: bool) -> Self {
        self
    }
}

impl BitOr for Interest {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self
    }
}

#[derive(Default)]
pub struct Poller;

impl Poller {
    pub fn add<S>(&mut self, source: &S, interest: Interest) -> usize {
        todo!()
    }

    pub fn reserve(&mut self) -> usize {
        todo!()
    }

    pub fn bind<S>(&mut self, slot: usize, source: &S, interest: Interest) {
        todo!()
    }

    pub fn unbind(&mut self, slot: usize) {
        todo!()
    }

    pub fn set(&mut self, slot: usize, interest: Interest) {
        todo!()
    }

    pub fn truncate(&mut self, len: usize) {
        todo!()
    }

    pub fn swap_remove(&mut self, slot: usize) {
        todo!()
    }

    pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        todo!()
    }

    pub fn is_bound(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn fired(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn readable(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn read_ready(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn write_ready(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn can_read(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn can_write(&self, slot: usize) -> bool {
        todo!()
    }

    pub fn woken(&self, slot: usize, waker: &Waker) -> bool {
        todo!()
    }
}

pub mod signals {
    use super::*;

    pub struct Signals;

    pub fn install() -> io::Result<Signals> {
        todo!()
    }

    impl Signals {
        pub fn stop(&self) -> &'static AtomicBool {
            todo!()
        }

        pub fn take_reload(&self) -> bool {
            todo!()
        }

        pub fn waker(&self) -> &Arc<Waker> {
            todo!()
        }
    }
}

pub struct TunQueue;

impl TunQueue {
    pub fn set_active(&self, active: bool) -> io::Result<()> {
        todo!()
    }
}

pub mod tun {
    use super::*;

    pub fn open_queue(name: &str) -> io::Result<TunQueue> {
        todo!()
    }

    pub fn create(name: &str, queues: usize) -> io::Result<Vec<TunQueue>> {
        todo!()
    }
}

pub struct TunDriver<'a>(&'a TunQueue);

impl<'a> TunDriver<'a> {
    pub fn new(queue: &'a TunQueue, stride: usize, headroom: usize) -> Self {
        todo!()
    }

    pub fn bind_ring(&self, poller: &mut Poller, slot: usize) -> bool {
        todo!()
    }

    pub fn has_reads(&self) -> bool {
        todo!()
    }

    pub fn wants_write(&self) -> bool {
        todo!()
    }

    pub fn read_budget(&self) -> (usize, usize) {
        todo!()
    }

    pub fn service(&mut self, attached: bool, read_allowed: bool) {
        todo!()
    }

    pub fn read_batch<'b>(
        &'b mut self,
        scratch: &'b mut [u8],
        scratch_stride: usize,
        room: impl Fn(usize, usize) -> bool,
        encap: impl FnMut(&mut [u8], usize) -> bool,
    ) -> (usize, std::iter::Empty<&'b [u8]>) {
        todo!()
    }

    pub fn write(&mut self, packet: &[u8]) -> bool {
        todo!()
    }

    pub fn flush(&mut self) {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

pub mod route {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::net::{Cidr, OuterFamily};

    pub struct Route {
        pub src: IpAddr,
        pub dev: String,
    }

    pub fn route_to(destination: IpAddr, device: Option<&str>) -> io::Result<Route> {
        todo!()
    }

    pub fn default_route_dev(family: OuterFamily) -> io::Result<String> {
        todo!()
    }

    pub fn configure_tun(
        name: &str,
        mtu: u32,
        txqueuelen: u32,
        v4: Cidr<Ipv4Addr>,
        v6: Option<Cidr<Ipv6Addr>>,
    ) -> io::Result<bool> {
        todo!()
    }
}

pub mod tcp {
    use std::io;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    pub fn set_notsent_lowat(stream: &TcpStream, bytes: u32) -> io::Result<()> {
        todo!()
    }

    pub fn listener(addr: SocketAddr, dev: Option<&str>) -> io::Result<TcpListener> {
        todo!()
    }

    pub fn connect(remote: SocketAddr, dev: Option<&str>) -> io::Result<TcpStream> {
        todo!()
    }
}

pub mod udp {
    use std::io;
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    use super::BATCH;
    use crate::net::OuterFamily;

    pub fn listener(
        family: OuterFamily,
        listen_ip: Option<IpAddr>,
        port: u16,
        bind_dev: Option<&str>,
    ) -> io::Result<UdpSocket> {
        todo!()
    }

    pub fn connect_entry(
        local_ip: IpAddr,
        remote: SocketAddr,
        bind_dev: Option<&str>,
    ) -> io::Result<(UdpSocket, SocketAddr)> {
        todo!()
    }

    pub fn connect_exit(
        local: SocketAddr,
        peer: SocketAddr,
        bind_dev: Option<&str>,
    ) -> io::Result<UdpSocket> {
        todo!()
    }

    pub fn recv_unconnected(
        socket: &UdpSocket,
        family: OuterFamily,
        listen_port: u16,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        todo!()
    }

    pub fn send_unconnected(
        socket: &UdpSocket,
        local: SocketAddr,
        peer: SocketAddr,
        frame: &[u8],
    ) -> io::Result<()> {
        todo!()
    }

    pub fn send(socket: &UdpSocket, frame: &[u8]) -> io::Result<()> {
        todo!()
    }

    pub struct Sender;

    impl Sender {
        pub fn new() -> Self {
            todo!()
        }

        pub fn send<'a>(
            &mut self,
            socket: &UdpSocket,
            frames: impl ExactSizeIterator<Item = &'a [u8]>,
        ) -> usize {
            todo!()
        }
    }

    pub struct Receiver {
        pub lens: [usize; BATCH],
    }

    impl Receiver {
        pub fn new(stride: usize) -> Self {
            todo!()
        }

        pub fn buffers(&self) -> &[u8] {
            todo!()
        }

        pub fn buffers_mut(&mut self) -> &mut [u8] {
            todo!()
        }

        pub fn receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
            todo!()
        }
    }
}

pub fn usable_cpus() -> Vec<usize> {
    todo!()
}

pub fn pin_to_cpu(cpu: usize) -> io::Result<()> {
    todo!()
}

pub fn iface_mtu(dev: &str) -> io::Result<u32> {
    todo!()
}
