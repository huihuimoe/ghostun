//! Kernel TCP sockets for the TCP transport.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{bind_to_device, cvt, setsockopt, SockAddr};

pub fn set_notsent_lowat(stream: &TcpStream, bytes: u32) -> io::Result<()> {
    setsockopt(stream, libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT, &bytes)
}

/// Binds a single-family kernel listener; IPv6 never silently accepts IPv4-mapped peers.
pub fn listener(addr: SocketAddr, dev: Option<&str>) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket returns an owned descriptor or an error.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let fd = unsafe { OwnedFd::from_raw_fd(cvt(fd)?) };
    bind_to_device(&fd, dev)?;
    setsockopt(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &1i32)?;
    if addr.is_ipv6() {
        setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &1i32)?;
    }
    let sa = SockAddr::from_socket(addr);
    let (ptr, len) = sa.as_ptr_len();
    // SAFETY: `sa` outlives `bind` and `ptr`/`len` match its active family.
    unsafe {
        cvt(libc::bind(fd.as_raw_fd(), ptr, len))?;
        cvt(libc::listen(fd.as_raw_fd(), 128))?;
    }
    Ok(TcpListener::from(fd))
}

/// Starts a kernel TCP connection without blocking the worker or its attempt deadline.
pub fn connect(remote: SocketAddr, dev: Option<&str>) -> io::Result<TcpStream> {
    let domain = if remote.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: constant socket flags, with immediate ownership of the returned fd.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    let fd = unsafe { OwnedFd::from_raw_fd(cvt(fd)?) };
    bind_to_device(&fd, dev)?;
    let sa = SockAddr::from_socket(remote);
    let (ptr, len) = sa.as_ptr_len();
    // SAFETY: `sa` outlives `connect` and `ptr`/`len` match its active family.
    unsafe {
        if libc::connect(fd.as_raw_fd(), ptr, len) < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e);
            }
        }
    }
    let stream = TcpStream::from(fd);
    stream.set_nodelay(true)?;
    Ok(stream)
}
