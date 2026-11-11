//! Kernel UDP sockets: unconnected listener with pktinfo and connected per-worker batched I/O.

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::{read_unaligned, write_unaligned};

use libc::{in_pktinfo, in6_pktinfo};

use super::{
    BATCH, CmsgBuf, SockAddr, bind_to_device, cvt, send_progress, set_socket_buffers, setsockopt,
};
use crate::net::OuterFamily;

fn socket_common(family: OuterFamily, bind_dev: Option<&str>, reuse: bool) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments; returned descriptor is owned immediately.
    let fd = cvt(unsafe {
        libc::socket(
            match family {
                OuterFamily::Ipv4 => libc::AF_INET,
                OuterFamily::Ipv6 => libc::AF_INET6,
            },
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    bind_to_device(&fd, bind_dev)?;
    let one: libc::c_int = 1;
    if reuse {
        setsockopt(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one)?;
        setsockopt(&fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &one)?;
    }
    match family {
        OuterFamily::Ipv4 => {
            setsockopt(
                &fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &libc::IP_PMTUDISC_DO,
            )?;
        }
        OuterFamily::Ipv6 => {
            setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &one)?;
            setsockopt(
                &fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &libc::IPV6_PMTUDISC_DO,
            )?;
        }
    }
    set_socket_buffers(&fd)?;
    Ok(fd)
}

fn sock_addr_with_dev(addr: SocketAddr, bind_dev: Option<&str>) -> io::Result<SockAddr> {
    let mut sa = SockAddr::from_socket(addr);
    if let (SockAddr::V6(v6), Some(dev)) = (&mut sa, bind_dev)
        && v6.sin6_scope_id == 0
        && Ipv6Addr::from(v6.sin6_addr.s6_addr).is_unicast_link_local()
    {
        let dev = CString::new(dev)?;
        // SAFETY: dev is a valid NUL-terminated interface name.
        v6.sin6_scope_id = unsafe { libc::if_nametoindex(dev.as_ptr()) };
    }
    Ok(sa)
}

#[inline]
fn from_raw_v4(v4: libc::sockaddr_in) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)),
        u16::from_be(v4.sin_port),
    ))
}

#[inline]
fn from_raw_v6(v6: libc::sockaddr_in6) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(v6.sin6_addr.s6_addr),
        u16::from_be(v6.sin6_port),
        v6.sin6_flowinfo,
        v6.sin6_scope_id,
    ))
}

fn local_addr(fd: &OwnedFd, family: OuterFamily) -> io::Result<SocketAddr> {
    let mut sa = SockAddr::from_ip(family.unspecified());
    let (_, mut len) = sa.as_ptr_len();
    let ptr: *mut libc::sockaddr = match &mut sa {
        SockAddr::V4(v4) => (v4 as *mut libc::sockaddr_in).cast(),
        SockAddr::V6(v6) => (v6 as *mut libc::sockaddr_in6).cast(),
    };
    // SAFETY: `ptr` and `len` reference writable sockaddr storage for `family`.
    cvt(unsafe { libc::getsockname(fd.as_raw_fd(), ptr, &mut len) })?;
    Ok(match sa {
        SockAddr::V4(v4) => from_raw_v4(v4),
        SockAddr::V6(v6) => from_raw_v6(v6),
    })
}

/// Unconnected Exit listener socket with packet-info enabled so replies and promoted workers
/// bind the exact destination IPv4/IPv6 address that the peer targeted.
pub fn listener(
    family: OuterFamily,
    listen_ip: Option<IpAddr>,
    port: u16,
    bind_dev: Option<&str>,
) -> io::Result<UdpSocket> {
    let fd = socket_common(family, bind_dev, true)?;
    let one: libc::c_int = 1;
    match family {
        OuterFamily::Ipv4 => setsockopt(&fd, libc::IPPROTO_IP, libc::IP_PKTINFO, &one)?,
        OuterFamily::Ipv6 => setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &one)?,
    }
    let addr = SocketAddr::new(listen_ip.unwrap_or_else(|| family.unspecified()), port);
    let sa = sock_addr_with_dev(addr, bind_dev)?;
    let (ptr, len) = sa.as_ptr_len();
    // SAFETY: `sa` outlives `bind` and `ptr`/`len` match its family.
    cvt(unsafe { libc::bind(fd.as_raw_fd(), ptr, len) })?;
    Ok(fd.into())
}

/// Connected Entry worker socket bound to `local_ip:0` (kernel-assigned ephemeral port).
pub fn connect_entry(
    local_ip: IpAddr,
    remote: SocketAddr,
    bind_dev: Option<&str>,
) -> io::Result<(UdpSocket, SocketAddr)> {
    let fd = connect_bound(SocketAddr::new(local_ip, 0), remote, bind_dev, false)?;
    let local = local_addr(&fd, OuterFamily::of(remote.ip()))?;
    Ok((fd.into(), local))
}

/// Connected Exit worker socket sharing `local` via `SO_REUSEADDR` + `SO_REUSEPORT` and connected
/// to `peer`, so the kernel routes matching 4-tuple datagrams directly to this worker.
pub fn connect_exit(
    local: SocketAddr,
    peer: SocketAddr,
    bind_dev: Option<&str>,
) -> io::Result<UdpSocket> {
    connect_bound(local, peer, bind_dev, true).map(UdpSocket::from)
}

fn connect_bound(
    local: SocketAddr,
    peer: SocketAddr,
    bind_dev: Option<&str>,
    reuse: bool,
) -> io::Result<OwnedFd> {
    let fd = socket_common(OuterFamily::of(local.ip()), bind_dev, reuse)?;
    for (addr, is_bind) in [(local, true), (peer, false)] {
        let sa = sock_addr_with_dev(addr, bind_dev)?;
        let (ptr, len) = sa.as_ptr_len();
        // SAFETY: `sa` is live and matches the socket family.
        unsafe {
            cvt(if is_bind {
                libc::bind(fd.as_raw_fd(), ptr, len)
            } else {
                libc::connect(fd.as_raw_fd(), ptr, len)
            })?;
        }
    }
    Ok(fd)
}

/// Receives one datagram on an unconnected listener socket, returning `(len, local, peer)`.
/// Truncated frames or frames missing packet-info return `len == 0`.
pub fn recv_unconnected(
    fd: &UdpSocket,
    family: OuterFamily,
    listen_port: u16,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: plain C structs zero-initialized before recvmsg populates them.
    let mut peer_storage: libc::sockaddr_in6 = unsafe { zeroed() };
    let mut control: CmsgBuf = [0; 8];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut peer_storage as *mut libc::sockaddr_in6).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in6>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<CmsgBuf>() as _;

    // SAFETY: msg references live stack storage.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let dummy = SocketAddr::new(family.unspecified(), 0);
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || n == 0 {
        return Ok((0, dummy, dummy));
    }
    // SAFETY: recvmsg populated peer_storage and control buffer for `family`.
    let (local, peer) = unsafe {
        match family {
            OuterFamily::Ipv4 => {
                let peer = from_raw_v4(read_unaligned(
                    (&peer_storage as *const libc::sockaddr_in6).cast(),
                ));
                let Some(dst) = pktinfo_v4(&msg) else {
                    return Ok((0, dummy, dummy));
                };
                (SocketAddr::new(IpAddr::V4(dst), listen_port), peer)
            }
            OuterFamily::Ipv6 => {
                let peer = from_raw_v6(peer_storage);
                let Some((dst, ifindex)) = pktinfo_v6(&msg) else {
                    return Ok((0, dummy, dummy));
                };
                let scope = if dst.is_unicast_link_local() {
                    ifindex
                } else {
                    0
                };
                let local = SocketAddr::V6(SocketAddrV6::new(dst, listen_port, 0, scope));
                (local, peer)
            }
        }
    };
    Ok((n as usize, local, peer))
}

/// Sends one datagram from an unconnected listener socket using `local.ip()` as source address.
pub fn send_unconnected(
    fd: &UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    frame: &[u8],
) -> io::Result<()> {
    let peer_sa = SockAddr::from_socket(peer);
    let (name_ptr, name_len) = peer_sa.as_ptr_len();
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let mut control: CmsgBuf = [0; 8];
    // SAFETY: plain C struct zero-initialized before populating fields.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = name_ptr.cast_mut().cast();
    msg.msg_namelen = name_len;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();

    // SAFETY: control buffer has 64 bytes, more than enough for a single in_pktinfo / in6_pktinfo cmsg.
    unsafe {
        match local {
            SocketAddr::V4(v4) => put_cmsg(
                &mut msg,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from(*v4.ip()).to_be(),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            ),
            SocketAddr::V6(v6) => put_cmsg(
                &mut msg,
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    ipi6_ifindex: v6.scope_id(),
                },
            ),
        }
        let n = libc::sendmsg(fd.as_raw_fd(), &msg, libc::MSG_DONTWAIT);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[inline]
unsafe fn put_cmsg<T>(msg: &mut libc::msghdr, level: libc::c_int, ty: libc::c_int, info: T) {
    // SAFETY: caller provides a control buffer large enough for `CMSG_SPACE(size_of::<T>())`.
    unsafe {
        msg.msg_controllen = libc::CMSG_SPACE(size_of::<T>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(msg);
        (*cmsg).cmsg_level = level;
        (*cmsg).cmsg_type = ty;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<T>() as u32) as _;
        write_unaligned(libc::CMSG_DATA(cmsg).cast::<T>(), info);
    }
}

#[inline]
pub fn send(fd: &UdpSocket, frame: &[u8]) -> io::Result<()> {
    // SAFETY: `frame` remains live for the synchronous send syscall.
    let n = unsafe {
        libc::send(
            fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Reusable batched descriptor storage for a connected UDP socket.
pub struct Sender {
    iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
}

impl Sender {
    pub fn new() -> Self {
        // SAFETY: zero is valid for plain C descriptors; iovec pointers are installed below.
        let mut sender = Self {
            iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
        };
        for k in 0..BATCH {
            sender.hdrs[k].msg_hdr.msg_iov = &mut sender.iovs[k];
            sender.hdrs[k].msg_hdr.msg_iovlen = 1;
        }
        sender
    }

    pub fn send<'a>(
        &mut self,
        fd: &UdpSocket,
        frames: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> usize {
        let count = frames.len();
        assert!(count <= BATCH);
        for (k, frame) in frames.enumerate() {
            self.iovs[k].iov_base = frame.as_ptr().cast_mut().cast();
            self.iovs[k].iov_len = frame.len();
        }
        send_progress("udp", count, |sent| {
            // SAFETY: active descriptors point into live frames and boxed iovecs.
            let n = unsafe {
                libc::sendmmsg(
                    fd.as_raw_fd(),
                    self.hdrs[sent..].as_mut_ptr(),
                    (count - sent) as _,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        })
    }
}

/// Owns fixed receive buffers for batched `recvmmsg` on a connected UDP socket.
pub struct Receiver {
    bufs: Box<[u8]>,
    pub lens: [usize; BATCH],
    _iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
}

impl Receiver {
    pub fn new(stride: usize) -> Self {
        // SAFETY: plain C descriptor structs zero-initialized before setting iovec pointers.
        let mut rx = Self {
            bufs: vec![0; BATCH * stride].into(),
            lens: [0; BATCH],
            _iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
        };
        for k in 0..BATCH {
            rx._iovs[k] = libc::iovec {
                iov_base: rx.bufs[k * stride..].as_mut_ptr().cast(),
                iov_len: stride,
            };
            let msg = &mut rx.hdrs[k].msg_hdr;
            msg.msg_iov = &mut rx._iovs[k];
            msg.msg_iovlen = 1;
        }
        rx
    }

    pub fn buffers(&self) -> &[u8] {
        &self.bufs
    }

    pub fn buffers_mut(&mut self) -> &mut [u8] {
        &mut self.bufs
    }

    /// Truncated frames have length zero.
    pub fn receive(&mut self, fd: &UdpSocket) -> io::Result<usize> {
        // SAFETY: boxed buffers and descriptors remain live and fixed.
        let m = unsafe {
            libc::recvmmsg(
                fd.as_raw_fd(),
                self.hdrs.as_mut_ptr(),
                BATCH as _,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if m < 0 {
            return Err(io::Error::last_os_error());
        }
        let used = m as usize;
        for k in 0..used {
            let hdr = &self.hdrs[k];
            self.lens[k] = if hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                0
            } else {
                hdr.msg_len as usize
            };
        }
        Ok(used)
    }
}

#[inline]
unsafe fn pktinfo_v4(msg: &libc::msghdr) -> Option<Ipv4Addr> {
    // SAFETY: caller guarantees msg points to a valid msghdr with initialized control buffer.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP
                && (*cmsg).cmsg_type == libc::IP_PKTINFO
                && (*cmsg).cmsg_len >= libc::CMSG_LEN(size_of::<in_pktinfo>() as u32) as _
            {
                let info = read_unaligned(libc::CMSG_DATA(cmsg).cast::<in_pktinfo>());
                return Some(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr)));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
        None
    }
}

#[inline]
unsafe fn pktinfo_v6(msg: &libc::msghdr) -> Option<(Ipv6Addr, u32)> {
    // SAFETY: caller guarantees msg points to a valid msghdr with initialized control buffer.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                && (*cmsg).cmsg_len >= libc::CMSG_LEN(size_of::<in6_pktinfo>() as u32) as _
            {
                let info = read_unaligned(libc::CMSG_DATA(cmsg).cast::<in6_pktinfo>());
                return Some((Ipv6Addr::from(info.ipi6_addr.s6_addr), info.ipi6_ifindex));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_exit_socket_steers_peer_traffic_away_from_wildcard_listener() {
        for (family, ip) in [
            (OuterFamily::Ipv4, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (OuterFamily::Ipv6, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            let lis = listener(family, None, 0, None).unwrap();
            let port = lis.local_addr().unwrap().port();
            let target = SocketAddr::new(ip, port);

            let (entry1, entry1_local) = connect_entry(ip, target, None).unwrap();
            send(&entry1, b"hello-1").unwrap();

            let mut buf = [0u8; 64];
            let (n, local, peer) = recv_unconnected(&lis, family, port, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello-1");
            assert_eq!(local, target);
            assert_eq!(peer, entry1_local);

            send_unconnected(&lis, local, peer, b"challenge-1").unwrap();
            let mut rx1 = Receiver::new(64);
            assert_eq!(rx1.receive(&entry1).unwrap(), 1);
            assert_eq!(&rx1.buffers()[..rx1.lens[0]], b"challenge-1");

            // Promote peer1 to a connected Exit worker socket on the same port.
            let worker1 = connect_exit(local, peer, None).unwrap();
            let mut tx_entry = Sender::new();
            assert_eq!(
                tx_entry.send(&entry1, [b"data-a".as_slice(), b"data-b"].into_iter()),
                2
            );

            // Kernel delivers peer1's datagrams to worker1, not the wildcard listener.
            assert_eq!(
                recv_unconnected(&lis, family, port, &mut buf)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            let mut rx_worker = Receiver::new(64);
            assert_eq!(rx_worker.receive(&worker1).unwrap(), 2);
            assert_eq!(&rx_worker.buffers()[..rx_worker.lens[0]], b"data-a");
            assert_eq!(&rx_worker.buffers()[64..64 + rx_worker.lens[1]], b"data-b");

            // A second peer on a different ephemeral port still reaches the wildcard listener.
            let (entry2, entry2_local) = connect_entry(ip, target, None).unwrap();
            send(&entry2, b"hello-2").unwrap();
            let (n2, local2, peer2) = recv_unconnected(&lis, family, port, &mut buf).unwrap();
            assert_eq!(&buf[..n2], b"hello-2");
            assert_eq!(local2, target);
            assert_eq!(peer2, entry2_local);
        }
    }
}
