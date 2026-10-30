//! Raw TCP sockets with caller-built IP headers, and their batched send/receive storage.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::{bind_to_device, cvt, setsockopt, SockAddr};
use crate::net::{ipv6, OuterFamily};

/// fwmark on every frame ghostun sends, so the netfilter RST-suppression rule spares our own RSTs.
pub const SOCKET_MARK: u32 = 0x6768_7374;
const SOCKET_BUF: libc::c_int = 4 << 20;
pub const BATCH: usize = 64;
type CmsgBuf = [usize; 8];

/// Non-blocking raw TCP socket with caller-supplied IP headers and per-worker cBPF steering.
pub fn socket(
    family: OuterFamily,
    bind_dev: Option<&str>,
    filter: &[libc::sock_filter],
    entry_addresses: Option<(IpAddr, IpAddr)>,
) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments; the fd is owned immediately.
    let fd = cvt(unsafe {
        libc::socket(
            match family {
                OuterFamily::Ipv4 => libc::AF_INET,
                OuterFamily::Ipv6 => libc::AF_INET6,
            },
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    })?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    bind_to_device(&fd, bind_dev)?;
    let one: libc::c_int = 1;
    match family {
        OuterFamily::Ipv4 => setsockopt(&fd, libc::IPPROTO_IP, libc::IP_HDRINCL, &one)?,
        OuterFamily::Ipv6 => {
            setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_HDRINCL, &one)?;
            setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &one)?;
            setsockopt(
                &fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &libc::IPV6_PMTUDISC_DO,
            )?;
        }
    }
    if let Some((local, remote)) = entry_addresses {
        for (ip, bind) in [(local, true), (remote, false)] {
            let mut address = SockAddr::from_ip(ip);
            if let (SockAddr::V6(v6), Some(dev)) = (&mut address, bind_dev) {
                let dev = std::ffi::CString::new(dev)?;
                // SAFETY: dev is a valid NUL-terminated interface name.
                v6.sin6_scope_id = unsafe { libc::if_nametoindex(dev.as_ptr()) };
            }
            let (ptr, len) = address.as_ptr_len();
            // SAFETY: address is live and its length matches its family. Raw ports remain zero.
            unsafe {
                cvt(if bind {
                    libc::bind(fd.as_raw_fd(), ptr, len)
                } else {
                    libc::connect(fd.as_raw_fd(), ptr, len)
                })?;
            }
        }
    }
    setsockopt(&fd, libc::SOL_SOCKET, libc::SO_MARK, &SOCKET_MARK)?;
    for (force, plain) in [
        (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF),
        (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF),
    ] {
        if setsockopt(&fd, libc::SOL_SOCKET, force, &SOCKET_BUF).is_err() {
            setsockopt(&fd, libc::SOL_SOCKET, plain, &SOCKET_BUF)?;
        }
    }
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr().cast_mut(),
    };
    setsockopt(&fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &prog)?;
    // Frames queued between socket() and the filter attach bypassed the filter; discard them.
    let mut buf = [0u8; 2048];
    // SAFETY: recv into a local buffer of the stated length.
    while unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    } >= 0
    {}
    Ok(fd)
}

/// Reusable descriptor storage. Every pointer targets a separate stable heap allocation.
pub struct Sender {
    iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
    destinations: Box<[SockAddr]>,
}

impl Sender {
    pub fn new(family: OuterFamily) -> Self {
        // SAFETY: zero is valid for these plain C descriptors; pointers are installed below.
        let mut sender = Self {
            iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            destinations: vec![SockAddr::from_ip(family.unspecified()); BATCH].into(),
        };
        for k in 0..BATCH {
            sender.hdrs[k].msg_hdr.msg_iov = &mut sender.iovs[k];
            sender.hdrs[k].msg_hdr.msg_iovlen = 1;
        }
        sender
    }

    pub fn send<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        frames: impl ExactSizeIterator<Item = (&'a [u8], IpAddr)>,
    ) -> usize {
        let count = frames.len();
        assert!(count <= BATCH);
        for (k, (frame, dst)) in frames.enumerate() {
            self.destinations[k] = SockAddr::from_ip(dst);
            let (addr, len) = self.destinations[k].as_ptr_len();
            self.iovs[k].iov_base = frame.as_ptr().cast_mut().cast();
            self.iovs[k].iov_len = frame.len();
            self.hdrs[k].msg_hdr.msg_name = addr.cast_mut().cast();
            self.hdrs[k].msg_hdr.msg_namelen = len;
        }
        send_progress(count, |sent| {
            // SAFETY: active descriptors point into live frames, destinations and boxed iovecs.
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

/// Counts the completed prefix, including explicitly dropped non-retryable packets.
fn send_progress(count: usize, mut send: impl FnMut(usize) -> io::Result<usize>) -> usize {
    let mut completed = 0;
    while completed < count {
        match send(completed) {
            Ok(0) => break,
            Ok(n) => completed += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                log::debug!("raw send: {e}; dropping packet");
                completed += 1;
            }
        }
    }
    completed
}

#[inline]
pub fn send(fd: BorrowedFd<'_>, frame: &[u8], dst: IpAddr) -> io::Result<()> {
    let sa = SockAddr::from_ip(dst);
    let (addr, len) = sa.as_ptr_len();
    // SAFETY: frame and destination remain live until the synchronous sendto returns.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT,
            addr,
            len,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Owns receive buffers and ancillary storage; none of the backing allocations are resized.
pub struct Receiver {
    bufs: Box<[u8]>,
    pub lens: [usize; BATCH],
    stride: usize,
    family: OuterFamily,
    _iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
    sources: Box<[libc::sockaddr_in6]>,
    _controls: Box<[CmsgBuf]>,
    used: usize,
}

impl Receiver {
    pub fn new(family: OuterFamily, stride: usize) -> Self {
        // SAFETY: all zeroed types are plain C storage; initialized pointers are set below.
        let mut rx = Self {
            bufs: vec![0; BATCH * stride].into(),
            lens: [0; BATCH],
            stride,
            family,
            _iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            sources: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            _controls: vec![[0; 8]; BATCH].into(),
            used: BATCH,
        };
        let offset = if family == OuterFamily::Ipv6 {
            ipv6::HDR_LEN
        } else {
            0
        };
        for k in 0..BATCH {
            rx._iovs[k] = libc::iovec {
                iov_base: rx.bufs[k * stride + offset..].as_mut_ptr().cast(),
                iov_len: stride - offset,
            };
            let msg = &mut rx.hdrs[k].msg_hdr;
            msg.msg_iov = &mut rx._iovs[k];
            msg.msg_iovlen = 1;
            if family == OuterFamily::Ipv6 {
                msg.msg_name = (&mut rx.sources[k] as *mut libc::sockaddr_in6).cast();
                msg.msg_control = rx._controls[k].as_mut_ptr().cast();
            }
        }
        rx
    }

    pub fn buffers(&self) -> &[u8] {
        &self.bufs
    }

    pub fn buffers_mut(&mut self) -> &mut [u8] {
        &mut self.bufs
    }

    fn reset(&mut self) {
        for hdr in &mut self.hdrs[..self.used] {
            hdr.msg_len = 0;
            hdr.msg_hdr.msg_flags = 0;
            if self.family == OuterFamily::Ipv6 {
                hdr.msg_hdr.msg_namelen = size_of::<libc::sockaddr_in6>() as _;
                hdr.msg_hdr.msg_controllen = size_of::<CmsgBuf>() as _;
            }
        }
    }

    /// Truncated frames and malformed IPv6 ancillary data have length zero.
    pub fn receive(&mut self, fd: BorrowedFd<'_>) -> io::Result<usize> {
        self.reset();
        // SAFETY: boxed buffers, descriptors and ancillary storage remain live and fixed.
        let m = unsafe {
            libc::recvmmsg(
                fd.as_raw_fd(),
                self.hdrs.as_mut_ptr(),
                BATCH as _,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        self.used = 0;
        if m < 0 {
            return Err(io::Error::last_os_error());
        }
        self.used = m as usize;
        for k in 0..self.used {
            let hdr = &self.hdrs[k];
            let msg = &hdr.msg_hdr;
            let n = hdr.msg_len as usize;
            self.lens[k] = if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                0
            } else if self.family == OuterFamily::Ipv4 {
                n
            // SAFETY: recvmmsg populated the bounded ancillary buffer referenced by msg.
            } else if let Some(dst) = unsafe { pktinfo_dst(msg) } {
                ipv6::write_header(
                    &mut self.bufs[k * self.stride..(k + 1) * self.stride],
                    n as u16,
                    Ipv6Addr::from(self.sources[k].sin6_addr.s6_addr),
                    dst,
                );
                ipv6::HDR_LEN + n
            } else {
                0
            };
        }
        Ok(self.used)
    }
}

#[inline]
unsafe fn pktinfo_dst(msg: &libc::msghdr) -> Option<Ipv6Addr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
            && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
            && (*cmsg).cmsg_len >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as _
        {
            let info = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>());
            return Some(Ipv6Addr::from(info.ipi6_addr.s6_addr));
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{self, ipv4, tcp};
    use std::net::UdpSocket;
    use std::os::fd::AsFd;
    use zerocopy::FromBytes;

    #[test]
    fn partial_send_keeps_progress_across_interrupt_and_backpressure() {
        let mut results = [
            Ok(2),
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::ErrorKind::WouldBlock.into()),
        ]
        .into_iter();
        let mut positions = Vec::new();
        assert_eq!(
            send_progress(5, |offset| {
                positions.push(offset);
                results.next().unwrap()
            }),
            2
        );
        assert_eq!(positions, [0, 2, 2]);
        let mut results = [Err(io::Error::from_raw_os_error(libc::EMSGSIZE)), Ok(2)].into_iter();
        let mut positions = Vec::new();
        assert_eq!(
            send_progress(3, |offset| {
                positions.push(offset);
                results.next().unwrap()
            }),
            3
        );
        assert_eq!(positions, [0, 1]);
    }

    /// A header-only RST from `ip:40000` to `ip:40001`.
    fn rst_frame(ip: IpAddr) -> ([u8; ipv6::HDR_LEN + tcp::HDR_LEN], usize) {
        let mut frame = [0u8; ipv6::HDR_LEN + tcp::HDR_LEN];
        let ihl = OuterFamily::of(ip).overhead() - tcp::HDR_LEN;
        let len = ihl + tcp::HDR_LEN;
        match ip {
            IpAddr::V4(ip) => ipv4::write_header(&mut frame, len as u16, 0, ip, ip),
            IpAddr::V6(ip) => ipv6::write_header(&mut frame, tcp::HDR_LEN as u16, ip, ip),
        }
        let (header, _) = tcp::Header::mut_from_prefix(&mut frame[ihl..]).unwrap();
        header.src_port.set(40000);
        header.dst_port.set(40001);
        header.seq.set(1);
        header.data_offset = ((tcp::HDR_LEN / 4) as u8) << 4;
        header.flags = 0x04;
        let csum = net::tcp_checksum(&frame, ihl, tcp::HDR_LEN);
        let (header, _) = tcp::Header::mut_from_prefix(&mut frame[ihl..]).unwrap();
        header.checksum.set(csum);
        (frame, len)
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW and CAP_NET_ADMIN; run in the e2e container"]
    fn entry_raw_socket_binds_and_connects_both_families() {
        let filter = [libc::sock_filter {
            code: 6,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        for ip in [
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse().unwrap(),
        ] {
            let family = OuterFamily::of(ip);
            let fd = socket(family, None, &filter, Some((ip, ip))).unwrap();
            {
                let address = SockAddr::from_ip(family.unspecified());
                let (_, mut len) = address.as_ptr_len();
                // SAFETY: address has writable storage of the selected family's exact size.
                let mut address = address;
                let ptr = match &mut address {
                    SockAddr::V4(v) => (v as *mut libc::sockaddr_in).cast(),
                    SockAddr::V6(v) => (v as *mut libc::sockaddr_in6).cast(),
                };
                // SAFETY: ptr and len describe the live, correctly aligned address storage.
                let result = unsafe { libc::getsockname(fd.as_raw_fd(), ptr, &mut len) };
                assert_eq!(result, 0, "{}", io::Error::last_os_error());
                let got = match address {
                    SockAddr::V4(v) => IpAddr::from(v.sin_addr.s_addr.to_ne_bytes()),
                    SockAddr::V6(v) => IpAddr::from(v.sin6_addr.s6_addr),
                };
                assert_eq!(got, ip);
            }
            let (frame, len) = rst_frame(ip);
            // Raw sockets use port zero, so getpeername reports ENOTCONN even after connect.
            // Sending without a destination must fail before connect and succeed after it.
            let unconnected = socket(family, None, &filter, None).unwrap();
            for (socket, connected) in [(&unconnected, false), (&fd, true)] {
                // SAFETY: frame holds len initialized bytes and the socket is live.
                let sent = unsafe { libc::send(socket.as_raw_fd(), frame.as_ptr().cast(), len, 0) };
                if connected {
                    assert_eq!(sent, len as isize, "{}", io::Error::last_os_error());
                } else {
                    assert_eq!(sent, -1);
                    assert_eq!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::EDESTADDRREQ)
                    );
                }
            }
        }
    }

    #[test]
    fn receive_reuses_storage_after_move_truncation_and_empty_read() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx = Receiver::new(OuterFamily::Ipv4, 32);
        let mut moved = Box::new(rx);
        peer.send_to(&[7; 40], socket.local_addr().unwrap())
            .unwrap();
        assert_eq!(moved.receive(socket.as_fd()).unwrap(), 1);
        assert_eq!(moved.lens[0], 0);
        assert_eq!(
            moved.receive(socket.as_fd()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        for payload in [b"one".as_slice(), b"second"] {
            peer.send_to(payload, socket.local_addr().unwrap()).unwrap();
            assert_eq!(moved.receive(socket.as_fd()).unwrap(), 1);
            assert_eq!(&moved.buffers()[..moved.lens[0]], payload);
        }
    }

    #[test]
    fn ipv6_ancillary_capacity_is_restored_for_repeated_short_batches() {
        let socket = UdpSocket::bind("[::1]:0").unwrap();
        let peer = UdpSocket::bind("[::1]:0").unwrap();
        let fd: OwnedFd = socket.try_clone().unwrap().into();
        setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &1i32).unwrap();
        let mut rx = Receiver::new(OuterFamily::Ipv6, 128);
        for _ in 0..3 {
            peer.send_to(b"packet", socket.local_addr().unwrap())
                .unwrap();
            assert_eq!(rx.receive(socket.as_fd()).unwrap(), 1);
            assert_eq!(rx.lens[0], ipv6::HDR_LEN + 6);
            assert_eq!(&rx.buffers()[ipv6::HDR_LEN..rx.lens[0]], b"packet");
            assert_eq!(&rx.buffers()[24..40], &Ipv6Addr::LOCALHOST.octets());
        }
    }
}
