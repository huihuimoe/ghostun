//! Thin OS wrappers: TUN, raw/TCP sockets, poll, signals, CSPRNG, CPU affinity, routing.

pub mod netlink;

use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::OuterFamily;
use crate::faketcp::pkt::{self, IPV6_HDR};

/// fwmark on every frame ghostun sends, so the netfilter RST-suppression rule spares our own RSTs.
pub const SOCKET_MARK: u32 = 0x6768_7374;
const SOCKET_BUF: libc::c_int = 4 << 20;
pub const RAW_BATCH: usize = 64;
pub const READ_READY: i16 = libc::POLLIN | libc::POLLERR | libc::POLLHUP;
pub const WRITE_READY: i16 = libc::POLLOUT | libc::POLLERR | libc::POLLHUP;
type CmsgBuf = [usize; 8];

#[inline(always)]
fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[inline]
pub fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|_| io::Error::other("OS cryptographic randomness unavailable"))
}

pub fn install_signal_handlers(handler: extern "C" fn(libc::c_int)) -> io::Result<()> {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `sigaction` is zero-initialized and populated with a valid C signal handler.
        unsafe {
            let mut sa: libc::sigaction = zeroed();
            sa.sa_sigaction = handler as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            cvt(libc::sigaction(sig, &sa, std::ptr::null_mut()))?;
        }
    }
    Ok(())
}

pub fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: constant flags; returned descriptor is owned immediately.
    let fd = cvt(unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[inline]
pub fn eventfd_notify(fd: RawFd) {
    if fd >= 0 {
        let one = 1u64.to_ne_bytes();
        // SAFETY: async-signal-safe 8-byte write to a valid nonblocking eventfd.
        unsafe {
            let _ = libc::write(fd, one.as_ptr().cast(), one.len());
        }
    }
}

#[inline]
pub fn eventfd_drain(fd: BorrowedFd<'_>) {
    let mut buf = [0u8; 8];
    // SAFETY: 8-byte read from a valid nonblocking eventfd.
    unsafe {
        let _ = libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len());
    }
}

#[inline]
pub fn poll_wake(pfd: libc::pollfd, fd: BorrowedFd<'_>) -> bool {
    let ready = pfd.revents & libc::POLLIN != 0;
    if ready {
        eventfd_drain(fd);
    }
    ready
}

#[inline(always)]
pub const fn pollfd(fd: i32, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// Rounds up sub-millisecond waits so callers never wake just before a deadline and spin.
#[inline(always)]
pub fn poll_ms(wait: Duration) -> libc::c_int {
    wait.as_micros().div_ceil(1000) as libc::c_int
}

#[inline]
pub fn poll(fds: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<bool> {
    // SAFETY: `fds` is a valid slice of `pollfd` structs of length `fds.len()`.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

#[inline]
pub fn tun_read(tun: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    // SAFETY: valid nonblocking descriptor and writable buffer of the supplied length.
    let n = unsafe { libc::read(tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            Ok(None)
        } else {
            Err(e)
        }
    } else if n == 0 {
        Err(io::ErrorKind::UnexpectedEof.into())
    } else {
        Ok(Some(n as usize))
    }
}

#[inline]
pub fn tun_write(tun: BorrowedFd<'_>, packet: &[u8]) -> io::Result<bool> {
    // SAFETY: valid descriptor and readable packet slice. TUN writes preserve packet boundaries.
    let n = unsafe { libc::write(tun.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
    if n == packet.len() as isize {
        return Ok(true);
    }
    if n >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short TUN packet write",
        ));
    }
    let e = io::Error::last_os_error();
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(false)
    } else {
        Err(e)
    }
}

fn ifreq_with_flags(flags: libc::c_int) -> libc::ifreq {
    // SAFETY: `libc::ifreq` is a plain C union/struct valid when zero-initialized.
    let mut req: libc::ifreq = unsafe { zeroed() };
    req.ifr_ifru.ifru_flags = flags as libc::c_short;
    req
}

fn tun_ioctl(fd: BorrowedFd<'_>, request: libc::Ioctl, req: &mut libc::ifreq) -> io::Result<()> {
    // SAFETY: `request` is a TUN ioctl reading/writing a live `libc::ifreq`.
    cvt(unsafe { libc::ioctl(fd.as_raw_fd(), request, req as *mut libc::ifreq) }).map(drop)
}

/// Opens `queues` non-blocking, initially detached queue fds of one multi-queue TUN device.
/// Without `IFF_PERSIST` the kernel destroys the device when the last fd closes, including on SIGKILL.
pub fn create_tun(name: &str, queues: usize) -> io::Result<Vec<OwnedFd>> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let mut req = ifreq_with_flags(libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE);
    for (dst, &src) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = src as libc::c_char;
    }
    (0..queues)
        .map(|_| {
            // SAFETY: plain open(2) of a NUL-terminated path; the fd is owned immediately.
            let fd = cvt(unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            tun_ioctl(fd.as_fd(), libc::TUNSETIFF as _, &mut req)?;
            set_tun_queue(fd.as_fd(), false)?;
            Ok(fd)
        })
        .collect()
}

/// Attaches or detaches one multi-queue TUN fd so the kernel only hashes inner flows onto
/// `Established` workers instead of black-holing `1/N` of traffic into reconnecting slots.
pub fn set_tun_queue(fd: BorrowedFd<'_>, attach: bool) -> io::Result<()> {
    let mut req = ifreq_with_flags(if attach {
        libc::IFF_ATTACH_QUEUE
    } else {
        libc::IFF_DETACH_QUEUE
    });
    tun_ioctl(fd, libc::TUNSETQUEUE as _, &mut req)
}

fn setsockopt<T>(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` points to a live T of the length passed.
    cvt(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    })
    .map(drop)
}

fn bind_to_device(fd: &OwnedFd, dev: Option<&str>) -> io::Result<()> {
    if let Some(dev) = dev {
        // SAFETY: `dev` points to `dev.len()` valid interface-name bytes.
        cvt(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                dev.as_ptr().cast(),
                dev.len() as libc::socklen_t,
            )
        })?;
    }
    Ok(())
}

/// Non-blocking raw TCP socket with caller-supplied IP headers and per-worker cBPF steering.
pub fn raw_socket(
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

#[derive(Clone, Copy)]
enum SockAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl SockAddr {
    #[inline]
    fn from_ip(dst: IpAddr) -> Self {
        match dst {
            IpAddr::V4(ip) => Self::V4(libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(ip).to_be(),
                },
                sin_zero: [0; 8],
            }),
            IpAddr::V6(ip) => Self::V6(libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_scope_id: 0,
            }),
        }
    }

    #[inline]
    fn from_socket(addr: SocketAddr) -> Self {
        let mut sa = Self::from_ip(addr.ip());
        match (&mut sa, addr) {
            (Self::V4(v4), SocketAddr::V4(_)) => v4.sin_port = addr.port().to_be(),
            (Self::V6(v6), SocketAddr::V6(s)) => {
                v6.sin6_port = s.port().to_be();
                v6.sin6_scope_id = s.scope_id();
            }
            _ => unreachable!(),
        }
        sa
    }

    #[inline(always)]
    fn as_ptr_len(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(v4) => (
                (v4 as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(v6) => (
                (v6 as *const libc::sockaddr_in6).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

/// Binds a single-family kernel listener; IPv6 never silently accepts IPv4-mapped peers.
pub fn tcp_listener(addr: SocketAddr, dev: Option<&str>) -> io::Result<TcpListener> {
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
pub fn tcp_connect(remote: SocketAddr, dev: Option<&str>) -> io::Result<TcpStream> {
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

/// Reusable descriptor storage. Every pointer targets a separate stable heap allocation.
pub struct RawSender {
    iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
    destinations: Box<[SockAddr]>,
}

impl RawSender {
    pub fn new(family: OuterFamily) -> Self {
        // SAFETY: zero is valid for these plain C descriptors; pointers are installed below.
        let mut sender = Self {
            iovs: (0..RAW_BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..RAW_BATCH).map(|_| unsafe { zeroed() }).collect(),
            destinations: vec![SockAddr::from_ip(family.unspecified()); RAW_BATCH].into(),
        };
        for k in 0..RAW_BATCH {
            sender.hdrs[k].msg_hdr.msg_iov = &mut sender.iovs[k];
            sender.hdrs[k].msg_hdr.msg_iovlen = 1;
        }
        sender
    }

    pub fn send<'a>(
        &mut self,
        fd: BorrowedFd<'_>,
        frames: impl ExactSizeIterator<Item = (&'a [u8], IpAddr)>,
    ) -> io::Result<()> {
        let count = frames.len();
        assert!(count <= RAW_BATCH);
        for (k, (frame, dst)) in frames.enumerate() {
            self.destinations[k] = SockAddr::from_ip(dst);
            let (addr, len) = self.destinations[k].as_ptr_len();
            self.iovs[k].iov_base = frame.as_ptr().cast_mut().cast();
            self.iovs[k].iov_len = frame.len();
            self.hdrs[k].msg_hdr.msg_name = addr.cast_mut().cast();
            self.hdrs[k].msg_hdr.msg_namelen = len;
        }
        let mut first_err = None;
        let mut sent = 0;
        while sent < count {
            // SAFETY: active descriptors point into live frames, destinations and boxed iovecs.
            let n = unsafe {
                libc::sendmmsg(
                    fd.as_raw_fd(),
                    self.hdrs[sent..].as_mut_ptr(),
                    (count - sent) as _,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if n > 0 {
                sent += n as usize;
                continue;
            }
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(e);
            }
            first_err.get_or_insert(e);
            sent += 1;
        }
        first_err.map_or(Ok(()), Err)
    }
}

#[inline]
pub fn send_raw(fd: BorrowedFd<'_>, frame: &[u8], dst: IpAddr) -> io::Result<()> {
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
pub struct RawReceiver {
    bufs: Box<[u8]>,
    pub lens: [usize; RAW_BATCH],
    stride: usize,
    family: OuterFamily,
    _iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
    sources: Box<[libc::sockaddr_in6]>,
    _controls: Box<[CmsgBuf]>,
    used: usize,
}

impl RawReceiver {
    pub fn new(family: OuterFamily, stride: usize) -> Self {
        // SAFETY: all zeroed types are plain C storage; initialized pointers are set below.
        let mut rx = Self {
            bufs: vec![0; RAW_BATCH * stride].into(),
            lens: [0; RAW_BATCH],
            stride,
            family,
            _iovs: (0..RAW_BATCH).map(|_| unsafe { zeroed() }).collect(),
            hdrs: (0..RAW_BATCH).map(|_| unsafe { zeroed() }).collect(),
            sources: (0..RAW_BATCH).map(|_| unsafe { zeroed() }).collect(),
            _controls: vec![[0; 8]; RAW_BATCH].into(),
            used: RAW_BATCH,
        };
        let offset = if family == OuterFamily::Ipv6 {
            IPV6_HDR
        } else {
            0
        };
        for k in 0..RAW_BATCH {
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
                hdr.msg_hdr.msg_controllen = size_of::<CmsgBuf>();
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
                RAW_BATCH as _,
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
                pkt::write_ipv6_header(
                    &mut self.bufs[k * self.stride..(k + 1) * self.stride],
                    Ipv6Addr::from(self.sources[k].sin6_addr.s6_addr),
                    dst,
                    n,
                );
                IPV6_HDR + n
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

/// Returns the calling thread's allowed CPU IDs in ascending order.
pub fn usable_cpus() -> Vec<usize> {
    // SAFETY: cpu_set_t is plain data; CPU_ISSET stays within CPU_SETSIZE.
    unsafe {
        let mut allowed: libc::cpu_set_t = zeroed();
        if libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut allowed) != 0 {
            return Vec::new();
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| libc::CPU_ISSET(c, &allowed))
            .collect()
    }
}

/// Pins the calling thread to `cpu`.
pub fn pin_to_cpu(cpu: usize) -> io::Result<()> {
    // SAFETY: cpu_set_t is plain data; CPU_SET stays within its bounds.
    unsafe {
        let mut set: libc::cpu_set_t = zeroed();
        libc::CPU_SET(cpu, &mut set);
        cvt(libc::sched_setaffinity(
            0,
            size_of::<libc::cpu_set_t>(),
            &set,
        ))
        .map(drop)
    }
}

pub fn iface_mtu(dev: &str) -> io::Result<u32> {
    let text = std::fs::read_to_string(Path::new("/sys/class/net").join(dev).join("mtu"))?;
    text.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad MTU for {dev}: {text:?}"),
        )
    })
}

/// No-op when the value is already set, so read-only `/proc/sys` (containers) works if the host pre-set it.
pub fn sysctl_set(key: &str, value: &str) -> io::Result<()> {
    let path = PathBuf::from("/proc/sys").join(key.replace('.', "/"));
    let annotate = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
    if std::fs::read_to_string(&path).map_err(annotate)?.trim() == value {
        return Ok(());
    }
    File::create(&path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .map_err(annotate)
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use std::net::UdpSocket;

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
            let fd = raw_socket(family, None, &filter, Some((ip, ip))).unwrap();
            for peer in [false, true] {
                let address = SockAddr::from_ip(family.unspecified());
                let (_, mut len) = address.as_ptr_len();
                // SAFETY: address has writable storage of the selected family's exact size.
                let mut address = address;
                let ptr = match &mut address {
                    SockAddr::V4(v) => (v as *mut libc::sockaddr_in).cast(),
                    SockAddr::V6(v) => (v as *mut libc::sockaddr_in6).cast(),
                };
                // SAFETY: ptr and len describe the live, correctly aligned address storage.
                let result = unsafe {
                    if peer {
                        libc::getpeername(fd.as_raw_fd(), ptr, &mut len)
                    } else {
                        libc::getsockname(fd.as_raw_fd(), ptr, &mut len)
                    }
                };
                assert_eq!(result, 0);
                let got = match address {
                    SockAddr::V4(v) => IpAddr::from(v.sin_addr.s_addr.to_ne_bytes()),
                    SockAddr::V6(v) => IpAddr::from(v.sin6_addr.s6_addr),
                };
                assert_eq!(got, ip);
            }
        }
    }

    #[test]
    fn receive_reuses_storage_after_move_truncation_and_empty_read() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx = RawReceiver::new(OuterFamily::Ipv4, 32);
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
        let mut rx = RawReceiver::new(OuterFamily::Ipv6, 128);
        for _ in 0..3 {
            peer.send_to(b"packet", socket.local_addr().unwrap())
                .unwrap();
            assert_eq!(rx.receive(socket.as_fd()).unwrap(), 1);
            assert_eq!(rx.lens[0], IPV6_HDR + 6);
            assert_eq!(&rx.buffers()[IPV6_HDR..rx.lens[0]], b"packet");
            assert_eq!(&rx.buffers()[24..40], &Ipv6Addr::LOCALHOST.octets());
        }
    }
}
