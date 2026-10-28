//! Thin OS wrappers: TUN, raw/TCP sockets, poll, signals, CSPRNG, CPU affinity, routing.

pub mod netlink;

use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, zeroed, MaybeUninit};
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
fn uninit_batch<T>() -> [MaybeUninit<T>; RAW_BATCH] {
    [const { MaybeUninit::uninit() }; RAW_BATCH]
}

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

#[inline]
pub fn send_raw(fd: BorrowedFd<'_>, frame: &[u8], dst: IpAddr) -> io::Result<()> {
    send_raw_batch(fd, frame, frame.len(), &[frame.len()], dst)
}

#[inline]
pub fn send_raw_batch(
    fd: BorrowedFd<'_>,
    bufs: &[u8],
    stride: usize,
    lens: &[usize],
    dst: IpAddr,
) -> io::Result<()> {
    let count = lens.len();
    let sa = SockAddr::from_ip(dst);
    let (addr_ptr, namelen) = sa.as_ptr_len();
    let mut iovs = uninit_batch::<libc::iovec>();
    let mut hdrs = uninit_batch::<libc::mmsghdr>();
    // SAFETY: POD socket structs; active indices 0..count are fully initialized before sendmmsg.
    unsafe {
        let mut base: libc::mmsghdr = zeroed();
        base.msg_hdr.msg_name = addr_ptr.cast_mut().cast();
        base.msg_hdr.msg_namelen = namelen;
        base.msg_hdr.msg_iovlen = 1;
        for (k, &len) in lens.iter().enumerate() {
            let iov = iovs[k].write(libc::iovec {
                iov_base: bufs[k * stride..].as_ptr().cast_mut().cast(),
                iov_len: len,
            });
            let mut hdr = base;
            hdr.msg_hdr.msg_iov = iov;
            hdrs[k].write(hdr);
        }
    }
    let mut first_err = None;
    let mut sent = 0;
    while sent < count {
        // SAFETY: hdrs[sent..count] were initialized above and reference live iovecs and buffers.
        let n = unsafe {
            libc::sendmmsg(
                fd.as_raw_fd(),
                hdrs[sent..].as_mut_ptr().cast(),
                (count - sent) as libc::c_uint,
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

/// Receives up to `RAW_BATCH` frames via `recvmmsg`, normalizing IPv6 headers in place.
/// Slots with truncated or malformed ancillary data are marked with length `0`.
#[inline]
pub fn recv_raw_batch(
    fd: BorrowedFd<'_>,
    family: OuterFamily,
    bufs: &mut [u8],
    stride: usize,
    lens: &mut [usize; RAW_BATCH],
) -> io::Result<usize> {
    // SAFETY: receive buffers and ancillary storage live through recvmmsg; CMSG traversal is
    // bounded by the returned controllen, and flags are checked before reading pktinfo.
    unsafe {
        let mut iovs = uninit_batch::<libc::iovec>();
        let mut hdrs = uninit_batch::<libc::mmsghdr>();
        let mut sources = uninit_batch::<libc::sockaddr_in6>();
        let mut controls = uninit_batch::<CmsgBuf>();
        let mut base: libc::mmsghdr = zeroed();
        base.msg_hdr.msg_iovlen = 1;
        let offset = if family == OuterFamily::Ipv6 {
            base.msg_hdr.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            base.msg_hdr.msg_controllen = size_of::<CmsgBuf>() as _;
            IPV6_HDR
        } else {
            0
        };
        for k in 0..RAW_BATCH {
            let iov = iovs[k].write(libc::iovec {
                iov_base: bufs[k * stride + offset..].as_mut_ptr().cast(),
                iov_len: stride - offset,
            });
            let mut hdr = base;
            hdr.msg_hdr.msg_iov = iov;
            if family == OuterFamily::Ipv6 {
                hdr.msg_hdr.msg_name = sources[k].as_mut_ptr().cast();
                hdr.msg_hdr.msg_control = controls[k].as_mut_ptr().cast();
            }
            hdrs[k].write(hdr);
        }
        let m = libc::recvmmsg(
            fd.as_raw_fd(),
            hdrs.as_mut_ptr().cast(),
            RAW_BATCH as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        );
        if m < 0 {
            return Err(io::Error::last_os_error());
        }
        let m = m as usize;
        for k in 0..m {
            let hdr = hdrs[k].assume_init_ref();
            let msg = &hdr.msg_hdr;
            let n = hdr.msg_len as usize;
            if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                lens[k] = 0;
            } else if family == OuterFamily::Ipv4 {
                lens[k] = n;
            } else if let Some(dst) = pktinfo_dst(msg) {
                pkt::write_ipv6_header(
                    &mut bufs[k * stride..(k + 1) * stride],
                    Ipv6Addr::from(sources[k].assume_init_ref().sin6_addr.s6_addr),
                    dst,
                    n,
                );
                lens[k] = IPV6_HDR + n;
            } else {
                lens[k] = 0;
            }
        }
        Ok(m)
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
