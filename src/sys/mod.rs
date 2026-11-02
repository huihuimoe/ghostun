//! Thin OS wrappers: poll, signals, CSPRNG, CPU affinity, sysctl, plus TUN, socket and route-netlink submodules.

pub mod raw;
pub mod route;
pub mod tcp;
pub mod tun;
pub mod uring;

use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const READ_READY: i16 = libc::POLLIN | libc::POLLERR | libc::POLLHUP;
pub const WRITE_READY: i16 = libc::POLLOUT | libc::POLLERR | libc::POLLHUP;

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

fn setsockopt<T>(
    fd: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
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
