//! Thin Linux syscall and `ip` command wrappers: TUN, raw sockets, CPU affinity, routing lookups.

use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::OuterFamily;
use crate::faketcp::pkt::{self, IPV6_HDR};

/// fwmark on every frame ghostun sends, so the netfilter RST-suppression rule spares our own RSTs.
pub const SOCKET_MARK: u32 = 0x6768_7374;
const SOCKET_BUF: libc::c_int = 4 << 20;
pub const RAW_BATCH: usize = 64;
/// Multi-queue TUN divides `tx_queue_len / numqueues` per ring; 8192 prevents burst tail-drops.
const TUN_TXQUEUELEN: &str = "8192";
type CmsgBuf = [usize; 8];

fn uninit_batch<T>() -> [MaybeUninit<T>; RAW_BATCH] {
    [const { MaybeUninit::uninit() }; RAW_BATCH]
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[repr(C)]
struct IfReqFlags {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}
impl IfReqFlags {
    fn new(flags: libc::c_int) -> Self {
        Self {
            name: [0; libc::IFNAMSIZ],
            flags: flags as libc::c_short,
            _pad: [0; 22],
        }
    }
}

fn tun_ioctl(fd: BorrowedFd<'_>, request: libc::Ioctl, req: &mut IfReqFlags) -> io::Result<()> {
    // SAFETY: `request` is a TUN ioctl reading/writing an `ifreq`-sized struct that outlives the call.
    cvt(unsafe { libc::ioctl(fd.as_raw_fd(), request, req as *mut IfReqFlags) }).map(drop)
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
    let mut req = IfReqFlags::new(libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE);
    req.name[..name.len()].copy_from_slice(name.as_bytes());
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
    let mut req = IfReqFlags::new(if attach {
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
    if let Some(dev) = bind_dev {
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

#[repr(C)]
union Destination {
    v4: libc::sockaddr_in,
    v6: libc::sockaddr_in6,
}

fn destination(dst: IpAddr) -> (Destination, libc::socklen_t) {
    match dst {
        IpAddr::V4(ip) => (
            Destination {
                v4: libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(ip).to_be(),
                    },
                    sin_zero: [0; 8],
                },
            },
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ),
        IpAddr::V6(ip) => (
            Destination {
                v6: libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                    sin6_scope_id: 0,
                },
            },
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ),
    }
}

/// Binds a single-family kernel listener; IPv6 never silently accepts IPv4-mapped peers.
pub fn tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket returns an owned descriptor or an error.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let fd = unsafe { OwnedFd::from_raw_fd(cvt(fd)?) };
    setsockopt(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &1i32)?;
    if addr.is_ipv6() {
        setsockopt(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &1i32)?;
    }
    let (mut raw, len) = destination(addr.ip());
    // SAFETY: destination initializes the union member selected by the address family.
    unsafe {
        if addr.is_ipv4() {
            raw.v4.sin_port = addr.port().to_be();
        } else {
            raw.v6.sin6_port = addr.port().to_be();
        }
        cvt(libc::bind(
            fd.as_raw_fd(),
            (&raw as *const Destination).cast(),
            len,
        ))?;
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
    if let Some(dev) = dev {
        // SAFETY: interface bytes remain valid for the entire call.
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
    let (mut addr, len) = destination(remote.ip());
    // SAFETY: destination selected the matching active union field and sockaddr length.
    unsafe {
        match remote {
            SocketAddr::V4(_) => addr.v4.sin_port = remote.port().to_be(),
            SocketAddr::V6(v6) => {
                addr.v6.sin6_port = remote.port().to_be();
                addr.v6.sin6_scope_id = v6.scope_id();
            }
        }
        if libc::connect(fd.as_raw_fd(), (&addr as *const Destination).cast(), len) < 0 {
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

pub fn send_raw(fd: BorrowedFd<'_>, frame: &[u8], dst: IpAddr) -> io::Result<()> {
    send_raw_batch(fd, frame, frame.len(), &[frame.len()], dst)
}

pub fn send_raw_batch(
    fd: BorrowedFd<'_>,
    bufs: &[u8],
    stride: usize,
    lens: &[usize],
    dst: IpAddr,
) -> io::Result<()> {
    let count = lens.len();
    let (addr, namelen) = destination(dst);
    let mut iovs = uninit_batch::<libc::iovec>();
    let mut hdrs = uninit_batch::<libc::mmsghdr>();
    // SAFETY: POD socket structs; active indices 0..count are fully initialized before sendmmsg.
    unsafe {
        let mut base: libc::mmsghdr = std::mem::zeroed();
        base.msg_hdr.msg_name = (&addr as *const Destination).cast_mut().cast();
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
        let mut base: libc::mmsghdr = std::mem::zeroed();
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
        let mut allowed: libc::cpu_set_t = std::mem::zeroed();
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
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        cvt(libc::sched_setaffinity(
            0,
            size_of::<libc::cpu_set_t>(),
            &set,
        ))
        .map(drop)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub src: IpAddr,
    pub dev: String,
}

fn token_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut it = line.split_whitespace();
    it.by_ref().find(|t| *t == key)?;
    it.next()
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn parse_route_get(out: &str) -> Option<Route> {
    let line = out.lines().next()?;
    Some(Route {
        src: token_after(line, "src")?.parse().ok()?,
        dev: token_after(line, "dev")?.to_owned(),
    })
}

fn parse_default_dev(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| token_after(l, "dev"))
        .map(str::to_owned)
}

pub fn route_to(dst: IpAddr, dev: Option<&str>) -> io::Result<Route> {
    let address = dst.to_string();
    let mut args = vec![OuterFamily::of(dst).ip_flag(), "route", "get", &address];
    if let Some(dev) = dev {
        args.extend(["oif", dev]);
    }
    let out = run("ip", &args, None)?;
    parse_route_get(&out).ok_or_else(|| invalid(format!("cannot parse route to {dst}: {out:?}")))
}

pub fn default_route_dev(family: OuterFamily) -> io::Result<String> {
    let out = run("ip", &[family.ip_flag(), "route", "show", "default"], None)?;
    parse_default_dev(&out).ok_or_else(|| invalid(format!("no {family:?} default route")))
}

pub fn iface_mtu(dev: &str) -> io::Result<u32> {
    let text = std::fs::read_to_string(Path::new("/sys/class/net").join(dev).join("mtu"))?;
    text.trim()
        .parse()
        .map_err(|_| invalid(format!("bad MTU for {dev}: {text:?}")))
}

/// Sets MTU and `TUN_TXQUEUELEN` (avoiding per-queue burst tail-drops), brings the device up, and
/// assigns inner addresses. An IPv6 failure only warns; returns whether IPv6 got configured.
pub fn configure_tun(name: &str, mtu: u32, v4: &str, v6: Option<&str>) -> io::Result<bool> {
    run(
        "ip",
        &[
            "link",
            "set",
            "dev",
            name,
            "mtu",
            &mtu.to_string(),
            "txqueuelen",
            TUN_TXQUEUELEN,
            "up",
        ],
        None,
    )?;
    run("ip", &["-4", "addr", "add", v4, "dev", name], None)?;
    let Some(v6) = v6 else { return Ok(false) };
    match run("ip", &["-6", "addr", "add", v6, "dev", name, "nodad"], None) {
        Ok(_) => Ok(true),
        Err(e) => {
            log::warn!("inner IPv6 disabled: cannot add {v6} to {name}: {e}");
            Ok(false)
        }
    }
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

/// `/usr/sbin` and `/sbin` are often missing from service and non-root `PATH`s.
fn find_program(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/sbin", "/usr/bin", "/bin"].map(PathBuf::from))
        .map(|dir| dir.join(prog))
        .find(|p| p.is_file())
}

pub fn run(prog: &str, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
    let path = find_program(prog)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{prog} not found")))?;
    let mut child = Command::new(&path)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "`{prog} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn route_get_via_gateway() {
        let out = "203.0.113.9 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000 \n    cache \n";
        assert_eq!(
            parse_route_get(out),
            Some(Route {
                src: Ipv4Addr::new(10, 0, 0, 5).into(),
                dev: "eth0".into()
            })
        );
    }

    #[test]
    fn route_get_on_link() {
        let out = "10.1.0.2 dev veth-e src 10.1.0.1 uid 0 \n    cache \n";
        assert_eq!(
            parse_route_get(out),
            Some(Route {
                src: Ipv4Addr::new(10, 1, 0, 1).into(),
                dev: "veth-e".into()
            })
        );
        assert_eq!(
            parse_route_get("RTNETLINK answers: Network is unreachable\n"),
            None
        );
    }

    #[test]
    fn default_route_dev_parsed() {
        assert_eq!(
            parse_default_dev(
                "default via 10.0.0.1 dev ens3 proto dhcp src 10.0.0.5 metric 100 \n"
            )
            .as_deref(),
            Some("ens3")
        );
        assert_eq!(parse_default_dev(""), None);
    }

    #[test]
    fn run_reports_failure_with_stderr() {
        assert_eq!(run("sh", &["-c", "cat"], Some("hi")).unwrap(), "hi");
        let err = run("sh", &["-c", "echo boom >&2; exit 3"], None).unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert_eq!(
            run("definitely-not-a-program-xyz", &[], None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
