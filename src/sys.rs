//! Thin Linux syscall and `ip` command wrappers: TUN, raw sockets, CPU affinity, routing lookups.

use std::fs::File;
use std::io::{self, Write};
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::OuterFamily;
use crate::pkt::{self, IPV6_HDR};

/// fwmark on every frame ghostun sends, so the netfilter RST-suppression rule spares our own RSTs.
pub const SOCKET_MARK: u32 = 0x6768_7374;
const SOCKET_BUF: libc::c_int = 4 << 20;

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

/// Opens `queues` non-blocking queue fds of one multi-queue TUN device. Without `IFF_PERSIST` the
/// kernel destroys the device when the last fd closes, including on SIGKILL.
pub fn create_tun(name: &str, queues: usize) -> io::Result<Vec<OwnedFd>> {
    let mut req = IfReqFlags {
        name: [0; libc::IFNAMSIZ],
        flags: (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE) as libc::c_short,
        _pad: [0; 22],
    };
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
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
            // SAFETY: TUNSETIFF reads/writes an ifreq-sized struct that outlives the call.
            cvt(unsafe {
                libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req as *mut IfReqFlags)
            })?;
            Ok(fd)
        })
        .collect()
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

pub fn send_raw(fd: BorrowedFd<'_>, frame: &[u8], dst: IpAddr) -> io::Result<()> {
    #[repr(C)]
    union Destination {
        v4: libc::sockaddr_in,
        v6: libc::sockaddr_in6,
    }
    let (addr, len) = match dst {
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
            size_of::<libc::sockaddr_in>(),
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
            size_of::<libc::sockaddr_in6>(),
        ),
    };
    // SAFETY: frame and addr are valid for the lengths passed.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT,
            (&addr as *const Destination).cast(),
            len as libc::socklen_t,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Normalizes IPv6 raw TCP receives into a complete frame without moving the TCP payload.
pub fn recv_raw(fd: BorrowedFd<'_>, family: OuterFamily, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: receive buffers and ancillary storage live through recvmsg; CMSG traversal is bounded
    // by the returned controllen, and the data length is checked before reading pktinfo.
    unsafe {
        if family == OuterFamily::Ipv4 {
            let n = libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
            );
            return if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            };
        }
        let mut source: libc::sockaddr_in6 = std::mem::zeroed();
        let mut control = [0usize; 8];
        let mut iov = libc::iovec {
            iov_base: buf[IPV6_HDR..].as_mut_ptr().cast(),
            iov_len: buf.len() - IPV6_HDR,
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut source as *mut libc::sockaddr_in6).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control);
        let n = libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(invalid("truncated IPv6 raw frame or pktinfo".into()));
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                && (*cmsg).cmsg_len
                    >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as usize
            {
                let info =
                    std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>());
                pkt::write_ipv6_header(
                    buf,
                    Ipv6Addr::from(source.sin6_addr.s6_addr),
                    Ipv6Addr::from(info.ipi6_addr.s6_addr),
                    n as usize,
                );
                return Ok(IPV6_HDR + n as usize);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Err(invalid("missing IPv6 destination pktinfo".into()))
    }
}

/// Pins the calling thread to `explicit` CPU if set, else the `worker`-th allowed CPU (wrapping).
pub fn pin_to_cpu(worker: usize, explicit: Option<usize>) -> io::Result<()> {
    // SAFETY: cpu_set_t is plain data; the libc CPU_* helpers stay within its bounds.
    unsafe {
        let target = match explicit {
            Some(cpu) => cpu,
            None => {
                let mut allowed: libc::cpu_set_t = std::mem::zeroed();
                cvt(libc::sched_getaffinity(
                    0,
                    size_of::<libc::cpu_set_t>(),
                    &mut allowed,
                ))?;
                let usable: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
                    .filter(|&c| libc::CPU_ISSET(c, &allowed))
                    .collect();
                let Some(&target) = usable.get(worker % usable.len().max(1)) else {
                    return Ok(());
                };
                target
            }
        };
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(target, &mut set);
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

/// Sets MTU, brings the device up and assigns addresses. An IPv6 failure (IPv6 disabled in the
/// kernel) only warns; returns whether IPv6 got configured.
pub fn configure_tun(name: &str, mtu: u32, v4: &str, v6: Option<&str>) -> io::Result<bool> {
    run(
        "ip",
        &["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"],
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
