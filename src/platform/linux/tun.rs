//! Multi-queue TUN device: creation, queue attachment, and nonblocking packet I/O.

use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::cvt;

/// One queue of the multi-queue TUN device; packets are moved through a [`super::TunDriver`].
pub struct TunQueue(OwnedFd);

impl AsRawFd for TunQueue {
    #[inline(always)]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
impl From<OwnedFd> for TunQueue {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}

#[inline]
pub(super) fn read(tun: &TunQueue, buf: &mut [u8]) -> io::Result<Option<usize>> {
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
pub(super) fn write(tun: &TunQueue, packet: &[u8]) -> io::Result<bool> {
    loop {
        // SAFETY: valid descriptor and readable packet slice. TUN preserves packet boundaries.
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
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(false),
            _ => return Err(e),
        }
    }
}

fn ifreq_with_flags(flags: libc::c_int) -> libc::ifreq {
    // SAFETY: `libc::ifreq` is a plain C union/struct valid when zero-initialized.
    let mut req: libc::ifreq = unsafe { zeroed() };
    req.ifr_ifru.ifru_flags = flags as libc::c_short;
    req
}

fn tun_ioctl(fd: &TunQueue, request: libc::Ioctl, req: &mut libc::ifreq) -> io::Result<()> {
    // SAFETY: `request` is a TUN ioctl reading/writing a live `libc::ifreq`.
    cvt(unsafe { libc::ioctl(fd.as_raw_fd(), request, req as *mut libc::ifreq) }).map(drop)
}

/// Opens one non-blocking, initially detached queue fd of a multi-queue TUN device.
/// Without `IFF_PERSIST` the kernel destroys the device when the last fd closes, including on SIGKILL.
pub fn open_queue(name: &str) -> io::Result<TunQueue> {
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
    // SAFETY: plain open(2) of a NUL-terminated path; the fd is owned immediately.
    let fd = cvt(unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    let queue = TunQueue(unsafe { OwnedFd::from_raw_fd(fd) });
    tun_ioctl(&queue, libc::TUNSETIFF as _, &mut req)?;
    queue.set_active(false)?;
    Ok(queue)
}

/// Opens `queues` non-blocking, initially detached queue fds of one multi-queue TUN device.
pub fn create(name: &str, queues: usize) -> io::Result<Vec<TunQueue>> {
    (0..queues).map(|_| open_queue(name)).collect()
}

impl TunQueue {
    /// Attaches or detaches the queue so the kernel only hashes inner flows onto `Established`
    /// workers instead of black-holing `1/N` of traffic into reconnecting slots.
    pub fn set_active(&self, active: bool) -> io::Result<()> {
        let mut req = ifreq_with_flags(if active {
            libc::IFF_ATTACH_QUEUE
        } else {
            libc::IFF_DETACH_QUEUE
        });
        tun_ioctl(self, libc::TUNSETQUEUE as _, &mut req)
    }
}
