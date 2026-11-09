//! Optional TUN fast path. The pending queue owns writes until their CQEs complete.
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use super::queue::{BYTE_LIMIT, Pending};
use crate::sys;
use crate::sys::uring::{self, Cqe, Ring, Sqe};

const BUFFERS: usize = sys::raw::BATCH;
const GROUP: u16 = 1;
const READ: u64 = 1;
const PROVIDE: u64 = 2;
const CANCEL: u64 = 3;
const WRITE_BASE: u64 = 256;

pub struct TunDriver<'a> {
    fd: BorrowedFd<'a>,
    fast: Option<Box<Fast>>,
    pending: Pending<()>,
    stride: usize,
    headroom: usize,
    recovered: VecDeque<Vec<u8>>,
    batch: [(usize, usize); BUFFERS],
}

#[derive(Clone)]
pub struct Batch<'a> {
    base: *const u8,
    stride: usize,
    items: std::slice::Iter<'a, (usize, usize)>,
}

impl<'a> Iterator for Batch<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &(index, len) = self.items.next()?;
        // SAFETY: `index * self.stride + len` lies within `fast.buffers` (in the fast path,
        // where recycled slots are not returned to the kernel until `Fast::drive`) or within
        // `scratch` (in the poll/recovery path), and both stay borrowed for `'a`.
        Some(unsafe { std::slice::from_raw_parts(self.base.add(index * self.stride), len) })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.items.size_hint()
    }
}

impl ExactSizeIterator for Batch<'_> {}

struct Fast {
    ring: Ring,
    buffers: Box<[UnsafeCell<u8>]>,
    slots: usize,
    ready: VecDeque<(usize, usize)>,
    recycle: Vec<(usize, usize)>,
    completions: Vec<Cqe>,
    reading: bool,
    writes: usize,
    results: [Option<i32>; BUFFERS],
    blocked: bool,
    canceling: bool,
}

fn kernel_supported(release: &str) -> bool {
    let mut parts = release.split('.');
    let major = parts.next().and_then(|v| v.parse::<u32>().ok());
    let minor = parts.next().and_then(|v| {
        v.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse::<u32>()
            .ok()
    });
    matches!((major, minor), (Some(7..), _) | (Some(6), Some(7..)))
}

fn available() -> io::Result<()> {
    if let Ok(value) = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled") {
        // SAFETY: geteuid has no arguments and cannot fail.
        if value.trim() == "2" || (value.trim() == "1" && unsafe { libc::geteuid() } != 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "io_uring disabled by system policy",
            ));
        }
    }
    // SAFETY: utsname is plain C data; uname initializes its fixed NUL-terminated fields.
    let mut name: libc::utsname = unsafe { mem::zeroed() };
    // SAFETY: name is writable utsname storage.
    if unsafe { libc::uname(&mut name) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful uname NUL-terminates release.
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }.to_string_lossy();
    if !kernel_supported(&release) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN multishot read requires Linux 6.7",
        ));
    }
    Ok(())
}

impl Fast {
    fn new(stride: usize, headroom: usize) -> io::Result<Self> {
        available()?;
        let slots = BUFFERS.min(BYTE_LIMIT / 2 / stride).max(1);
        let mut fast = Self {
            ring: Ring::new()?,
            buffers: (0..slots * stride).map(|_| UnsafeCell::new(0)).collect(),
            slots,
            ready: VecDeque::with_capacity(BUFFERS),
            recycle: Vec::with_capacity(4),
            completions: Vec::with_capacity(512),
            reading: false,
            writes: 0,
            results: [None; BUFFERS],
            blocked: false,
            canceling: false,
        };
        fast.provide(0, slots, stride, headroom)?;
        fast.ring.submit()?;
        Ok(fast)
    }

    fn recycle(&mut self, index: usize) {
        if let Some((start, count)) = self.recycle.last_mut()
            && *start + *count == index
        {
            *count += 1;
        } else {
            self.recycle.push((index, 1));
        }
    }

    fn provide(
        &mut self,
        index: usize,
        count: usize,
        stride: usize,
        headroom: usize,
    ) -> io::Result<()> {
        // When headroom > 0, each slot's kernel buffer is shorter than `stride`, so register
        // slots individually to prevent `PROVIDE_BUFFERS` from stepping by `stride - headroom`
        // or overlapping the next slot's headroom.
        let step = if headroom == 0 { count } else { 1 };
        for slot in (index..index + count).step_by(step) {
            // SAFETY: the UnsafeCell pool stays allocated until cancellation completes; each
            // `[slot * stride + headroom .. (slot + 1) * stride]` range is disjoint from every
            // other slot and from its own `[slot * stride .. slot * stride + headroom]` prefix.
            unsafe {
                self.ring.push(Sqe {
                    opcode: uring::PROVIDE_BUFFERS,
                    fd: step as i32,
                    addr: self.buffers[slot * stride + headroom].get() as u64,
                    len: (stride - headroom) as u32,
                    off: slot as u64,
                    buf_group: GROUP,
                    user_data: PROVIDE,
                    ..Sqe::default()
                })?;
            }
        }
        Ok(())
    }

    fn collect(
        &mut self,
        pending: &mut Pending<()>,
        max_len: usize,
        stopping: bool,
    ) -> io::Result<()> {
        self.ring.completions(&mut self.completions);
        let mut incompatible = None;
        for cqe in &self.completions {
            match cqe.user_data {
                READ => {
                    self.reading = cqe.flags & uring::MORE != 0;
                    if cqe.flags & uring::BUFFER != 0 {
                        let index = (cqe.flags >> 16) as usize;
                        if index >= self.slots || cqe.result as usize > max_len {
                            incompatible = Some(io::Error::other("invalid TUN read completion"));
                        } else if cqe.result > 0 {
                            self.ready.push_back((index, cqe.result as usize));
                        }
                    }
                    if cqe.result < 0
                        && !matches!(-cqe.result, libc::ENOBUFS | libc::EAGAIN | libc::ECANCELED)
                    {
                        incompatible = Some(io::Error::from_raw_os_error(-cqe.result));
                    }
                }
                PROVIDE if cqe.result < 0 && !(stopping && cqe.result == -libc::ECANCELED) => {
                    incompatible = Some(io::Error::from_raw_os_error(-cqe.result));
                }
                CANCEL => self.canceling = false,
                tag if (WRITE_BASE..WRITE_BASE + self.writes as u64).contains(&tag) => {
                    self.results[(tag - WRITE_BASE) as usize] = Some(cqe.result);
                }
                _ => {}
            }
        }
        if self.writes != 0 && (stopping || self.results[..self.writes].iter().all(Option::is_some))
        {
            let mut completed = 0;
            for index in 0..self.writes {
                let result = self.results[index].unwrap_or(-libc::ECANCELED);
                self.blocked |= result == -libc::EAGAIN;
                if matches!(result, n if n == -libc::EINVAL || n == -libc::EOPNOTSUPP || n == -libc::EBADF)
                {
                    incompatible = Some(io::Error::from_raw_os_error(-result));
                    break;
                } else if matches!(result, n if n == -libc::EAGAIN || n == -libc::EINTR || n == -libc::ECANCELED)
                {
                    break;
                } else {
                    if result != pending.packets[index].bytes.len() as i32 {
                        log::debug!("TUN io_uring write result {result}; dropping packet");
                    }
                    completed += 1;
                }
            }
            // Linked writes complete a prefix; a failed operation cancels the remaining tail.
            for _ in 0..completed {
                pending.pop();
            }
            self.writes = 0;
        }
        incompatible.map_or(Ok(()), Err)
    }

    fn arm_read(&mut self, fd: RawFd, attached: bool, read_allowed: bool) -> io::Result<bool> {
        if attached
            && read_allowed
            && !self.reading
            && !self.canceling
            && self.ready.len() < self.slots
        {
            // SAFETY: read uses only the provided UnsafeCell pool, retained through cancellation.
            unsafe {
                self.ring.push(Sqe {
                    opcode: uring::READ_MULTISHOT,
                    fd,
                    flags: uring::BUFFER_SELECT,
                    off: u64::MAX,
                    buf_group: GROUP,
                    user_data: READ,
                    ..Sqe::default()
                })?;
            }
            self.reading = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn drive(
        &mut self,
        fd: RawFd,
        pending: &mut Pending<()>,
        stride: usize,
        headroom: usize,
        attached: bool,
        read_allowed: bool,
    ) -> io::Result<()> {
        let max_len = stride - headroom;
        self.collect(pending, max_len, false)?;
        for index in 0..self.recycle.len() {
            let (start, count) = self.recycle[index];
            self.provide(start, count, stride, headroom)?;
        }
        self.recycle.clear();
        if !read_allowed && self.reading && !self.canceling {
            // SAFETY: cancellation references only the stable READ request tag.
            unsafe {
                self.ring.push(Sqe {
                    opcode: 14,
                    fd: -1,
                    addr: READ,
                    user_data: CANCEL,
                    ..Sqe::default()
                })?;
            }
            self.canceling = true;
        }
        if attached && !self.blocked && self.writes == 0 && !pending.packets.is_empty() {
            self.writes = pending.packets.len().min(BUFFERS);
            self.results.fill(None);
            for (index, packet) in pending.packets.iter().take(self.writes).enumerate() {
                // SAFETY: pending owns each Vec allocation until every write CQE is consumed
                // or stop synchronously cancels the batch. The kernel only reads these bytes.
                unsafe {
                    self.ring.push(Sqe {
                        opcode: uring::WRITE,
                        fd,
                        off: u64::MAX,
                        flags: if index + 1 < self.writes {
                            uring::LINK
                        } else {
                            0
                        },
                        addr: packet.bytes.as_ptr() as u64,
                        len: packet.bytes.len() as u32,
                        user_data: WRITE_BASE + index as u64,
                        ..Sqe::default()
                    })?;
                }
            }
        }
        while {
            self.arm_read(fd, attached, read_allowed)?;
            self.ring.submit()?
        } {
            self.collect(pending, max_len, false)?;
        }
        Ok(())
    }

    fn stop(&mut self, pending: &mut Pending<()>, max_len: usize) {
        if let Err(error) = self.ring.stop() {
            // A failed cancellation cannot prove that the kernel released these allocations.
            // Retain only possibly borrowed buffers rather than free or replay uncertain writes.
            log::error!("TUN io_uring cancellation failed: {error}; retaining in-flight storage");
            mem::forget(mem::take(&mut self.buffers));
            self.ready.clear();
            for _ in 0..self.writes {
                if let Some(packet) = pending.take_front() {
                    mem::forget(packet);
                }
            }
            self.writes = 0;
        } else {
            let _ = self.collect(pending, max_len, true);
        }
    }
}

impl Drop for Fast {
    fn drop(&mut self) {
        if self.ring.stop().is_err() {
            mem::forget(mem::take(&mut self.buffers));
        }
    }
}

impl<'a> TunDriver<'a> {
    pub fn new(fd: BorrowedFd<'a>, stride: usize, headroom: usize) -> Self {
        let fast = match Fast::new(stride, headroom) {
            Ok(fast) => {
                log::info!("TUN io_uring fast-path enabled");
                Some(Box::new(fast))
            }
            Err(error) => {
                log::info!("TUN io_uring fast-path unavailable ({error}), using poll fallback");
                None
            }
        };
        let mut driver = Self::poll(fd, stride, headroom);
        driver.fast = fast;
        driver
    }

    pub(crate) fn poll(fd: BorrowedFd<'a>, stride: usize, headroom: usize) -> Self {
        Self {
            fd,
            fast: None,
            pending: Pending::default(),
            stride,
            headroom,
            recovered: VecDeque::new(),
            batch: [(0, 0); BUFFERS],
        }
    }

    pub fn read_fd(&self) -> RawFd {
        self.fast
            .as_ref()
            .map_or(self.fd.as_raw_fd(), |fast| fast.ring.fd())
    }

    pub fn has_reads(&self) -> bool {
        !self.recovered.is_empty()
            || self
                .fast
                .as_ref()
                .is_some_and(|fast| !fast.ready.is_empty())
    }

    pub fn wants_write(&self) -> bool {
        !self.pending.packets.is_empty() && self.fast.as_ref().is_none_or(|fast| fast.blocked)
    }

    pub fn read_budget(&self) -> (usize, usize) {
        self.fast.as_ref().map_or_else(
            || {
                (
                    self.recovered.iter().map(|p| self.headroom + p.len()).sum(),
                    self.recovered.len(),
                )
            },
            |fast| (fast.buffers.len(), fast.slots),
        )
    }

    pub fn service(&mut self, attached: bool, read_allowed: bool) {
        let error = self.fast.as_mut().and_then(|fast| {
            fast.drive(
                self.fd.as_raw_fd(),
                &mut self.pending,
                self.stride,
                self.headroom,
                attached,
                read_allowed,
            )
            .err()
        });
        if let Some(error) = error {
            self.fallback(error);
        }
    }

    fn fallback(&mut self, error: io::Error) {
        log::info!("TUN io_uring fast-path failed ({error}), using poll fallback");
        if let Some(mut fast) = self.fast.take() {
            fast.stop(&mut self.pending, self.stride - self.headroom);
            for &(index, len) in &fast.ready {
                // SAFETY: the CQE transferred this slot to userspace; stop ended all I/O.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        fast.buffers[index * self.stride + self.headroom].get(),
                        len,
                    )
                };
                self.recovered.push_back(bytes.to_vec());
            }
        }
    }

    fn read(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if let Some(packet) = self.recovered.pop_front() {
            output[..packet.len()].copy_from_slice(&packet);
            return Ok(Some(packet.len()));
        }
        let Some(fast) = &mut self.fast else {
            return sys::tun::read(self.fd, output);
        };
        let Some((index, len)) = fast.ready.pop_front() else {
            return Ok(None);
        };
        let result = if len <= output.len() {
            // SAFETY: this CQE-owned slot is not returned to the kernel until drive flushes recycle.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    fast.buffers[index * self.stride + self.headroom].get(),
                    output.as_mut_ptr(),
                    len,
                );
            }
            Ok(Some(len))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized TUN packet",
            ))
        };
        fast.recycle(index);
        result
    }

    /// `room(bytes, count)` must report whether the caller can still accept a batch of `count`
    /// frames totalling `bytes`; each check already includes one more worst-case slot. Callers
    /// that must absorb every in-flight ring read add `read_budget()` themselves.
    pub fn read_batch<'b>(
        &'b mut self,
        scratch: &'b mut [u8],
        scratch_stride: usize,
        room: impl Fn(usize, usize) -> bool,
        mut encap: impl FnMut(&mut [u8], usize) -> bool,
    ) -> (usize, Batch<'b>) {
        let fast_mode = self.recovered.is_empty() && self.fast.is_some();
        let mut reads = 0;
        let mut count = 0;
        let mut bytes = 0;
        while reads < BUFFERS && room(bytes + scratch_stride, count + 1) {
            let (index, len, slot) = if fast_mode {
                let fast = self.fast.as_mut().unwrap();
                let Some((index, len)) = fast.ready.pop_front() else {
                    break;
                };
                fast.recycle(index);
                // SAFETY: this CQE-owned slot is not returned to the kernel until `Fast::drive`
                // flushes `fast.recycle`, so userspace has exclusive access to its headroom + data.
                let slot = unsafe {
                    std::slice::from_raw_parts_mut(
                        fast.buffers[index * self.stride].get(),
                        self.headroom + len,
                    )
                };
                (index, len, slot)
            } else {
                let slot = &mut scratch[count * scratch_stride..(count + 1) * scratch_stride];
                let Some(len) = self.read(&mut slot[self.headroom..]).ok().flatten() else {
                    break;
                };
                (count, len, &mut slot[..self.headroom + len])
            };
            reads += 1;
            let frame_len = slot.len();
            if encap(slot, len) {
                self.batch[count] = (index, frame_len);
                bytes += frame_len;
                count += 1;
            }
        }
        let (base, stride) = match &self.fast {
            Some(fast) if fast_mode => (fast.buffers.as_ptr().cast::<u8>(), self.stride),
            _ => (scratch.as_ptr(), scratch_stride),
        };
        (
            reads,
            Batch {
                base,
                stride,
                items: self.batch[..count].iter(),
            },
        )
    }

    pub fn write(&mut self, packet: &[u8]) -> bool {
        if !self.pending.room(packet.len()) {
            return false;
        }
        if self.fast.is_none() && self.pending.packets.is_empty() && self.write_poll(packet) {
            return true;
        }
        self.pending.push(packet, (), false)
    }

    fn write_poll(&self, packet: &[u8]) -> bool {
        match sys::tun::write(self.fd, packet) {
            Ok(done) => done,
            Err(error) => {
                log::debug!("TUN write: {error}; dropping packet");
                true
            }
        }
    }

    pub fn flush(&mut self) {
        if let Some(fast) = &mut self.fast {
            fast.blocked = false;
            return;
        }
        for _ in 0..BUFFERS {
            let Some(packet) = self.pending.packets.front() else {
                break;
            };
            if !self.write_poll(&packet.bytes) {
                break;
            }
            self.pending.pop();
        }
    }

    pub fn reset(&mut self) {
        if let Some(mut fast) = self.fast.take() {
            fast.stop(&mut self.pending, self.stride - self.headroom);
            // Session changes discard both completed reads and old queued writes.
            self.fast = match Fast::new(self.stride, self.headroom) {
                Ok(fast) => Some(Box::new(fast)),
                Err(error) => {
                    log::info!("TUN io_uring restart failed ({error}), using poll fallback");
                    None
                }
            };
        }
        self.pending.clear();
        self.recovered.clear();
    }
}

impl Drop for TunDriver<'_> {
    fn drop(&mut self) {
        if let Some(mut fast) = self.fast.take() {
            fast.stop(&mut self.pending, self.stride - self.headroom);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixDatagram;

    #[test]
    #[ignore = "requires permitted io_uring; run in the privileged e2e container"]
    fn uring_recycles_buffers_and_preserves_backlog_across_runtime_fallback() {
        let (socket, peer) = UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut driver = TunDriver::new(socket.as_fd(), 2048, 0);
        assert!(driver.fast.is_some(), "test must exercise io_uring");
        let mut buffer = [0; 2048];
        for sequence in 0u32..200 {
            peer.send(&sequence.to_be_bytes()).unwrap();
            let mut received = false;
            for _ in 0..100 {
                driver.service(true, true);
                if let Some(len) = driver.read(&mut buffer).unwrap() {
                    assert_eq!(&buffer[..len], sequence.to_be_bytes());
                    received = true;
                    break;
                }
                sys::poll(&mut [sys::pollfd(driver.read_fd(), libc::POLLIN)], 10).unwrap();
            }
            assert!(received);
            assert!(driver.fast.is_some());
        }
        for _ in 0..100 {
            driver.service(true, false);
            let fast = driver.fast.as_ref().unwrap();
            if !fast.reading && !fast.canceling {
                break;
            }
            sys::poll(&mut [sys::pollfd(driver.read_fd(), libc::POLLIN)], 10).unwrap();
        }
        assert!(!driver.fast.as_ref().unwrap().reading);
        peer.send(b"paused").unwrap();
        driver.service(true, false);
        assert!(!driver.has_reads());
        let mut resumed = false;
        for _ in 0..100 {
            driver.service(true, true);
            if let Some(len) = driver.read(&mut buffer).unwrap() {
                assert_eq!(&buffer[..len], b"paused");
                resumed = true;
                break;
            }
            sys::poll(&mut [sys::pollfd(driver.read_fd(), libc::POLLIN)], 10).unwrap();
        }
        assert!(resumed);
        for sequence in 0..200 {
            assert!(driver.write(&vec![sequence; 1024]));
        }
        driver.service(true, true);
        peer.send(b"before fallback").unwrap();
        for _ in 0..100 {
            driver.service(true, true);
            if driver.has_reads() {
                break;
            }
            sys::poll(&mut [sys::pollfd(driver.read_fd(), libc::POLLIN)], 10).unwrap();
        }
        assert!(driver.has_reads());
        driver.fallback(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        assert!(driver.fast.is_none());
        peer.send(b"after fallback").unwrap();
        let len = driver.read(&mut buffer).unwrap().unwrap();
        assert_eq!(&buffer[..len], b"before fallback");
        let len = driver.read(&mut buffer).unwrap().unwrap();
        assert_eq!(&buffer[..len], b"after fallback");
        let mut received = 0;
        for _ in 0..10000 {
            while let Ok(len) = peer.recv(&mut buffer) {
                assert_eq!(len, 1024);
                assert!(buffer[..len].iter().all(|&v| v == received as u8));
                received += 1;
            }
            driver.flush();
            if received == 200 {
                break;
            }
        }
        assert_eq!(received, 200);
        assert!(driver.pending.packets.is_empty());
        assert!(driver.pending.room(BYTE_LIMIT));
        assert_eq!(
            peer.recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn poll_backpressure_preserves_packet_order_without_duplicates() {
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let mut driver = TunDriver::poll(writer.as_fd(), 2048, 0);
        let mut count = 0usize;
        loop {
            let packet = vec![(count % 251) as u8; 1024];
            if !driver.write(&packet) {
                break;
            }
            count += 1;
        }
        assert!(!driver.pending.packets.is_empty());
        let mut received = 0;
        let mut buffer = [0; 2048];
        for _ in 0..10000 {
            while let Ok(len) = reader.recv(&mut buffer) {
                assert_eq!(len, 1024);
                assert!(buffer[..len].iter().all(|&v| v == (received % 251) as u8));
                received += 1;
            }
            driver.flush();
            if received == count {
                break;
            }
        }
        assert_eq!(received, count);
        assert!(driver.pending.packets.is_empty());
        assert_eq!(
            reader.recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn multishot_kernel_version_gate() {
        for version in ["6.7.0", "6.12.1-custom", "7.2.0"] {
            assert!(kernel_supported(version));
        }
        for version in ["5.19.0", "6.6.99", "invalid", "6"] {
            assert!(!kernel_supported(version));
        }
    }
}
