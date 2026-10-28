//! Minimal Linux io_uring UAPI. No runtime, SQPOLL thread, or external library is needed.
use std::io;
use std::mem::{self, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

pub const PROVIDE_BUFFERS: u8 = 31;
pub const READ_MULTISHOT: u8 = 49;
pub const WRITE: u8 = 23;
pub const BUFFER_SELECT: u8 = 1 << 5;
pub const LINK: u8 = 1 << 2;
pub const BUFFER: u32 = 1;
pub const MORE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_group: u16,
    pub personality: u16,
    pub file_index: u32,
    pub extra: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cqe {
    pub user_data: u64,
    pub result: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct Offsets {
    fields: [u32; 8],
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    reserved: [u32; 3],
    sq: Offsets,
    cq: Offsets,
}

struct Mapping {
    ptr: *mut u8,
    len: usize,
}

impl Mapping {
    fn new(fd: RawFd, len: usize, offset: libc::off_t) -> io::Result<Self> {
        // SAFETY: the ring fd and kernel-returned size describe the requested shared mapping.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn atomic(&self, offset: u32) -> &AtomicU32 {
        assert!((offset as usize) + size_of::<AtomicU32>() <= self.len);
        assert_eq!(offset as usize % mem::align_of::<AtomicU32>(), 0);
        // SAFETY: mmap is page aligned; the checked offset holds a kernel UAPI atomic counter.
        unsafe { &*self.ptr.add(offset as usize).cast() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns this exact mmap region.
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

pub struct Ring {
    fd: OwnedFd,
    sq: Mapping,
    cq: Mapping,
    sqes: Mapping,
    params: Params,
    stopped: bool,
}

impl Ring {
    pub fn new() -> io::Result<Self> {
        let mut params = Params::default();
        // SAFETY: params has the io_uring_params ABI and is writable for setup.
        let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 256u32, &mut params) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: setup returned a new, uniquely owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        let sq_len = params.sq.fields[6] as usize + params.sq_entries as usize * 4;
        let cq_len = params.cq.fields[5] as usize + params.cq_entries as usize * size_of::<Cqe>();
        let sq = Mapping::new(fd.as_raw_fd(), sq_len, 0)?;
        let cq = Mapping::new(fd.as_raw_fd(), cq_len, 0x0800_0000)?;
        let sqes = Mapping::new(
            fd.as_raw_fd(),
            params.sq_entries as usize * size_of::<Sqe>(),
            0x1000_0000,
        )?;
        let ring = Self {
            fd,
            sq,
            cq,
            sqes,
            params,
            stopped: false,
        };
        ring.probe()?;
        // Establish synchronous cancellation support before lending any packet buffers.
        ring.cancel_all()?;
        Ok(ring)
    }

    fn probe(&self) -> io::Result<()> {
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Op {
            code: u8,
            reserved: u8,
            flags: u16,
            reserved2: u32,
        }
        #[repr(C)]
        struct Probe {
            header: [u8; 16],
            ops: [Op; 256],
        }
        let mut probe = Probe {
            header: [0; 16],
            ops: [Op::default(); 256],
        };
        // SAFETY: Probe is the UAPI header followed by storage for 256 probe entries.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                8u32,
                &mut probe,
                256u32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        for code in [PROVIDE_BUFFERS, READ_MULTISHOT, WRITE] {
            if !probe.ops[..usize::from(probe.header[1])]
                .iter()
                .any(|op| op.code == code && op.flags & 1 != 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "required io_uring opcode unavailable",
                ));
            }
        }
        Ok(())
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// # Safety
    /// Referenced memory must satisfy the opcode's requirements and remain live until completion
    /// or successful synchronous cancellation. Kernel-writable buffers require interior mutability.
    pub unsafe fn push(&mut self, sqe: Sqe) -> io::Result<()> {
        let offsets = &self.params.sq.fields;
        let head = self.sq.atomic(offsets[0]).load(Ordering::Acquire);
        let tail = self.sq.atomic(offsets[1]).load(Ordering::Relaxed);
        if tail.wrapping_sub(head) == self.params.sq_entries {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let index = tail & (self.params.sq_entries - 1);
        // SAFETY: index is within both SQ allocations; only this worker publishes SQ entries.
        unsafe {
            self.sqes.ptr.cast::<Sqe>().add(index as usize).write(sqe);
            self.sq
                .ptr
                .add(offsets[6] as usize)
                .cast::<u32>()
                .add(index as usize)
                .write(index);
        }
        self.sq
            .atomic(offsets[1])
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    pub fn submit(&mut self) -> io::Result<()> {
        loop {
            let offsets = &self.params.sq.fields;
            let head = self.sq.atomic(offsets[0]).load(Ordering::Acquire);
            let tail = self.sq.atomic(offsets[1]).load(Ordering::Acquire);
            // GETEVENTS with min_complete=0 runs pending task work without blocking.
            // SAFETY: this owned ring uses the normal (non-SQPOLL) submission ABI.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    self.fd.as_raw_fd(),
                    tail.wrapping_sub(head),
                    0u32,
                    1u32,
                    std::ptr::null::<libc::sigset_t>(),
                    0usize,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let consumed = self.sq.atomic(offsets[0]).load(Ordering::Acquire);
            if consumed == tail {
                return Ok(());
            }
            if result == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
    }

    pub fn completions(&mut self, output: &mut Vec<Cqe>) {
        output.clear();
        let offsets = &self.params.cq.fields;
        let head = self.cq.atomic(offsets[0]).load(Ordering::Relaxed);
        let tail = self.cq.atomic(offsets[1]).load(Ordering::Acquire);
        for offset in 0..tail.wrapping_sub(head) {
            let index = head.wrapping_add(offset);
            let slot = index & (self.params.cq_entries - 1);
            // SAFETY: acquire observed CQ publication; slot is bounded by the kernel CQ size.
            output.push(unsafe {
                self.cq
                    .ptr
                    .add(offsets[5] as usize)
                    .cast::<Cqe>()
                    .add(slot as usize)
                    .read()
            });
        }
        self.cq.atomic(offsets[0]).store(tail, Ordering::Release);
    }

    fn cancel_all(&self) -> io::Result<()> {
        #[repr(C)]
        struct Cancel {
            addr: u64,
            fd: i32,
            flags: u32,
            timeout: [i64; 2],
            padding: [u64; 4],
        }
        let request = Cancel {
            addr: 0,
            fd: -1,
            flags: (1 << 2) | 1,
            timeout: [-1, -1],
            padding: [0; 4],
        };
        loop {
            // SAFETY: request matches io_uring_sync_cancel_reg and stays live through register.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_register,
                    self.fd.as_raw_fd(),
                    24u32,
                    &request,
                    1u32,
                )
            };
            if result >= 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ENOENT) => return Ok(()),
                Some(libc::EINTR) => continue,
                _ => return Err(error),
            }
        }
    }

    /// On success no submitted operation can access its packet buffers again.
    pub fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.cancel_all()?;
        self.stopped = true;
        Ok(())
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.cancel_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_abi_layouts() {
        assert_eq!(size_of::<Sqe>(), 64);
        assert_eq!(size_of::<Cqe>(), 16);
        assert_eq!(size_of::<Params>(), 120);
        assert_eq!(mem::offset_of!(Sqe, user_data), 32);
        assert_eq!(mem::offset_of!(Sqe, buf_group), 40);
    }
}
