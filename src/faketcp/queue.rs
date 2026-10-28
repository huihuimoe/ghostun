//! Backpressure storage; the normal writable path does not allocate packet buffers.
use std::collections::VecDeque;

pub const BYTE_LIMIT: usize = 256 * 1024;
pub const PACKET_LIMIT: usize = 256;
const CONTROL_LIMIT: usize = 16;

pub struct Packet<T> {
    pub bytes: Vec<u8>,
    pub metadata: T,
    control: bool,
}

pub struct Pending<T> {
    pub packets: VecDeque<Packet<T>>,
    bytes: usize,
    data: usize,
    controls: usize,
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            bytes: 0,
            data: 0,
            controls: 0,
        }
    }
}

impl<T> Pending<T> {
    pub fn room(&self, len: usize) -> bool {
        self.room_for(len, 1)
    }

    pub fn room_for(&self, len: usize, count: usize) -> bool {
        self.data + count <= PACKET_LIMIT && self.bytes + len <= BYTE_LIMIT
    }

    pub fn push(&mut self, bytes: &[u8], metadata: T, control: bool) -> bool {
        if if control {
            self.controls == CONTROL_LIMIT
        } else {
            !self.room(bytes.len())
        } {
            return false;
        }
        if control {
            self.controls += 1;
        } else {
            self.bytes += bytes.len();
            self.data += 1;
        }
        self.packets.push_back(Packet {
            bytes: bytes.to_vec(),
            metadata,
            control,
        });
        true
    }

    pub fn pop(&mut self) {
        if let Some(packet) = self.packets.pop_front() {
            if packet.control {
                self.controls -= 1;
            } else {
                self.bytes -= packet.bytes.len();
                self.data -= 1;
            }
        }
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.bytes = 0;
        self.data = 0;
        self.controls = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_reserve_control_space_and_preserve_fifo_and_destinations() {
        let mut q = Pending::default();
        for n in 0..PACKET_LIMIT {
            assert!(q.push(&[n as u8], n, false));
        }
        assert!(!q.push(b"full", 999, false));
        for n in 0..CONTROL_LIMIT {
            assert!(q.push(b"control", n, true));
        }
        assert!(!q.push(b"full", 999, true));
        for n in 0..PACKET_LIMIT {
            assert_eq!(q.packets.front().unwrap().metadata, n);
            assert_eq!(q.packets.front().unwrap().bytes, [n as u8]);
            q.pop();
        }
        assert!(q.room(BYTE_LIMIT));
        q.clear();
        assert!(q.push(&vec![0; BYTE_LIMIT], 1, false));
        assert!(!q.push(b"x", 2, false));
        q.pop();
        assert!(q.room(BYTE_LIMIT));
    }
}
