//! Transmit queue of length-prefixed frames, bounded by the shared byte budget.

use std::collections::VecDeque;
use std::io::{self, IoSlice, Write};

use super::frame::{FRAME_PREFIX_LEN, TX_LIMIT};

pub struct SendQueue {
    blocks: VecDeque<SendBlock>,
    free: Vec<SendBlock>,
    bytes: usize,
    established: bool,
    write_batch: usize,
}

#[derive(Default)]
struct SendBlock {
    bytes: Vec<u8>,
    head: usize,
    tail: usize,
}

impl SendQueue {
    pub fn new(write_batch: usize) -> Self {
        Self {
            blocks: VecDeque::new(),
            free: Vec::new(),
            bytes: 0,
            established: false,
            write_batch,
        }
    }

    #[inline(always)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    #[inline(always)]
    pub fn room(&self, payload: usize) -> bool {
        self.bytes() + payload + FRAME_PREFIX_LEN <= TX_LIMIT
    }

    pub fn grow(&mut self) {
        self.established = true;
    }

    #[inline]
    fn tail(&mut self, space: usize) -> &mut SendBlock {
        if let Some(block) = self.blocks.back_mut() {
            if block.head == block.tail && block.bytes.len() < space {
                block.bytes.resize(space, 0);
            }
        }
        if self
            .blocks
            .back()
            .is_none_or(|b| b.bytes.len() - b.tail < space)
        {
            let mut block = self.free.pop().unwrap_or_default();
            // Leave a whole queue budget before the largest contiguous direct-read reservation.
            // A full block therefore holds at least TX_LIMIT committed bytes; at most two such
            // blocks can be live, even when a maximum-MTU read returns a tiny packet.
            let size = if self.established {
                TX_LIMIT + usize::from(u16::MAX) + FRAME_PREFIX_LEN + 1
            } else {
                256
            };
            block
                .bytes
                .resize(block.bytes.len().max(size).max(space), 0);
            block.head = 0;
            block.tail = 0;
            self.blocks.push_back(block);
        }
        self.blocks.back_mut().expect("tail block was allocated")
    }

    #[inline]
    pub fn push(&mut self, payload: &[u8]) -> bool {
        if !self.room(payload.len()) {
            return false;
        }
        let frame = FRAME_PREFIX_LEN + payload.len();
        let block = self.tail(frame);
        block.bytes[block.tail..block.tail + FRAME_PREFIX_LEN]
            .copy_from_slice(&(payload.len() as u16).to_be_bytes());
        block.bytes[block.tail + FRAME_PREFIX_LEN..block.tail + frame].copy_from_slice(payload);
        block.tail += frame;
        self.bytes += frame;
        true
    }

    #[inline]
    pub fn push_in_place<F>(&mut self, max: usize, f: F) -> io::Result<bool>
    where
        F: FnOnce(&mut [u8]) -> io::Result<Option<usize>>,
    {
        if !self.room(max) {
            return Ok(false);
        }
        let block = self.tail(max + FRAME_PREFIX_LEN + 1);
        let payload_start = block.tail + FRAME_PREFIX_LEN;
        let Some(len) = f(&mut block.bytes[payload_start..payload_start + max + 1])? else {
            return Ok(false);
        };
        assert!((1..=max).contains(&len));
        block.bytes[block.tail..block.tail + FRAME_PREFIX_LEN]
            .copy_from_slice(&(len as u16).to_be_bytes());
        block.tail += FRAME_PREFIX_LEN + len;
        self.bytes += FRAME_PREFIX_LEN + len;
        Ok(true)
    }

    #[inline]
    pub fn flush(&mut self, output: &mut impl Write) -> io::Result<()> {
        while self.bytes != 0 {
            let mut slices = [IoSlice::new(&[]); 8];
            let count = self.blocks.len().min(slices.len());
            let mut allowance = self.write_batch;
            for (slice, block) in slices.iter_mut().zip(&self.blocks) {
                let len = (block.tail - block.head).min(allowance);
                *slice = IoSlice::new(&block.bytes[block.head..block.head + len]);
                allowance -= len;
            }
            match output.write_vectored(&slices[..count]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.bytes -= n;
                    let mut remaining = n;
                    while remaining != 0 {
                        let block = self.blocks.front_mut().expect("queued bytes own a block");
                        let consumed = remaining.min(block.tail - block.head);
                        block.head += consumed;
                        remaining -= consumed;
                        if block.head == block.tail {
                            self.free
                                .push(self.blocks.pop_front().expect("front block exists"));
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_mtu_tiny_reads_keep_retained_storage_bounded() {
        let mut queue = SendQueue::new(crate::transport::budget::TCP_NOTSENT as usize);
        queue.grow();
        for _ in 0..3 {
            let mut packets = 0;
            while queue
                .push_in_place(65000, |buffer| {
                    buffer[..40].fill(7);
                    Ok(Some(40))
                })
                .unwrap()
            {
                packets += 1;
            }
            assert!(packets > 1000);
            let retained: usize = queue
                .blocks
                .iter()
                .chain(&queue.free)
                .map(|b| b.bytes.len())
                .sum();
            assert!(retained <= 2 * (TX_LIMIT + usize::from(u16::MAX) + FRAME_PREFIX_LEN + 1));
            let mut bytes = Vec::new();
            queue.flush(&mut bytes).unwrap();
            assert_eq!(bytes.len(), packets * 42);
            for frame in bytes.as_chunks::<42>().0 {
                assert_eq!(&frame[..2], &[0, 40]);
                assert!(frame[2..].iter().all(|&v| v == 7));
            }
        }
    }
}
