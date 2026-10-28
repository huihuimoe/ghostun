//! Per-worker backlog budgets shared by TUN and both transports.
pub const BYTES: usize = 256 * 1024;
pub const PACKETS: usize = 256;
pub const TCP_NOTSENT: u32 = (BYTES / 4) as u32;
pub const TCP_WRITE_BATCH: usize = BYTES / 4;

// Linux applies txqueuelen to every TUN ring independently, including detached queues.
pub fn tun_packets(mtu: u32) -> u32 {
    (BYTES as u32 / mtu).clamp(1, PACKETS as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_ring_budget_is_per_queue_and_accounts_for_mtu() {
        for mtu in [576, 1280, 1380, 1460, 65000] {
            let packets = tun_packets(mtu);
            assert!(packets <= PACKETS as u32);
            assert!(packets * mtu <= BYTES as u32);
        }
        assert_eq!(tun_packets(1380), 189);
    }
}
