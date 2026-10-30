//! Blocking nf_tables transactions; every mutation is committed as one batch.

use std::io;

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NlasIterator, NLM_F_ACK, NLM_F_ACK_TLVS, NLM_F_REQUEST,
};
use netlink_packet_netfilter::nftables::NfTablesMessage;
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};
use netlink_sys::protocols::NETLINK_NETFILTER;
use netlink_sys::{Socket, SocketAddr};

pub(super) struct Batch {
    messages: Vec<NetlinkMessage<NetfilterMessage>>,
}

impl Batch {
    pub(super) fn new() -> Self {
        Self {
            messages: vec![control(ControlMessage::BatchBegin)],
        }
    }

    pub(super) fn push(&mut self, message: NfTablesMessage, flags: u16) {
        let mut packet = NetlinkMessage::new(
            Default::default(),
            NetlinkPayload::InnerMessage(NetfilterMessage::new(
                NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
                message,
            )),
        );
        packet.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        self.messages.push(packet);
    }

    pub(super) fn commit(mut self) -> io::Result<()> {
        self.messages.push(control(ControlMessage::BatchEnd));
        // Unsubscribed sockets keep this batch independent of other instances and route requests.
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        let local = socket.bind_auto()?;
        let kernel = SocketAddr::new(0, 0);
        socket.set_cap_ack(true)?;
        if let Err(error) = socket.set_ext_ack(true) {
            if error.raw_os_error() != Some(libc::ENOPROTOOPT) {
                return Err(error);
            }
        }
        let mut pending = vec![false; self.messages.len() + 1];
        pending[2..self.messages.len()].fill(true);
        let mut remaining = self.messages.len() - 2;
        let length = self
            .messages
            .iter_mut()
            .map(|packet| {
                packet.finalize();
                (packet.header.length as usize).next_multiple_of(4)
            })
            .sum();
        let mut buffer = vec![0; length];
        let mut offset = 0;
        for (index, packet) in self.messages.iter_mut().enumerate() {
            packet.header.sequence_number = (index + 1) as u32;
            packet.header.port_number = local.port_number();
            let length = packet.header.length as usize;
            packet.serialize(&mut buffer[offset..offset + length]);
            offset += length.next_multiple_of(4);
        }
        let sent = retry_interrupted(|| socket.send_to(&buffer, &kernel, 0))?;
        if sent != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete nf_tables batch",
            ));
        }
        while remaining != 0 {
            let (length, _) = retry_interrupted(|| {
                socket.recv_from(&mut &mut [0u8; 0][..], libc::MSG_PEEK | libc::MSG_TRUNC)
            })?;
            buffer.clear();
            buffer.reserve(length);
            let (received, sender) =
                retry_interrupted(|| socket.recv_from(&mut buffer, libc::MSG_TRUNC))?;
            if received != length || sender != kernel {
                return Err(invalid("invalid nf_tables datagram length or sender"));
            }
            remaining -= acknowledgements(&buffer, local.port_number(), &mut pending)?;
        }
        // nfnetlink sends successful per-request ACKs only after committing the entire batch.
        Ok(())
    }
}

fn control(message: ControlMessage) -> NetlinkMessage<NetfilterMessage> {
    let mut packet = NetlinkMessage::new(
        Default::default(),
        NetlinkPayload::InnerMessage(NetfilterMessage::new(
            // NFNL_SUBSYS_NFTABLES, in network byte order on the wire.
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 10),
            message,
        )),
    );
    packet.header.flags = NLM_F_REQUEST;
    packet
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn acknowledgements(mut bytes: &[u8], port: u32, pending: &mut [bool]) -> io::Result<usize> {
    if bytes.is_empty() {
        return Err(invalid("empty nf_tables response"));
    }
    let mut acknowledged = 0;
    while !bytes.is_empty() {
        let response = NetlinkMessage::<NetfilterMessage>::deserialize(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let sequence = response.header.sequence_number as usize;
        if response.header.port_number != port || sequence == 0 || sequence >= pending.len() {
            return Err(invalid("nf_tables response does not match batch"));
        }
        bytes = &bytes[(response.header.length as usize)
            .next_multiple_of(4)
            .min(bytes.len())..];
        match response.payload {
            NetlinkPayload::Error(error) => {
                if error.code.is_some() {
                    let cause = error.to_io();
                    let mut detail = String::new();
                    if response.header.flags & NLM_F_ACK_TLVS != 0 {
                        // NETLINK_CAP_ACK leaves only the 16-byte original nlmsghdr before TLVs.
                        if let Some(attributes) = error.header.get(16..) {
                            for attribute in NlasIterator::new(attributes) {
                                let attribute = attribute.map_err(|error| {
                                    io::Error::new(io::ErrorKind::InvalidData, error)
                                })?;
                                if attribute.kind() == 1 {
                                    // NLMSGERR_ATTR_MSG
                                    detail = format!(
                                        ": {}",
                                        String::from_utf8_lossy(
                                            attribute
                                                .value()
                                                .strip_suffix(&[0])
                                                .unwrap_or(attribute.value())
                                        )
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    return Err(io::Error::new(
                        cause.kind(),
                        format!("nf_tables request {sequence}: {cause}{detail}"),
                    ));
                }
                if !pending[sequence] {
                    return Err(invalid("duplicate or unsolicited nf_tables ACK"));
                }
                pending[sequence] = false;
                acknowledged += 1;
            }
            NetlinkPayload::Overrun(_) => return Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
            _ => return Err(invalid("unexpected nf_tables response")),
        }
    }
    Ok(acknowledged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::ErrorMessage;
    use std::num::NonZeroI32;

    fn ack(sequence: u32, code: i32) -> Vec<u8> {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(code);
        let mut packet = NetlinkMessage::<NetfilterMessage>::new(
            Default::default(),
            NetlinkPayload::Error(error),
        );
        packet.header.sequence_number = sequence;
        packet.header.port_number = 42;
        packet.finalize();
        let mut bytes = vec![0; packet.buffer_len()];
        packet.serialize(&mut bytes);
        bytes
    }

    #[test]
    fn all_requests_must_be_acknowledged_once() {
        let mut pending = [false, false, true, true, false];
        assert_eq!(acknowledgements(&ack(3, 0), 42, &mut pending).unwrap(), 1);
        assert!(pending[2], "an early ACK must not complete the batch");
        assert!(acknowledgements(&ack(3, 0), 42, &mut pending).is_err());
        assert!(acknowledgements(&ack(2, 0), 43, &mut pending).is_err());
        assert!(acknowledgements(&ack(4, 0), 42, &mut pending).is_err());
        assert_eq!(acknowledgements(&ack(2, 0), 42, &mut pending).unwrap(), 1);
        assert!(!pending.iter().any(|value| *value));
    }

    #[test]
    fn failure_after_successful_ack_is_not_hidden() {
        let mut pending = [false, false, true, true, false];
        let mut bytes = ack(2, 0);
        bytes.extend(ack(3, -libc::EINVAL));
        let error = acknowledgements(&bytes, 42, &mut pending).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(pending[3]);
        assert!(acknowledgements(&[], 42, &mut pending).is_err());
        assert!(acknowledgements(&ack(3, 0)[..17], 42, &mut pending).is_err());
    }
}
