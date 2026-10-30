//! Blocking route-netlink operations used only during network setup.

use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR,
    NLM_F_EXCL, NLM_F_MULTIPART, NLM_F_REQUEST,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

use crate::net::{Cidr, OuterFamily};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub src: IpAddr,
    pub dev: String,
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

fn request(
    message: RouteNetlinkMessage,
    flags: u16,
    mut on_message: impl FnMut(RouteNetlinkMessage) -> io::Result<()>,
) -> io::Result<()> {
    // A separate, unsubscribed socket per transaction leaves no pending ACKs or dump state.
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    let local = socket.bind_auto()?;
    let kernel = SocketAddr::new(0, 0);
    let mut packet = NetlinkMessage::from(message);
    packet.header.flags = NLM_F_REQUEST | flags;
    packet.header.sequence_number = 1;
    packet.header.port_number = local.port_number();
    packet.finalize();
    let mut buffer = vec![0; packet.buffer_len()];
    packet.serialize(&mut buffer);
    let sent = retry_interrupted(|| socket.send_to(&buffer, &kernel, 0))?;
    if sent != buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete netlink request",
        ));
    }
    loop {
        // Probe the whole datagram, then reuse the buffer instead of imposing a dump-size limit.
        let (length, _) = retry_interrupted(|| {
            socket.recv_from(&mut &mut [0u8; 0][..], libc::MSG_PEEK | libc::MSG_TRUNC)
        })?;
        buffer.clear();
        buffer.reserve(length);
        let (received, sender) =
            retry_interrupted(|| socket.recv_from(&mut buffer, libc::MSG_TRUNC))?;
        if received != length || sender != kernel {
            return Err(invalid("invalid netlink datagram length or sender"));
        }
        if replies(
            &buffer,
            local.port_number(),
            flags & NLM_F_ACK != 0,
            &mut on_message,
        )? {
            return Ok(());
        }
    }
}

fn replies(
    mut bytes: &[u8],
    port: u32,
    ack: bool,
    on_message: &mut impl FnMut(RouteNetlinkMessage) -> io::Result<()>,
) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(invalid("empty netlink response"));
    }
    while !bytes.is_empty() {
        let response = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if response.header.sequence_number != 1 || response.header.port_number != port {
            return Err(invalid("netlink response does not match request"));
        }
        if response.header.flags & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "netlink dump interrupted",
            ));
        }
        let length = response.header.length as usize;
        bytes = &bytes[length.next_multiple_of(4).min(bytes.len())..];
        match response.payload {
            NetlinkPayload::Error(error) => {
                return if error.code.is_some() {
                    Err(error.to_io())
                } else {
                    Ok(true)
                };
            }
            NetlinkPayload::Done(done) => {
                return if done.code != 0 {
                    Err(io::Error::from_raw_os_error(done.code.abs()))
                } else {
                    Ok(true)
                };
            }
            NetlinkPayload::InnerMessage(message) => {
                on_message(message)?;
                if !ack && response.header.flags & NLM_F_MULTIPART == 0 {
                    return Ok(true);
                }
            }
            NetlinkPayload::Noop => {}
            NetlinkPayload::Overrun(_) => return Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
            _ => return Err(invalid("unexpected netlink response")),
        }
    }
    Ok(false)
}

fn iface_index(name: &str) -> io::Result<u32> {
    let name =
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: name is NUL-terminated and lives through the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

fn iface_name(index: u32) -> io::Result<String> {
    let mut name = [0; libc::IFNAMSIZ];
    // SAFETY: name has the IFNAMSIZ bytes required by if_indextoname.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful if_indextoname writes a NUL-terminated name.
    Ok(unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

pub fn route_to(destination: IpAddr, device: Option<&str>) -> io::Result<Route> {
    let mut message = RouteMessage::default();
    let address = match destination {
        IpAddr::V4(address) => {
            message.header.address_family = AddressFamily::Inet;
            message.header.destination_prefix_length = 32;
            message.header.flags = RouteFlags::LookupTable;
            RouteAddress::Inet(address)
        }
        IpAddr::V6(address) => {
            message.header.address_family = AddressFamily::Inet6;
            message.header.destination_prefix_length = 128;
            RouteAddress::Inet6(address)
        }
    };
    message
        .attributes
        .push(RouteAttribute::Destination(address));
    if let Some(device) = device {
        message
            .attributes
            .push(RouteAttribute::Oif(iface_index(device)?));
    }
    let mut source = None;
    let mut index = None;
    request(RouteNetlinkMessage::GetRoute(message), 0, |message| {
        let RouteNetlinkMessage::NewRoute(message) = message else {
            return Err(invalid("expected a route lookup response"));
        };
        for attribute in message.attributes {
            match attribute {
                RouteAttribute::PrefSource(RouteAddress::Inet(address)) => {
                    source = Some(address.into())
                }
                RouteAttribute::PrefSource(RouteAddress::Inet6(address)) => {
                    source = Some(address.into())
                }
                RouteAttribute::Oif(value) => index = Some(value),
                _ => {}
            }
        }
        Ok(())
    })?;
    match (source, index) {
        (Some(src), Some(index)) => Ok(Route {
            src,
            dev: iface_name(index)?,
        }),
        _ => Err(invalid(
            "route lookup returned no source address or output interface",
        )),
    }
}

fn default_route_index(message: &RouteMessage) -> Option<u32> {
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));
    if table != u32::from(RouteHeader::RT_TABLE_MAIN)
        || message.header.destination_prefix_length != 0
    {
        return None;
    }
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            RouteAttribute::MultiPath(hops) => hops
                .iter()
                .find(|hop| hop.interface_index != 0)
                .map(|hop| hop.interface_index),
            _ => None,
        })
}

pub fn default_route_dev(family: OuterFamily) -> io::Result<String> {
    let mut message = RouteMessage::default();
    message.header.address_family = match family {
        OuterFamily::Ipv4 => AddressFamily::Inet,
        OuterFamily::Ipv6 => AddressFamily::Inet6,
    };
    let mut index = None;
    request(
        RouteNetlinkMessage::GetRoute(message),
        NLM_F_DUMP,
        |message| {
            let RouteNetlinkMessage::NewRoute(message) = message else {
                return Err(invalid("expected a route dump response"));
            };
            if index.is_none() {
                index = default_route_index(&message);
            }
            Ok(())
        },
    )?;
    iface_name(index.ok_or_else(|| invalid("no default route output interface"))?)
}

fn add_address(index: u32, address: IpAddr, prefix: u8) -> io::Result<()> {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = prefix;
    message.attributes.push(AddressAttribute::Address(address));
    match address {
        IpAddr::V4(v4) => {
            message.header.family = AddressFamily::Inet;
            // ip address add gives all 127/8 addresses host scope, including on a TUN.
            if v4.is_loopback() {
                message.header.scope = AddressScope::Host;
            }
            message.attributes.push(AddressAttribute::Local(address));
        }
        IpAddr::V6(_) => {
            message.header.family = AddressFamily::Inet6;
            message.header.flags = AddressHeaderFlags::Nodad;
        }
    }
    request(
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        |_| Ok(()),
    )
}

/// Brings up the existing TUN and assigns addresses; only IPv6-add failures are nonfatal.
pub fn configure_tun(
    name: &str,
    mtu: u32,
    txqueuelen: u32,
    v4: Cidr<Ipv4Addr>,
    v6: Option<Cidr<Ipv6Addr>>,
) -> io::Result<bool> {
    let index = iface_index(name)?;
    let mut message = LinkMessage::default();
    message.header.index = index;
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    message.attributes = vec![
        LinkAttribute::Mtu(mtu),
        LinkAttribute::TxQueueLen(txqueuelen),
    ];
    request(RouteNetlinkMessage::NewLink(message), NLM_F_ACK, |_| Ok(()))?;
    add_address(index, v4.addr.into(), v4.prefix)?;
    let Some(v6) = v6 else { return Ok(false) };
    match add_address(index, v6.addr.into(), v6.prefix) {
        Ok(()) => Ok(true),
        Err(error) => {
            log::warn!("inner IPv6 disabled: cannot add {v6} to {name}: {error}");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DoneMessage, ErrorMessage};
    use netlink_packet_route::route::RouteNextHop;

    fn packet(payload: NetlinkPayload<RouteNetlinkMessage>, flags: u16) -> Vec<u8> {
        let mut message = NetlinkMessage::new(Default::default(), payload);
        message.header.flags = flags;
        message.header.port_number = 42;
        message.header.sequence_number = 1;
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }

    #[test]
    fn multipart_and_ack_have_distinct_completion_boundaries() {
        let route = RouteNetlinkMessage::NewRoute(RouteMessage::default());
        let data = packet(NetlinkPayload::InnerMessage(route.clone()), NLM_F_MULTIPART);
        assert!(!replies(&data, 42, false, &mut |_| Ok(())).unwrap());
        let done = packet(
            NetlinkPayload::Done(DoneMessage::default()),
            NLM_F_MULTIPART,
        );
        assert!(replies(&done, 42, false, &mut |_| Ok(())).unwrap());

        let data = packet(NetlinkPayload::InnerMessage(route), 0);
        assert!(!replies(&data, 42, true, &mut |_| Ok(())).unwrap());
        assert!(replies(&data, 42, false, &mut |_| Ok(())).unwrap());
        let ack = packet(NetlinkPayload::Error(ErrorMessage::default()), 0);
        assert!(replies(&ack, 42, true, &mut |_| Ok(())).unwrap());
    }

    #[test]
    fn multipart_datagram_does_not_skip_later_errors() {
        let route = RouteNetlinkMessage::NewRoute(RouteMessage::default());
        let mut bytes = packet(NetlinkPayload::InnerMessage(route), NLM_F_MULTIPART);
        let mut done = DoneMessage::default();
        done.code = -libc::EINVAL;
        bytes.extend(packet(NetlinkPayload::Done(done), NLM_F_MULTIPART));
        assert_eq!(
            replies(&bytes, 42, false, &mut |_| Ok(()))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn kernel_errors_and_interrupted_dumps_are_not_success() {
        let mut error = ErrorMessage::default();
        error.code = std::num::NonZeroI32::new(-libc::EACCES);
        let bytes = packet(NetlinkPayload::Error(error), 0);
        assert_eq!(
            replies(&bytes, 42, true, &mut |_| Ok(()))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let bytes = packet(
            NetlinkPayload::Done(DoneMessage::default()),
            NLM_F_DUMP_INTR,
        );
        assert_eq!(
            replies(&bytes, 42, false, &mut |_| Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn reply_identity_is_checked_before_delivery() {
        let mut message =
            NetlinkMessage::from(RouteNetlinkMessage::NewRoute(RouteMessage::default()));
        message.header.port_number = 42;
        message.header.sequence_number = 2;
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        let mut delivered = false;
        let mut receive = |_| {
            delivered = true;
            Ok(())
        };
        assert_eq!(
            replies(&bytes, 42, false, &mut receive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        message.header.sequence_number = 1;
        message.header.port_number = 43;
        message.serialize(&mut bytes);
        assert_eq!(
            replies(&bytes, 42, false, &mut receive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!delivered);
    }

    #[test]
    fn default_route_requires_main_table_and_zero_prefix() {
        let mut message = RouteMessage::default();
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.attributes.push(RouteAttribute::Oif(7));
        assert_eq!(default_route_index(&message), Some(7));
        message.header.destination_prefix_length = 24;
        assert_eq!(default_route_index(&message), None);
        message.header.destination_prefix_length = 0;
        message.attributes.push(RouteAttribute::Table(100));
        assert_eq!(default_route_index(&message), None);
        message.header.table = 100;
        message.attributes.pop();
        message
            .attributes
            .push(RouteAttribute::Table(u32::from(RouteHeader::RT_TABLE_MAIN)));
        assert_eq!(default_route_index(&message), Some(7));
    }

    #[test]
    fn multipath_default_uses_first_named_interface() {
        let mut message = RouteMessage::default();
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        let mut first = RouteNextHop::default();
        first.interface_index = 7;
        let mut second = RouteNextHop::default();
        second.interface_index = 8;
        message.attributes.push(RouteAttribute::MultiPath(vec![
            RouteNextHop::default(),
            first,
            second,
        ]));
        assert_eq!(default_route_index(&message), Some(7));
    }
}
