//! The rtnetlink requests the TUN setup makes (what sing-tun does through
//! `github.com/sagernet/netlink`): link MTU and state, addresses, routes and
//! policy rules, each message built the way that library builds it.

use std::io;
use std::net::IpAddr;

use rb_platform::Prefix;

use crate::rules::{Rule, AF_INET, AF_INET6};

const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_UID_RANGE: u16 = 20;
const FRA_DPORT_RANGE: u16 = 24;

const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;
const FR_ACT_GOTO: u8 = 2;
const FR_ACT_NOP: u8 = 3;
const FIB_RULE_INVERT: u32 = 0x2;
const IFF_UP: u32 = 0x1;

/// A request being built: the header, then the fixed message, then attributes.
pub struct Message {
    pub kind: u16,
    pub flags: u16,
    pub data: Vec<u8>,
}

impl Message {
    fn new(kind: u16, flags: u16) -> Self {
        Message { kind, flags: NLM_F_REQUEST | NLM_F_ACK | flags, data: Vec::new() }
    }

    fn attr(&mut self, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        self.data.extend_from_slice(&(length as u16).to_ne_bytes());
        self.data.extend_from_slice(&kind.to_ne_bytes());
        self.data.extend_from_slice(value);
        while !self.data.len().is_multiple_of(4) {
            self.data.push(0);
        }
    }

    fn attr_u32(&mut self, kind: u16, value: u32) {
        self.attr(kind, &value.to_ne_bytes());
    }

    /// The whole message with its header.
    pub fn encode(&self, sequence: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.data.len());
        out.extend_from_slice(&((16 + self.data.len()) as u32).to_ne_bytes());
        out.extend_from_slice(&self.kind.to_ne_bytes());
        out.extend_from_slice(&self.flags.to_ne_bytes());
        out.extend_from_slice(&sequence.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn family(address: IpAddr) -> u8 {
    if address.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    }
}

/// `RTM_NEWLINK` setting the MTU, or the up flag.
pub fn link_message(index: u32, mtu: Option<u32>, up: bool) -> Message {
    let mut message = Message::new(RTM_NEWLINK, 0);
    // struct ifinfomsg
    message.data.extend_from_slice(&[0, 0]);
    message.data.extend_from_slice(&0u16.to_ne_bytes());
    message.data.extend_from_slice(&(index as i32).to_ne_bytes());
    let (flags, change) = if up { (IFF_UP, IFF_UP) } else { (0, 0) };
    message.data.extend_from_slice(&flags.to_ne_bytes());
    message.data.extend_from_slice(&change.to_ne_bytes());
    if let Some(mtu) = mtu {
        message.attr_u32(IFLA_MTU, mtu);
    }
    message
}

/// `RTM_NEWADDR` / `RTM_DELADDR` (netlink `AddrAdd`: local and address,
/// and the broadcast address for IPv4 prefixes shorter than /31).
pub fn address_message(index: u32, prefix: Prefix, add: bool) -> Message {
    let mut message =
        if add { Message::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL) } else { Message::new(RTM_DELADDR, 0) };
    // struct ifaddrmsg
    message.data.extend_from_slice(&[family(prefix.address), prefix.len, 0, 0]);
    message.data.extend_from_slice(&index.to_ne_bytes());
    let bytes = address_bytes(prefix.address);
    message.attr(IFA_LOCAL, &bytes);
    message.attr(IFA_ADDRESS, &bytes);
    if let IpAddr::V4(v4) = prefix.address {
        if prefix.len < 31 {
            let host = if prefix.len == 0 { u32::MAX } else { u32::MAX >> prefix.len };
            message.attr(IFA_BROADCAST, &(u32::from(v4) | host).to_be_bytes());
        }
    }
    message
}

/// `RTM_NEWROUTE` / `RTM_DELROUTE` for `destination` through the link.
pub fn route_message(index: u32, destination: Prefix, gateway: Option<IpAddr>, table: i64, add: bool) -> Message {
    let mut message =
        if add { Message::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL) } else { Message::new(RTM_DELROUTE, 0) };
    let table_byte = if (0..256).contains(&table) { table as u8 } else { 0 };
    // struct rtmsg
    message.data.extend_from_slice(&[
        family(destination.address),
        destination.len,
        0,
        0,
        table_byte,
        RTPROT_BOOT,
        0,
        RTN_UNICAST,
    ]);
    message.data.extend_from_slice(&0u32.to_ne_bytes());
    message.attr(RTA_DST, &address_bytes(destination.address));
    if let Some(gateway) = gateway {
        message.attr(RTA_GATEWAY, &address_bytes(gateway));
    }
    message.attr_u32(RTA_OIF, index);
    if table >= 256 {
        message.attr_u32(RTA_TABLE, table as u32);
    }
    message
}

/// `RTM_NEWRULE` / `RTM_DELRULE` (netlink `ruleHandle`).
pub fn rule_message(rule: &Rule, add: bool) -> Message {
    let mut message =
        if add { Message::new(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL) } else { Message::new(RTM_DELRULE, 0) };
    let action = if rule.kind > 0 {
        rule.kind
    } else if rule.table >= 0 {
        FR_ACT_TO_TBL
    } else if rule.goto >= 0 {
        FR_ACT_GOTO
    } else if add {
        FR_ACT_NOP
    } else {
        0
    };
    let mut family = rule.family;
    if let Some(dst) = rule.dst {
        family = self::family(dst.address);
    }
    if let Some(src) = rule.src {
        family = self::family(src.address);
    }
    let table_byte = if (0..256).contains(&rule.table) { rule.table as u8 } else { 0 };
    // struct fib_rule_hdr
    message.data.extend_from_slice(&[
        family,
        rule.dst.map_or(0, |dst| dst.len),
        rule.src.map_or(0, |src| src.len),
        0,
        table_byte,
        RTPROT_BOOT,
        0,
        action,
    ]);
    let flags = if rule.invert { FIB_RULE_INVERT } else { 0 };
    message.data.extend_from_slice(&flags.to_ne_bytes());
    if let Some(dst) = rule.dst {
        message.attr(RTA_DST, &address_bytes(dst.address));
    }
    if let Some(src) = rule.src {
        message.attr(RTA_SRC, &address_bytes(src.address));
    }
    if rule.priority >= 0 {
        message.attr_u32(FRA_PRIORITY, rule.priority as u32);
    }
    if let Some(mark) = rule.mark {
        message.attr_u32(FRA_FWMARK, mark);
    }
    if let Some(mask) = rule.mask {
        message.attr_u32(FRA_FWMASK, mask);
    }
    if rule.table >= 0 {
        message.attr_u32(FRA_TABLE, rule.table as u32);
        if rule.suppress_prefixlen >= 0 {
            message.attr_u32(FRA_SUPPRESS_PREFIXLEN, rule.suppress_prefixlen as u32);
        }
    }
    if !rule.iif.is_empty() {
        message.attr(FRA_IIFNAME, format!("{}\0", rule.iif).as_bytes());
    }
    if !rule.oif.is_empty() {
        message.attr(FRA_OIFNAME, format!("{}\0", rule.oif).as_bytes());
    }
    if rule.goto >= 0 {
        message.attr_u32(FRA_GOTO, rule.goto as u32);
    }
    if let Some((start, end)) = rule.dport {
        let mut value = start.to_ne_bytes().to_vec();
        value.extend_from_slice(&end.to_ne_bytes());
        message.attr(FRA_DPORT_RANGE, &value);
    }
    if let Some((start, end)) = rule.uid {
        let mut value = start.to_ne_bytes().to_vec();
        value.extend_from_slice(&end.to_ne_bytes());
        message.attr(FRA_UID_RANGE, &value);
    }
    message
}

/// A policy rule as the kernel lists it: its family and priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListedRule {
    pub family: u8,
    pub priority: u32,
}

/// A NETLINK_ROUTE socket.
pub struct Netlink {
    fd: std::os::fd::OwnedFd,
    sequence: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        // SAFETY: plain socket creation.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just created.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Ok(Netlink { fd, sequence: 1 })
    }

    fn send(&mut self, message: &Message) -> io::Result<u32> {
        use std::os::fd::AsRawFd;
        self.sequence += 1;
        let bytes = message.encode(self.sequence);
        // SAFETY: a zeroed sockaddr_nl addresses the kernel.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: sending a buffer of the given length to the kernel.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(self.sequence)
    }

    /// Reads replies to `sequence` until the ACK (or the end of a dump),
    /// collecting the dumped messages.
    fn receive(&mut self, sequence: u32) -> io::Result<Vec<(u16, Vec<u8>)>> {
        use std::os::fd::AsRawFd;
        let mut collected = Vec::new();
        let mut buffer = vec![0u8; 65536];
        loop {
            // SAFETY: reading into a buffer of the given length.
            let length = unsafe { libc::recv(self.fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut data = &buffer[..length as usize];
            while data.len() >= 16 {
                let message_length = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
                if message_length < 16 || message_length > data.len() {
                    break;
                }
                let kind = u16::from_ne_bytes(data[4..6].try_into().unwrap());
                let message_sequence = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                let body = &data[16..message_length];
                if message_sequence == sequence {
                    match kind {
                        NLMSG_ERROR => {
                            let code = i32::from_ne_bytes(body[0..4].try_into().unwrap());
                            return if code == 0 { Ok(collected) } else { Err(io::Error::from_raw_os_error(-code)) };
                        }
                        NLMSG_DONE => return Ok(collected),
                        _ => collected.push((kind, body.to_vec())),
                    }
                }
                let aligned = (message_length + 3) & !3;
                data = &data[aligned.min(data.len())..];
            }
        }
    }

    /// Sends a request and waits for its ACK.
    pub fn request(&mut self, message: &Message) -> io::Result<()> {
        let sequence = self.send(message)?;
        self.receive(sequence).map(|_| ())
    }

    /// Every policy rule of both families (`ip rule list`).
    pub fn list_rules(&mut self) -> io::Result<Vec<ListedRule>> {
        let mut message = Message { kind: RTM_GETRULE, flags: NLM_F_REQUEST | NLM_F_DUMP, data: Vec::new() };
        message.data.extend_from_slice(&[0u8; 12]);
        let sequence = self.send(&message)?;
        let mut rules = Vec::new();
        for (_, body) in self.receive(sequence)? {
            if body.len() < 12 {
                continue;
            }
            let family = body[0];
            let mut priority = 0;
            let mut attributes = &body[12..];
            while attributes.len() >= 4 {
                let length = u16::from_ne_bytes([attributes[0], attributes[1]]) as usize;
                let kind = u16::from_ne_bytes([attributes[2], attributes[3]]);
                if length < 4 || length > attributes.len() {
                    break;
                }
                if kind == FRA_PRIORITY && length >= 8 {
                    priority = u32::from_ne_bytes(attributes[4..8].try_into().unwrap());
                }
                attributes = &attributes[((length + 3) & !3).min(attributes.len())..];
            }
            rules.push(ListedRule { family, priority });
        }
        Ok(rules)
    }
}

/// The index of an interface (`if_nametoindex`).
pub fn interface_index(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: a NUL-terminated name.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut data = data;
        while data.len() >= 4 {
            let length = u16::from_ne_bytes([data[0], data[1]]) as usize;
            out.push((u16::from_ne_bytes([data[2], data[3]]), data[4..length].to_vec()));
            data = &data[((length + 3) & !3).min(data.len())..];
        }
        out
    }

    #[test]
    fn rule_messages_like_netlink() {
        // ip rule add pref 9002 iif tun0 goto 9010
        let mut rule = Rule::new(AF_INET, 9002);
        rule.iif = "tun0".into();
        rule.goto = 9010;
        let message = rule_message(&rule, true);
        assert_eq!(message.kind, RTM_NEWRULE);
        assert_eq!(&message.data[..8], &[AF_INET, 0, 0, 0, 0, RTPROT_BOOT, 0, FR_ACT_GOTO]);
        assert_eq!(
            attrs(&message.data[12..]),
            vec![
                (FRA_PRIORITY, 9002u32.to_ne_bytes().to_vec()),
                (FRA_IIFNAME, b"tun0\0".to_vec()),
                (FRA_GOTO, 9010u32.to_ne_bytes().to_vec()),
            ]
        );
        // ip rule add pref 9001 not dport 53 lookup main suppress_prefixlength 0
        let mut rule = Rule::new(AF_INET6, 9001);
        rule.table = 254;
        rule.invert = true;
        rule.dport = Some((53, 53));
        rule.suppress_prefixlen = 0;
        let message = rule_message(&rule, true);
        assert_eq!(&message.data[..8], &[AF_INET6, 0, 0, 0, 254, RTPROT_BOOT, 0, FR_ACT_TO_TBL]);
        assert_eq!(u32::from_ne_bytes(message.data[8..12].try_into().unwrap()), FIB_RULE_INVERT);
        let attributes = attrs(&message.data[12..]);
        assert_eq!(attributes[1], (FRA_TABLE, 254u32.to_ne_bytes().to_vec()));
        assert_eq!(attributes[2], (FRA_SUPPRESS_PREFIXLEN, 0u32.to_ne_bytes().to_vec()));
        assert_eq!(attributes[3].0, FRA_DPORT_RANGE);
        // A rule with neither table nor goto is a nop when added; deleting
        // matches on family and priority alone.
        let rule = Rule::new(AF_INET, 9010);
        assert_eq!(rule_message(&rule, true).data[7], FR_ACT_NOP);
        let delete = rule_message(&rule, false);
        assert_eq!((delete.kind, delete.data[7]), (RTM_DELRULE, 0));
        // from 172.19.0.0/30 lookup 2022: the table goes in the attribute.
        let mut rule = Rule::new(AF_INET, 9003);
        rule.table = 2022;
        rule.src = Some(Prefix::new("172.19.0.0".parse().unwrap(), 30));
        let message = rule_message(&rule, true);
        assert_eq!(&message.data[..8], &[AF_INET, 0, 30, 0, 0, RTPROT_BOOT, 0, FR_ACT_TO_TBL]);
        assert_eq!(attrs(&message.data[12..])[0], (RTA_SRC, vec![172, 19, 0, 0]));
    }

    #[test]
    fn address_and_route_messages() {
        let message = address_message(7, Prefix::new("172.19.0.1".parse().unwrap(), 30), true);
        assert_eq!(&message.data[..8], &[AF_INET, 30, 0, 0, 7, 0, 0, 0]);
        let attributes = attrs(&message.data[8..]);
        assert_eq!(attributes[2], (IFA_BROADCAST, vec![172, 19, 0, 3]));
        let message = route_message(7, Prefix::new("0.0.0.0".parse().unwrap(), 0), None, 2022, true);
        assert_eq!(message.data[4], 0);
        let attributes = attrs(&message.data[12..]);
        assert_eq!(attributes.last().unwrap(), &(RTA_TABLE, 2022u32.to_ne_bytes().to_vec()));
        let encoded = message.encode(9);
        assert_eq!(u32::from_ne_bytes(encoded[0..4].try_into().unwrap()) as usize, encoded.len());
    }
}
