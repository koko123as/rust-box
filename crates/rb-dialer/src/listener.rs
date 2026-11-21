//! Inbound sockets with the listen fields applied (sing-box
//! `common/listener`: `ListenTCP`, `ListenPacket`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;

use rb_config::ListenOptions;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::{sys, DEFAULT_KEEP_ALIVE_IDLE, DEFAULT_KEEP_ALIVE_INTERVAL};

/// The listen fields of one inbound, checked (sing-box `listener.Listener`).
#[derive(Debug, Clone)]
pub struct Listener {
    address: SocketAddr,
    bind_interface: Option<String>,
    routing_mark: Option<u32>,
    reuse_addr: bool,
    netns: Option<PathBuf>,
    keep_alive: Option<(Duration, Duration)>,
    tcp_fast_open: bool,
    tcp_multi_path: bool,
    udp_fragment: Option<bool>,
}

impl Listener {
    pub fn new(options: &ListenOptions) -> Result<Self, String> {
        if !options.bind_interface.is_empty() && !sys::IS_LINUX {
            return Err("`bind_interface` is not supported by rust-box on this platform".into());
        }
        if options.routing_mark.0 != 0 && !sys::IS_LINUX {
            return Err("`routing_mark` is only supported on Linux".into());
        }
        if !options.netns.is_empty() && !sys::IS_LINUX {
            return Err("`netns` is only supported on Linux".into());
        }
        if options.tcp_fast_open && !sys::IS_LINUX {
            return Err("`tcp_fast_open` is not supported by rust-box on this platform".into());
        }
        // `listen` defaults to 127.0.0.1 (sing-box `Listen.Build(127.0.0.1)`).
        let ip = options.listen.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let keep_alive = (!options.disable_tcp_keep_alive).then(|| {
            let idle =
                if options.tcp_keep_alive.0.is_zero() { DEFAULT_KEEP_ALIVE_IDLE } else { options.tcp_keep_alive.0 };
            let interval = if options.tcp_keep_alive_interval.0.is_zero() {
                DEFAULT_KEEP_ALIVE_INTERVAL
            } else {
                options.tcp_keep_alive_interval.0
            };
            (idle, interval)
        });
        Ok(Listener {
            address: SocketAddr::new(ip, options.listen_port),
            bind_interface: (!options.bind_interface.is_empty()).then(|| options.bind_interface.clone()),
            routing_mark: (options.routing_mark.0 != 0).then_some(options.routing_mark.0),
            reuse_addr: options.reuse_addr,
            netns: (!options.netns.is_empty()).then(|| sys::netns_path(&options.netns)),
            keep_alive,
            tcp_fast_open: options.tcp_fast_open,
            tcp_multi_path: options.tcp_multi_path,
            udp_fragment: options.udp_fragment,
        })
    }

    /// The configured address (before binding).
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Options every inbound socket gets (sing-box appends them to each
    /// listen config: interface, mark, reuse).
    fn common(&self, socket: &Socket) -> io::Result<()> {
        let fd = socket.as_raw_fd();
        if let Some(name) = &self.bind_interface {
            sys::bind_to_interface(fd, name)
                .map_err(|error| io::Error::new(error.kind(), format!("bind to interface {name}: {error}")))?;
        }
        if let Some(mark) = self.routing_mark {
            sys::set_mark(fd, mark)
                .map_err(|error| io::Error::new(error.kind(), format!("set mark {mark}: {error}")))?;
        }
        if self.reuse_addr {
            sys::set_reuse_addr(fd)?;
        }
        Ok(())
    }

    /// The TCP listener (sing-box `Listener.ListenTCP`). `0.0.0.0` listens
    /// on IPv4 only and `::` on both families, as Go does.
    pub fn listen_tcp(&self) -> io::Result<TcpListener> {
        let address = self.address;
        let socket = sys::maybe_in_netns(self.netns.as_deref(), || {
            let domain = Domain::for_address(address);
            let multipath = if self.tcp_multi_path && sys::IS_LINUX {
                Socket::new(domain, Type::STREAM, Some(Protocol::from(crate::mptcp_protocol()))).ok()
            } else {
                None
            };
            let socket = match multipath {
                Some(socket) => socket,
                None => Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?,
            };
            socket.set_nonblocking(true)?;
            // Go sets SO_REUSEADDR on every Unix listener.
            socket.set_reuse_address(true)?;
            if domain == Domain::IPV6 {
                socket.set_only_v6(!address.ip().is_unspecified())?;
            }
            self.common(&socket)?;
            if self.tcp_fast_open {
                sys::set_tcp_fast_open_listener(socket.as_raw_fd())?;
            }
            socket.bind(&address.into())?;
            socket.listen(1024)?;
            Ok(socket)
        })
        .map_err(|error| io::Error::new(error.kind(), format!("listen {address}: {error}")))?;
        TcpListener::from_std(std::net::TcpListener::from(socket))
    }

    /// Applies the keep-alive fields to an accepted connection (Go's
    /// `ListenConfig.KeepAliveConfig`).
    pub fn accepted(&self, stream: &TcpStream) -> io::Result<()> {
        let _ = stream.set_nodelay(true);
        if let Some((idle, interval)) = self.keep_alive {
            sys::set_keep_alive(stream.as_raw_fd(), idle, interval)?;
        }
        Ok(())
    }

    /// The inbound's UDP socket on the listen address (sing-box
    /// `Listener.ListenUDP`): interface, mark, reuse, `udp_fragment` (off
    /// unless set) and namespace. `::` listens on both families, as Go does.
    pub fn listen_udp(&self) -> io::Result<UdpSocket> {
        let address = self.address;
        let fragment = self.udp_fragment.unwrap_or(false);
        let socket = sys::maybe_in_netns(self.netns.as_deref(), || {
            let domain = Domain::for_address(address);
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_nonblocking(true)?;
            if domain == Domain::IPV6 {
                socket.set_only_v6(!address.ip().is_unspecified())?;
            }
            self.common(&socket)?;
            sys::set_udp_fragment(socket.as_raw_fd(), domain == Domain::IPV6, fragment)?;
            socket.bind(&address.into())?;
            Ok(socket)
        })
        .map_err(|error| io::Error::new(error.kind(), format!("listen {address}: {error}")))?;
        UdpSocket::from_std(std::net::UdpSocket::from(socket))
    }

    /// A UDP socket for the inbound's own use, such as a SOCKS5 UDP
    /// ASSOCIATE on `local` (sing-box `Listener.ListenPacket`: interface,
    /// mark, reuse and namespace, but not `udp_fragment`).
    pub fn listen_packet(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        let socket = sys::maybe_in_netns(self.netns.as_deref(), || {
            let domain = Domain::for_address(local);
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_nonblocking(true)?;
            if domain == Domain::IPV6 && local.ip().is_unspecified() {
                socket.set_only_v6(false)?;
            }
            self.common(&socket)?;
            socket.bind(&local.into())?;
            Ok(socket)
        })?;
        UdpSocket::from_std(std::net::UdpSocket::from(socket))
    }
}
