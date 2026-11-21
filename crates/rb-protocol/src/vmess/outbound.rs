//! The `vmess` outbound (sing-box `protocol/vmess/outbound.go` with
//! sing-vmess `Client`).

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rb_adapter::{BoxStream, InboundContext, Network, Outbound, SharedPacketConn, Socksaddr};
use rb_config::VmessOutbound as OutboundOptions;
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};

use super::protocol::{self, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP};
use super::session::ClientConfig;
use super::stream::{VmessPacketConn, VmessStream};
use crate::vless::packet::{PacketAddrConn, XudpPacketConn, PACKET_ADDR_MAGIC};
use crate::vless::protocol::parse_uuid;

/// How UDP goes (`packet_encoding`; none by default, unlike vless).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessPacketEncoding {
    None,
    PacketAddr,
    Xudp,
}

/// The `vmess` outbound.
pub struct VmessOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    tls: Option<rb_tls::TlsClient>,
    server: Socksaddr,
    client: ClientConfig,
    packet_encoding: VmessPacketEncoding,
    networks: Vec<Network>,
}

impl VmessOutbound {
    /// sing-box `vmess.NewOutbound`.
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Self, String> {
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/vmess[{tag}]"),
        )?;
        let tls = match options.tls.as_ref().filter(|tls| tls.enabled) {
            Some(tls) => Some(rb_tls::TlsClient::new(tls, &options.server, certificates)?),
            None => None,
        };
        if options.transport.is_some() {
            return Err("`transport` is not supported by rust-box yet".into());
        }
        if options.multiplex.as_ref().is_some_and(|multiplex| multiplex.enabled) {
            return Err("`multiplex` is not supported by rust-box yet".into());
        }
        let packet_encoding = match options.packet_encoding.as_str() {
            "" => VmessPacketEncoding::None,
            "packetaddr" => VmessPacketEncoding::PacketAddr,
            "xudp" => VmessPacketEncoding::Xudp,
            other => return Err(format!("unknown packet encoding: {other}")),
        };
        let mut security = if options.security.is_empty() { "auto" } else { options.security.as_str() };
        if security == "auto" && tls.is_some() {
            security = "zero";
        }
        let security = protocol::client_security(security)?;
        let client = ClientConfig::new(
            &parse_uuid(&options.uuid),
            security,
            options.alter_id,
            options.global_padding,
            options.authenticated_length,
        );
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(VmessOutbound { tag, dialer, tls, server, client, packet_encoding, networks })
    }

    async fn dial_server(&self) -> io::Result<BoxStream> {
        let stream = self.dialer.dial_tcp(&self.server).await?;
        match &self.tls {
            Some(tls) => Ok(Box::new(tls.handshake(stream).await?)),
            None => Ok(stream),
        }
    }

    /// A VMess TCP connection to `destination` with its request sent
    /// (sing-vmess `DialEarlyConn`; rust-box sends the request at once). A
    /// multiplex client dials its sessions with this.
    pub async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let conn = self.dial_server().await?;
        let (writer, reader) = self.client.handshake(COMMAND_TCP, destination)?;
        let mut stream = VmessStream::new(conn, writer, reader);
        stream.write_header().await?;
        Ok(Box::new(stream))
    }

    /// The UDP of `destination` (sing-box `vmessDialer.ListenPacket`).
    pub async fn connect_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let conn = self.dial_server().await?;
        match self.packet_encoding {
            VmessPacketEncoding::PacketAddr => {
                if destination.domain().is_some() {
                    return Err(io::Error::other("packetaddr: domain destination is not supported"));
                }
                let magic = Socksaddr::from_host_port(PACKET_ADDR_MAGIC, 0);
                let (writer, reader) = self.client.handshake(COMMAND_UDP, &magic)?;
                let inner: SharedPacketConn = Arc::new(VmessPacketConn::new(conn, writer, reader, magic.clone()));
                Ok(Arc::new(PacketAddrConn::new(inner, magic)))
            }
            VmessPacketEncoding::Xudp => {
                // sing-vmess `DialEarlyXUDPPacketConn`: Mux.Cool frames of
                // session 0 in a mux request, sent with the first frame.
                let (writer, reader) = self.client.handshake(COMMAND_MUX, destination)?;
                let stream: BoxStream = Box::new(VmessStream::new(conn, writer, reader));
                Ok(Arc::new(XudpPacketConn::new(stream, destination.clone())))
            }
            VmessPacketEncoding::None => {
                let (writer, reader) = self.client.handshake(COMMAND_UDP, destination)?;
                Ok(Arc::new(VmessPacketConn::new(conn, writer, reader, destination.clone())))
            }
        }
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        self.connect(&context.destination).await
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        self.connect_packet(&context.destination).await
    }
}
