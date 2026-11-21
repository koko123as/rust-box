//! The `vless` outbound (sing-box `protocol/vless/outbound.go` with
//! sing-vmess `vless.Client`).

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rb_adapter::{BoxStream, InboundContext, Network, Outbound, SharedPacketConn, Socksaddr};
use rb_config::{V2RayWebSocketOptions, VlessOutbound as OutboundOptions};
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};

use super::packet::{PacketAddrConn, VlessPacketConn, XudpPacketConn, PACKET_ADDR_MAGIC};
use super::protocol::{self, Request, VlessStream, COMMAND_MUX, COMMAND_TCP, FLOW_VISION};
use super::vision::{RecordGate, RecordStream, VisionStream};

/// How UDP goes (`packet_encoding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    /// A plain UDP request: every packet to the first destination.
    None,
    PacketAddr,
    Xudp,
}

/// sing-vmess's error for Vision without TLS (`NewVisionConn` with a
/// plain TCP connection).
pub(crate) const VISION_WITHOUT_TLS: &str =
    "initialize vision: vision: not a valid supported TLS connection: *net.TCPConn";
pub(crate) const VISION_WITH_WEBSOCKET: &str =
    "initialize vision: vision: not a valid supported TLS connection: *v2raywebsocket.WebsocketConn";

/// The `vless` outbound.
pub struct VlessOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    tls: Option<rb_tls::TlsClient>,
    transport: Option<V2RayWebSocketOptions>,
    server: Socksaddr,
    uuid: [u8; 16],
    vision: bool,
    packet_encoding: PacketEncoding,
    networks: Vec<Network>,
    /// The sing-mux client when `multiplex` is enabled.
    mux: Option<rb_mux::Client>,
}

/// A connection to the server: TLS kept typed for Vision.
enum ServerConn {
    /// With the gate of its record stream (Vision).
    Tls(Box<rb_tls::TlsClientStream>, RecordGate),
    Plain(BoxStream),
}

impl ServerConn {
    fn boxed(self) -> BoxStream {
        match self {
            ServerConn::Tls(stream, _) => stream,
            ServerConn::Plain(stream) => stream,
        }
    }
}

impl VlessOutbound {
    /// sing-box `vless.NewOutbound`.
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Arc<Self>, String> {
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let transport = crate::v2ray::websocket_options(options.transport.as_ref())?;
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/vless[{tag}]"),
        )?;
        let tls = match options.tls.as_ref().filter(|tls| tls.enabled) {
            Some(tls) => Some(rb_tls::TlsClient::new(tls, &options.server, certificates)?),
            None => None,
        };
        let tls = if transport.is_some() { tls.map(crate::v2ray::websocket_tls_client) } else { tls };
        let packet_encoding = match options.packet_encoding.as_deref() {
            None | Some("xudp") => PacketEncoding::Xudp,
            Some("") => PacketEncoding::None,
            Some("packetaddr") => PacketEncoding::PacketAddr,
            Some(other) => return Err(format!("unknown packet encoding: {other}")),
        };
        // sing-vmess `NewClient`.
        let vision = match options.flow.as_str() {
            "" => false,
            FLOW_VISION => true,
            flow => return Err(format!("unsupported flow: {flow}")),
        };
        let multiplex = crate::multiplex::client_options(options.multiplex.as_ref())?;
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(Arc::new_cyclic(|this| VlessOutbound {
            tag,
            dialer,
            tls,
            transport,
            server,
            uuid: protocol::parse_uuid(&options.uuid),
            vision,
            packet_encoding,
            networks,
            mux: crate::multiplex::new_client(this, multiplex),
        }))
    }

    async fn dial_server(&self) -> io::Result<ServerConn> {
        let stream = self.dialer.dial_tcp(&self.server).await?;
        let conn = match &self.tls {
            Some(tls) => {
                // Vision needs the raw bytes past the current TLS record
                // kept out of rustls.
                let (stream, gate) = if self.vision {
                    let stream = RecordStream::new(stream);
                    let gate = stream.gate();
                    (Box::new(stream) as BoxStream, gate)
                } else {
                    (stream, RecordGate::default())
                };
                ServerConn::Tls(Box::new(tls.handshake(stream).await?), gate)
            }
            None => ServerConn::Plain(stream),
        };
        if let Some(options) = &self.transport {
            let stream = crate::v2ray::websocket::client(conn.boxed(), &self.server, options).await?;
            return Ok(ServerConn::Plain(stream));
        }
        Ok(conn)
    }

    fn request(&self, command: u8, destination: &Socksaddr) -> io::Result<Vec<u8>> {
        protocol::encode_request(&Request {
            uuid: self.uuid,
            command,
            destination: Some(destination.clone()),
            flow: if self.vision { FLOW_VISION.into() } else { String::new() },
        })
    }

    /// A VLESS TCP connection to `destination` with its request sent
    /// (sing-vmess `DialEarlyConn`, kicked as sing-box's
    /// `kickWriteHandshake` does: with Vision an empty padded block goes
    /// with the request). A multiplex client dials its sessions with this.
    pub async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let conn = self.dial_server().await?;
        let request = self.request(COMMAND_TCP, destination)?;
        if self.vision {
            let ServerConn::Tls(tls, gate) = conn else {
                return Err(io::Error::other(if self.transport.is_some() {
                    VISION_WITH_WEBSOCKET
                } else {
                    VISION_WITHOUT_TLS
                }));
            };
            let mut stream = VisionStream::new(VlessStream::client(*tls, request), self.uuid, gate);
            stream.kick().await?;
            return Ok(Box::new(stream));
        }
        let mut stream = VlessStream::client(conn.boxed(), request);
        stream.write_header().await?;
        Ok(Box::new(stream))
    }

    /// The UDP of `destination` (sing-box `vlessDialer.ListenPacket`).
    pub async fn connect_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        if self.packet_encoding == PacketEncoding::PacketAddr && destination.domain().is_some() {
            return Err(io::Error::other("packetaddr: domain destination is not supported"));
        }
        let conn = self.dial_server().await?;
        match self.packet_encoding {
            PacketEncoding::Xudp => {
                // sing-vmess `DialEarlyXUDPPacketConn`: the mux request
                // goes out alone (not through Vision), then the frames.
                let request = protocol::encode_request(&Request {
                    uuid: self.uuid,
                    command: COMMAND_MUX,
                    destination: None,
                    flow: if self.vision { FLOW_VISION.into() } else { String::new() },
                })?;
                let stream: BoxStream = if self.vision {
                    let ServerConn::Tls(tls, gate) = conn else {
                        return Err(io::Error::other(if self.transport.is_some() {
                            VISION_WITH_WEBSOCKET
                        } else {
                            VISION_WITHOUT_TLS
                        }));
                    };
                    let mut vless = VlessStream::client(*tls, request);
                    vless.write_header().await?;
                    Box::new(VisionStream::new(vless, self.uuid, gate))
                } else {
                    let mut vless = VlessStream::client(conn.boxed(), request);
                    vless.write_header().await?;
                    Box::new(vless)
                };
                Ok(Arc::new(XudpPacketConn::new(stream, destination.clone())))
            }
            PacketEncoding::PacketAddr => {
                let magic = Socksaddr::from_host_port(PACKET_ADDR_MAGIC, 0);
                let inner: SharedPacketConn =
                    Arc::new(VlessPacketConn::client(conn.boxed(), &self.uuid, magic.clone())?);
                Ok(Arc::new(PacketAddrConn::new(inner, magic)))
            }
            PacketEncoding::None => {
                Ok(Arc::new(VlessPacketConn::client(conn.boxed(), &self.uuid, destination.clone())?))
            }
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        match &self.mux {
            Some(mux) => mux.dial_tcp(&context.destination).await,
            None => self.connect(&context.destination).await,
        }
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        match &self.mux {
            Some(mux) => mux.listen_packet(&context.destination).await,
            None => self.connect_packet(&context.destination).await,
        }
    }
}

#[async_trait]
impl crate::multiplex::MuxConnect for VlessOutbound {
    async fn connect_mux(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        self.connect(destination).await
    }
}
