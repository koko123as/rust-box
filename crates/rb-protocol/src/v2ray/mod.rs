pub mod grpc_lite;
pub mod h2;
pub mod httpupgrade;
pub mod websocket;

use std::io;

use rb_adapter::{BoxStream, Socksaddr};
use rb_config::{
    InboundTlsOptions, V2RayGrpcOptions, V2RayHttpUpgradeOptions, V2RayTransportConfig, V2RayTransportOptions,
    V2RayWebSocketOptions,
};

#[derive(Debug, Clone)]
pub(crate) enum StreamTransport {
    WebSocket(V2RayWebSocketOptions),
    HttpUpgrade(V2RayHttpUpgradeOptions),
    Grpc(V2RayGrpcOptions),
}

impl StreamTransport {
    pub(crate) fn is_websocket(&self) -> bool {
        matches!(self, Self::WebSocket(_))
    }

    pub(crate) fn log_name(&self) -> &'static str {
        match self {
            Self::WebSocket(_) => "WebSocket",
            Self::HttpUpgrade(_) => "HTTPUpgrade",
            Self::Grpc(_) => "gRPC",
        }
    }
}

pub(crate) fn transport_options(transport: Option<&V2RayTransportOptions>) -> Result<Option<StreamTransport>, String> {
    let Some(transport) = transport else { return Ok(None) };
    match &transport.config {
        V2RayTransportConfig::WebSocket(options) if options.max_early_data == 0 => {
            if !options.early_data_header_name.is_empty() {
                return Err("transport.early_data_header_name is not supported by rust-box yet".into());
            }
            Ok(Some(StreamTransport::WebSocket(options.clone())))
        }
        V2RayTransportConfig::WebSocket(_) => Err("transport.max_early_data is not supported by rust-box yet".into()),
        V2RayTransportConfig::HttpUpgrade(options) => Ok(Some(StreamTransport::HttpUpgrade(options.clone()))),
        V2RayTransportConfig::Grpc(options) => Ok(Some(StreamTransport::Grpc(options.clone()))),
        _ => Err("transport is not supported by rust-box yet".into()),
    }
}

pub(crate) async fn transport_client(
    stream: BoxStream,
    server: &Socksaddr,
    transport: &StreamTransport,
    tls_server_name: Option<&str>,
) -> io::Result<BoxStream> {
    match transport {
        StreamTransport::WebSocket(options) => websocket::client(stream, server, options).await,
        StreamTransport::HttpUpgrade(options) => httpupgrade::client(stream, server, options, tls_server_name).await,
        StreamTransport::Grpc(options) => grpc_lite::client(stream, server, tls_server_name, options).await,
    }
}

pub(crate) async fn transport_server(stream: BoxStream, transport: &StreamTransport) -> io::Result<BoxStream> {
    match transport {
        StreamTransport::WebSocket(options) => websocket::server(stream, options).await,
        StreamTransport::HttpUpgrade(options) => httpupgrade::server(stream, options).await,
        StreamTransport::Grpc(_) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, "gRPC-lite server is not supported"))
        }
    }
}

pub(crate) fn transport_tls_client(tls: rb_tls::TlsClient, transport: Option<&StreamTransport>) -> rb_tls::TlsClient {
    if tls.alpn().is_empty() {
        if matches!(transport, Some(StreamTransport::Grpc(_))) {
            tls.with_alpn(&["h2"])
        } else {
            tls.with_alpn(&["http/1.1"])
        }
    } else {
        tls
    }
}
pub(crate) fn transport_tls_server(
    tls: &InboundTlsOptions,
    transport: Option<&StreamTransport>,
) -> Result<rb_tls::TlsServer, String> {
    match transport {
        Some(StreamTransport::Grpc(_)) => {
            let mut options = tls.clone();
            if !options.alpn.iter().any(|protocol| protocol == "h2") {
                options.alpn.0.insert(0, "h2".into());
            }
            rb_tls::TlsServer::new(&options)
        }
        Some(_) => rb_tls::TlsServer::new_with_default_alpn(tls, &["http/1.1"]),
        None => rb_tls::TlsServer::new(tls),
    }
}
