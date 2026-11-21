pub mod websocket;

use rb_config::{V2RayTransportConfig, V2RayTransportOptions, V2RayWebSocketOptions};

pub(crate) fn websocket_options(
    transport: Option<&V2RayTransportOptions>,
) -> Result<Option<V2RayWebSocketOptions>, String> {
    let Some(transport) = transport else { return Ok(None) };
    let V2RayTransportConfig::WebSocket(options) = &transport.config else {
        return Err("transport is not supported by rust-box yet".into());
    };
    if options.max_early_data > 0 {
        return Err("transport.max_early_data is not supported by rust-box yet".into());
    }
    if !options.early_data_header_name.is_empty() {
        return Err("transport.early_data_header_name is not supported by rust-box yet".into());
    }
    Ok(Some(options.clone()))
}

pub(crate) fn websocket_tls_client(tls: rb_tls::TlsClient) -> rb_tls::TlsClient {
    if tls.alpn().is_empty() {
        tls.with_alpn(&["http/1.1"])
    } else {
        tls
    }
}
