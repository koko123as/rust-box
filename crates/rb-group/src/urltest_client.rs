//! sing-box `common/urltest.URLTest`: the delay of one outbound, as the time
//! from the TCP connection being open to the response headers of a `HEAD`
//! request for the test URL.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rb_adapter::{Host, InboundContext, Network, Outbound, Socksaddr};
use rb_certificate::Store;
use rb_config::OutboundTlsOptions;
use rb_tls::TlsClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The test URL when none is set.
pub const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
/// sing-box `C.TCPTimeout`: the limit of one test.
pub const TCP_TIMEOUT: Duration = Duration::from_secs(15);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Tests `outbound` against `link` (the default URL when empty) and returns
/// the delay in milliseconds, within [`TCP_TIMEOUT`].
pub async fn url_test(link: &str, outbound: &Arc<dyn Outbound>, store: &Arc<Store>) -> io::Result<u16> {
    tokio::time::timeout(TCP_TIMEOUT, test(link, outbound, store))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "context deadline exceeded"))?
}

async fn test(link: &str, outbound: &Arc<dyn Outbound>, store: &Arc<Store>) -> io::Result<u16> {
    let link = if link.is_empty() { DEFAULT_URL } else { link };
    let uri: http::Uri = link.parse().map_err(|error: http::uri::InvalidUri| invalid(error.to_string()))?;
    let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
    let https = match scheme.as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(invalid(format!("unsupported protocol scheme \"{scheme}\""))),
    };
    let authority = uri.authority().ok_or_else(|| invalid("missing host"))?;
    let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_string();
    let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
    let destination = Socksaddr::new(
        match host.parse() {
            Ok(address) => Host::Ip(address),
            Err(_) => Host::Domain(host.clone()),
        },
        port,
    );
    let context = InboundContext::internal(Network::Tcp, destination);
    let start = Instant::now();
    let mut stream = outbound.dial_tcp(&context).await?;
    if https {
        let options = OutboundTlsOptions { enabled: true, ..Default::default() };
        let client = TlsClient::new(&options, &host, store).map_err(invalid)?;
        stream = client.connect(stream).await?;
    }
    let path = uri.path_and_query().map(|path| path.as_str()).filter(|path| !path.is_empty()).unwrap_or("/");
    let request = format!("HEAD {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Go-http-client/1.1\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buffer) {
            Ok(httparse::Status::Complete(_)) => break,
            Ok(httparse::Status::Partial) if buffer.len() < 64 * 1024 => continue,
            Ok(httparse::Status::Partial) => return Err(invalid("response headers too large")),
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string())),
        }
    }
    let _ = stream.shutdown().await;
    Ok(start.elapsed().as_millis().min(u128::from(u16::MAX)) as u16)
}
