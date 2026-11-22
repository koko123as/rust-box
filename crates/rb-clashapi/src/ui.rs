//! The external UI: serving its directory under `/ui/` (Go
//! `http.FileServer`) and downloading it as a ZIP archive
//! (`server_resources.go`).

use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rb_adapter::OutboundRegistry;
use rb_dialer::DetourDialer;
use rb_rule_set::http::Client;

use crate::http::{http_date, Response};

/// The archive downloaded when `external_ui_download_url` is empty.
pub const DEFAULT_DOWNLOAD_URL: &str = "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip";
/// sing-box `C.TCPTimeout`, which bounds the TLS handshake; the whole
/// download gets a generous limit instead of none.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// `mime.TypeByExtension` for what a dashboard ships.
fn content_type(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    Some(match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "xml" => "text/xml; charset=utf-8",
        _ => return None,
    })
}

fn not_found() -> Response {
    Response::new(404)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(b"404 page not found\n".to_vec())
}

fn redirect(location: &str) -> Response {
    Response::new(301).header("Location", location)
}

/// Serves `rest` (the request path after `/ui/`, still escaped) from
/// `root` the way `http.FileServer` does.
pub fn serve(root: &Path, rest: &str) -> Response {
    let Some(decoded) = crate::util::unescape(rest, false) else { return not_found() };
    let name = format!("/{decoded}");
    // `index.html` is served as its directory.
    if name.ends_with("/index.html") {
        return redirect("./");
    }
    let mut path = root.to_path_buf();
    for component in Path::new(&name).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::RootDir | Component::CurDir => {}
            _ => return not_found(),
        }
    }
    let Ok(metadata) = std::fs::metadata(&path) else { return not_found() };
    let mut file_path = path.clone();
    if metadata.is_dir() {
        if !name.ends_with('/') {
            let last = name.rsplit('/').next().unwrap_or("");
            return redirect(&format!("{last}/"));
        }
        file_path = path.join("index.html");
        if !file_path.is_file() {
            return directory_listing(&path);
        }
    } else if name.ends_with('/') {
        let last = name.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        return redirect(&format!("../{last}"));
    }
    let Ok(body) = std::fs::read(&file_path) else { return not_found() };
    let mut response = Response::new(200).header("Accept-Ranges", "bytes");
    if let Ok(modified) = std::fs::metadata(&file_path).and_then(|metadata| metadata.modified()) {
        response.set("Last-Modified", http_date(modified));
    }
    if let Some(kind) = content_type(&file_path) {
        response.set("Content-Type", kind);
    }
    response.body(body)
}

fn directory_listing(path: &Path) -> Response {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| {
                    let mut name = entry.file_name().to_string_lossy().into_owned();
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        name.push('/');
                    }
                    name
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut body = String::from("<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n");
    for name in names {
        let escaped = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;");
        body.push_str(&format!("<a href=\"{escaped}\">{escaped}</a>\n"));
    }
    body.push_str("</pre>\n");
    Response::new(200).header("Content-Type", "text/html; charset=utf-8").body(body.into_bytes())
}

/// One file of a ZIP archive.
struct Entry {
    name: String,
    data: Vec<u8>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zip: {message}"))
}

fn u16_at(data: &[u8], offset: usize) -> io::Result<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| invalid("not a valid zip file"))
}

fn u32_at(data: &[u8], offset: usize) -> io::Result<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| invalid("not a valid zip file"))
}

/// Reads the files of a ZIP archive through its central directory
/// (stored and deflated entries, as `archive/zip`).
fn read_zip(data: &[u8]) -> io::Result<Vec<Entry>> {
    let search_start = data.len().saturating_sub(65_557);
    let end = (search_start..data.len().saturating_sub(21))
        .rev()
        .find(|&offset| data[offset..offset + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or_else(|| invalid("not a valid zip file"))?;
    let count = u16_at(data, end + 10)? as usize;
    let mut offset = u32_at(data, end + 16)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(data, offset)? != 0x0201_4b50 {
            return Err(invalid("not a valid zip file"));
        }
        let method = u16_at(data, offset + 10)?;
        let compressed = u32_at(data, offset + 20)? as usize;
        let name_length = u16_at(data, offset + 28)? as usize;
        let extra_length = u16_at(data, offset + 30)? as usize;
        let comment_length = u16_at(data, offset + 32)? as usize;
        let local = u32_at(data, offset + 42)? as usize;
        let name_bytes =
            data.get(offset + 46..offset + 46 + name_length).ok_or_else(|| invalid("not a valid zip file"))?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        offset += 46 + name_length + extra_length + comment_length;
        if name.ends_with('/') {
            continue;
        }
        if u32_at(data, local)? != 0x0403_4b50 {
            return Err(invalid("not a valid zip file"));
        }
        let start = local + 30 + u16_at(data, local + 26)? as usize + u16_at(data, local + 28)? as usize;
        let raw = data.get(start..start + compressed).ok_or_else(|| invalid("not a valid zip file"))?;
        let content = match method {
            0 => raw.to_vec(),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(raw).read_to_end(&mut out)?;
                out
            }
            _ => return Err(invalid("unsupported compression algorithm")),
        };
        entries.push(Entry { name, data: content });
    }
    Ok(entries)
}

/// `zipIsInSingleDirectory`.
fn in_single_directory(entries: &[Entry]) -> bool {
    let mut single: Option<&str> = None;
    for entry in entries {
        let first = entry.name.split('/').next().unwrap_or("");
        match single {
            None => single = Some(first),
            Some(directory) if directory != first => return false,
            Some(_) => {}
        }
    }
    true
}

fn safe_join(base: &Path, parts: &[&str]) -> io::Result<PathBuf> {
    let mut path = base.to_path_buf();
    for part in parts {
        match Path::new(part).components().next() {
            Some(Component::Normal(_)) if !part.contains('\\') => path.push(part),
            _ => return Err(invalid("illegal file path")),
        }
    }
    Ok(path)
}

/// `downloadZIP`: extracts the archive into `output`, dropping its single
/// top directory.
pub fn extract_zip(data: &[u8], output: &Path) -> io::Result<()> {
    let entries = read_zip(data)?;
    let trim = in_single_directory(&entries);
    for entry in &entries {
        let mut parts: Vec<&str> = entry.name.split('/').collect();
        if trim {
            parts.remove(0);
        }
        let parts: Vec<&str> = parts.into_iter().filter(|part| !part.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        let path = safe_join(output, &parts)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &entry.data)?;
    }
    Ok(())
}

/// `removeAllInDirectory`.
pub fn remove_all_in(directory: &Path) {
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let _ = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
        }
    }
}

/// `downloadExternalUI`: downloads the archive through `detour` and
/// extracts it into `directory`; a failed extraction empties it.
pub async fn download(
    directory: &Path,
    url: &str,
    outbounds: &Arc<OutboundRegistry>,
    detour: &str,
    store: &Arc<rb_certificate::Store>,
) -> io::Result<()> {
    let client = Client {
        dialer: Arc::new(DetourDialer::new(outbounds.clone(), detour.to_string())),
        roots: Arc::new(store.pool().roots().clone()),
        timeout: DOWNLOAD_TIMEOUT,
    };
    let url = if url.is_empty() { DEFAULT_DOWNLOAD_URL } else { url };
    let response = client.get(url, None).await?;
    if response.status != 200 {
        return Err(io::Error::other(format!("download external ui failed: {}", response.status_text())));
    }
    std::fs::create_dir_all(directory)?;
    let result = extract_zip(&response.body, directory);
    if result.is_err() {
        remove_all_in(directory);
    }
    result
}
