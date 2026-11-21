use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record};
use rb_config::HostsDnsServer;

use super::{Answer, QTYPE_A, QTYPE_AAAA};

const DEFAULT_DNS_TTL: u32 = 600;
const FILE_CACHE_MAX_AGE: Duration = Duration::from_secs(5);

pub struct HostsTransport {
    files: Vec<HostsFile>,
    predefined: HashMap<String, Vec<IpAddr>>,
}

struct HostsFile {
    path: PathBuf,
    cache: Mutex<HostsFileCache>,
}

#[derive(Default)]
struct HostsFileCache {
    by_name: HashMap<String, Vec<IpAddr>>,
    expires: Option<Instant>,
    modified: Option<SystemTime>,
    size: u64,
}

impl HostsTransport {
    pub(super) fn new(options: &HostsDnsServer) -> io::Result<Self> {
        let paths = if options.path.is_empty() {
            vec![default_hosts_path()?]
        } else {
            options.path.iter().map(|path| PathBuf::from(expand_environment(path))).collect()
        };
        let predefined = options
            .predefined
            .as_ref()
            .into_iter()
            .flat_map(|entries| entries.iter())
            .map(|(name, addresses)| (canonical_name(name), addresses.iter().copied().collect()))
            .collect();
        Ok(HostsTransport {
            files: paths
                .into_iter()
                .map(|path| HostsFile { path, cache: Mutex::new(HostsFileCache::default()) })
                .collect(),
            predefined,
        })
    }

    fn addresses(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let name = canonical_name(domain);
        if let Some(addresses) = self.predefined.get(&name) {
            return Some(addresses.clone());
        }
        self.files.iter().find_map(|file| {
            let addresses = file.lookup(&name);
            (!addresses.is_empty()).then_some(addresses)
        })
    }

    pub(super) fn query(&self, domain: &str, query_type: u16) -> io::Result<Answer> {
        let addresses = self
            .addresses(domain)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{domain}: no addresses")))?;
        let addresses = addresses
            .into_iter()
            .filter(|address| match address {
                IpAddr::V4(_) => query_type == QTYPE_A,
                IpAddr::V6(_) => query_type == QTYPE_AAAA,
            })
            .collect();
        Ok(Answer { addresses, ttl: DEFAULT_DNS_TTL })
    }

    pub(super) fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let request = Message::from_vec(query).map_err(invalid_message)?;
        let Some(question) = request.queries().first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS message has no question"));
        };
        let query_type = u16::from(question.query_type());
        let addresses = if query_type == QTYPE_A || query_type == QTYPE_AAAA {
            self.addresses(&question.name().to_ascii())
        } else {
            None
        };

        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_response_code(if addresses.is_some() { ResponseCode::NoError } else { ResponseCode::NXDomain })
            .add_queries(vec![question.clone()]);
        if let Some(addresses) = addresses {
            response.set_authoritative(true).set_recursion_desired(true).set_recursion_available(true);
            for address in addresses {
                let data = match (address, query_type) {
                    (IpAddr::V4(address), QTYPE_A) => Some(RData::A(address.into())),
                    (IpAddr::V6(address), QTYPE_AAAA) => Some(RData::AAAA(address.into())),
                    _ => None,
                };
                if let Some(data) = data {
                    response.add_answer(Record::from_rdata(question.name().clone(), DEFAULT_DNS_TTL, data));
                }
            }
        }
        response.to_vec().map_err(invalid_message)
    }
}

impl HostsFile {
    fn lookup(&self, domain: &str) -> Vec<IpAddr> {
        let mut cache = self.cache.lock().unwrap();
        self.update(&mut cache);
        cache.by_name.get(&canonical_name(domain)).cloned().unwrap_or_default()
    }

    fn update(&self, cache: &mut HostsFileCache) {
        let now = Instant::now();
        if now < cache.expires.unwrap_or(now) && !cache.by_name.is_empty() {
            return;
        }
        let Ok(metadata) = fs::metadata(&self.path) else { return };
        let modified = metadata.modified().ok();
        if modified.is_some() && cache.modified == modified && cache.size == metadata.len() {
            cache.expires = Some(now + FILE_CACHE_MAX_AGE);
            return;
        }
        let Ok(contents) = fs::read(&self.path) else { return };
        let mut by_name: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in String::from_utf8_lossy(&contents).lines() {
            let line = line.split_once('#').map_or(line, |(content, _)| content);
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else { continue };
            for name in fields {
                by_name.entry(canonical_name(name)).or_default().push(address);
            }
        }
        cache.by_name = by_name;
        cache.expires = Some(now + FILE_CACHE_MAX_AGE);
        cache.modified = modified;
        cache.size = metadata.len();
    }
}

fn canonical_name(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.').to_ascii_lowercase())
}

fn expand_environment(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        let name = if chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
                name.push(next);
            }
            name
        } else {
            let mut name = String::new();
            while chars.peek().is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_') {
                name.push(chars.next().unwrap());
            }
            name
        };
        if name.is_empty() {
            output.push('$');
        } else if let Some(value) = std::env::var_os(name) {
            output.push_str(&value.to_string_lossy());
        }
    }
    output
}

#[cfg(not(windows))]
fn default_hosts_path() -> io::Result<PathBuf> {
    Ok(PathBuf::from("/etc/hosts"))
}

#[cfg(windows)]
fn default_hosts_path() -> io::Result<PathBuf> {
    let system_root = std::env::var_os("SystemRoot")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resolve default hosts path: SystemRoot is unset"))?;
    Ok(Path::new(&system_root).join("System32").join("Drivers").join("etc").join("hosts"))
}

fn invalid_message(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_platform_default_hosts_path_when_path_is_empty() {
        let options: HostsDnsServer = serde_json::from_str("{}").unwrap();
        let hosts = HostsTransport::new(&options).unwrap();
        assert_eq!(hosts.files.len(), 1);
        assert_eq!(hosts.files[0].path, default_hosts_path().unwrap());
    }

    #[test]
    fn canonicalizes_and_parses_hosts_lines() {
        let path = std::env::temp_dir().join(format!("rust-box-hosts-{}.txt", std::process::id()));
        fs::write(&path, "127.0.0.1 Example.test alias.test # comment\ninvalid skipped.test\n::1 example.test\n")
            .unwrap();
        let file = HostsFile { path: path.clone(), cache: Mutex::new(HostsFileCache::default()) };
        assert_eq!(file.lookup("EXAMPLE.TEST."), vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);
        assert_eq!(file.lookup("alias.test"), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refreshes_hosts_file_after_cache_expiry() {
        let path = std::env::temp_dir().join(format!("rust-box-hosts-refresh-{}.txt", std::process::id()));
        fs::write(&path, "192.0.2.1 refresh.test\n").unwrap();
        let file = HostsFile { path: path.clone(), cache: Mutex::new(HostsFileCache::default()) };
        assert_eq!(file.lookup("refresh.test"), vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        fs::write(&path, "198.51.100.2 refresh.test # updated\n").unwrap();
        file.cache.lock().unwrap().expires = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(file.lookup("refresh.test"), vec!["198.51.100.2".parse::<IpAddr>().unwrap()]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("RUST_BOX_HOSTS_TEST", "/tmp/hosts");
        assert_eq!(expand_environment("${RUST_BOX_HOSTS_TEST}/$MISSING"), "/tmp/hosts/");
        std::env::remove_var("RUST_BOX_HOSTS_TEST");
    }
}
