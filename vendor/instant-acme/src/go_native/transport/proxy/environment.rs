// Copyright 2009, 2017 The Go Authors. All rights reserved.
// Adapted from Go's vendored x/net/http/httpproxy; see LICENSE-GO.

use std::{net::IpAddr, sync::OnceLock};

use super::super::url::Url;
use super::{BoxError, invalid};

static ENVIRONMENT: OnceLock<Environment> = OnceLock::new();

struct Environment {
    http: Option<Url>,
    https: Option<Url>,
    cgi: bool,
    rules: Vec<Rule>,
}

enum Rule {
    All,
    Network(IpAddr, u8),
    Address(IpAddr, String),
    Domain(Vec<u8>, String, bool),
}

fn value(upper: &str, lower: &str) -> Vec<u8> {
    [upper, lower]
        .into_iter()
        .find_map(|name| std::env::var_os(name).filter(|value| !value.is_empty()))
        .map(environment_bytes)
        .unwrap_or_default()
}

#[cfg(unix)]
fn environment_bytes(value: std::ffi::OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt;
    value.into_vec()
}

#[cfg(not(unix))]
fn environment_bytes(value: std::ffi::OsString) -> Vec<u8> {
    // Go's Unix byte environment is the production target. Other platforms
    // retain the standard library's platform-native string projection.
    value.to_string_lossy().into_owned().into_bytes()
}

fn parse_proxy(raw: &[u8]) -> Option<Url> {
    if raw.is_empty() {
        return None;
    }
    let original = Url::parse_bytes(raw);
    if original
        .as_ref()
        .map_or(true, |url| url.scheme().is_empty() || url.host().is_empty())
    {
        let mut prefixed = b"http://".to_vec();
        prefixed.extend_from_slice(raw);
        if let Ok(url) = Url::parse_bytes(&prefixed) {
            return Some(url);
        }
    }
    original.ok()
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub(super) fn split_host_port(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if raw.first() == Some(&b'[') {
        let close = raw.iter().position(|byte| *byte == b']')?;
        (raw.get(close + 1) == Some(&b':')).then(|| (&raw[1..close], &raw[close + 2..]))
    } else {
        let colon = raw.iter().rposition(|byte| *byte == b':')?;
        (!raw[..colon].contains(&b':')).then(|| (&raw[..colon], &raw[colon + 1..]))
    }
}

pub(super) fn hostname_port(url: &Url) -> (Vec<u8>, String) {
    let host = url.ascii_hostname_bytes();
    let port = split_host_port(url.host())
        .and_then(|(_, port)| std::str::from_utf8(port).ok())
        .filter(|port| !port.is_empty())
        .unwrap_or(match url.scheme() {
            "https" => "443",
            "socks5" | "socks5h" => "1080",
            _ => "80",
        });
    (host, port.to_owned())
}

fn parse_ip(host: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(host).ok()?.parse().ok()
}

impl Environment {
    fn load() -> Self {
        let mut result = Self {
            http: parse_proxy(&value("HTTP_PROXY", "http_proxy")),
            https: parse_proxy(&value("HTTPS_PROXY", "https_proxy")),
            cgi: std::env::var_os("REQUEST_METHOD").is_some_and(|value| !value.is_empty()),
            rules: Vec::new(),
        };
        for entry in value("NO_PROXY", "no_proxy").split(|byte| *byte == b',') {
            let entry = lower_trimmed_bytes(entry);
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                result.rules.clear();
                result.rules.push(Rule::All);
                break;
            }
            if let Some((ip, bits)) = entry.split_once('/') {
                // net.ParseCIDR's dtoi accepts ASCII decimal digits only.
                if !bits.is_empty() && bits.bytes().all(|byte| byte.is_ascii_digit()) {
                    if let (Ok(ip), Ok(bits)) = (ip.parse::<IpAddr>(), bits.parse::<u8>()) {
                        if bits <= if ip.is_ipv4() { 32 } else { 128 } {
                            let (network, prefix) = masked_network(ip, bits);
                            result.rules.push(Rule::Network(network, prefix));
                            continue;
                        }
                    }
                }
            }
            let (host, port) = split_host_port(entry.as_bytes())
                .map(|(h, p)| (h, String::from_utf8_lossy(p).into_owned()))
                .unwrap_or((entry.as_bytes(), String::new()));
            if host.is_empty() {
                continue;
            }
            if let Some(ip) = parse_ip(host) {
                result.rules.push(Rule::Address(unmap(ip), port));
                continue;
            }
            let mut host = host.to_vec();
            if host.starts_with(b"*.") {
                host.remove(0);
            }
            let exact = !host.starts_with(b".");
            if exact {
                host.insert(0, b'.');
            }
            // Go applies IDNA to the entire token, without URL parsing its
            // slash, question-mark, fragment or authority delimiters.
            host = super::super::url::idna_ascii_bytes(&host);
            result.rules.push(Rule::Domain(host, port, exact));
        }
        result
    }

    fn select(&self, url: &Url) -> Result<Option<Url>, BoxError> {
        let selected = match url.scheme() {
            "http" => {
                if self.http.is_some() && self.cgi {
                    return Err(invalid(
                        "refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy",
                    ));
                }
                &self.http
            }
            "https" => &self.https,
            _ => return Ok(None),
        };
        if selected.is_none() {
            return Ok(None);
        }
        let (host, port) = hostname_port(url);
        if host == b"localhost" {
            return Ok(None);
        }
        // netip.ParseAddr accepts IPv6 zones; the subsequent net.IP projection
        // drops that zone before loopback and NO_PROXY matching.
        let ip = parse_ip(&host)
            .or_else(|| {
                host.iter()
                    .position(|byte| *byte == b'%')
                    .filter(|zone| *zone + 1 < host.len())
                    .and_then(|zone| parse_ip(&host[..zone]))
                    .filter(IpAddr::is_ipv6)
            })
            .map(unmap);
        if ip.is_some_and(|ip| ip.is_loopback()) {
            return Ok(None);
        }
        let host = lower_trimmed_bytes(&host).into_bytes();
        for rule in &self.rules {
            let matches = match rule {
                Rule::All => true,
                Rule::Address(expected, p) => ip == Some(*expected) && (p.is_empty() || p == &port),
                Rule::Network(network, prefix) => {
                    ip.is_some_and(|ip| network_contains(*network, *prefix, ip))
                }
                Rule::Domain(domain, p, exact) => {
                    ip.is_none()
                        && (p.is_empty() || p == &port)
                        && (host.ends_with(domain) || *exact && host == domain[1..])
                }
            };
            if matches {
                return Ok(None);
            }
        }
        Ok(selected.clone())
    }
}

/// strings.TrimSpace preserves invalid bytes; the following strings.ToLower
/// runs strings.Map and emits one RuneError for each invalid UTF-8 byte. Rust's
/// from_utf8_lossy groups malformed prefixes and cannot implement this phase.
fn lower_trimmed_bytes(raw: &[u8]) -> String {
    let mut start = 0;
    while start < raw.len() {
        let (character, width) = decode_rune(&raw[start..]);
        if !is_space(character) {
            break;
        }
        start += width;
    }
    let mut end = start;
    let mut at = start;
    while at < raw.len() {
        let (character, width) = decode_rune(&raw[at..]);
        at += width;
        if !is_space(character) {
            end = at;
        }
    }
    let mut decoded = String::with_capacity(end - start);
    at = start;
    while at < end {
        let (character, width) = decode_rune(&raw[at..end]);
        decoded.push(character);
        at += width;
    }
    super::unicode::to_lowercase(&decoded)
}

fn decode_rune(raw: &[u8]) -> (char, usize) {
    let first = raw[0];
    if first < 0x80 {
        return (char::from(first), 1);
    }
    let width = match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return ('\u{fffd}', 1),
    };
    if let Some(bytes) = raw.get(..width) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return (text.chars().next().expect("nonempty UTF-8 rune"), width);
        }
    }
    ('\u{fffd}', 1)
}

fn is_space(character: char) -> bool {
    matches!(character as u32,0x0009..=0x000d | 0x0020 | 0x0085 | 0x00a0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

fn masked_network(ip: IpAddr, prefix: u8) -> (IpAddr, u8) {
    match ip {
        IpAddr::V4(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (IpAddr::V4((u32::from(ip) & mask).into()), prefix)
        }
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = std::net::Ipv6Addr::from(u128::from(ip) & mask);
            // Go IPNet first masks the full network, then uses To4 to decide
            // whether its 128-bit mask's final 32 bits describe an IPv4 net.
            // A prefix that erases the mapped marker must remain IPv6.
            match network.to_ipv4_mapped() {
                Some(network) => (IpAddr::V4(network), prefix.saturating_sub(96)),
                None => (IpAddr::V6(network), prefix),
            }
        }
    }
}

fn network_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            prefix == 0 || u32::from(a) >> (32 - prefix) == u32::from(b) >> (32 - prefix)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            prefix == 0 || u128::from(a) >> (128 - prefix) == u128::from(b) >> (128 - prefix)
        }
        _ => false,
    }
}

pub(super) fn select(url: &Url) -> Result<Option<Url>, BoxError> {
    ENVIRONMENT.get_or_init(Environment::load).select(url)
}
