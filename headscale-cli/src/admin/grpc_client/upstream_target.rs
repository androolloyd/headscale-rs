//! grpc-go v1.81.1 target extraction, independent of HTTP URL transport rules.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use super::upstream_dns::DnsAuthority;

#[derive(Clone, Debug)]
pub(super) enum RemoteTarget {
    Tcp {
        endpoint: String,
        dns: bool,
        dns_server: Option<DnsAuthority>,
    },
    Unix(PathBuf),
}

impl RemoteTarget {
    pub(super) fn parse(address: &str) -> Result<Self, String> {
        let parsed = parse_url(address);
        let (scheme, authority, mut endpoint, _opaque) = match parsed {
            Ok(parsed)
                if matches!(
                    parsed.0.as_str(),
                    "dns" | "passthrough" | "unix" | "unix-abstract"
                ) =>
            {
                parsed
            }
            // DialContext uses passthrough as its default, including when an
            // unregistered scheme such as http/https appears in the input.
            _ => parse_url(&format!("passthrough:///{address}"))?,
        };
        if scheme == "unix" || scheme == "unix-abstract" {
            if !authority.is_empty() {
                return Err(format!("invalid (non-empty) authority: {authority}"));
            }
            if scheme == "unix-abstract" || endpoint.starts_with(b"@") {
                // Go's Unix network interprets a leading @ as an abstract
                // address on Linux. Tokio accepts a leading NUL instead.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    if scheme == "unix-abstract" {
                        endpoint.insert(0, 0);
                    } else {
                        endpoint[0] = 0;
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                if scheme == "unix-abstract" {
                    endpoint.insert(0, b'@');
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                return Ok(Self::Unix(std::ffi::OsString::from_vec(endpoint).into()));
            }
            #[cfg(not(unix))]
            return Err("Unix gRPC targets are unsupported on this platform".into());
        }
        // resolver.Target.Endpoint strips exactly one leading slash, for
        // either Path or Opaque; it does not clean or normalize the path.
        if endpoint.starts_with(b"/") {
            endpoint.remove(0);
        }
        let endpoint = String::from_utf8(endpoint)
            .map_err(|_| "gRPC TCP target contains invalid UTF-8".to_string())?;
        if endpoint.is_empty() {
            return Err(if scheme == "dns" {
                "dns resolver: missing address".into()
            } else {
                "passthrough: received empty target in Build()".into()
            });
        }
        // grpc-go bypasses the DNS resolver authority for an IP literal.
        let literal = scheme == "dns"
            && tcp_destination(&endpoint, true)
                .is_ok_and(|(host, _)| host.parse::<IpAddr>().is_ok());
        let dns_server = if scheme == "dns" && !literal {
            Some(if authority.is_empty() {
                DnsAuthority::system()
            } else {
                DnsAuthority::new(&authority)?
            })
        } else {
            None
        };
        Ok(Self::Tcp {
            endpoint,
            dns: scheme == "dns",
            dns_server,
        })
    }

    pub(super) fn authority(&self) -> String {
        match self {
            Self::Unix(_) => "localhost".into(),
            Self::Tcp { endpoint, .. } => {
                let endpoint = if endpoint.starts_with(':') {
                    format!("localhost{endpoint}")
                } else {
                    endpoint.clone()
                };
                encode_authority(&endpoint)
            }
        }
    }
}

/// (scheme, host authority, endpoint bytes, opaque). This preserves Go's
/// rootless opaque form and decodes hierarchical paths without URL cleaning.
fn parse_url(value: &str) -> Result<(String, String, Vec<u8>, bool), String> {
    let (without_fragment, fragment) = value.split_once('#').unwrap_or((value, ""));
    if !fragment.is_empty() {
        decode_path(fragment)?;
    }
    if without_fragment
        .bytes()
        .any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err("net/url: invalid control character in URL".into());
    }
    let mut scheme = "";
    let mut rest = without_fragment;
    for (index, byte) in without_fragment.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' if index > 0 => {
                scheme = &without_fragment[..index];
                rest = &without_fragment[index + 1..];
                break;
            }
            b':' => return Err("missing protocol scheme".into()),
            _ => break,
        }
    }
    let scheme = scheme.to_ascii_lowercase();
    rest = rest.split_once('?').map_or(rest, |(path, _)| path);
    if !scheme.is_empty() && !rest.starts_with('/') {
        return Ok((scheme, String::new(), rest.as_bytes().to_vec(), true));
    }
    if scheme.is_empty() && rest.split('/').next().unwrap_or_default().contains(':') {
        return Err("first path segment in URL cannot contain colon".into());
    }
    let mut authority = String::new();
    if rest.starts_with("//") && (!scheme.is_empty() || !rest.starts_with("///")) {
        let host_path = &rest[2..];
        let (host, path) = host_path
            .find('/')
            .map_or((host_path, ""), |index| host_path.split_at(index));
        // Userinfo is independent of URL.Host and does not become part of a
        // DNS resolver authority. An encoded @ in Host remains invalid.
        let host = if let Some((userinfo, host)) = host.rsplit_once('@') {
            decode_path(userinfo)?;
            host
        } else {
            host
        };
        authority = decode_host(host)?;
        rest = path;
    }
    Ok((scheme, authority, decode_path(rest)?, false))
}

fn decode_path(value: &str) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(hex);
            let low = bytes.next().and_then(hex);
            match (high, low) {
                (Some(high), Some(low)) => decoded.push(high * 16 + low),
                _ => return Err("invalid URL escape".into()),
            }
        } else {
            decoded.push(byte);
        }
    }
    Ok(decoded)
}

fn decode_host(value: &str) -> Result<String, String> {
    let close_bracket = value.rfind(']');
    let zone_start = value
        .find("%25")
        .filter(|index| value.starts_with('[') && close_bracket.is_some_and(|end| *index < end));
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = bytes.get(index + 1).copied().and_then(hex);
            let low = bytes.get(index + 2).copied().and_then(hex);
            let (Some(high), Some(low)) = (high, low) else {
                return Err("invalid URL escape in resolver host".into());
            };
            let byte = high * 16 + low;
            let in_zone = zone_start.is_some_and(|start| index >= start)
                && close_bracket.is_some_and(|end| index < end);
            if if in_zone {
                byte != b'%' && byte != b' ' && !host_byte(byte)
            } else {
                byte < 0x80 && byte != b'%'
            } {
                return Err("invalid URL escape in resolver host".into());
            }
            decoded.push(byte);
            index += 3;
        } else {
            if byte < 0x80 && !host_byte(byte) {
                return Err("invalid character in resolver host".into());
            }
            decoded.push(byte);
            index += 1;
        }
    }
    let host = String::from_utf8(decoded).map_err(|_| "invalid resolver host".to_string())?;
    if let Some(literal) = host.strip_prefix('[') {
        let (literal, port) = literal.split_once(']').ok_or("missing ']' in host")?;
        let address = literal
            .split_once('%')
            .map_or(literal, |(address, _)| address);
        if address.parse::<std::net::Ipv6Addr>().is_err() || !optional_url_port(port) {
            return Err("invalid IP literal or resolver port".into());
        }
    } else if let Some((name, port)) = host.split_once(':') {
        if name.contains(['[', ']']) || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid resolver host or port".into());
        }
    } else if host.contains(['[', ']']) {
        return Err("invalid resolver host".into());
    }
    Ok(host)
}

fn host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&byte)
}

fn optional_url_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_authority(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]@".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

pub(super) fn tcp_destination(endpoint: &str, dns: bool) -> io::Result<(String, u16)> {
    destination(endpoint, dns.then_some("443"))
}

pub(super) fn dns_server_destination(endpoint: &str) -> io::Result<(String, u16)> {
    destination(endpoint, Some("53"))
}

fn destination(endpoint: &str, default_port: Option<&str>) -> io::Result<(String, u16)> {
    if let Some(default_port) = default_port
        && let Ok(ip) = endpoint.parse::<IpAddr>()
    {
        return Ok((
            ip.to_string(),
            default_port.parse().map_err(|_| invalid_tcp_target())?,
        ));
    }
    let (host, port) = if let Some(host) = endpoint.strip_prefix('[') {
        let (host, rest) = host.split_once(']').ok_or_else(invalid_tcp_target)?;
        if let Some(port) = rest.strip_prefix(':') {
            (host, port)
        } else if rest.is_empty()
            && let Some(default_port) = default_port
        {
            (host, default_port)
        } else {
            return Err(invalid_tcp_target());
        }
    } else if let Some((host, port)) = endpoint.rsplit_once(':') {
        if host.contains(':') || host.contains(['[', ']']) {
            return Err(invalid_tcp_target());
        }
        (host, port)
    } else if let Some(default_port) = default_port {
        (endpoint, default_port)
    } else {
        return Err(invalid_tcp_target());
    };
    if default_port.is_some() && port.is_empty() {
        return Err(invalid_tcp_target());
    }
    let digits = port.strip_prefix(['+', '-']).unwrap_or(port);
    let port = if port.is_empty() {
        0
    } else if digits.bytes().all(|byte| byte.is_ascii_digit()) {
        let port_number = if digits.is_empty() {
            0
        } else {
            digits.parse::<u16>().map_err(|_| invalid_tcp_target())?
        };
        if port.starts_with('-') && port_number != 0 {
            return Err(invalid_tcp_target());
        }
        port_number
    } else {
        service_port(port).ok_or_else(invalid_tcp_target)?
    };
    Ok((
        if host.is_empty() { "localhost" } else { host }.into(),
        port,
    ))
}

fn invalid_tcp_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid gRPC TCP host/port")
}

fn service_port(service: &str) -> Option<u16> {
    if service.len() > "mobility-header".len() + 10 {
        return None;
    }
    static SERVICES: OnceLock<HashMap<String, u16>> = OnceLock::new();
    SERVICES
        .get_or_init(|| {
            let mut services = HashMap::from([
                ("http".into(), 80),
                ("https".into(), 443),
                ("ssh".into(), 22),
                ("domain".into(), 53),
                ("smtp".into(), 25),
                ("ftp".into(), 21),
                ("ftps".into(), 990),
                ("gopher".into(), 70),
                ("imap2".into(), 143),
                ("imap3".into(), 220),
                ("imaps".into(), 993),
                ("pop3".into(), 110),
                ("pop3s".into(), 995),
                ("submissions".into(), 465),
                ("telnet".into(), 23),
            ]);
            if let Ok(source) = std::fs::read_to_string("/etc/services") {
                for line in source.lines() {
                    let mut fields = line
                        .split('#')
                        .next()
                        .unwrap_or_default()
                        .split_whitespace();
                    let (Some(name), Some(port_protocol)) = (fields.next(), fields.next()) else {
                        continue;
                    };
                    let Some(port) = port_protocol
                        .strip_suffix("/tcp")
                        .and_then(|port| port.parse::<u16>().ok())
                    else {
                        continue;
                    };
                    if port == 0 {
                        continue;
                    }
                    services.insert(name.into(), port);
                    for alias in fields {
                        services.insert(alias.into(), port);
                    }
                }
            }
            services
        })
        .get(&service.to_ascii_lowercase())
        .copied()
}
