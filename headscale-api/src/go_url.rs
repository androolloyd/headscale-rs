// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//! Selected Go 1.26.9 net/url Parse and String for native API boundaries.
//! Adapted from the workspace's byte-preserving URL implementation; no HTTP
//! transport, WHATWG normalization or IDNA policy is applied by this parser.
use headscale_api_acl::go_strconv as quote;
use std::net::Ipv6Addr;
mod godebug;

/// Selected net/url query-count admission, shared by native URL.Query users.
/// Stack-conditioned settings retain the Go default because Rust call-stack
/// PCs cannot stand in for Go bisect identities; reporting counters are not
/// reproduced by this private environment adapter.
pub(crate) fn query_params_within_max(count: usize) -> bool {
    let default = count <= 10_000;
    let godebug::Resolution::Plain(value) = godebug::lookup(b"urlmaxqueryparams") else {
        return default;
    };
    let Ok(value) = std::str::from_utf8(&value) else {
        return default;
    };
    let Ok(limit) = value.parse::<isize>() else {
        return default;
    };
    limit == 0 || (limit > 0 && count < limit as usize)
}

fn cut(bytes: &[u8], delimiter: u8) -> (&[u8], &[u8]) {
    bytes
        .iter()
        .position(|byte| *byte == delimiter)
        .map_or((bytes, &[]), |at| (&bytes[..at], &bytes[at + 1..]))
}

#[derive(Clone, Default)]
pub(crate) struct Url {
    scheme: String,
    opaque: Vec<u8>,
    user: Option<User>,
    host: Vec<u8>,
    path: Vec<u8>,
    raw_path: String,
    force_query: bool,
    raw_query: Vec<u8>,
    fragment: Vec<u8>,
    raw_fragment: String,
    omit_host: bool,
}

#[derive(Clone)]
struct User {
    username: Vec<u8>,
    password: Option<Vec<u8>>,
}

impl User {
    fn encoded(&self) -> String {
        let mut value = escape(&self.username, Mode::User);
        if let Some(password) = &self.password {
            value.push(':');
            value.push_str(&escape(password, Mode::User));
        }
        value
    }
}

impl Url {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        Self::parse_bytes(raw.as_bytes())
    }

    pub(crate) fn parse_bytes(raw: &[u8]) -> Result<Self, String> {
        let (source, fragment) = cut(raw, b'#');
        let mut url = Self::parse_inner(source)
            .map_err(|error| format!("parse {}: {error}", quote::quote_bytes(source)))?;
        if !fragment.is_empty() {
            url.fragment = unescape(fragment, Mode::Fragment)
                .map_err(|error| format!("parse {}: {error}", quote::quote_bytes(raw)))?;
            if escape(&url.fragment, Mode::Fragment).as_bytes() != fragment {
                // Invalid UTF-8 cannot be a valid encoded fragment: Go's
                // EscapedFragment ignores that raw hint and escapes bytes.
                std::str::from_utf8(fragment)
                    .unwrap_or_default()
                    .clone_into(&mut url.raw_fragment);
            }
        }
        Ok(url)
    }

    fn parse_inner(raw: &[u8]) -> Result<Self, String> {
        if raw.iter().any(|byte| *byte < b' ' || *byte == 0x7f) {
            return Err("net/url: invalid control character in URL".into());
        }
        let mut url = Self::default();
        if raw == b"*" {
            url.path = b"*".to_vec();
            return Ok(url);
        }
        let (scheme, mut rest) = scheme(raw)?;
        url.scheme = scheme.to_ascii_lowercase();
        // Exactly one `?` (two split pieces), and it is the last byte.
        if rest.ends_with(b"?") && rest.split(|byte| *byte == b'?').count() == 2 {
            url.force_query = true;
            rest = &rest[..rest.len() - 1];
        } else {
            let (path, query) = cut(rest, b'?');
            rest = path;
            url.raw_query = query.to_vec();
        }
        if !rest.starts_with(b"/") {
            if !url.scheme.is_empty() {
                rest.clone_into(&mut url.opaque);
                return Ok(url);
            }
            if rest
                .split(|byte| *byte == b'/')
                .next()
                .unwrap_or_default()
                .contains(&b':')
            {
                return Err("first path segment in URL cannot contain colon".into());
            }
        }
        if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
            let end = rest[2..]
                .iter()
                .position(|byte| *byte == b'/')
                .map_or(rest.len(), |at| at + 2);
            let authority = &rest[2..end];
            rest = &rest[end..];
            let (user, host) = authority_parts(&url.scheme, authority)?;
            url.user = user;
            url.host = host;
        } else if !url.scheme.is_empty() && rest.starts_with(b"/") {
            url.omit_host = true;
        }
        url.set_path_bytes(rest)?;
        Ok(url)
    }

    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        if !self.scheme.is_empty() {
            output.extend_from_slice(self.scheme.as_bytes());
            output.push(b':');
        }
        if self.opaque.is_empty() {
            let has_authority_source =
                !self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some();
            let host_omitted = self.omit_host && self.host.is_empty() && self.user.is_none();
            if has_authority_source && !host_omitted {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    output.extend_from_slice(b"//");
                }
                if let Some(user) = &self.user {
                    output.extend_from_slice(user.encoded().as_bytes());
                    output.push(b'@');
                }
                output.extend_from_slice(escape(&self.host, Mode::Host).as_bytes());
            }
            let path = self.escaped_path();
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                output.push(b'/');
            }
            if output.is_empty() && path.split('/').next().unwrap_or_default().contains(':') {
                output.extend_from_slice(b"./");
            }
            output.extend_from_slice(path.as_bytes());
        } else {
            output.extend_from_slice(&self.opaque);
        }
        if self.force_query || !self.raw_query.is_empty() {
            output.push(b'?');
            output.extend_from_slice(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            output.push(b'#');
            output.extend_from_slice(
                escaped(&self.fragment, &self.raw_fragment, Mode::Fragment).as_bytes(),
            );
        }
        output
    }

    fn set_path_bytes(&mut self, path: &[u8]) -> Result<(), String> {
        self.path = unescape(path, Mode::Path)?;
        self.raw_path = if escape(&self.path, Mode::Path).as_bytes() == path {
            String::new()
        } else {
            std::str::from_utf8(path).unwrap_or_default().to_owned()
        };
        Ok(())
    }

    fn escaped_path(&self) -> String {
        if self.path == b"*" && self.raw_path.is_empty() {
            "*".into()
        } else {
            escaped(&self.path, &self.raw_path, Mode::Path)
        }
    }
    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }
    pub(crate) fn path(&self) -> &[u8] {
        &self.path
    }
    pub(crate) fn raw_query(&self) -> &[u8] {
        &self.raw_query
    }
    pub(crate) fn set_raw_query(&mut self, query: Vec<u8>) {
        self.raw_query = query;
    }
    pub(crate) fn set_decoded_path(&mut self, path: Vec<u8>) {
        self.path = path;
    }
}
fn scheme(raw: &[u8]) -> Result<(&str, &[u8]), String> {
    for (at, byte) in raw.iter().copied().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if at != 0 => {}
            b':' if at == 0 => return Err("missing protocol scheme".into()),
            b':' => {
                return Ok((
                    std::str::from_utf8(&raw[..at]).expect("scheme is ASCII"),
                    &raw[at + 1..],
                ));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn authority_parts(scheme: &str, authority: &[u8]) -> Result<(Option<User>, Vec<u8>), String> {
    let (userinfo, host) = match authority.iter().rposition(|byte| *byte == b'@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let host = parse_host(scheme, host)?;
    let Some(userinfo) = userinfo else {
        return Ok((None, host));
    };
    if !userinfo
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(byte))
    {
        return Err("net/url: invalid userinfo".into());
    }
    let (username, password) = match userinfo.iter().position(|byte| *byte == b':') {
        Some(at) => (
            unescape(&userinfo[..at], Mode::User)?,
            Some(unescape(&userinfo[at + 1..], Mode::User)?),
        ),
        None => (unescape(userinfo, Mode::User)?, None),
    };
    Ok((Some(User { username, password }), host))
}

fn parse_host(scheme: &str, host: &[u8]) -> Result<Vec<u8>, String> {
    match host.iter().rposition(|byte| *byte == b'[') {
        Some(0) => {
            let close = host
                .iter()
                .rposition(|byte| *byte == b']')
                .ok_or_else(|| "missing ']' in host".to_owned())?;
            let port = &host[close + 1..];
            if !valid_port(port) {
                return Err(format!(
                    "invalid port {} after host",
                    quote::quote_bytes(port)
                ));
            }
            let port = unescape(port, Mode::Host)?;
            let hostname = &host[1..close];
            let zone = hostname.windows(3).position(|part| part == b"%25");
            let hostname = match zone {
                Some(at) => [
                    unescape(&hostname[..at], Mode::Host)?,
                    unescape(&hostname[at..], Mode::Zone)?,
                ]
                .concat(),
                None => unescape(hostname, Mode::Host)?,
            };
            let (address, zone) = hostname
                .iter()
                .position(|byte| *byte == b'%')
                .map_or((hostname.as_slice(), None), |at| {
                    (&hostname[..at], Some(&hostname[at + 1..]))
                });
            if zone.is_some_and(<[u8]>::is_empty)
                || std::str::from_utf8(address)
                    .ok()
                    .and_then(|address| address.parse::<Ipv6Addr>().ok())
                    .is_none()
            {
                return Err("invalid host: invalid IPv6 address".into());
            }
            return Ok([b"[".as_slice(), &hostname, b"]", &port].concat());
        }
        Some(_) => return Err("invalid IP-literal".into()),
        None => {}
    }
    if let Some(first) = host.iter().position(|byte| *byte == b':') {
        let last = host.iter().rposition(|byte| *byte == b':').unwrap();
        let strict_scheme = scheme == "http" || scheme == "https";
        let legacy_colons = strict_scheme
            && first != last
            && matches!(
                godebug::lookup(b"urlstrictcolons"),
                godebug::Resolution::Plain(value) if value == b"0"
            );
        // Unsupported stack-conditioned settings explicitly retain Go 1.26's
        // strict default; raw/plain settings and constant matchers are resolved.
        let at = if strict_scheme && !legacy_colons {
            first
        } else {
            last
        };
        if !valid_port(&host[at..]) {
            return Err(format!(
                "invalid port {} after host",
                quote::quote_bytes(&host[at..])
            ));
        }
    }
    unescape(host, Mode::Host)
}

fn valid_port(port: &[u8]) -> bool {
    port.is_empty() || port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit)
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Path,
    Host,
    Zone,
    User,
    Fragment,
}

fn should_escape(byte: u8, mode: Mode) -> bool {
    if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone) && b"!$&'()*+,;=:[]<>\"".contains(&byte) {
        return false;
    }
    if b"$&+,/:;=?@".contains(&byte) {
        return match mode {
            Mode::Path => byte == b'?',
            Mode::User => b"@/?:".contains(&byte),
            Mode::Fragment => false,
            _ => true,
        };
    }
    !(mode == Mode::Fragment && b"!()*".contains(&byte))
}

fn escape(bytes: &[u8], mode: Mode) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        if should_escape(*byte, mode) {
            output.push('%');
            output.push(HEX[usize::from(byte >> 4)] as char);
            output.push(HEX[usize::from(byte & 15)] as char);
        } else {
            output.push(*byte as char);
        }
    }
    output
}

fn unescape(bytes: &[u8], mode: Mode) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b'%' {
            let value = bytes
                .get(at + 1..at + 3)
                .and_then(|digits| Some(hex(digits[0])? << 4 | hex(digits[1])?));
            let Some(value) = value else {
                return Err(format!(
                    "invalid URL escape {}",
                    quote::quote_bytes(&bytes[at..bytes.len().min(at + 3)])
                ));
            };
            if mode == Mode::Host && value < 128 && value != b'%'
                || mode == Mode::Zone
                    && value != b'%'
                    && value != b' '
                    && should_escape(value, Mode::Host)
            {
                return Err(format!(
                    "invalid URL escape {}",
                    quote::quote_bytes(&bytes[at..at + 3])
                ));
            }
            output.push(value);
            at += 3;
        } else {
            if matches!(mode, Mode::Host | Mode::Zone) && byte < 128 && should_escape(byte, mode) {
                return Err(format!(
                    "invalid character {} in host name",
                    quote::quote_bytes(&bytes[at..=at])
                ));
            }
            output.push(byte);
            at += 1;
        }
    }
    Ok(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn escaped(bytes: &[u8], raw: &str, mode: Mode) -> String {
    if !raw.is_empty()
        && raw
            .bytes()
            .all(|byte| b"!$&'()*+,;=:@[]%".contains(&byte) || !should_escape(byte, mode))
        && unescape(raw.as_bytes(), mode).is_ok_and(|decoded| decoded == bytes)
    {
        raw.to_owned()
    } else {
        escape(bytes, mode)
    }
}
