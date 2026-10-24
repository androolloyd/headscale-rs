// Copyright 2009 The Go Authors. All rights reserved.
// Adapted from Go 1.26.9 net/url and net/http URL helpers; see LICENSE-GO.

//! Native redirect URL state. Decoded components retain bytes, because Go
//! strings can contain percent-decoded invalid UTF8. Only the final HTTP URI
//! conversion is constrained by the selected Rust HTTP transport.

use std::net::Ipv6Addr;

use crate::Error;

use super::super::{native_error, quote};

mod idna;

/// net/http and httpproxy call IDNA on the entire hostname/domain token,
/// without parsing it as a new URL or normalizing the ASCII fast path.
pub(super) fn idna_ascii_bytes(hostname: &[u8]) -> Vec<u8> {
    if hostname.is_ascii() {
        return hostname.to_vec();
    }
    std::str::from_utf8(hostname)
        .ok()
        .and_then(idna::lookup)
        .map(String::into_bytes)
        .unwrap_or_else(|| hostname.to_vec())
}

fn cut(bytes: &[u8], delimiter: u8) -> (&[u8], &[u8]) {
    bytes
        .iter()
        .position(|byte| *byte == delimiter)
        .map_or((bytes, &[]), |at| (&bytes[..at], &bytes[at + 1..]))
}

fn replace_first(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    match bytes.windows(from.len()).position(|part| part == from) {
        Some(at) => [&bytes[..at], to, &bytes[at + from.len()..]].concat(),
        None => bytes.to_vec(),
    }
}

#[derive(Clone, Default)]
pub(super) struct Url {
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
    pub(super) fn parse(raw: &str) -> Result<Self, Error> {
        Self::parse_bytes(raw.as_bytes())
    }

    pub(super) fn parse_bytes(raw: &[u8]) -> Result<Self, Error> {
        let (source, fragment) = cut(raw, b'#');
        let mut url = Self::parse_inner(source).map_err(|error| {
            native_error(format!("parse {}: {error}", quote::quote_bytes(source)))
        })?;
        if !fragment.is_empty() {
            url.fragment = unescape(fragment, Mode::Fragment).map_err(|error| {
                native_error(format!("parse {}: {error}", quote::quote_bytes(raw)))
            })?;
            if escape(&url.fragment, Mode::Fragment).as_bytes() != fragment {
                // Invalid UTF-8 cannot be a valid encoded fragment: Go's
                // EscapedFragment ignores that raw hint and escapes bytes.
                url.raw_fragment = std::str::from_utf8(fragment).unwrap_or_default().to_owned();
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
        if rest.ends_with(b"?") && rest.iter().filter(|byte| **byte == b'?').count() == 1 {
            url.force_query = true;
            rest = &rest[..rest.len() - 1];
        } else {
            let (path, query) = cut(rest, b'?');
            rest = path;
            url.raw_query = query.to_vec();
        }
        if !rest.starts_with(b"/") {
            if !url.scheme.is_empty() {
                url.opaque = rest.to_owned();
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

    pub(super) fn resolve(&self, location: &str) -> Result<Self, Error> {
        self.resolve_bytes(location.as_bytes())
    }

    pub(super) fn resolve_bytes(&self, location: &[u8]) -> Result<Self, Error> {
        let reference = Self::parse_bytes(location)?;
        let mut url = reference.clone();
        if reference.scheme.is_empty() {
            url.scheme.clone_from(&self.scheme);
        }
        if !reference.scheme.is_empty() || !reference.host.is_empty() || reference.user.is_some() {
            url.set_path(&resolve_path(&reference.escaped_path(), ""))
                .map_err(native_error)?;
            return Ok(url);
        }
        if !reference.opaque.is_empty() {
            url.user = None;
            url.host.clear();
            url.path.clear();
            return Ok(url);
        }
        if reference.path.is_empty() && !reference.force_query && reference.raw_query.is_empty() {
            url.raw_query.clone_from(&self.raw_query);
            if reference.fragment.is_empty() {
                url.fragment.clone_from(&self.fragment);
                url.raw_fragment.clone_from(&self.raw_fragment);
            }
        }
        if reference.path.is_empty() && !self.opaque.is_empty() {
            url.opaque.clone_from(&self.opaque);
            url.user = None;
            url.host.clear();
            url.path.clear();
            return Ok(url);
        }
        url.host.clone_from(&self.host);
        url.user.clone_from(&self.user);
        url.set_path(&resolve_path(
            &self.escaped_path(),
            &reference.escaped_path(),
        ))
        .map_err(native_error)?;
        Ok(url)
    }

    pub(super) fn is_absolute(&self) -> bool {
        !self.scheme.is_empty()
    }

    pub(super) fn scheme(&self) -> &str {
        &self.scheme
    }

    pub(super) fn host(&self) -> &[u8] {
        &self.host
    }

    /// HTTP/2 uses authorityAddr and the zero-option IDNA Punycode profile,
    /// separately from net/http's Lookup-profile canonicalAddr dial key.
    pub(super) fn h2_authority_addr(&self) -> Vec<u8> {
        let (host, port) = strict_split_host_port(&self.host).unwrap_or((&self.host, b""));
        let port = if port.is_empty() {
            if self.scheme == "http" {
                b"80".as_slice()
            } else {
                b"443".as_slice()
            }
        } else {
            port
        };
        let host = idna::minimal_ascii(host).unwrap_or_else(|| host.to_vec());
        if host.starts_with(b"[") && host.ends_with(b"]") || !host.contains(&b':') {
            [host.as_slice(), b":", port].concat()
        } else {
            [b"[".as_slice(), &host, b"]:", port].concat()
        }
    }

    fn hostname_bytes(&self) -> &[u8] {
        let (mut hostname, _) = split_host_port(&self.host);
        if hostname.starts_with(b"[") && hostname.ends_with(b"]") {
            hostname = &hostname[1..hostname.len() - 1];
        }
        hostname
    }

    pub(super) fn ascii_hostname_bytes(&self) -> Vec<u8> {
        idna_ascii_bytes(self.hostname_bytes())
    }

    pub(super) fn credentials(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.user.as_ref().map(|user| {
            (
                user.username.clone(),
                user.password.clone().unwrap_or_default(),
            )
        })
    }

    /// NewRequest alone removes an empty port. Redirects use URL.Parse
    /// directly and must not silently apply this cleanup a second time.
    pub(super) fn remove_empty_port(&mut self) {
        if self.host.ends_with(b":") {
            self.host.pop();
        }
    }

    pub(super) fn as_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        if !self.scheme.is_empty() {
            output.extend_from_slice(self.scheme.as_bytes());
            output.push(b':');
        }
        if !self.opaque.is_empty() {
            output.extend_from_slice(&self.opaque);
        } else {
            if !self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some() {
                if !(self.omit_host && self.host.is_empty() && self.user.is_none()) {
                    if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                        output.extend_from_slice(b"//");
                    }
                    if let Some(user) = &self.user {
                        output.extend_from_slice(user.encoded().as_bytes());
                        output.push(b'@');
                    }
                    output.extend_from_slice(escape(&self.host, Mode::Host).as_bytes());
                }
            }
            let path = self.escaped_path();
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                output.push(b'/');
            }
            if output.is_empty() && path.split('/').next().unwrap_or_default().contains(':') {
                output.extend_from_slice(b"./");
            }
            output.extend_from_slice(path.as_bytes());
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

    /// net/http's Referer removes only authentication, retaining the fragment.
    pub(super) fn referer(&self) -> Vec<u8> {
        let text = self.as_bytes();
        match &self.user {
            Some(user) => replace_first(&text, (user.encoded() + "@").as_bytes(), b""),
            None => text,
        }
    }

    /// net/http's stripPassword representation for request error context.
    pub(super) fn redacted(&self) -> Vec<u8> {
        let text = self.as_bytes();
        match &self.user {
            Some(user) if user.password.is_some() => replace_first(
                &text,
                (user.encoded() + "@").as_bytes(),
                &[user.username.as_slice(), b":***@"].concat(),
            ),
            _ => text,
        }
    }

    pub(super) fn wire_uri(&self) -> Result<http::Uri, Error> {
        if self.scheme != "http" && self.scheme != "https" {
            return Err(native_error(format!(
                "unsupported protocol scheme {}",
                quote::quote(&self.scheme),
            )));
        }
        if self.host.is_empty() {
            return Err(native_error("http: no Host in request URL"));
        }
        let ascii_hostname = self.ascii_hostname_bytes();
        // A Go URL may retain invalid UTF8 host bytes. The selected Rust URI
        // and TLS/DNS APIs cannot carry that identity; never replace it with a
        // different lossy hostname for an outgoing request.
        let hostname = std::str::from_utf8(&ascii_hostname).map_err(|_| {
            native_error("native HTTP transport cannot represent non-UTF8 URL host")
        })?;
        let (_, port) = split_host_port(&self.host);
        let bracketed = self.host.starts_with(b"[");
        let mut authority = if bracketed {
            format!("[{hostname}]")
        } else {
            hostname.to_owned()
        };
        if let Some(port) = port {
            authority.push(':');
            authority
                .push_str(std::str::from_utf8(port).map_err(|_| native_error("invalid URL port"))?);
        }
        // Keep the URL host's zone escaping while excluding credentials and
        // fragments. URI/backend restrictions are errors, not URL rewrites.
        let authority = escape(authority.as_bytes(), Mode::Host);
        let mut path = self.escaped_path();
        if path.is_empty() {
            path.push('/');
        }
        if self.force_query || !self.raw_query.is_empty() {
            path.push('?');
            // URI validation remains the backend's responsibility, including
            // raw query bytes Go URL deliberately does not percent-normalize.
        }
        let mut target = format!("{}://{authority}{path}", self.scheme).into_bytes();
        if self.force_query || !self.raw_query.is_empty() {
            target.extend_from_slice(&self.raw_query);
        }
        http::Uri::from_maybe_shared(bytes::Bytes::from(target))
            .map_err(|error| native_error(format!("native HTTP URI conversion: {error}")))
    }

    fn set_path(&mut self, path: &str) -> Result<(), String> {
        self.set_path_bytes(path.as_bytes())
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
                super::super::godebug::lookup(b"urlstrictcolons"),
                super::super::godebug::Resolution::Plain(value) if value == b"0"
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

// net.SplitHostPort's structural acceptance for an already URL-validated Host.
// In particular, bare IPv6 and stray brackets take authorityAddr's fallback
// of treating the entire authority as a host, rather than splitting the last
// colon as the URL's permissive non-HTTP/GODEBUG path can do.
fn strict_split_host_port(host: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = host.iter().rposition(|byte| *byte == b':')?;
    if host.starts_with(b"[") {
        let close = host.iter().position(|byte| *byte == b']')?;
        if close + 1 != colon {
            return None;
        }
        let hostname = &host[1..close];
        let port = &host[colon + 1..];
        if hostname
            .iter()
            .chain(port)
            .any(|byte| matches!(*byte, b'[' | b']'))
        {
            return None;
        }
        Some((hostname, port))
    } else if host[..colon].contains(&b':') || host.iter().any(|byte| matches!(*byte, b'[' | b']'))
    {
        None
    } else {
        Some((&host[..colon], &host[colon + 1..]))
    }
}

fn split_host_port(host: &[u8]) -> (&[u8], Option<&[u8]>) {
    match host.iter().rposition(|byte| *byte == b':') {
        Some(at) if valid_port(&host[at..]) => (&host[..at], Some(&host[at + 1..])),
        _ => (host, None),
    }
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
                    quote::quote_bytes(&bytes[at..at + 1])
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

fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_owned()
    } else if !reference.starts_with('/') {
        format!(
            "{}{reference}",
            &base[..base.rfind('/').map_or(0, |at| at + 1)]
        )
    } else {
        reference.to_owned()
    };
    if full.is_empty() {
        return full;
    }
    let mut output = vec![b'/'];
    let mut first = true;
    let mut last = "";
    for element in full.split('/') {
        last = element;
        match element {
            "." => {
                first = false;
            }
            ".." => {
                let length = output[1..]
                    .iter()
                    .rposition(|byte| *byte == b'/')
                    .map_or(1, |at| at + 1);
                output.truncate(length);
                first = output.len() == 1;
            }
            _ => {
                if !first {
                    output.push(b'/');
                }
                output.extend_from_slice(element.as_bytes());
                first = false;
            }
        }
    }
    if last == "." || last == ".." {
        output.push(b'/');
    }
    if output.len() > 1 && output[1] == b'/' {
        output.remove(0);
    }
    // All copies originate from valid UTF8 strings and only ASCII separators
    // are removed. Escaped paths normally contain ASCII alone.
    String::from_utf8(output).expect("resolved URL path preserves UTF8")
}
