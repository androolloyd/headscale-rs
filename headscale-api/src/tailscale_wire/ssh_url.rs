// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2025 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Adapted from Go 1.26.9 net/url for SSH delegation. See UPSTREAM.md.

//! Parse the concatenated SSH URL before generating an auth ID, then replace
//! query values without normalizing its host, userinfo, escaped path or fragment.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Fragment,
    Host,
    Zone,
    User,
}

pub(super) struct DelegationUrl {
    scheme: String,
    opaque: String,
    user: Option<String>,
    host: Vec<u8>,
    path: String,
    omit_host: bool,
    query: String,
    fragment: String,
}

impl DelegationUrl {
    pub(super) fn parse(base: &str) -> Result<Self, String> {
        let raw = format!("{base}/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID");
        let (without_fragment, fragment) = raw.split_once('#').unwrap_or((&raw, ""));
        if without_fragment
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err("net/url: invalid control character in URL".into());
        }
        let (scheme, rest) = scheme(without_fragment)?;
        let (mut rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut url = Self {
            scheme: scheme.to_ascii_lowercase(),
            opaque: String::new(),
            user: None,
            host: Vec::new(),
            path: String::new(),
            omit_host: false,
            query: query.into(),
            fragment: String::new(),
        };
        // The replacement query is always nonempty, so ForceQuery's original
        // distinction has no observable effect on the final String.
        if !rest.starts_with('/') && !url.scheme.is_empty() {
            url.opaque = rest.into();
        } else {
            if !rest.starts_with('/') && rest.split('/').next().unwrap_or_default().contains(':') {
                return Err("first path segment in URL cannot contain colon".into());
            }
            if rest.starts_with("//") && (!url.scheme.is_empty() || !rest.starts_with("///")) {
                let authority = &rest[2..];
                let (authority, path) = authority
                    .find('/')
                    .map_or((authority, ""), |index| authority.split_at(index));
                let (userinfo, host) = authority
                    .rsplit_once('@')
                    .map_or((None, authority), |(user, host)| (Some(user), host));
                url.host = parse_host(&url.scheme, host)?;
                if let Some(userinfo) = userinfo {
                    if !userinfo.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&byte)
                    }) {
                        return Err("net/url: invalid userinfo".into());
                    }
                    let (user, password) = userinfo
                        .split_once(':')
                        .map_or((userinfo, None), |(user, password)| (user, Some(password)));
                    let mut user = escape(&unescape(user, Mode::User)?, Mode::User);
                    if let Some(password) = password {
                        user.push(':');
                        user.push_str(&escape(&unescape(password, Mode::User)?, Mode::User));
                    }
                    url.user = Some(user);
                }
                rest = path;
            } else if !url.scheme.is_empty() && rest.starts_with('/') {
                url.omit_host = true;
            }
            url.path = escaped_component(rest, Mode::Path)?;
        }
        if !fragment.is_empty() {
            url.fragment = escaped_component(fragment, Mode::Fragment)?;
        }
        Ok(url)
    }

    pub(super) fn with_auth(self, auth_id: &str, local_user: &[u8]) -> String {
        let mut query = super::query::values(&self.query);
        query.insert(b"auth_id".to_vec(), vec![auth_id.as_bytes().to_vec()]);
        query.insert(b"local_user".to_vec(), vec![local_user.to_vec()]);
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push(':');
        }
        if self.opaque.is_empty() {
            // Equivalent to Go's
            // `(scheme != "" || host != "" || user != nil) &&
            //  !(omitHost && host == "" && user == nil)`.
            let has_authority = !self.host.is_empty() || self.user.is_some();
            if has_authority || (!self.scheme.is_empty() && !self.omit_host) {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    out.push_str("//");
                }
                if let Some(user) = self.user {
                    out.push_str(&user);
                    out.push('@');
                }
                out.push_str(&escape(&self.host, Mode::Host));
            }
            if !self.path.is_empty() && !self.path.starts_with('/') && !self.host.is_empty() {
                out.push('/');
            }
            if out.is_empty()
                && self
                    .path
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .contains(':')
            {
                out.push_str("./");
            }
            out.push_str(&self.path);
        } else {
            out.push_str(&self.opaque);
        }
        out.push('?');
        out.push_str(&super::query::encode_values(&query));
        if !self.fragment.is_empty() {
            out.push('#');
            out.push_str(&self.fragment);
        }
        out
    }
}

fn scheme(value: &str) -> Result<(&str, &str), String> {
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' if index > 0 => return Ok((&value[..index], &value[index + 1..])),
            b':' => return Err("missing protocol scheme".into()),
            _ => break,
        }
    }
    Ok(("", value))
}

fn parse_host(scheme: &str, host: &str) -> Result<Vec<u8>, String> {
    if host.rfind('[').is_some_and(|index| index > 0) {
        return Err("invalid IP-literal".into());
    }
    if host.starts_with('[') {
        let close = host.rfind(']').ok_or("missing ']' in host")?;
        let port = &host[close + 1..];
        if !optional_port(port) {
            return Err("invalid port after host".into());
        }
        let name = &host[1..close];
        let name = if let Some(zone) = name.find("%25") {
            let mut decoded = unescape(&name[..zone], Mode::Host)?;
            decoded.extend(unescape(&name[zone..], Mode::Zone)?);
            decoded
        } else {
            unescape(name, Mode::Host)?
        };
        // ParseAddr checks the literal's family and nonempty zone without
        // changing its original spelling, which URL.Host retains.
        let text = std::str::from_utf8(&name).map_err(|_| "invalid IPv6 host")?;
        let (address, _) = headscale_api_acl::go_netip::parse_addr(text)
            .map_err(|error| format!("invalid host: {error}"))?;
        if address.is_ipv4() {
            return Err("invalid IP-literal".into());
        }
        let mut out = vec![b'['];
        out.extend(name);
        out.push(b']');
        out.extend(unescape(port, Mode::Host)?);
        return Ok(out);
    }
    if let Some(first) = host.find(':') {
        let index = if scheme == "http" || scheme == "https" {
            first
        } else {
            host.rfind(':').unwrap_or(first)
        };
        if !optional_port(&host[index..]) {
            return Err("invalid port after host".into());
        }
    }
    unescape(host, Mode::Host)
}

fn optional_port(value: &str) -> bool {
    value.is_empty()
        || value
            .strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn escaped_component(raw: &str, mode: Mode) -> Result<String, String> {
    let decoded = unescape(raw, mode)?;
    if raw
        .bytes()
        .all(|byte| b"!$&'()*+,;=:@[]%".contains(&byte) || !should_escape(byte, mode))
    {
        Ok(raw.into())
    } else {
        Ok(escape(&decoded, mode))
    }
}

fn unescape(raw: &str, mode: Mode) -> Result<Vec<u8>, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = bytes.get(index + 1).copied().and_then(hex);
            let low = bytes.get(index + 2).copied().and_then(hex);
            let (Some(high), Some(low)) = (high, low) else {
                return Err("invalid URL escape".into());
            };
            let value = high * 16 + low;
            if mode == Mode::Host && value < 0x80 && value != b'%' {
                return Err("invalid URL escape in host".into());
            }
            if mode == Mode::Zone
                && value != b'%'
                && value != b' '
                && should_escape(value, Mode::Host)
            {
                return Err("invalid URL escape in zone".into());
            }
            out.push(value);
            index += 3;
        } else {
            if matches!(mode, Mode::Host | Mode::Zone) && byte < 0x80 && should_escape(byte, mode) {
                return Err("invalid character in host name".into());
            }
            out.push(byte);
            index += 1;
        }
    }
    Ok(out)
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
            Mode::Fragment => false,
            Mode::User => b"@/?:".contains(&byte),
            _ => true,
        };
    }
    if mode == Mode::Fragment && b"!()*".contains(&byte) {
        return false;
    }
    true
}

fn escape(value: &[u8], mode: Mode) -> String {
    let mut out = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value {
        if should_escape(byte, mode) {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 15)] as char);
        } else {
            out.push(byte as char);
        }
    }
    out
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
