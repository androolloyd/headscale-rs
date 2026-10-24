// Copyright 2020 The Go Authors. All rights reserved.
// Text parsing rules adapt Go 1.26.9 net/netip.ParseAddrPort and ParsePrefix.
// BSD terms are retained in headscale-api-acl/LICENSE-GO-STDLIB.

//! Canonical Go netip text at policy, wire and storage boundaries.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn address_error(input: &str, message: &str, at: &str) -> String {
    let mut error = format!("ParseAddr({}): {message}", crate::go_strconv::quote(input));
    if !at.is_empty() {
        error.push_str(" (at ");
        error.push_str(&crate::go_strconv::quote(at));
        error.push(')');
    }
    error
}

fn ipv4_fields(input: &str, text: &str) -> Result<[u8; 4], String> {
    let mut fields = [0; 4];
    let mut value = 0u16;
    let mut position = 0usize;
    let mut digits = 0usize;
    for (index, byte) in text.bytes().enumerate() {
        if byte.is_ascii_digit() {
            if digits == 1 && value == 0 {
                return Err(address_error(
                    input,
                    "IPv4 field has octet with leading zero",
                    "",
                ));
            }
            value = value * 10 + u16::from(byte - b'0');
            digits += 1;
            if value > 255 {
                return Err(address_error(input, "IPv4 field has value >255", ""));
            }
        } else if byte == b'.' {
            if index == 0 || index == text.len() - 1 || text.as_bytes()[index - 1] == b'.' {
                return Err(address_error(
                    input,
                    "IPv4 field must have at least one digit",
                    &text[index..],
                ));
            }
            if position == 3 {
                return Err(address_error(input, "IPv4 address too long", ""));
            }
            fields[position] = value as u8;
            position += 1;
            value = 0;
            digits = 0;
        } else {
            return Err(address_error(input, "unexpected character", &text[index..]));
        }
    }
    if position < 3 {
        return Err(address_error(input, "IPv4 address too short", ""));
    }
    fields[3] = value as u8;
    Ok(fields)
}

fn ipv6_address(input: &str) -> Result<(IpAddr, Option<&str>), String> {
    let (mut text, zone) = match input.split_once('%') {
        Some((_, "")) => return Err(address_error(input, "zone must be a non-empty string", "")),
        Some((ip, zone)) => (ip, Some(zone)),
        None => (input, None),
    };
    let mut octets = [0u8; 16];
    let mut ellipsis = None;
    if let Some(rest) = text.strip_prefix("::") {
        ellipsis = Some(0usize);
        text = rest;
        if text.is_empty() {
            return Ok((IpAddr::V6(Ipv6Addr::UNSPECIFIED), zone));
        }
    }
    let mut position = 0usize;
    while position < 16 {
        let mut offset = 0usize;
        let mut value = 0u32;
        for byte in text.bytes() {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => break,
            };
            value = (value << 4) + digit;
            if offset > 3 {
                return Err(address_error(
                    input,
                    "each group must have 4 or less digits",
                    text,
                ));
            }
            if value > u32::from(u16::MAX) {
                return Err(address_error(input, "IPv6 field has value >=2^16", text));
            }
            offset += 1;
        }
        if offset == 0 {
            return Err(address_error(
                input,
                "each colon-separated field must have at least one digit",
                text,
            ));
        }
        if text.as_bytes().get(offset) == Some(&b'.') {
            if ellipsis.is_none() && position != 12 {
                return Err(address_error(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    text,
                ));
            }
            if position + 4 > 16 {
                return Err(address_error(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    text,
                ));
            }
            octets[position..position + 4].copy_from_slice(&ipv4_fields(input, text)?);
            text = "";
            position += 4;
            break;
        }
        octets[position] = (value >> 8) as u8;
        octets[position + 1] = value as u8;
        position += 2;
        text = &text[offset..];
        if text.is_empty() {
            break;
        }
        if !text.starts_with(':') {
            return Err(address_error(
                input,
                "unexpected character, want colon",
                text,
            ));
        }
        if text.len() == 1 {
            return Err(address_error(
                input,
                "colon must be followed by more characters",
                text,
            ));
        }
        text = &text[1..];
        if text.starts_with(':') {
            if ellipsis.is_some() {
                return Err(address_error(input, "multiple :: in address", text));
            }
            ellipsis = Some(position);
            text = &text[1..];
            if text.is_empty() {
                break;
            }
        }
    }
    if !text.is_empty() {
        return Err(address_error(input, "trailing garbage after address", text));
    }
    if position < 16 {
        let Some(ellipsis) = ellipsis else {
            return Err(address_error(input, "address string too short", ""));
        };
        let count = 16 - position;
        octets.copy_within(ellipsis..position, ellipsis + count);
        octets[ellipsis..ellipsis + count].fill(0);
    } else if ellipsis.is_some() {
        return Err(address_error(
            input,
            "the :: must expand to at least one field of zeros",
            "",
        ));
    }
    Ok((IpAddr::V6(Ipv6Addr::from(octets)), zone))
}

fn parse_address(text: &str) -> Result<(IpAddr, Option<&str>), String> {
    for byte in text.bytes() {
        match byte {
            b'.' => {
                return ipv4_fields(text, text)
                    .map(|bytes| (IpAddr::V4(Ipv4Addr::from(bytes)), None));
            }
            b':' => return ipv6_address(text),
            b'%' => return Err(address_error(text, "missing IPv6 address", "")),
            _ => {}
        }
    }
    Err(address_error(text, "unable to parse IP", ""))
}

fn address(text: &str) -> Option<(IpAddr, Option<&str>)> {
    parse_address(text).ok()
}

/// Go ParseAddr, including its error order and an optional IPv6 zone. Empty
/// text is rejected here; Addr.UnmarshalText's empty zero is handled separately.
pub fn parse_addr(text: &str) -> Result<(IpAddr, Option<&str>), String> {
    parse_address(text)
}

fn address_text(ip: IpAddr, zone: Option<&str>) -> String {
    let mut text = match ip {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ipv4) => format!("::ffff:{ipv4}"),
            None => ip.to_string(),
        },
        IpAddr::V4(ip) => ip.to_string(),
    };
    if let Some(zone) = zone {
        text.push('%');
        text.push_str(zone);
    }
    text
}

/// Addr.UnmarshalText/MarshalText representation. Empty text is the invalid
/// zero Addr, distinct from SQL NULL at a nullable database boundary. IPv6
/// zones and address families follow ParseAddr, regardless of column name.
pub fn addr_text(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some(String::new());
    }
    let (ip, zone) = parse_address(text).ok()?;
    Some(address_text(ip, zone))
}

fn decimal(text: &str) -> Option<u16> {
    if text.is_empty() {
        return None;
    }
    text.bytes().try_fold(0u16, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))
    })
}

/// PrefixFrom(addr, addr.BitLen()).MarshalText: a typed zero Addr yields
/// the zero prefix, and a valid IPv6 address loses its zone.
pub fn addr_host_prefix_text(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some(String::new());
    }
    let (ip, _) = parse_address(text).ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    Some(format!("{}/{bits}", address_text(ip, None)))
}

/// Decode AddrPort's text form. Empty text is its zero value, as accepted by
/// UnmarshalText; a nonempty port is unsigned decimal and may have leading zeros.
pub fn addr_port_text(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some(String::new());
    }
    let (ip, port) = text.rsplit_once(':')?;
    let (ip, bracketed) = match ip.strip_prefix('[') {
        Some(ip) => (ip.strip_suffix(']')?, true),
        None => (ip, false),
    };
    let (ip, zone) = address(ip)?;
    if ip.is_ipv6() != bracketed {
        return None;
    }
    let port = decimal(port)?;
    let ip = address_text(ip, zone);
    Some(if bracketed {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    })
}

/// Decode Prefix's text form without masking the address's host bits. IPv6
/// zones, signs and leading zeros in a multi-digit prefix length are rejected.
/// Empty text is the zero prefix's MarshalText/UnmarshalText representation.
pub fn prefix_text(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some(String::new());
    }
    parse_prefix_text(text).ok()
}

/// ParsePrefix's canonical display text, preserving host bits and family.
pub fn parse_prefix_text(text: &str) -> Result<String, String> {
    let (ip, bits) = parse_prefix(text)?;
    Ok(format!("{}/{bits}", address_text(ip, None)))
}

/// Parse a nonempty request/config prefix using Go netip's grammar and error
/// order. Unlike Prefix.UnmarshalText, ParsePrefix rejects the empty string.
pub fn parse_prefix(text: &str) -> Result<(IpAddr, u8), String> {
    let error = |message: String| {
        format!(
            "netip.ParsePrefix({}): {message}",
            crate::go_strconv::quote(text)
        )
    };
    let (address, bits) = text
        .rsplit_once('/')
        .ok_or_else(|| error("no '/'".into()))?;
    let (ip, zone) = parse_address(address).map_err(error)?;
    if zone.is_some() {
        return Err(error("IPv6 zones cannot be present in a prefix".into()));
    }
    let bad_bits = || {
        error(format!(
            "bad bits after slash: {}",
            crate::go_strconv::quote(bits)
        ))
    };
    if bits.len() > 1 && !matches!(bits.as_bytes()[0], b'1'..=b'9') {
        return Err(bad_bits());
    }
    // Go's pinned 64-bit strconv.Atoi distinguishes overflow from a valid
    // integer whose value exceeds the address family's maximum prefix length.
    let bits = bits.parse::<i64>().map_err(|_| bad_bits())?;
    let maximum = if ip.is_ipv4() { 32 } else { 128 };
    if !(0..=maximum).contains(&bits) {
        return Err(error("prefix length out of range".into()));
    }
    Ok((ip, bits as u8))
}

fn prefix_parts(text: &str) -> Option<(IpAddr, u8)> {
    parse_prefix(text).ok()
}

fn masked<const N: usize>(mut address: [u8; N], bits: u8) -> [u8; N] {
    let mut remaining = usize::from(bits);
    for byte in &mut address {
        if remaining >= 8 {
            remaining -= 8;
        } else {
            *byte &= if remaining == 0 {
                0
            } else {
                u8::MAX << (8 - remaining)
            };
            remaining = 0;
        }
    }
    address
}

fn compare_address<const N: usize>(a: [u8; N], a_bits: u8, b: [u8; N], b_bits: u8) -> Ordering {
    masked(a, a_bits)
        .cmp(&masked(b, b_bits))
        .then(a_bits.cmp(&b_bits))
        .then(a.cmp(&b))
}

/// Go Prefix.Compare ordering: zero values, address family, masked address,
/// prefix length, then original address. Invalid nonempty text returns None.
pub fn prefix_compare(a: &str, b: &str) -> Option<Ordering> {
    let a = if a.is_empty() {
        None
    } else {
        Some(prefix_parts(a)?)
    };
    let b = if b.is_empty() {
        None
    } else {
        Some(prefix_parts(b)?)
    };
    Some(match (a, b) {
        (None, None) => Ordering::Equal,
        (Some((IpAddr::V4(a), a_bits)), Some((IpAddr::V4(b), b_bits))) => {
            compare_address(a.octets(), a_bits, b.octets(), b_bits)
        }
        (Some((IpAddr::V6(a), a_bits)), Some((IpAddr::V6(b), b_bits))) => {
            compare_address(a.octets(), a_bits, b.octets(), b_bits)
        }
        (None, Some(_)) | (Some((IpAddr::V4(_), _)), Some((IpAddr::V6(_), _))) => Ordering::Less,
        (Some(_), None) | (Some((IpAddr::V6(_), _)), Some((IpAddr::V4(_), _))) => Ordering::Greater,
    })
}
