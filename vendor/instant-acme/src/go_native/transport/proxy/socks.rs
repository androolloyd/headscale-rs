// Copyright 2018 The Go Authors. All rights reserved.
// Adapted from Go 1.26.9 net/http/socks_bundle.go. See LICENSE-GO.

use std::net::IpAddr;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::url::Url;
use super::{BoxError, Stream, environment, invalid};

pub(super) async fn connect(stream: Stream, origin: &Url, proxy: &Url) -> Result<Stream, BoxError> {
    let (host, port) = environment::hostname_port(origin);
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| invalid(format!("port number out of range {port}")))?;
    let mut io = TokioIo::new(stream);
    let credentials = proxy.credentials();
    io.write_all(if credentials.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    })
    .await?;
    let mut reply = [0; 2];
    io.read_exact(&mut reply).await?;
    if reply[0] != 5 {
        return Err(invalid(format!("unexpected protocol version {}", reply[0])));
    }
    if reply[1] == 255 {
        return Err(invalid("no acceptable authentication methods"));
    }
    if let Some((username, password)) = credentials {
        match reply[1] {
            0 => {}
            2 => {
                if username.is_empty() || username.len() > 255 || password.len() > 255 {
                    return Err(invalid("invalid username/password"));
                }
                let mut auth = vec![1, username.len() as u8];
                auth.extend(username);
                auth.push(password.len() as u8);
                auth.extend(password);
                io.write_all(&auth).await?;
                io.read_exact(&mut reply).await?;
                if reply[0] != 1 {
                    return Err(invalid("invalid username/password version"));
                }
                if reply[1] != 0 {
                    return Err(invalid("username/password authentication failed"));
                }
            }
            method => {
                return Err(invalid(format!(
                    "unsupported authentication method {method}"
                )));
            }
        }
    }
    // With no configured Authenticate callback Go deliberately proceeds for
    // any selected method except 0xff, rather than inventing credentials.
    let mut request = vec![5, 1, 0];
    match std::str::from_utf8(&host)
        .ok()
        .and_then(|host| host.parse::<IpAddr>().ok())
    {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                request.push(1);
                request.extend(ip.octets());
            } else {
                request.push(4);
                request.extend(ip.octets());
            }
        }
        None => {
            if host.len() > 255 {
                return Err(invalid("FQDN too long"));
            }
            request.push(3);
            request.push(host.len() as u8);
            request.extend(host);
        }
    }
    request.extend(port.to_be_bytes());
    io.write_all(&request).await?;
    let mut response = [0; 4];
    io.read_exact(&mut response).await?;
    if response[0] != 5 {
        return Err(invalid(format!(
            "unexpected protocol version {}",
            response[0]
        )));
    }
    if response[1] != 0 {
        let cause = match response[1] {
            1 => "general SOCKS server failure".to_owned(),
            2 => "connection not allowed by ruleset".to_owned(),
            3 => "network unreachable".to_owned(),
            4 => "host unreachable".to_owned(),
            5 => "connection refused".to_owned(),
            6 => "TTL expired".to_owned(),
            7 => "command not supported".to_owned(),
            8 => "address type not supported".to_owned(),
            code => format!("unknown code: {code}"),
        };
        return Err(invalid(format!("unknown error {cause}")));
    }
    if response[2] != 0 {
        return Err(invalid("non-zero reserved field"));
    }
    let address_length = match response[3] {
        1 => 4,
        4 => 16,
        3 => io.read_u8().await? as usize,
        kind => return Err(invalid(format!("unknown address type {kind}"))),
    };
    let mut bound = vec![0; address_length + 2];
    io.read_exact(&mut bound).await?;
    Ok(io.into_inner())
}
