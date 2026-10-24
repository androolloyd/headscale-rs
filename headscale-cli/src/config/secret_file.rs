// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the crate's LICENSE-GO-STDLIB file.

//! Native secret-file loading follows Headscale v0.29.5 config.go and
//! Go 1.26.9 os/env.go. The existing public String projection still cannot
//! preserve arbitrary non-UTF-8 path, environment, or secret bytes.
//! os/env.go SHA-256:
//! e7eb15de93fccf8c0706285c350f32eab6c4a1f752bb8594ce7da3a0215ee92b

use std::{env, fs, io};

use anyhow::Result;
use headscale_core::config::{ConfigError, OidcConfig};

pub(super) fn resolve(oidc: &mut OidcConfig) -> Result<()> {
    // Viper's empty configured path is not an active secret source. An
    // initially nonempty path that expands to empty still attempts ReadFile.
    if oidc
        .client_secret_path
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        oidc.client_secret_path = None;
    }
    if oidc.client_secret_path.is_some() && !oidc.client_secret.is_empty() {
        return Err(ConfigError::OidcClientSecretConflict.into());
    }
    if let Some(path) = oidc.client_secret_path.take() {
        // Retain the existing lossy boundary for non-UTF-8 paths and file
        // contents; expanding valid UTF-8 uses Go's grammar below.
        let path = expand_env(&path.to_string_lossy());
        let bytes = fs::read(&path).map_err(|error| read_error(&path, &error))?;
        headscale_api_acl::go_unicode::trim_space(&String::from_utf8_lossy(&bytes))
            .clone_into(&mut oidc.client_secret);
    }
    Ok(())
}

fn expand_env(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut expanded = String::new();
    let mut literal_start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'$' && at + 1 < bytes.len() {
            expanded.push_str(&value[literal_start..at]);
            let (name, width) = shell_name(&value[at + 1..]);
            if name.is_empty() {
                if width == 0 {
                    expanded.push('$');
                }
            } else {
                // Preserve the existing String boundary: non-UTF-8 variable
                // values remain unavailable, as with the former core loader.
                expanded.push_str(&env::var(name).unwrap_or_default());
            }
            at += width + 1;
            literal_start = at;
        } else {
            at += 1;
        }
    }
    expanded.push_str(&value[literal_start..]);
    expanded
}

fn shell_name(value: &str) -> (&str, usize) {
    let bytes = value.as_bytes();
    if bytes[0] == b'{' {
        if bytes.len() > 2 && shell_special(bytes[1]) && bytes[2] == b'}' {
            return (&value[1..2], 3);
        }
        if let Some(end) = bytes
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(at, byte)| (*byte == b'}').then_some(at))
        {
            return (&value[1..end], end + 1);
        }
        // Invalid syntax eats only "${", leaving the following text literal.
        return ("", 1);
    }
    if shell_special(bytes[0]) {
        return (&value[..1], 1);
    }
    let width = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    (&value[..width], width)
}

fn shell_special(byte: u8) -> bool {
    matches!(
        byte,
        b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-' | b'0'..=b'9'
    )
}

fn read_error(path: &str, source: &io::Error) -> anyhow::Error {
    // Go returns ReadFile's PathError directly, before the command adds its
    // configuration-error envelope.
    let operation = if source.kind() == io::ErrorKind::IsADirectory {
        "read"
    } else {
        "open"
    };
    let message = match source.kind() {
        io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        io::ErrorKind::IsADirectory => "is a directory".to_owned(),
        io::ErrorKind::NotADirectory => "not a directory".to_owned(),
        _ => {
            let mut message = source.to_string();
            if let Some(code) = source.raw_os_error() {
                let suffix = format!(" (os error {code})");
                if message.ends_with(&suffix) {
                    message.truncate(message.len() - suffix.len());
                }
            }
            message
        }
    };
    anyhow::anyhow!("{operation} {path}: {message}")
}
