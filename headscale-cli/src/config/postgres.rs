//! Pinned headscale-go v0.29.5 Postgres keyword/value projection.
//!
//! The scanner follows pgx v5.10.0 pgconn/config.go's
//! parseKeywordValueSettings. The SQLx transport still has separate driver,
//! service-file, multi-host and environment qualification requirements.
//!
//! Scanner adaptation license:
//! Copyright (c) 2013-2021 Jack Christensen
//!
//! MIT License
//!
//! Permission is hereby granted, free of charge, to any person obtaining
//! a copy of this software and associated documentation files (the
//! "Software"), to deal in the Software without restriction, including
//! without limitation the rights to use, copy, modify, merge, publish,
//! distribute, sublicense, and/or sell copies of the Software, and to
//! permit persons to whom the Software is furnished to do so, subject to
//! the following conditions:
//!
//! The above copyright notice and this permission notice shall be
//! included in all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//! LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
//! WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use std::collections::BTreeMap;
use std::fmt::Write;

use anyhow::{Context, Result, bail};

use super::UpstreamPostgresConfig;

pub(super) fn connection_url(config: &UpstreamPostgresConfig) -> Result<String> {
    // Keep Go's append order and raw values. Quotes, escapes, empty values and
    // embedded keyword/value pairs are interpreted by pgx, not by YAML or URL
    // normalization. Never include this string in a diagnostic: it has secrets.
    let mut keywords = format!(
        "host={} dbname={} user={}",
        config.host(),
        config.name(),
        config.user()
    );
    if let Some(mode) = config.ssl_mode() {
        write!(&mut keywords, " sslmode={mode}").expect("writing to String cannot fail");
    }
    if config.port() != 0 {
        write!(&mut keywords, " port={}", config.port()).expect("writing to String cannot fail");
    }
    if !config.pass().is_empty() {
        write!(&mut keywords, " password={}", config.pass())
            .expect("writing to String cannot fail");
    }
    let settings = parse_keywords(&keywords)?;
    let mut url = url::Url::parse("postgres:///").context("build Postgres connection URL")?;
    {
        // Leave environment/service/default resolution to the native driver at
        // database-open time. Query encoding keeps explicit values lossless.
        let mut query = url.query_pairs_mut();
        for (key, value) in &settings {
            query.append_pair(if key == "database" { "dbname" } else { key }, value);
        }
    }
    Ok(url.to_string())
}

fn ascii_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}')
}

fn unescape(value: &str) -> String {
    // Match pgx's two ordered replacements; a backslash before a space or
    // another character changes scanning but is not otherwise stripped.
    value.replace("\\\\", "\\").replace("\\'", "'")
}

fn parse_keywords(mut input: &str) -> Result<BTreeMap<String, String>> {
    let mut settings = BTreeMap::new();
    input = input.trim_start_matches(ascii_space);
    while !input.is_empty() {
        let Some(equals) = input.find('=') else {
            bail!("invalid Postgres keyword/value settings");
        };
        let key = input[..equals].trim_matches(ascii_space);
        input = input[equals + 1..].trim_start_matches(ascii_space);
        let (value, remainder) = if let Some(quoted) = input.strip_prefix('\'') {
            let bytes = quoted.as_bytes();
            let mut end = 0;
            while end < bytes.len() && bytes[end] != b'\'' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            if end >= bytes.len() {
                bail!("unterminated quoted string in Postgres connection settings");
            }
            (unescape(&quoted[..end]), &quoted[end + 1..])
        } else {
            let bytes = input.as_bytes();
            let mut end = 0;
            while end < bytes.len() && !ascii_space(char::from(bytes[end])) {
                if bytes[end] == b'\\' {
                    end += 1;
                    if end == bytes.len() {
                        bail!("invalid backslash in Postgres connection settings");
                    }
                }
                end += 1;
            }
            (unescape(&input[..end]), &input[end..])
        };
        if key.is_empty() {
            bail!("invalid Postgres keyword/value settings");
        }
        if key != "user" || !value.is_empty() {
            let key = if key == "dbname" { "database" } else { key };
            settings.insert(key.to_string(), value);
        }
        input = remainder.trim_start_matches(ascii_space);
    }
    Ok(settings)
}
