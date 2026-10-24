//! Native headscale-go v0.29.5 configuration bridge.
//!
//! Sources: pgx v5.10.0 pgconn/config.go and defaults*.go;
//! pgservicefile 5a60cdf6a761; pgpassfile v1.0.0.
//! Copyright (c) 2019 Jack Christensen
//! Copyright (c) 2020 Jack Christensen
//!
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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx_core::error::Error;
use sqlx_core::percent_encoding::percent_decode_str;
use sqlx_core::Url;

use super::{PgConnectOptions, PgSslMode};
use crate::net::tls::CertificateInput;

type Settings = BTreeMap<String, String>;

mod connector;
pub(super) use connector::connect;
mod auth;
mod pem;
mod query;
pub(crate) use auth::{GoAuthMethod, GoChannelBinding, GoRequireAuth};
pub(crate) use query::GoQueryExecMode;

#[derive(Clone, Debug)]
pub(crate) enum GoDialTarget {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

#[derive(Clone, Debug)]
struct GoHost {
    name: String,
    port: u16,
}

#[derive(Clone, Copy, Debug)]
enum TargetSessionAttrs {
    Any,
    ReadWrite,
    ReadOnly,
    Primary,
    Standby,
    PreferStandby,
}

impl TargetSessionAttrs {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "any" => Ok(Self::Any),
            "read-write" => Ok(Self::ReadWrite),
            "read-only" => Ok(Self::ReadOnly),
            "primary" => Ok(Self::Primary),
            "standby" => Ok(Self::Standby),
            "prefer-standby" => Ok(Self::PreferStandby),
            _ => Err(config_error("invalid Postgres target_session_attrs")),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GoCompat {
    pub(crate) runtime_params: Settings,
    connector_timeout: Option<Duration>,
    hosts: Vec<GoHost>,
    target_session_attrs: TargetSessionAttrs,
    pub(crate) tls_direct: bool,
    pub(crate) tls_sni: bool,
    pub(crate) channel_binding: GoChannelBinding,
    pub(crate) require_auth: GoRequireAuth,
    pub(crate) min_protocol_version: u32,
    pub(crate) max_protocol_version: u32,
    pub(crate) query_exec_mode: GoQueryExecMode,
    pub(crate) description_cache_capacity: usize,
    pub(crate) dial_target: Option<GoDialTarget>,
}

impl PgConnectOptions {
    /// Resolve a headscale-go connection URL using pinned pgx defaults,
    /// environment/service precedence and pgpass lookup. This constructor
    /// performs local configuration-file I/O, but no network I/O. Ordinary
    /// SQLx URL parsing retains its existing environment and startup defaults.
    pub fn from_headscale_go_url(input: &str) -> Result<Self, Error> {
        let mut settings = default_settings()?;
        settings.extend(environment_settings()?);
        let explicit = url_settings(input)?;
        if let Some(service) = explicit.get("service").or_else(|| settings.get("service")) {
            let service = service.clone();
            let file = explicit
                .get("servicefile")
                .or_else(|| settings.get("servicefile"))
                .map(String::as_str)
                .unwrap_or("");
            settings.extend(service_settings(Path::new(file), &service)?);
        }
        settings.extend(explicit);
        let connector_timeout = connect_timeout(settings.get("connect_timeout"))?;

        let hosts = host_specs(&settings)?;
        let primary = hosts
            .first()
            .ok_or_else(|| config_error("no Postgres hosts"))?;
        let host = primary.name.clone();
        let port = primary.port;
        let username = settings.get("user").cloned().unwrap_or_default();
        let database = settings.get("database").cloned().unwrap_or_default();
        let mut password = settings.get("password").cloned().unwrap_or_default();
        // TCP TLS configuration is built even if the primary is a Unix
        // directory, because a later configured host may need it.
        let unix_socket = hosts.iter().all(|host| is_socket_directory(&host.name));
        let root = settings
            .get("sslrootcert")
            .filter(|value| !value.is_empty());
        let system_roots = !unix_socket && root.is_some_and(|value| value == "system");
        // pgx parses a configured CA even for sslmode=disable. Snapshot it
        // before parsing the mode or dialing, so fallback cannot hide a local
        // trust-file failure or observe a different file on a later attempt.
        let root_snapshot = if unix_socket || system_roots {
            None
        } else if let Some(path) = root {
            let data =
                std::fs::read(path).map_err(|_| config_error("unable to read Postgres CA file"))?;
            let data = pem::certificates(&data, false);
            Some(sqlx_core::net::tls::prepare_headscale_go_ca(&data)?)
        } else {
            None
        };
        let tls_direct = settings
            .get("sslnegotiation")
            .is_some_and(|mode| mode == "direct");
        let tls_sni = settings
            .get("sslsni")
            .is_none_or(|value| value.is_empty() || value == "1");
        let mode = if system_roots {
            // The system override also replaces an otherwise invalid mode.
            "verify-full"
        } else {
            settings.get("sslmode").map(String::as_str).unwrap_or("")
        };
        // pgx promotes direct prefer (including its empty default) to require.
        let mode = if tls_direct && matches!(mode, "" | "prefer") {
            "require"
        } else {
            mode
        };
        let mut ssl_mode = if unix_socket {
            PgSslMode::Disable
        } else {
            match mode {
                "" | "prefer" => PgSslMode::Prefer,
                "disable" => PgSslMode::Disable,
                "allow" => PgSslMode::Allow,
                "require" => PgSslMode::Require,
                "verify-ca" => PgSslMode::VerifyCa,
                "verify-full" => PgSslMode::VerifyFull,
                _ => return Err(config_error("invalid Postgres sslmode")),
            }
        };
        // pgx require verifies the CA (without the hostname) when a root file
        // is configured. SQLx's ordinary Require mode does not enforce that.
        if matches!(ssl_mode, PgSslMode::Require) && root.is_some() {
            ssl_mode = PgSslMode::VerifyCa;
        }
        let client_cert = settings.get("sslcert").filter(|value| !value.is_empty());
        let client_key = settings.get("sslkey").filter(|value| !value.is_empty());
        if !unix_socket
            && !matches!(ssl_mode, PgSslMode::Disable)
            && client_cert.is_some() != client_key.is_some()
        {
            return Err(config_error("Postgres sslcert and sslkey must both be set"));
        }
        let (ssl_client_cert, ssl_client_key) =
            if !unix_socket && !matches!(ssl_mode, PgSslMode::Disable) {
                if let (Some(cert), Some(key)) = (client_cert, client_key) {
                    let key = std::fs::read(key)
                        .map_err(|_| config_error("unable to read Postgres sslkey"))?;
                    let key = pem::key(
                        &key,
                        settings
                            .get("sslpassword")
                            .map(String::as_str)
                            .unwrap_or(""),
                    )?;
                    let cert = std::fs::read(cert)
                        .map_err(|_| config_error("unable to read Postgres sslcert"))?;
                    let cert = pem::certificates(&cert, true);
                    if cert.is_empty() {
                        return Err(config_error("no Postgres client certificate PEM block"));
                    }
                    let key = key.into_der()?;
                    let (cert, key) =
                        sqlx_core::net::tls::prepare_headscale_go_client_der(&cert, &key)?;
                    (
                        Some(CertificateInput::SharedInline(cert.into())),
                        Some(CertificateInput::SharedInline(key.into())),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };
        // pgx reads/parses the whole passfile even when a password is already
        // present, then ignores read/scan errors. Empty passwords use pgpass.
        let passfile = read_go_lines(Path::new(
            settings.get("passfile").map(String::as_str).unwrap_or(""),
        ))
        .ok();
        if password.is_empty() {
            if let Some(lines) = passfile {
                password = find_password(
                    lines,
                    if is_socket_directory(&host) {
                        "localhost"
                    } else {
                        &host
                    },
                    &port.to_string(),
                    &database,
                    &username,
                );
            }
        }

        let target_session_attrs = TargetSessionAttrs::parse(
            settings
                .get("target_session_attrs")
                .map(String::as_str)
                .unwrap_or("any"),
        )?;
        let (min_protocol_version, max_protocol_version) = protocol_versions(&settings)?;
        let channel_binding = GoChannelBinding::parse(
            settings
                .get("channel_binding")
                .map(String::as_str)
                .unwrap_or(""),
        )?;
        let require_auth = GoRequireAuth::parse(
            settings
                .get("require_auth")
                .map(String::as_str)
                .unwrap_or(""),
        )?;
        let statement_cache_capacity = cache_capacity(&settings, "statement_cache_capacity")?;
        let description_cache_capacity = cache_capacity(&settings, "description_cache_capacity")?;
        let query_exec_mode =
            GoQueryExecMode::parse(settings.get("default_query_exec_mode").map(String::as_str))?;
        let mut runtime_params = settings
            .iter()
            .filter(|(key, _)| !not_runtime_parameter(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Settings>();
        let application_name = runtime_params.remove("application_name");
        let options = runtime_params.remove("options");

        Ok(Self {
            socket: is_socket_directory(&host).then(|| PathBuf::from(host.as_str())),
            host,
            port,
            username,
            password: Some(password),
            database: (!database.is_empty()).then_some(database),
            ssl_mode,
            ssl_root_cert: if unix_socket {
                None
            } else if system_roots
                || (root.is_none()
                    && matches!(ssl_mode, PgSslMode::VerifyCa | PgSslMode::VerifyFull))
            {
                Some(CertificateInput::System)
            } else {
                root_snapshot.map(|data| CertificateInput::ExclusiveInline(data.into()))
            },
            ssl_client_cert,
            ssl_client_key,
            statement_cache_capacity,
            application_name,
            extra_float_digits: None,
            log_settings: Default::default(),
            options,
            go_compat: Some(GoCompat {
                runtime_params,
                connector_timeout,
                hosts,
                target_session_attrs,
                tls_direct,
                tls_sni,
                channel_binding,
                require_auth,
                min_protocol_version,
                max_protocol_version,
                query_exec_mode,
                description_cache_capacity,
                dial_target: None,
            }),
        })
    }

    /// Connector timeout resolved by the native headscale-go constructor.
    pub fn headscale_go_connector_timeout(&self) -> Option<Duration> {
        self.go_compat
            .as_ref()
            .and_then(|config| config.connector_timeout)
    }
}

fn config_error(message: &'static str) -> Error {
    Error::Configuration(message.into())
}

fn is_socket_directory(host: &str) -> bool {
    let bytes = host.as_bytes();
    host.starts_with('/')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_uppercase()
            && bytes[1] == b':'
            && bytes[2] == b'\\')
}

fn host_specs(settings: &Settings) -> Result<Vec<GoHost>, Error> {
    let ports = settings
        .get("port")
        .map(String::as_str)
        .unwrap_or("5432")
        .split(',')
        .collect::<Vec<_>>();
    settings
        .get("host")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .enumerate()
        .map(|(index, name)| {
            // pgx reuses the first port when the host list is longer. Extra
            // ports beyond the host list are not parsed or used.
            let text = ports.get(index).copied().unwrap_or(ports[0]);
            let port = if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
                text.parse::<u16>().ok().filter(|port| *port != 0)
            } else {
                None
            }
            .ok_or_else(|| config_error("invalid Postgres port"))?;
            Ok(GoHost {
                name: name.to_string(),
                port,
            })
        })
        .collect()
}

fn canonical_key(key: &str) -> &str {
    if key == "dbname" {
        "database"
    } else {
        key
    }
}

fn decoded(value: &str) -> Result<String, Error> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| config_error("Postgres connection URL is not UTF-8"))
}

struct MultiAuthority {
    parse_url: String,
    hosts: Vec<String>,
    ports: Vec<String>,
}

fn multi_authority(input: &str) -> Result<Option<MultiAuthority>, Error> {
    let Some((scheme, rest)) = input.split_once("://") else {
        return Ok(None);
    };
    let end = rest
        .find(|character| matches!(character, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(end);
    let (userinfo, host_list) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(user, hosts)| (Some(user), hosts));
    if !host_list.contains(',') {
        return Ok(None);
    }
    if host_list.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
        return Err(config_error("invalid Postgres multi-host authority"));
    }
    let mut hosts = Vec::new();
    let mut ports = Vec::new();
    for item in host_list.split(',').filter(|item| !item.is_empty()) {
        let unbracketed = item.trim_matches(&['[', ']'][..]);
        if unbracketed.parse::<std::net::IpAddr>().is_ok() || !item.contains(':') {
            hosts.push(decoded(unbracketed)?);
            continue;
        }
        let (host, port) = if let Some(bracketed) = item.strip_prefix('[') {
            let closing = bracketed
                .find(']')
                .ok_or_else(|| config_error("invalid Postgres multi-host authority"))?;
            let (host, tail) = bracketed.split_at(closing);
            let port = tail
                .strip_prefix("]:")
                .ok_or_else(|| config_error("invalid Postgres multi-host authority"))?;
            (host, port)
        } else {
            let (host, port) = item
                .rsplit_once(':')
                .ok_or_else(|| config_error("invalid Postgres multi-host authority"))?;
            if host.contains(':') {
                return Err(config_error("invalid Postgres multi-host authority"));
            }
            (host, port)
        };
        if !host.is_empty() {
            hosts.push(decoded(host)?);
        }
        if !port.is_empty() {
            ports.push(port.to_string());
        }
    }
    // Preserve userinfo/path/query parsing while taking the multi-host list
    // out of URL's single-authority host/port parser. Query settings override
    // these lists below, just as in pgx's parseURLSettings.
    let userinfo = userinfo.map_or_else(String::new, |user| format!("{user}@"));
    Ok(Some(MultiAuthority {
        parse_url: format!("{scheme}://{userinfo}localhost{suffix}"),
        hosts,
        ports,
    }))
}

fn url_settings(input: &str) -> Result<Settings, Error> {
    let authority = multi_authority(input)?;
    let parse_url = authority
        .as_ref()
        .map_or(input, |authority| authority.parse_url.as_str());
    let url = Url::parse(parse_url).map_err(|_| config_error("invalid Postgres connection URL"))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(config_error("invalid Postgres connection URL scheme"));
    }
    let mut settings = Settings::new();
    if !url.username().is_empty() {
        settings.insert("user".into(), decoded(url.username())?);
    }
    if let Some(password) = url.password() {
        settings.insert("password".into(), decoded(password)?);
    }
    if let Some(authority) = authority {
        if !authority.hosts.is_empty() {
            settings.insert("host".into(), authority.hosts.join(","));
        }
        if !authority.ports.is_empty() {
            settings.insert("port".into(), authority.ports.join(","));
        }
    } else {
        if let Some(host) = url.host_str() {
            settings.insert(
                "host".into(),
                host.trim_start_matches('[').trim_end_matches(']').into(),
            );
        }
        if let Some(port) = url.port() {
            settings.insert("port".into(), port.to_string());
        }
    }
    let database = url.path().trim_start_matches('/');
    if !database.is_empty() {
        settings.insert("database".into(), decoded(database)?);
    }
    // Avoid URL's lossy UTF-8 replacement for credential-bearing query values.
    // The native bridge supports UTF-8 settings and rejects other byte strings.
    if let Some(query) = url.query() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            decoded(&key.replace('+', " "))?;
            decoded(&value.replace('+', " "))?;
        }
    }
    // pgx uses the first value for each raw query key.
    let mut seen = BTreeSet::new();
    for (key, value) in url.query_pairs() {
        if seen.insert(key.to_string()) {
            settings.insert(canonical_key(&key).to_string(), value.into_owned());
        }
    }
    Ok(settings)
}

fn environment_settings() -> Result<Settings, Error> {
    let mappings = [
        ("PGHOST", "host"),
        ("PGPORT", "port"),
        ("PGDATABASE", "database"),
        ("PGUSER", "user"),
        ("PGPASSWORD", "password"),
        ("PGPASSFILE", "passfile"),
        ("PGAPPNAME", "application_name"),
        ("PGCONNECT_TIMEOUT", "connect_timeout"),
        ("PGSSLMODE", "sslmode"),
        ("PGSSLKEY", "sslkey"),
        ("PGSSLCERT", "sslcert"),
        ("PGSSLSNI", "sslsni"),
        ("PGSSLROOTCERT", "sslrootcert"),
        ("PGSSLPASSWORD", "sslpassword"),
        ("PGSSLNEGOTIATION", "sslnegotiation"),
        ("PGTARGETSESSIONATTRS", "target_session_attrs"),
        ("PGSERVICE", "service"),
        ("PGSERVICEFILE", "servicefile"),
        ("PGTZ", "timezone"),
        ("PGOPTIONS", "options"),
        ("PGMINPROTOCOLVERSION", "min_protocol_version"),
        ("PGMAXPROTOCOLVERSION", "max_protocol_version"),
        ("PGCHANNELBINDING", "channel_binding"),
        ("PGREQUIREAUTH", "require_auth"),
    ];
    let mut settings = Settings::new();
    for (name, key) in mappings {
        match std::env::var(name) {
            Ok(value) if !value.is_empty() => {
                settings.insert(key.to_string(), value);
            }
            Ok(_) | Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(config_error("Postgres environment setting is not UTF-8"));
            }
        }
    }
    Ok(settings)
}

#[cfg(all(unix, not(target_os = "redox")))]
fn os_identity() -> Option<(String, PathBuf)> {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid()).ok()??;
    Some((user.name, user.dir))
}

#[cfg(any(not(unix), target_os = "redox"))]
fn os_identity() -> Option<(String, PathBuf)> {
    let username = whoami::fallible::username().ok()?;
    Some((
        username
            .rsplit('\\')
            .next()
            .unwrap_or(&username)
            .to_string(),
        home::home_dir().unwrap_or_default(),
    ))
}

fn insert_path(settings: &mut Settings, key: &str, path: &Path) -> Result<(), Error> {
    let value = path
        .to_str()
        .ok_or_else(|| config_error("Postgres default path is not UTF-8"))?;
    settings.insert(key.into(), value.into());
    Ok(())
}

fn default_settings() -> Result<Settings, Error> {
    #[cfg(windows)]
    let host = "localhost";
    #[cfg(not(windows))]
    let host = ["/var/run/postgresql", "/private/tmp", "/tmp"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .unwrap_or("localhost");
    let mut settings = Settings::from([
        ("host".into(), host.into()),
        ("port".into(), "5432".into()),
        ("target_session_attrs".into(), "any".into()),
    ]);
    if let Some((username, home)) = os_identity() {
        settings.insert("user".into(), username);
        insert_path(&mut settings, "servicefile", &home.join(".pg_service.conf"))?;
        #[cfg(windows)]
        let (passfile, certificate_dir) = {
            let directory =
                PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default()).join("postgresql");
            (directory.join("pgpass.conf"), directory)
        };
        #[cfg(not(windows))]
        let (passfile, certificate_dir) = (home.join(".pgpass"), home.join(".postgresql"));
        insert_path(&mut settings, "passfile", &passfile)?;
        let cert = certificate_dir.join("postgresql.crt");
        let key = certificate_dir.join("postgresql.key");
        if cert.exists() && key.exists() {
            insert_path(&mut settings, "sslcert", &cert)?;
            insert_path(&mut settings, "sslkey", &key)?;
        }
        let root = certificate_dir.join("root.crt");
        if root.exists() {
            insert_path(&mut settings, "sslrootcert", &root)?;
        }
    }
    Ok(settings)
}

fn read_go_lines(path: &Path) -> io::Result<Vec<String>> {
    const MAX_SCAN_TOKEN: usize = 65_536;
    let mut reader = BufReader::new(File::open(path)?);
    let mut lines = Vec::new();
    loop {
        let mut line = Vec::new();
        let length = Read::take(&mut reader, 65_537).read_until(b'\n', &mut line)?;
        if length == 0 {
            return Ok(lines);
        }
        let newline = line.last() == Some(&b'\n');
        if length > MAX_SCAN_TOKEN || (length == MAX_SCAN_TOKEN && !newline) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Postgres configuration line too long",
            ));
        }
        if newline {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        lines.push(String::from_utf8(line).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Postgres configuration file is not UTF-8",
            )
        })?);
    }
}

fn service_settings(path: &Path, name: &str) -> Result<Settings, Error> {
    let lines =
        read_go_lines(path).map_err(|_| config_error("failed to read Postgres service file"))?;
    let mut sections: BTreeMap<String, Settings> = BTreeMap::new();
    let mut current = None;
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
        {
            sections.insert(name.to_string(), Settings::new());
            current = Some(name.to_string());
        } else {
            let section = current
                .as_ref()
                .ok_or_else(|| config_error("Postgres service value is not in a section"))?;
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| config_error("invalid Postgres service file line"))?;
            sections
                .get_mut(section)
                .expect("current service section exists")
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    let selected = sections
        .remove(name)
        .ok_or_else(|| config_error("Postgres service not found"))?;
    Ok(selected
        .into_iter()
        .map(|(key, value)| (canonical_key(&key).to_string(), value))
        .collect())
}

fn find_password(lines: Vec<String>, host: &str, port: &str, database: &str, user: &str) -> String {
    for line in lines {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let escaped = line.replace(r"\\", "\r").replace(r"\:", "\n");
        let fields = escaped
            .split(':')
            .map(|part| part.replace('\r', "\\").replace('\n', ":"))
            .collect::<Vec<_>>();
        if fields.len() == 5
            && fields[..4]
                .iter()
                .zip([host, port, database, user])
                .all(|(pattern, expected)| pattern == "*" || pattern == expected)
        {
            return fields[4].clone();
        }
    }
    String::new()
}

fn connect_timeout(value: Option<&String>) -> Result<Option<Duration>, Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let seconds = value
        .parse::<i64>()
        .map_err(|_| config_error("invalid Postgres connect_timeout"))?;
    if seconds < 0 {
        return Err(config_error("negative Postgres connect_timeout"));
    }
    let nanos = seconds.wrapping_mul(1_000_000_000);
    Ok(match nanos.cmp(&0) {
        std::cmp::Ordering::Less => Some(Duration::ZERO),
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => Some(Duration::from_nanos(nanos.unsigned_abs())),
    })
}

fn cache_capacity(settings: &Settings, key: &str) -> Result<usize, Error> {
    match settings.get(key) {
        None => Ok(512),
        Some(value) => value
            .parse::<i32>()
            .map(|value| usize::try_from(value).unwrap_or_default())
            .map_err(|_| config_error("invalid Postgres cache capacity")),
    }
}

fn protocol_versions(settings: &Settings) -> Result<(u32, u32), Error> {
    const V30: u32 = 3 << 16;
    const V32: u32 = V30 | 2;
    let parse = |key: &str| match settings.get(key).map(String::as_str).unwrap_or("") {
        "" | "3.0" => Ok(V30),
        "3.2" | "latest" => Ok(V32),
        _ => Err(config_error("invalid Postgres protocol version")),
    };
    let minimum = parse("min_protocol_version")?;
    let mut maximum = parse("max_protocol_version")?;
    if settings
        .get("max_protocol_version")
        .is_none_or(String::is_empty)
    {
        maximum = if minimum > V30 { V32 } else { V30 };
    } else if minimum > maximum {
        return Err(config_error(
            "min_protocol_version cannot be greater than max_protocol_version",
        ));
    }
    Ok((minimum, maximum))
}

fn not_runtime_parameter(key: &str) -> bool {
    matches!(
        key,
        "host"
            | "port"
            | "database"
            | "user"
            | "password"
            | "passfile"
            | "connect_timeout"
            | "sslmode"
            | "sslkey"
            | "sslcert"
            | "sslrootcert"
            | "sslnegotiation"
            | "sslpassword"
            | "sslsni"
            | "krbspn"
            | "krbsrvname"
            | "target_session_attrs"
            | "service"
            | "servicefile"
            | "min_protocol_version"
            | "max_protocol_version"
            | "channel_binding"
            | "require_auth"
            | "statement_cache_capacity"
            | "description_cache_capacity"
            | "default_query_exec_mode"
    )
}
