//! Pinned pgx v5.10.0 host/TLS preference and session-target selection.
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

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use sqlx_core::connection::Connection;
use sqlx_core::error::Error;
use sqlx_core::executor::Executor;
use sqlx_core::row::Row;

use super::{config_error, is_socket_directory, GoDialTarget, TargetSessionAttrs};
use crate::{PgConnectOptions, PgConnection, PgSslMode};

#[derive(Clone, Debug)]
struct Attempt {
    hostname: String,
    port: u16,
    mode: PgSslMode,
    target: GoDialTarget,
}

impl Attempt {
    fn endpoint(&self) -> String {
        match &self.target {
            GoDialTarget::Tcp(address) => {
                let literal = self.hostname.parse::<std::net::IpAddr>().is_ok()
                    || self.hostname.split_once('%').is_some_and(|(ip, zone)| {
                        !zone.is_empty() && ip.parse::<std::net::Ipv6Addr>().is_ok()
                    });
                if literal {
                    if self.hostname.contains(':') {
                        format!("[{}]:{}", self.hostname, address.port())
                    } else {
                        format!("{}:{}", self.hostname, address.port())
                    }
                } else {
                    address.to_string()
                }
            }
            GoDialTarget::Unix(path) => path.to_string_lossy().into_owned(),
        }
    }
}

#[derive(Debug)]
struct DialError {
    hostname: String,
    endpoint: String,
    error: Error,
}

impl fmt::Display for DialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({}): {}",
            self.endpoint, self.hostname, self.error
        )
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
struct JoinedErrors(Vec<DialError>);

impl fmt::Display for JoinedErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("\n")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for JoinedErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.first().map(|error| error as &dyn std::error::Error)
    }
}

fn joined(mut errors: Vec<DialError>) -> Error {
    if errors.is_empty() {
        errors.push(DialError {
            hostname: String::new(),
            endpoint: String::new(),
            error: Error::Io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no Postgres connection candidates",
            )),
        });
    }
    // Never attach the options/URL/password to diagnostic context.
    Error::Io(io::Error::other(JoinedErrors(errors)))
}

fn failed(attempt: &Attempt, error: Error) -> DialError {
    DialError {
        hostname: attempt.hostname.clone(),
        endpoint: attempt.endpoint(),
        error,
    }
}

fn terminal(error: &Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| matches!(code.as_ref(), "28P01" | "3D000" | "42501"))
}

fn timeout_error() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "Postgres connection timed out",
    ))
}

fn deadline(timeout: Option<Duration>) -> Result<Option<Instant>, Error> {
    timeout
        .map(|timeout| {
            Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| config_error("Postgres timeout exceeds the monotonic clock range"))
        })
        .transpose()
}

fn socket_path(host: &str, port: u16) -> PathBuf {
    // filepath.Join cleans lexically, before dialing. OS traversal through
    // symlinks and parent components must not replace that step.
    let joined = Path::new(host).join(format!(".s.PGSQL.{port}"));
    let mut cleaned = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(cleaned.components().next_back(), Some(Component::Normal(_))) {
                    cleaned.pop();
                } else if !cleaned.has_root() {
                    cleaned.push(component.as_os_str());
                }
            }
            _ => cleaned.push(component.as_os_str()),
        }
    }
    cleaned
}

async fn build_attempts(
    options: &PgConnectOptions,
) -> Result<(Vec<Attempt>, Vec<DialError>), Error> {
    let go = options
        .go_compat
        .as_ref()
        .ok_or_else(|| config_error("native Postgres settings are missing"))?;
    let mut attempts = Vec::new();
    let mut errors = Vec::new();
    for host in &go.hosts {
        let socket = is_socket_directory(&host.name);
        let modes = if socket {
            vec![PgSslMode::Disable]
        } else {
            match options.ssl_mode {
                PgSslMode::Allow => vec![PgSslMode::Disable, PgSslMode::Require],
                PgSslMode::Prefer => vec![PgSslMode::Require, PgSslMode::Disable],
                mode => vec![mode],
            }
        };
        // pgx resolves each TLS fallback independently and expands all of its
        // IPs before advancing to the next TLS/plain fallback or hostname.
        for mode in modes {
            if socket {
                attempts.push(Attempt {
                    hostname: host.name.clone(),
                    port: host.port,
                    mode,
                    target: GoDialTarget::Unix(socket_path(&host.name, host.port)),
                });
            } else {
                match sqlx_core::net::resolve_tcp(&host.name, host.port).await {
                    Ok(addresses) if !addresses.is_empty() => {
                        for address in addresses {
                            attempts.push(Attempt {
                                hostname: host.name.clone(),
                                port: host.port,
                                mode,
                                target: GoDialTarget::Tcp(address),
                            });
                        }
                    }
                    resolved => {
                        let error = match resolved {
                            Err(error) => error,
                            Ok(_) => Error::Io(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "Postgres hostname resolved to no addresses",
                            )),
                        };
                        errors.push(DialError {
                            hostname: host.name.clone(),
                            endpoint: format!("{}:{}", host.name, host.port),
                            error,
                        });
                    }
                }
            }
        }
    }
    Ok((attempts, errors))
}

enum Opened {
    Preferred(PgConnection),
    NotPreferred,
}

enum Checked {
    Preferred(PgConnection),
    NotPreferred(PgConnection),
    Rejected(PgConnection, Error),
}

async fn close_rejected(connection: PgConnection) {
    // Go TLS Close bounds its close-notify write. Dropping this owned future
    // on timeout also drops the transport; it cannot retain pool capacity.
    let _ = sqlx_core::rt::timeout(Duration::from_secs(5), connection.close_hard()).await;
}

async fn text_query(connection: &mut PgConnection, sql: &str) -> Result<String, Error> {
    let row = (&mut *connection).fetch_one(sql).await?;
    // These simple-protocol checks compare raw text, as pgconn Exec does,
    // including the text representation of the boolean recovery result.
    let value = row.try_get_unchecked::<String, _>(0)?;
    drop(row);
    connection.flush().await?;
    Ok(value)
}

async fn validate(
    connection: &mut PgConnection,
    target: TargetSessionAttrs,
    ignore_not_preferred: bool,
) -> Result<bool, Error> {
    match target {
        TargetSessionAttrs::Any => Ok(true),
        TargetSessionAttrs::ReadWrite => {
            if text_query(connection, "show transaction_read_only").await? == "on" {
                Err(config_error("read only connection"))
            } else {
                Ok(true)
            }
        }
        TargetSessionAttrs::ReadOnly => {
            if text_query(connection, "show transaction_read_only").await? != "on" {
                Err(config_error("connection is not read only"))
            } else {
                Ok(true)
            }
        }
        TargetSessionAttrs::Primary => {
            if text_query(connection, "select pg_is_in_recovery()").await? == "t" {
                Err(config_error("server is in standby mode"))
            } else {
                Ok(true)
            }
        }
        TargetSessionAttrs::Standby => {
            if text_query(connection, "select pg_is_in_recovery()").await? != "t" {
                Err(config_error("server is not in hot standby mode"))
            } else {
                Ok(true)
            }
        }
        TargetSessionAttrs::PreferStandby => {
            let standby = text_query(connection, "select pg_is_in_recovery()").await? == "t";
            Ok(standby || ignore_not_preferred)
        }
    }
}

async fn open_one(
    options: &PgConnectOptions,
    attempt: &Attempt,
    ignore_not_preferred: bool,
) -> Result<Checked, Error> {
    let mut selected = options.clone();
    selected.host.clone_from(&attempt.hostname);
    selected.port = attempt.port;
    selected.socket =
        is_socket_directory(&attempt.hostname).then(|| PathBuf::from(attempt.hostname.as_str()));
    selected.ssl_mode = attempt.mode;
    let go = selected
        .go_compat
        .as_mut()
        .ok_or_else(|| config_error("native Postgres settings are missing"))?;
    go.dial_target = Some(attempt.target.clone());
    let target = go.target_session_attrs;
    // Establish directly: calling ConnectOptions::connect here would recurse
    // into host selection. The TLS hostname remains the original name.
    let mut connection = PgConnection::establish(&selected).await?;
    match validate(&mut connection, target, ignore_not_preferred).await {
        Ok(true) => Ok(Checked::Preferred(connection)),
        Ok(false) => Ok(Checked::NotPreferred(connection)),
        Err(error) => Ok(Checked::Rejected(connection, error)),
    }
}

async fn run_one(
    options: &PgConnectOptions,
    attempt: &Attempt,
    deadline: Option<Instant>,
    ignore_not_preferred: bool,
) -> Result<Opened, Error> {
    let connect = open_one(options, attempt, ignore_not_preferred);
    let checked = match deadline {
        Some(deadline) => {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(timeout_error)?;
            sqlx_core::rt::timeout(remaining, connect)
                .await
                .map_err(|_| timeout_error())?
        }
        None => connect.await,
    }?;
    // Preserve the validation verdict/SQLSTATE while closing. Cleanup owns
    // its bounded TLS close deadline; expiration there must not turn a known
    // authentication/permission error into a retryable connect timeout.
    match checked {
        Checked::Preferred(connection) => Ok(Opened::Preferred(connection)),
        Checked::NotPreferred(connection) => {
            close_rejected(connection).await;
            Ok(Opened::NotPreferred)
        }
        Checked::Rejected(connection, error) => {
            close_rejected(connection).await;
            Err(error)
        }
    }
}

pub(crate) async fn connect(options: &PgConnectOptions) -> Result<PgConnection, Error> {
    let go = options
        .go_compat
        .as_ref()
        .ok_or_else(|| config_error("native Postgres settings are missing"))?;
    // Resolution uses the caller's context, not the per-address connect timeout.
    let (attempts, mut errors) = build_attempts(options).await?;
    let mut previous_endpoint = None;
    let mut group_deadline = None;
    let mut fallback = None;
    for attempt in attempts {
        let endpoint = attempt.endpoint();
        if previous_endpoint.as_ref() != Some(&endpoint) {
            group_deadline = deadline(go.connector_timeout)?;
            previous_endpoint = Some(endpoint);
        }
        match run_one(options, &attempt, group_deadline, false).await {
            Ok(Opened::Preferred(connection)) => return Ok(connection),
            Ok(Opened::NotPreferred) => {
                errors.push(failed(
                    &attempt,
                    config_error("server is not in hot standby mode"),
                ));
                fallback = Some(attempt);
            }
            Err(error) => {
                let stop = terminal(&error);
                errors.push(failed(&attempt, error));
                if stop {
                    return Err(joined(errors));
                }
            }
        }
    }
    // Retry the last nonpreferred candidate with a fresh timeout and the
    // prefer-standby exception, exactly once after ordinary candidates fail.
    if let Some(attempt) = fallback {
        match run_one(options, &attempt, deadline(go.connector_timeout)?, true).await {
            Ok(Opened::Preferred(connection)) => return Ok(connection),
            Ok(Opened::NotPreferred) => unreachable!("nonpreferred exception is enabled"),
            Err(error) => errors.push(failed(&attempt, error)),
        }
    }
    Err(joined(errors))
}
