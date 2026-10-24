use std::collections::BTreeMap;
use std::ops::{ControlFlow, Deref, DerefMut};
use std::str::FromStr;

use futures_channel::mpsc::UnboundedSender;
use futures_util::SinkExt;
use log::Level;
use sqlx_core::bytes::Buf;

use crate::connection::tls::MaybeUpgradeTls;
use crate::error::Error;
use crate::message::{
    BackendMessage, BackendMessageFormat, EncodeMessage, FrontendMessage, MAX_GO_MESSAGE_BODY_LEN,
    Notice, Notification, ParameterStatus, ReceivedMessage, validate_go_body,
};
use crate::net::{self, BufferedSocket, Socket};
use crate::{PgConnectOptions, PgDatabaseError, PgSeverity};

// the stream is a separate type from the connection to uphold the invariant where an instantiated
// [PgConnection] is a **valid** connection to postgres

// when a new connection is asked for, we work directly on the [PgStream] type until the
// connection is fully established

// in other words, `self` in any PgConnection method is a live connection to postgres that
// is fully prepared to receive queries

pub struct PgStream {
    // A trait object is okay here as the buffering amortizes the overhead of both the dynamic
    // function call as well as the syscall.
    inner: BufferedSocket<Box<dyn Socket>>,

    // buffer of unreceived notification messages from `PUBLISH`
    // this is set when creating a PgListener and only written to if that listener is
    // re-used for query execution in-between receiving messages
    pub(crate) notifications: Option<UnboundedSender<Notification>>,

    pub(crate) parameter_statuses: BTreeMap<String, String>,

    pub(crate) server_version_num: Option<u32>,

    // pgx permanently closes a connection after a malformed backend message.
    // Retain that failure even if a later ReadyForQuery could otherwise make
    // the SQLx pool's drain/reuse checks succeed.
    native_protocol: bool,
    protocol_failed: bool,
}

impl PgStream {
    pub(super) async fn connect(options: &PgConnectOptions) -> Result<Self, Error> {
        let socket_result = match options
            .go_compat
            .as_ref()
            .and_then(|go| go.dial_target.as_ref())
        {
            Some(crate::options::GoDialTarget::Tcp(address)) => {
                net::connect_tcp_addr(*address, MaybeUpgradeTls(options)).await?
            }
            Some(crate::options::GoDialTarget::Unix(path)) => {
                net::connect_uds(path, MaybeUpgradeTls(options)).await?
            }
            None => match options.fetch_socket() {
                Some(ref path) => net::connect_uds(path, MaybeUpgradeTls(options)).await?,
                None => {
                    net::connect_tcp(&options.host, options.port, MaybeUpgradeTls(options)).await?
                }
            },
        };

        let socket = socket_result?;

        Ok(Self {
            inner: BufferedSocket::new(socket),
            notifications: None,
            parameter_statuses: BTreeMap::default(),
            server_version_num: None,
            native_protocol: options.go_compat.is_some(),
            protocol_failed: false,
        })
    }

    /// Only receive/decode paths should call this: client-side encoding and
    /// argument validation errors do not imply a broken backend protocol.
    pub(super) fn mark_native_protocol_error(&mut self, error: &Error) {
        if self.native_protocol && matches!(error, Error::Protocol(_)) {
            self.protocol_failed = true;
        }
    }

    pub(super) fn protocol_failed(&self) -> bool {
        self.protocol_failed
    }

    pub(super) fn ensure_usable(&self) -> Result<(), Error> {
        if self.protocol_failed {
            return Err(err_protocol!(
                "native PostgreSQL connection closed after a protocol error"
            ));
        }
        Ok(())
    }

    /// Native framing is checked without allocation by recv_unchecked, before
    /// any executor or drain can discard a backend message.
    pub(super) fn validate_native_drain_message(
        &mut self,
        message: ReceivedMessage,
    ) -> Result<(), Error> {
        let _ = message;
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn write_msg(&mut self, message: impl FrontendMessage) -> Result<(), Error> {
        self.write(EncodeMessage(message))
    }

    pub(crate) async fn send<T>(&mut self, message: T) -> Result<(), Error>
    where
        T: FrontendMessage,
    {
        self.ensure_usable()?;
        self.write_msg(message)?;
        self.flush().await?;
        Ok(())
    }

    // Expect a specific type and format
    pub(crate) async fn recv_expect<B: BackendMessage>(&mut self) -> Result<B, Error> {
        let result = self.recv().await?.decode();
        if let Err(error) = &result {
            self.mark_native_protocol_error(error);
        }
        result
    }

    pub(crate) async fn recv_unchecked(&mut self) -> Result<ReceivedMessage, Error> {
        self.ensure_usable()?;
        let native_protocol = self.native_protocol;
        // NOTE: to not break everything, this should be cancel-safe;
        // DO NOT modify `buf` unless a full message has been read
        let result = self
            .inner
            .try_read(|buf| {
                // all packets in postgres start with a 5-byte header
                // this header contains the message type and the total length of the message
                let Some(mut header) = buf.get(..5) else {
                    return Ok(ControlFlow::Continue(5));
                };

                let format = BackendMessageFormat::try_from_u8(header.get_u8())?;

                let raw_message_len = header.get_u32();
                if native_protocol && (raw_message_len as i32) < 4 {
                    return Err(err_protocol!(
                        "invalid native Postgres message length: {}",
                        raw_message_len as i32
                    ));
                }
                let message_len = raw_message_len as usize;
                if message_len < 4 {
                    return Err(err_protocol!(
                        "invalid Postgres message length: {message_len}"
                    ));
                }
                if native_protocol && message_len - 4 > MAX_GO_MESSAGE_BODY_LEN {
                    return Err(err_protocol!(
                        "native Postgres message body exceeds pgx limit: {} > {}",
                        message_len - 4,
                        MAX_GO_MESSAGE_BODY_LEN
                    ));
                }

                let expected_len = message_len
                    .checked_add(1)
                    // this shouldn't really happen but is mostly a sanity check
                    .ok_or_else(|| {
                        err_protocol!("message_len + 1 overflows usize: {message_len}")
                    })?;

                if buf.len() < expected_len {
                    return Ok(ControlFlow::Continue(expected_len));
                }

                // `buf` SHOULD NOT be modified ABOVE this line

                // pop off the format code since it's not counted in `message_len`
                buf.advance(1);

                // consume the message, including the length prefix
                let mut contents = buf.split_to(message_len).freeze();

                // cut off the length prefix
                contents.advance(4);

                if native_protocol {
                    validate_go_body(&format, &contents)?;
                }

                Ok(ControlFlow::Break(ReceivedMessage { format, contents }))
            })
            .await;
        if let Err(error) = &result {
            self.mark_native_protocol_error(error);
        }
        result
    }

    // Get the next message from the server
    // May wait for more data from the server
    pub(crate) async fn recv(&mut self) -> Result<ReceivedMessage, Error> {
        let result = self.recv_inner().await;
        if let Err(error) = &result {
            self.mark_native_protocol_error(error);
        }
        result
    }

    async fn recv_inner(&mut self) -> Result<ReceivedMessage, Error> {
        loop {
            let message = self.recv_unchecked().await?;

            match message.format {
                BackendMessageFormat::ErrorResponse => {
                    // An error returned from the database server.
                    let error = if self.native_protocol {
                        PgDatabaseError(Notice::decode_go_body(message.contents)?)
                    } else {
                        message.decode::<PgDatabaseError>()?
                    };
                    // pgx's default OnPgError handler permanently closes on
                    // FATAL, while ordinary SQL errors can drain and recover.
                    if self.native_protocol && matches!(error.severity(), PgSeverity::Fatal) {
                        self.protocol_failed = true;
                    }
                    return Err(error.into());
                }

                BackendMessageFormat::NotificationResponse => {
                    if let Some(buffer) = &mut self.notifications {
                        let notification: Notification = message.decode()?;
                        let _ = buffer.send(notification).await;

                        continue;
                    }
                }

                BackendMessageFormat::ParameterStatus => {
                    // informs the frontend about the current (initial)
                    // setting of backend parameters

                    let ParameterStatus { name, value } = if self.native_protocol {
                        ParameterStatus::decode_go_body(message.contents)?
                    } else {
                        message.decode()?
                    };
                    // TODO: handle `client_encoding`, `DateStyle` change

                    match name.as_str() {
                        "server_version" => {
                            self.server_version_num = parse_server_version(&value);
                        }
                        _ => {
                            self.parameter_statuses.insert(name, value);
                        }
                    }

                    continue;
                }

                BackendMessageFormat::NoticeResponse => {
                    // do we need this to be more configurable?
                    // if you are reading this comment and think so, open an issue

                    let notice: Notice = if self.native_protocol {
                        Notice::decode_go_body(message.contents)?
                    } else {
                        message.decode()?
                    };

                    let (log_level, tracing_level) = match notice.severity() {
                        PgSeverity::Fatal | PgSeverity::Panic | PgSeverity::Error => {
                            (Level::Error, tracing::Level::ERROR)
                        }
                        PgSeverity::Warning => (Level::Warn, tracing::Level::WARN),
                        PgSeverity::Notice => (Level::Info, tracing::Level::INFO),
                        PgSeverity::Debug => (Level::Debug, tracing::Level::DEBUG),
                        PgSeverity::Info | PgSeverity::Log => (Level::Trace, tracing::Level::TRACE),
                    };

                    let log_is_enabled = log::log_enabled!(
                        target: "sqlx::postgres::notice",
                        log_level
                    ) || sqlx_core::private_tracing_dynamic_enabled!(
                        target: "sqlx::postgres::notice",
                        tracing_level
                    );
                    if log_is_enabled {
                        sqlx_core::private_tracing_dynamic_event!(
                            target: "sqlx::postgres::notice",
                            tracing_level,
                            message = notice.message()
                        );
                    }

                    continue;
                }

                _ => {}
            }

            return Ok(message);
        }
    }
}

impl Deref for PgStream {
    type Target = BufferedSocket<Box<dyn Socket>>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PgStream {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// reference:
// https://github.com/postgres/postgres/blob/6feebcb6b44631c3dc435e971bd80c2dd218a5ab/src/interfaces/libpq/fe-exec.c#L1030-L1065
fn parse_server_version(s: &str) -> Option<u32> {
    let mut parts = Vec::<u32>::with_capacity(3);

    let mut from = 0;
    let mut chs = s.char_indices().peekable();
    while let Some((i, ch)) = chs.next() {
        match ch {
            '.' => {
                if let Ok(num) = u32::from_str(&s[from..i]) {
                    parts.push(num);
                    from = i + 1;
                } else {
                    break;
                }
            }
            _ if ch.is_ascii_digit() => {
                if chs.peek().is_none() {
                    if let Ok(num) = u32::from_str(&s[from..]) {
                        parts.push(num);
                    }
                    break;
                }
            }
            _ => {
                if let Ok(num) = u32::from_str(&s[from..i]) {
                    parts.push(num);
                }
                break;
            }
        };
    }

    let version_num = match parts.as_slice() {
        [major, minor, rev] => (100 * major + minor) * 100 + rev,
        [major, minor] if *major >= 10 => 100 * 100 * major + minor,
        [major, minor] => (100 * major + minor) * 100,
        [major] => 100 * 100 * major,
        _ => return None,
    };

    Some(version_num)
}

#[cfg(test)]
mod tests {
    use super::parse_server_version;

    #[test]
    fn test_parse_server_version_num() {
        // old style
        assert_eq!(parse_server_version("9.6.1"), Some(90601));
        // new style
        assert_eq!(parse_server_version("10.1"), Some(100001));
        // old style without minor version
        assert_eq!(parse_server_version("9.6devel"), Some(90600));
        // new style without minor version, e.g.  */
        assert_eq!(parse_server_version("10devel"), Some(100000));
        assert_eq!(parse_server_version("13devel87"), Some(130000));
        // unknown
        assert_eq!(parse_server_version("unknown"), None);
    }
}
