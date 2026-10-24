use crate::HashMap;

use crate::common::StatementCache;
use crate::connection::{go_auth, sasl, stream::PgStream};
use crate::error::Error;
use crate::io::StatementId;
use crate::message::{
    Authentication, BackendKeyData, BackendMessageFormat, NegotiateProtocolVersion, Password,
    ReadyForQuery, Startup,
};
use crate::options::GoAuthMethod;
use crate::{PgConnectOptions, PgConnection};

use super::PgConnectionInner;

// https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.3
// https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.11

impl PgConnection {
    pub(crate) async fn establish(options: &PgConnectOptions) -> Result<Self, Error> {
        // Upgrade to TLS if we were asked to and the server supports it
        let mut stream = PgStream::connect(options).await?;

        // To begin a session, a frontend opens a connection to the server
        // and sends a startup message.

        let mut params = if let Some(go) = &options.go_compat {
            go.runtime_params
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>()
        } else {
            vec![
                // Sets the display format for date and time values,
                // as well as the rules for interpreting ambiguous date input values.
                ("DateStyle", "ISO, MDY"),
                // Sets the client-side encoding (character set).
                // <https://www.postgresql.org/docs/devel/multibyte.html#MULTIBYTE-CHARSET-SUPPORTED>
                ("client_encoding", "UTF8"),
                // Sets the time zone for displaying and interpreting time stamps.
                ("TimeZone", "UTC"),
            ]
        };

        if let Some(ref extra_float_digits) = options.extra_float_digits {
            params.push(("extra_float_digits", extra_float_digits));
        }

        if let Some(ref application_name) = options.application_name {
            params.push(("application_name", application_name));
        }

        if let Some(ref options) = options.options {
            params.push(("options", options));
        }

        stream.write(Startup {
            protocol_version: options
                .go_compat
                .as_ref()
                .map_or(196_608, |go| go.max_protocol_version),
            username: Some(&options.username),
            database: options.database.as_deref(),
            params: &params,
        })?;

        stream.flush().await?;

        // The server then uses this information and the contents of
        // its configuration files (such as pg_hba.conf) to determine whether the connection is
        // provisionally acceptable, and what additional
        // authentication is required (if any).

        let mut process_id = 0;
        let mut secret_key = sqlx_core::bytes::Bytes::new();
        let transaction_status;
        let mut client_finished_auth = false;

        loop {
            let message = stream.recv().await?;
            match message.format {
                BackendMessageFormat::Authentication => {
                    if let Some(go) = &options.go_compat {
                        let code: [u8; 4] = message
                            .contents
                            .get(..4)
                            .ok_or_else(|| err_protocol!("truncated authentication request"))?
                            .try_into()
                            .map_err(Error::protocol)?;
                        let code = u32::from_be_bytes(code);
                        let method = match code {
                            0 if go.require_auth.auth_required && !client_finished_auth => {
                                Some(GoAuthMethod::None)
                            }
                            3 => Some(GoAuthMethod::Password),
                            5 => Some(GoAuthMethod::Md5),
                            7 => Some(GoAuthMethod::Gss),
                            9 => Some(GoAuthMethod::Sspi),
                            10 => Some(GoAuthMethod::ScramSha256),
                            _ => None,
                        };
                        if let Some(method) = method {
                            // Reject a forbidden method before sending credentials.
                            go.require_auth.check(method)?;
                        }
                        if code == 7 {
                            // Pinned headscale/Gorm register no pgx GSS provider.
                            // Kerberos settings are inert for other auth methods.
                            return Err(err_protocol!(
                                "kerberos error: no GSSAPI provider registered, see https://github.com/otan/gopgkrb5"
                            ));
                        }
                    }
                    match message.decode()? {
                        Authentication::Ok => {
                            // the authentication exchange is successfully completed
                            // do nothing; no more information is required to continue
                        }

                        Authentication::CleartextPassword => {
                            // The frontend must now send a [PasswordMessage] containing the
                            // password in clear-text form.

                            stream
                                .send(Password::Cleartext(
                                    options.password.as_deref().unwrap_or_default(),
                                ))
                                .await?;
                            client_finished_auth = true;
                        }

                        Authentication::Md5Password(body) => {
                            // The frontend must now send a [PasswordMessage] containing the
                            // password (with user name) encrypted via MD5, then encrypted again
                            // using the 4-byte random salt specified in the
                            // [AuthenticationMD5Password] message.

                            stream
                                .send(Password::Md5 {
                                    username: &options.username,
                                    password: options.password.as_deref().unwrap_or_default(),
                                    salt: body.salt,
                                })
                                .await?;
                            client_finished_auth = true;
                        }

                        Authentication::Sasl(body) => {
                            if options.go_compat.is_some() {
                                go_auth::authenticate(&mut stream, options, body).await?;
                            } else {
                                sasl::authenticate(&mut stream, options, body).await?;
                            }
                            client_finished_auth = true;
                        }

                        method => {
                            return Err(err_protocol!(
                                "unsupported authentication method: {:?}",
                                method
                            ));
                        }
                    }
                }

                BackendMessageFormat::BackendKeyData => {
                    // provides secret-key data that the frontend must save if it wants to be
                    // able to issue cancel requests later

                    let data: BackendKeyData = message.decode()?;

                    process_id = data.process_id;
                    secret_key = data.secret_key;
                }

                BackendMessageFormat::NegotiateProtocolVersion => {
                    let go = options.go_compat.as_ref().ok_or_else(|| {
                        err_protocol!(
                            "unexpected protocol negotiation for ordinary SQLx connection"
                        )
                    })?;
                    let negotiation: NegotiateProtocolVersion = message.decode()?;
                    let server_version = (3_u32 << 16) | negotiation.newest_minor_protocol;
                    if server_version < go.min_protocol_version {
                        return Err(err_protocol!("server protocol version too low"));
                    }
                }

                BackendMessageFormat::ReadyForQuery => {
                    // start-up is completed. The frontend can now issue commands
                    transaction_status = message.decode::<ReadyForQuery>()?.transaction_status;

                    break;
                }

                _ => {
                    return Err(err_protocol!(
                        "establish: unexpected message: {:?}",
                        message.format
                    ))
                }
            }
        }

        Ok(PgConnection {
            inner: Box::new(PgConnectionInner {
                stream,
                process_id,
                secret_key,
                transaction_status,
                transaction_depth: 0,
                pending_ready_for_query_count: 0,
                next_statement_id: StatementId::NAMED_START,
                cache_statement: StatementCache::new(options.statement_cache_capacity),
                go_query: options.go_compat.as_ref().map(|go| {
                    super::go_query::GoQueryState::new(
                        go.query_exec_mode,
                        go.description_cache_capacity,
                    )
                }),
                cache_type_oid: HashMap::new(),
                cache_type_info: HashMap::new(),
                cache_elem_type_to_array: HashMap::new(),
                log_settings: options.log_settings.clone(),
            }),
        })
    }
}
