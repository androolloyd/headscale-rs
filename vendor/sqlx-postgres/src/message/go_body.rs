//! Backend framing adapted from pgx v5.10.0 pgproto3's Decode methods.
//! Copyright (c) 2013-2021 Jack Christensen
//! MIT license and permission notice: LICENSE-GO-PGX in this vendor directory.

use crate::error::Error;
use crate::message::BackendMessageFormat;

// NewFrontend's default, from pgproto3/pgproto3.go. Check before reserving the
// body, including while the server has supplied only its five-byte header.
pub(crate) const MAX_GO_MESSAGE_BODY_LEN: usize = 0x3fff_fffe;

/// Validate the framing of every native message, even one the query executor
/// discards. No storage is allocated from a count supplied by the backend.
pub(crate) fn validate_go_body(
    format: &BackendMessageFormat,
    mut body: &[u8],
) -> Result<(), Error> {
    use BackendMessageFormat::*;
    match format {
        BindComplete | CloseComplete | CopyDone | EmptyQueryResponse | NoData | ParseComplete
        | PortalSuspended => {
            if !body.is_empty() {
                return Err(err_protocol!("nonempty native {format:?} body"));
            }
        }
        CommandComplete => {
            let _ = cstring(&mut body)?;
            if !body.is_empty() {
                return Err(err_protocol!("CommandComplete string terminated too early"));
            }
        }
        CopyData => {}
        CopyInResponse | CopyOutResponse => {
            let prefix = take(&mut body, 3)?;
            let count = usize::from(u16::from_be_bytes([prefix[1], prefix[2]]));
            if body.len() != count * 2 {
                return Err(err_protocol!("invalid native COPY format-code body length"));
            }
        }
        BackendKeyData => {
            // Protocol 3.2 cancellation keys can have more than four bytes.
            let _ = take(&mut body, 8)?;
        }
        NotificationResponse => {
            let _ = take(&mut body, 4)?;
            let _ = cstring(&mut body)?;
            let _ = cstring(&mut body)?;
        }
        ParameterStatus => {
            let _ = cstring(&mut body)?;
            let _ = cstring(&mut body)?;
        }
        ParameterDescription => {
            // pgx ignores the reported count, inferring OIDs from complete
            // four-byte chunks after the count. A partial tail is ignored.
            let _ = take(&mut body, 2)?;
        }
        ReadyForQuery => {
            if body.len() != 1 {
                return Err(err_protocol!("invalid native ReadyForQuery length"));
            }
        }
        RowDescription => {
            let count = count16(&mut body)?;
            for _ in 0..count {
                let _ = cstring(&mut body)?;
                let _ = take(&mut body, 18)?;
            }
        }
        DataRow => {
            let count = count16(&mut body)?;
            for _ in 0..count {
                let bytes = take(&mut body, 4)?;
                let length = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                match length {
                    -1 => {}
                    0.. => {
                        let _ = take(&mut body, length as usize)?;
                    }
                    _ => return Err(err_protocol!("invalid native DataRow value length")),
                }
            }
        }
        ErrorResponse | NoticeResponse => loop {
            let field = take(&mut body, 1)?[0];
            if field == 0 {
                break;
            }
            let _ = cstring(&mut body)?;
        },
        NegotiateProtocolVersion => {
            let prefix = take(&mut body, 8)?;
            let count = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
            if u64::from(count) > body.len() as u64 {
                return Err(err_protocol!("invalid native protocol option count"));
            }
            for _ in 0..count {
                let _ = cstring(&mut body)?;
            }
        }
        Authentication => {
            let code = take(&mut body, 4)?;
            match u32::from_be_bytes([code[0], code[1], code[2], code[3]]) {
                0 | 3 if !body.is_empty() => {
                    return Err(err_protocol!(
                        "invalid native authentication message length"
                    ));
                }
                5 if body.len() != 4 => {
                    return Err(err_protocol!("invalid native MD5 authentication length"));
                }
                10 => {
                    // pgx's mechanism loop intentionally ignores a final
                    // zero or one-byte remainder, including a nonzero byte.
                    while body.len() > 1 {
                        let _ = cstring(&mut body)?;
                    }
                }
                0 | 3 | 5 | 7 | 8 | 11 | 12 => {}
                6 => return Err(err_protocol!("AuthTypeSCMCreds is unimplemented")),
                9 => return Err(err_protocol!("AuthTypeSSPI is unimplemented")),
                code => return Err(err_protocol!("unknown native authentication type: {code}")),
            }
        }
    }
    Ok(())
}

fn count16(body: &mut &[u8]) -> Result<u16, Error> {
    let bytes = take(body, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(body: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    let current = *body;
    let bytes = current
        .get(..count)
        .ok_or_else(|| err_protocol!("truncated native PostgreSQL message body"))?;
    *body = &current[count..];
    Ok(bytes)
}

fn cstring<'a>(body: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let current = *body;
    let end = memchr::memchr(0, current)
        .ok_or_else(|| err_protocol!("unterminated native PostgreSQL message string"))?;
    let bytes = &current[..end];
    *body = &current[end + 1..];
    Ok(bytes)
}
