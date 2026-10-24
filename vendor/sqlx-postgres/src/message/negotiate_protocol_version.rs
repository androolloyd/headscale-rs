//! Pinned pgx v5.10.0 pgproto3 protocol negotiation framing.
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

use sqlx_core::bytes::{Buf, Bytes};

use crate::error::Error;
use crate::message::{BackendMessage, BackendMessageFormat};

pub struct NegotiateProtocolVersion {
    pub newest_minor_protocol: u32,
}

impl BackendMessage for NegotiateProtocolVersion {
    const FORMAT: BackendMessageFormat = BackendMessageFormat::NegotiateProtocolVersion;

    fn decode_body(mut buf: Bytes) -> Result<Self, Error> {
        if buf.len() < 8 {
            return Err(err_protocol!("invalid NegotiateProtocolVersion length"));
        }
        let newest_minor_protocol = buf.get_u32();
        let count = buf.get_u32();
        // Every option needs at least one terminating byte. Do not allocate
        // from a server-provided count. pgx ignores the decoded option names.
        if u64::from(count) > u64::try_from(buf.len()).unwrap_or(u64::MAX) {
            return Err(err_protocol!("invalid protocol negotiation option count"));
        }
        for _ in 0..count {
            let end = memchr::memchr(0, &buf)
                .ok_or_else(|| err_protocol!("unterminated protocol negotiation option"))?;
            buf.advance(end + 1);
        }
        Ok(Self {
            newest_minor_protocol,
        })
    }
}
