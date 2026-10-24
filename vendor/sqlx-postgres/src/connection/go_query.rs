//! Native query paths following pgx v5.10.0 conn.go and values.go.
//! Copyright (c) 2013-2021 Jack Christensen
//! MIT license and permission notice: LICENSE-GO-PGX in this vendor directory.

use crate::common::StatementCache;
use crate::error::Error;
use crate::io::StatementId;
use crate::io::{PortalId, ProtocolEncode};
use crate::message::{self, Bind, FrontendMessage, Parse, Query};
use crate::options::GoQueryExecMode;
use crate::statement::PgStatementMetadata;
use crate::PgArguments;
use crate::{types::Oid, PgValueFormat};
use std::sync::{Arc, Mutex, MutexGuard};

mod sanitize;
mod text;

pub(super) struct GoQueryState {
    pub(super) mode: GoQueryExecMode,
    pub(super) descriptions: StatementCache<Arc<PgStatementMetadata>>,
    pub(super) invalidated: RetiredStatements,
}

#[derive(Clone, Default)]
pub(super) struct RetiredStatements(Arc<Mutex<Vec<StatementId>>>);

impl RetiredStatements {
    fn lock(&self) -> MutexGuard<'_, Vec<StatementId>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub(super) fn push(&self, statement: StatementId) {
        self.lock().push(statement);
    }

    pub(super) fn snapshot(&self) -> Vec<StatementId> {
        self.lock().clone()
    }

    pub(super) fn acknowledge(&self, count: usize) {
        drop(self.lock().drain(..count));
    }

    pub(super) fn preparing(&self, statement: StatementId) -> PreparingStatement {
        PreparingStatement {
            retired: self.clone(),
            statement: Some(statement),
        }
    }
}

// A prepare future can disappear at any await after Parse reaches the server.
// Retire its stable name on Drop without borrowing the connection across that
// future. Ordinary custom-type metadata queries can still run while it is armed.
pub(super) struct PreparingStatement {
    retired: RetiredStatements,
    statement: Option<StatementId>,
}

impl PreparingStatement {
    pub(super) fn complete(&mut self) {
        self.statement = None;
    }
}

impl Drop for PreparingStatement {
    fn drop(&mut self) {
        if let Some(statement) = self.statement {
            self.retired.push(statement);
        }
    }
}

impl GoQueryState {
    pub(super) fn new(mode: GoQueryExecMode, capacity: usize) -> Self {
        Self {
            mode,
            descriptions: StatementCache::new(capacity),
            invalidated: RetiredStatements::default(),
        }
    }
}

pub(super) fn arguments(arguments: &PgArguments) -> Result<Vec<Option<String>>, Error> {
    let mut bytes = &arguments.buffer[..];
    let mut output = Vec::with_capacity(arguments.types.len());
    for ty in &arguments.types {
        let length = i32::from_be_bytes(
            text::take(&mut bytes, 4)?
                .try_into()
                .map_err(Error::protocol)?,
        );
        if length == -1 {
            output.push(None);
        } else {
            let length = usize::try_from(length).map_err(Error::protocol)?;
            output.push(Some(text::value(text::take(&mut bytes, length)?, ty, 0)?));
        }
    }
    if !bytes.is_empty() {
        return Err(err_protocol!("trailing native query argument bytes"));
    }
    Ok(output)
}

fn bind_buffer(arguments: &[Option<String>]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for argument in arguments {
        if let Some(argument) = argument {
            let length = i32::try_from(argument.len()).map_err(Error::protocol)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(argument.as_bytes());
        } else {
            output.extend_from_slice(&(-1_i32).to_be_bytes());
        }
    }
    Ok(output)
}

pub(super) struct EncodedMessages(Vec<u8>);

impl ProtocolEncode<'_> for EncodedMessages {
    fn encode_with(&self, output: &mut Vec<u8>, _: ()) -> Result<(), Error> {
        output.try_reserve(self.0.len()).map_err(Error::protocol)?;
        output.extend_from_slice(&self.0);
        Ok(())
    }
}

pub(super) fn query_frame(sql: &str) -> Result<EncodedMessages, Error> {
    let mut output = Vec::new();
    Query(sql).encode_msg(&mut output)?;
    Ok(EncodedMessages(output))
}

pub(super) fn prepare_frame(
    sql: &str,
    statement: StatementId,
    parameters: &[Oid],
    describe: bool,
) -> Result<EncodedMessages, Error> {
    let mut output = Vec::new();
    Parse {
        param_types: parameters,
        query: sql,
        statement,
    }
    .encode_msg(&mut output)?;
    if describe {
        message::Describe::Statement(statement).encode_msg(&mut output)?;
    }
    message::Sync.encode_msg(&mut output)?;
    Ok(EncodedMessages(output))
}

pub(super) fn close_frame(statements: &[StatementId]) -> Result<EncodedMessages, Error> {
    let mut output = Vec::new();
    for statement in statements {
        message::Close::Statement(*statement).encode_msg(&mut output)?;
    }
    message::Sync.encode_msg(&mut output)?;
    Ok(EncodedMessages(output))
}

pub(super) fn extended_frame(
    sql: &str,
    statement: StatementId,
    parse_types: Option<&[Oid]>,
    arguments: &[Option<String>],
    result_formats: Option<&[PgValueFormat]>,
) -> Result<EncodedMessages, Error> {
    // Fully encode away from the live transport. Any client-side failure
    // discards this vector and cannot strand a partial extended-query cycle.
    let num_params = u16::try_from(arguments.len()).map_err(Error::protocol)?;
    let parameters = bind_buffer(arguments)?;
    let describe = result_formats.is_none();
    let result_formats = result_formats.unwrap_or_default();
    u16::try_from(result_formats.len()).map_err(Error::protocol)?;
    let mut output = Vec::new();
    if let Some(types) = parse_types {
        Parse {
            param_types: types,
            query: sql,
            statement,
        }
        .encode_msg(&mut output)?;
    }
    Bind {
        portal: PortalId::UNNAMED,
        statement,
        formats: &[PgValueFormat::Text],
        num_params,
        params: &parameters,
        result_formats,
    }
    .encode_msg(&mut output)?;
    if describe {
        message::Describe::Portal(PortalId::UNNAMED).encode_msg(&mut output)?;
    }
    message::Execute {
        portal: PortalId::UNNAMED,
        limit: 0,
    }
    .encode_msg(&mut output)?;
    message::Sync.encode_msg(&mut output)?;
    Ok(EncodedMessages(output))
}

/// pgx stdlib.QueryContext supplies databaseSQLResultFormats rather than the
/// core type map's preferences. Every OID outside this list requests text.
pub(super) fn database_sql_result_format(oid: Oid) -> PgValueFormat {
    match oid.0 {
        // bool, bytea, int8, int2, int4, oid, xid, cid, float4, float8,
        // date, timestamp, timestamptz.
        16 | 17 | 20 | 21 | 23 | 26 | 28 | 29 | 700 | 701 | 1082 | 1114 | 1184 => {
            PgValueFormat::Binary
        }
        _ => PgValueFormat::Text,
    }
}

pub(super) fn preferred_result_format(oid: Oid) -> PgValueFormat {
    // pgx v5.10.0 pgtype's default registered codecs. Unknown/custom OIDs use
    // text; SQLx's discovered type kind does not register a pgx codec. Arrays
    // prefer binary whenever their element codec supports it, including text,
    // JSON and XML elements whose scalar codecs prefer text.
    match oid.0 {
        // Binary-preferring scalar codecs.
        16 | 17 | 18 | 20 | 21 | 23 | 26 | 27 | 28 | 29 | 600 | 601 | 602 | 603 | 604 | 628
        | 650 | 700 | 701 | 718 | 774 | 829 | 869 | 1082 | 1083 | 1114 | 1184 | 1186 | 1560
        | 1562 | 1700 | 2249 | 2950 | 3614 | 5069
        // Registered ranges and multiranges.
        | 3904 | 3906 | 3908 | 3910 | 3912 | 3926 | 4451 | 4532 | 4533 | 4534 | 4535 | 4536
        // Registered binary-capable arrays. _aclitem and _jsonpath are text;
        // timetz, _macaddr8 and multirange arrays are not in the default map.
        | 143 | 199 | 271 | 629 | 651 | 719 | 1000 | 1001 | 1002 | 1003 | 1005 | 1007 | 1009
        | 1010 | 1011 | 1012 | 1014 | 1015 | 1016 | 1017 | 1018 | 1019 | 1020 | 1021 | 1022
        | 1027 | 1028 | 1040 | 1041 | 1115 | 1182 | 1183 | 1185 | 1187 | 1231 | 1561 | 1563
        | 2287 | 2951 | 3643 | 3807 | 3905 | 3907 | 3909 | 3911 | 3913 | 3927 => {
            PgValueFormat::Binary
        }
        _ => PgValueFormat::Text,
    }
}

pub(super) fn simple(sql: &str, arguments: &[Option<String>]) -> Result<String, Error> {
    sanitize::query(sql, arguments)
}
