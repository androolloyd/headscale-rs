//! Query mode names from pgx v5.10.0 conn.go.
//! Copyright (c) 2013-2021 Jack Christensen
//! MIT license and permission notice: LICENSE-GO-PGX in this vendor directory.
use super::config_error;
use sqlx_core::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GoQueryExecMode {
    CacheStatement,
    CacheDescribe,
    DescribeExec,
    Exec,
    SimpleProtocol,
}

impl GoQueryExecMode {
    pub(super) fn parse(value: Option<&str>) -> Result<Self, Error> {
        match value {
            None | Some("cache_statement") => Ok(Self::CacheStatement),
            Some("cache_describe") => Ok(Self::CacheDescribe),
            Some("describe_exec") => Ok(Self::DescribeExec),
            Some("exec") => Ok(Self::Exec),
            Some("simple_protocol") => Ok(Self::SimpleProtocol),
            _ => Err(config_error("invalid Postgres query execution mode")),
        }
    }
}
