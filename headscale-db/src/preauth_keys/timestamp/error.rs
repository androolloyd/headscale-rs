// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Go 1.26.9 database/sql/convert.go convertAssignRows.

//! A driver value that cannot scan into Gorm's pooled **time.Time. Native
//! conversion diagnostics do not include the source text.
//! Ordinary model SELECT * reads supply physical SQLite column metadata;
//! other callers retain the native conversion cause without an invented index.

use std::fmt;

#[derive(Debug)]
pub(crate) enum TimestampScanError {
    String(Option<(i64, &'static str)>),
    Int64(Option<(i64, &'static str)>),
    Float64(Option<(i64, &'static str)>),
    Bytes(Option<(i64, &'static str)>),
}

impl TimestampScanError {
    pub(super) fn with_column(self, index: Option<i64>, column: &str) -> Self {
        let context = index
            .filter(|index| *index >= 0)
            .and_then(|index| match column {
                "expiration" => Some((index, "expiration")),
                "expiry" => Some((index, "expiry")),
                _ => None,
            });
        match self {
            Self::String(_) => Self::String(context),
            Self::Int64(_) => Self::Int64(context),
            Self::Float64(_) => Self::Float64(context),
            Self::Bytes(_) => Self::Bytes(context),
        }
    }

    pub(crate) fn native_message(&self) -> String {
        let (kind, context) = match self {
            Self::String(context) => ("string", context),
            Self::Int64(context) => ("int64", context),
            Self::Float64(context) => ("float64", context),
            Self::Bytes(context) => ("[]uint8", context),
        };
        let cause =
            format!("unsupported Scan, storing driver.Value type {kind} into type *time.Time");
        match context {
            Some((index, column)) => {
                format!("sql: Scan error on column index {index}, name \"{column}\": {cause}")
            }
            None => cause,
        }
    }
}

impl fmt::Display for TimestampScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid persisted expiration timestamp")
    }
}

impl std::error::Error for TimestampScanError {}
