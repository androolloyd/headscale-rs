// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Go 1.26.9 Time.UnmarshalJSON grammar for the existing UTC projection and
//! private native debug timestamp state.
//! Its disabled strict fallback accepts one-digit hours, comma fractions and
//! timezone hour/minute bounds of 24/60. Leap seconds and JSON escapes reject.

use std::fmt::Write as _;

use chrono::{NaiveDate, NaiveDateTime, SecondsFormat, TimeDelta, Timelike};

fn digits(source: &[u8], at: usize, len: usize) -> Option<u32> {
    source
        .get(at..at.checked_add(len)?)?
        .iter()
        .try_fold(0u32, |value, digit| {
            digit
                .is_ascii_digit()
                .then(|| value * 10 + u32::from(*digit - b'0'))
        })
}

fn parse_parts(source: &[u8]) -> Option<(NaiveDateTime, i64)> {
    // Time.UnmarshalJSON deliberately strips quotes without JSON unquoting.
    let source = source.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    if source.get(4) != Some(&b'-') || source.get(7) != Some(&b'-') || source.get(10) != Some(&b'T')
    {
        return None;
    }
    let year = i32::try_from(digits(source, 0, 4)?).ok()?;
    let month = digits(source, 5, 2)?;
    let day = digits(source, 8, 2)?;
    let hour_end = if source.get(12) == Some(&b':') {
        12
    } else {
        13
    };
    let hour = digits(source, 11, hour_end - 11)?;
    if source.get(hour_end) != Some(&b':') || source.get(hour_end + 3) != Some(&b':') {
        return None;
    }
    let minute = digits(source, hour_end + 1, 2)?;
    let second = digits(source, hour_end + 4, 2)?;
    let mut at = hour_end + 6;
    let mut nanos = 0u32;
    if matches!(source.get(at), Some(b'.' | b',')) {
        at += 1;
        let start = at;
        while let Some(digit) = source.get(at).filter(|byte| byte.is_ascii_digit()) {
            if at - start < 9 {
                nanos = nanos * 10 + u32::from(*digit - b'0');
            }
            at += 1;
        }
        if at == start {
            return None;
        }
        nanos *= 10u32.pow(9 - u32::try_from((at - start).min(9)).ok()?);
    }
    let offset = match source.get(at..)? {
        b"Z" => 0i64,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hour = digits(source, at + 1, 2)?;
            let minute = digits(source, at + 4, 2)?;
            if hour > 24 || minute > 60 {
                return None;
            }
            let seconds = i64::from((hour * 60 + minute) * 60);
            if *sign == b'-' { -seconds } else { seconds }
        }
        _ => return None,
    };
    let local =
        NaiveDate::from_ymd_opt(year, month, day)?.and_hms_nano_opt(hour, minute, second, nanos)?;
    Some((local, offset))
}

fn parse(source: &[u8]) -> Option<String> {
    let (local, offset) = parse_parts(source)?;
    Some(
        local
            .checked_sub_signed(TimeDelta::seconds(offset))?
            .and_utc()
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
    )
}

pub(super) fn json_time(source: &[u8]) -> Result<String, String> {
    parse(source).ok_or_else(|| "invalid RFC3339 time".into())
}

/// Retain the decoded fixed offset for native debug re-encoding. In contrast
/// to the existing UTC projection, Go Time.MarshalJSON retains nonzero offsets
/// and trims fractional trailing zeroes individually. Decode permits offsets
/// that strict marshaling later rejects; keep those two error phases separate.
pub(super) struct DebugTime {
    local: NaiveDateTime,
    offset: i64,
}

impl Default for DebugTime {
    fn default() -> Self {
        Self {
            local: NaiveDate::from_ymd_opt(1, 1, 1)
                .expect("year one")
                .and_hms_opt(0, 0, 0)
                .expect("midnight"),
            offset: 0,
        }
    }
}

impl DebugTime {
    pub(super) fn decode(source: &[u8]) -> Result<Self, String> {
        let (local, offset) = parse_parts(source).ok_or("invalid RFC3339 time")?;
        Ok(Self { local, offset })
    }

    pub(super) fn is_zero(&self) -> bool {
        self.local
            .checked_sub_signed(TimeDelta::seconds(self.offset))
            == Some(Self::default().local)
    }

    pub(super) fn text(&self) -> Result<String, String> {
        if self.offset.abs() >= 24 * 60 * 60 {
            return Err("Time.MarshalJSON: timezone hour outside of range [0,23]".into());
        }
        let mut out = self.local.format("%Y-%m-%dT%H:%M:%S").to_string();
        let nanos = self.local.nanosecond();
        if nanos != 0 {
            out.push('.');
            out.push_str(format!("{nanos:09}").trim_end_matches('0'));
        }
        if self.offset == 0 {
            out.push('Z');
        } else {
            let minutes = self.offset.abs() / 60;
            out.push(if self.offset < 0 { '-' } else { '+' });
            let _ = write!(out, "{:02}:{:02}", minutes / 60, minutes % 60);
        }
        Ok(out)
    }
}
