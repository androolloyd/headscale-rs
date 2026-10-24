// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Go 1.26.9 time.Parse RFC3339Nano and protobuf v1.36.11 timestamp rules.
// Source terms are retained in LICENSE-GO-STDLIB and LICENSE-PROTOBUF-GO.

//! The RFC3339 fast path falls back to Go's layout parser. The fallback also
//! accepts a one-digit hour, comma fractions and offset hour/minute boundaries
//! of 24/60. Timestamp conversion depends only on the resulting UTC instant.

use headscale_api_acl::go_strconv::quote_time;

const LAYOUT: &str = "2006-01-02T15:04:05.999999999Z07:00";

pub(super) struct Parsed {
    pub(super) seconds: i64,
    pub(super) nanos: i32,
}

struct Parser<'a> {
    value: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn cannot(&self, layout: &str, at: usize) -> String {
        format!(
            "parsing time {} as {}: cannot parse {} as {}",
            quote_time(self.value),
            quote_time(LAYOUT),
            quote_time(&self.value[at..]),
            quote_time(layout)
        )
    }

    fn range(&self, name: &str) -> String {
        format!(
            "parsing time {}: {name} out of range",
            quote_time(self.value)
        )
    }

    fn literal(&mut self, expected: u8) -> Result<(), String> {
        if self.value.as_bytes().get(self.at) != Some(&expected) {
            return Err(self.cannot(&char::from(expected).to_string(), self.at));
        }
        self.at += 1;
        Ok(())
    }

    fn number(&mut self, layout: &str, fixed: bool) -> Result<i64, String> {
        let start = self.at;
        let bytes = self.value.as_bytes();
        let Some(&first) = bytes.get(start).filter(|byte| byte.is_ascii_digit()) else {
            return Err(self.cannot(layout, start));
        };
        let mut value = i64::from(first - b'0');
        self.at += 1;
        if let Some(&next) = bytes.get(self.at).filter(|byte| byte.is_ascii_digit()) {
            value = value * 10 + i64::from(next - b'0');
            self.at += 1;
        } else if fixed {
            self.at = start;
            return Err(self.cannot(layout, start));
        }
        Ok(value)
    }
}

/// Parse the accepted RFC3339Nano layout without host-local timezone state.
/// Zone identities affect Go Time's location, but not Unix seconds or nanos.
pub(super) fn parse(value: &str) -> Result<Parsed, String> {
    let mut parser = Parser { value, at: 0 };
    let bytes = value.as_bytes();
    let year = bytes
        .get(..4)
        .filter(|year| year.iter().all(u8::is_ascii_digit))
        .ok_or_else(|| parser.cannot("2006", 0))?
        .iter()
        .fold(0i64, |year, byte| year * 10 + i64::from(byte - b'0'));
    parser.at = 4;
    parser.literal(b'-')?;
    let month = parser.number("01", true)?;
    if !(1..=12).contains(&month) {
        return Err(parser.range("month"));
    }
    parser.literal(b'-')?;
    let day = parser.number("02", true)?;
    parser.literal(b'T')?;
    let hour = parser.number("15", false)?;
    if hour >= 24 {
        return Err(parser.range("hour"));
    }
    parser.literal(b':')?;
    let minute = parser.number("04", true)?;
    if minute >= 60 {
        return Err(parser.range("minute"));
    }
    parser.literal(b':')?;
    let second = parser.number("05", true)?;
    if second >= 60 {
        return Err(parser.range("second"));
    }

    let mut nanos = 0;
    if matches!(bytes.get(parser.at), Some(b'.' | b','))
        && bytes.get(parser.at + 1).is_some_and(u8::is_ascii_digit)
    {
        parser.at += 1;
        let start = parser.at;
        while bytes.get(parser.at).is_some_and(u8::is_ascii_digit) {
            let index = parser.at - start;
            if index < 9 {
                nanos = nanos * 10 + i32::from(bytes[parser.at] - b'0');
            }
            parser.at += 1;
        }
        for _ in (parser.at - start).min(9)..9 {
            nanos *= 10;
        }
    }

    let zone = parser.at;
    let offset = if bytes.get(zone) == Some(&b'Z') {
        parser.at += 1;
        0
    } else {
        let rest = bytes.get(zone..).unwrap_or_default();
        if rest.len() < 6 || rest[3] != b':' {
            return Err(parser.cannot("Z07:00", zone));
        }
        // Go consumes six bytes before getnum/range checks. Range errors win
        // over an invalid minute or sign, and minute range wins over hour.
        let hour = two_digits(&rest[1..3]);
        let minute = hour.and_then(|_| two_digits(&rest[4..6]));
        if minute.is_some_and(|minute| minute > 60) {
            return Err(parser.range("time zone offset minute"));
        }
        if hour.is_some_and(|hour| hour > 24) {
            return Err(parser.range("time zone offset hour"));
        }
        let (Some(hour), Some(minute)) = (hour, minute) else {
            return Err(parser.cannot("Z07:00", zone));
        };
        let offset = (hour * 60 + minute) * 60;
        let offset = match rest[0] {
            b'+' => offset,
            b'-' => -offset,
            _ => return Err(parser.cannot("Z07:00", zone)),
        };
        parser.at += 6;
        offset
    };
    if parser.at != bytes.len() {
        return Err(format!(
            "parsing time {}: extra text: {}",
            quote_time(value),
            quote_time(&value[parser.at..])
        ));
    }
    // Go validates the calendar day after all layout fields and extra text.
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > days_in_month {
        return Err(parser.range("day"));
    }

    // Gregorian civil date to Unix epoch days. Euclidean division retains
    // year zero's January/February in the preceding 400-year era.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_in_era = adjusted_year - era * 400;
    let march_month = month + if month > 2 { -3 } else { 9 };
    let day_in_year = (153 * march_month + 2) / 5 + day - 1;
    let day_in_era = year_in_era * 365 + year_in_era / 4 - year_in_era / 100 + day_in_year;
    let days = era * 146_097 + day_in_era - 719_468;
    Ok(Parsed {
        seconds: days * 86_400 + hour * 3_600 + minute * 60 + second - offset,
        nanos,
    })
}

fn two_digits(bytes: &[u8]) -> Option<i64> {
    bytes
        .iter()
        .all(u8::is_ascii_digit)
        .then(|| i64::from(bytes[0] - b'0') * 10 + i64::from(bytes[1] - b'0'))
}

/// Protojson adds range checks and a dot-fraction precision check after Parse.
/// Its check deliberately searches for '.', so comma fractions follow Go's
/// truncation even when they contain more than nine digits.
pub(super) fn parse_body(value: &str, raw: &str) -> Result<Parsed, String> {
    let invalid = || format!("invalid google.protobuf.Timestamp value {raw}");
    let parsed = parse(value).map_err(|_| invalid())?;
    if !(super::MIN_TIMESTAMP_SECONDS..=super::MAX_TIMESTAMP_SECONDS).contains(&parsed.seconds) {
        return Err(format!(
            "google.protobuf.Timestamp value out of range: {raw}"
        ));
    }
    if let (Some(fraction), Some(zone)) = (value.rfind('.'), value.rfind(['Z', '-', '+']))
        && zone >= fraction
        && zone - fraction > 10
    {
        return Err(invalid());
    }
    Ok(parsed)
}
