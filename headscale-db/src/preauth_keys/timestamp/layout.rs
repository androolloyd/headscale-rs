// Copyright 2009 The Go Authors. All rights reserved.
// Copyright (c) 2017 The Sqlite Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Go 1.26.9 time/format.go and glebarez/go-sqlite v1.22.0 sqlite.go.

//! SQLite driver parseTime, in source order. Unrecognized strings remain
//! driver strings and fail database/sql's time.Time scan; Gorm's now.Parse
//! string setter is not reached by normal model row scans.

use chrono::{DateTime, Duration, NaiveDate, Utc};

const STRING_LAYOUT: &str = "2006-01-02 15:04:05.999999999 -0700 MST";
const DRIVER_LAYOUTS: &[&str] = &[
    "2006-01-02 15:04:05.999999999-07:00",
    "2006-01-02T15:04:05.999999999-07:00",
    "2006-01-02 15:04:05.999999999",
    "2006-01-02T15:04:05.999999999",
    "2006-01-02 15:04:05",
    "2006-01-02T15:04:05",
    "2006-01-02 15:04",
    "2006-01-02T15:04",
    "2006-01-02",
];

struct Cursor<'a> {
    value: &'a str,
    at: usize,
}

impl Cursor<'_> {
    fn number(&mut self, count: usize, fixed: bool) -> Option<i32> {
        let start = self.at;
        let mut number = 0;
        while self.at - start < count
            && self
                .value
                .as_bytes()
                .get(self.at)
                .is_some_and(u8::is_ascii_digit)
        {
            number = number * 10 + i32::from(self.value.as_bytes()[self.at] - b'0');
            self.at += 1;
        }
        (self.at > start && (!fixed || self.at - start == count)).then_some(number)
    }

    fn literal(&mut self, expected: u8) -> Option<()> {
        if expected == b' ' {
            // Go skip permits exhausted input for a trailing layout space.
            if self.at < self.value.len() && self.value.as_bytes()[self.at] != b' ' {
                return None;
            }
            while self.value.as_bytes().get(self.at) == Some(&b' ') {
                self.at += 1;
            }
        } else {
            if self.value.as_bytes().get(self.at) != Some(&expected) {
                return None;
            }
            self.at += 1;
        }
        Some(())
    }

    fn fraction(&mut self) -> i32 {
        let bytes = self.value.as_bytes();
        if !matches!(bytes.get(self.at), Some(b'.' | b','))
            || !bytes.get(self.at + 1).is_some_and(u8::is_ascii_digit)
        {
            return 0;
        }
        self.at += 1;
        let start = self.at;
        let mut nanos = 0;
        while bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            if self.at - start < 9 {
                nanos = nanos * 10 + i32::from(bytes[self.at] - b'0');
            }
            self.at += 1;
        }
        for _ in (self.at - start).min(9)..9 {
            nanos *= 10;
        }
        nanos
    }

    fn offset(&mut self, colon: bool) -> Option<i32> {
        let sign = match self.value.as_bytes().get(self.at)? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        self.at += 1;
        let hour = self.number(2, true)?;
        if colon {
            self.literal(b':')?;
        }
        let minute = self.number(2, true)?;
        // Go's layout fallback permits offset hour 24 and minute 60.
        (hour <= 24 && minute <= 60).then_some(sign * (hour * 3600 + minute * 60))
    }

    fn zone_name(&mut self) -> Option<&str> {
        let value = &self.value[self.at..];
        if value.len() < 3 {
            return None;
        }
        let count = if value.starts_with("UTC") {
            3
        } else if let Some(offset) = value.strip_prefix("GMT") {
            3 + signed_name_len(offset).unwrap_or(0)
        } else if value.starts_with("ChST") || value.starts_with("MeST") {
            4
        } else if value.starts_with(['+', '-']) {
            signed_name_len(value)?
        } else {
            let count = value.bytes().take_while(u8::is_ascii_uppercase).count();
            match count {
                3 => count,
                4 if value.as_bytes()[3] == b'T' || value.starts_with("WITA") => count,
                5 if value.as_bytes()[4] == b'T' => count,
                _ => return None,
            }
        };
        let start = self.at;
        self.at += count;
        Some(&self.value[start..self.at])
    }
}

fn signed_name_len(value: &str) -> Option<usize> {
    if !value.starts_with(['+', '-']) {
        return None;
    }
    let mut count = 1;
    let mut hour = 0_u64;
    for digit in value.as_bytes()[1..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
    {
        hour = hour
            .checked_mul(10)?
            .checked_add(u64::from(*digit - b'0'))?;
        count += 1;
    }
    (count > 1 && hour <= 23).then_some(count)
}

fn parse(layout: &str, value: &str) -> Option<DateTime<Utc>> {
    let mut cursor = Cursor { value, at: 0 };
    let mut rest = layout;
    let (mut year, mut month, mut day) = (0, 1, 1);
    let (mut hour, mut minute, mut second, mut nanos) = (0, 0, 0, 0);
    let mut offset = 0;
    let mut utc = false;
    while !rest.is_empty() {
        if rest.starts_with(".999999999") {
            nanos = cursor.fraction();
            rest = &rest[10..];
            continue;
        }
        let token = [
            "2006", "-07:00", "-0700", "MST", "01", "02", "04", "05", "15",
        ]
        .into_iter()
        .find(|token| rest.starts_with(token));
        let Some(token) = token else {
            let literal = rest.as_bytes()[0];
            cursor.literal(literal)?;
            rest = &rest[1..];
            if literal == b' ' {
                rest = rest.trim_start_matches(' ');
            }
            continue;
        };
        rest = &rest[token.len()..];
        match token {
            "2006" => year = cursor.number(4, true)?,
            "01" => month = cursor.number(2, true)?,
            "02" => day = cursor.number(2, true)?,
            "15" => hour = cursor.number(2, false)?,
            "04" => minute = cursor.number(2, true)?,
            "05" => {
                second = cursor.number(2, true)?;
                if !rest.starts_with(".999999999") {
                    nanos = cursor.fraction();
                }
            }
            "MST" => utc = cursor.zone_name()? == "UTC",
            _ => offset = cursor.offset(token == "-07:00")?,
        }
        if !(1..=12).contains(&month) || hour >= 24 || minute >= 60 || second >= 60 {
            return None;
        }
    }
    if cursor.at != value.len() {
        return None;
    }
    let time = NaiveDate::from_ymd_opt(year, month as u32, day as u32)?
        .and_hms_nano_opt(hour as u32, minute as u32, second as u32, nanos as u32)?
        .and_utc();
    // UTC name overrides an earlier numeric offset in Go's layout parser.
    // Other name/location metadata never changes the explicit-offset instant.
    time.checked_sub_signed(Duration::seconds(if utc { 0 } else { i64::from(offset) }))
}

pub(super) fn read(value: &str) -> Option<DateTime<Utc>> {
    // Driver parseTimeString tries time.Time.String first and strips any
    // monotonic tail before trimming Unicode whitespace around this form.
    let string_value = value
        .find("m=")
        .filter(|index| *index > 0)
        .map_or(value, |index| &value[..index])
        .trim();
    if let Some(time) = parse(STRING_LAYOUT, string_value) {
        return Some(time);
    }
    let without_z = value.strip_suffix('Z').unwrap_or(value);
    DRIVER_LAYOUTS
        .iter()
        .find_map(|layout| parse(layout, without_z))
}
