// Copyright 2009 The Go Authors. All rights reserved.
// Go 1.26.9 net/http/header.go and time/format.go; see LICENSE-GO.

//! The three ordered net/http.ParseTime layouts. Weekdays are checked as
//! tokens, not compared with the date. RFC850 uses Go's fixed 69 year pivot.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod local;

const SHORT_DAYS: &[&[u8]] = &[b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const LONG_DAYS: &[&[u8]] = &[
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];
const MONTHS: &[&[u8]] = &[
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn literal(&mut self, text: &[u8]) -> Option<()> {
        for &byte in text {
            if byte == b' ' {
                if self.0.first().is_some_and(|byte| *byte != b' ') {
                    return None;
                }
                while self.0.first() == Some(&b' ') {
                    self.0 = &self.0[1..];
                }
            } else {
                if self.0.first() != Some(&byte) {
                    return None;
                }
                self.0 = &self.0[1..];
            }
        }
        Some(())
    }

    fn word(&mut self, words: &[&[u8]]) -> Option<usize> {
        let index = words.iter().position(|word| {
            self.0
                .get(..word.len())
                .is_some_and(|value| value.eq_ignore_ascii_case(word))
        })?;
        self.0 = &self.0[words[index].len()..];
        Some(index)
    }

    fn number(&mut self, width: usize, fixed: bool) -> Option<i64> {
        let count = self
            .0
            .iter()
            .take(width)
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if count == 0 || fixed && count != width {
            return None;
        }
        let mut number = 0;
        for byte in &self.0[..count] {
            number = number * 10 + i64::from(byte - b'0');
        }
        self.0 = &self.0[count..];
        Some(number)
    }

    fn year(&mut self, short: bool) -> Option<i64> {
        if !short {
            return self.number(4, true);
        }
        let raw = self.0.get(..2)?;
        let value: i64 = std::str::from_utf8(raw).ok()?.parse().ok()?;
        self.0 = &self.0[2..];
        Some(value + if value >= 69 { 1900 } else { 2000 })
    }

    fn clock(&mut self) -> Option<(i64, i64, i64, u32)> {
        let hour = self.number(2, false)?;
        self.literal(b":")?;
        let minute = self.number(2, true)?;
        self.literal(b":")?;
        let second = self.number(2, true)?;
        if hour >= 24 || minute >= 60 || second >= 60 {
            return None;
        }
        let mut nanos = 0;
        if matches!(self.0.first(), Some(b'.' | b','))
            && self.0.get(1).is_some_and(u8::is_ascii_digit)
        {
            self.0 = &self.0[1..];
            let count = self
                .0
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            for byte in self.0.iter().take(count.min(9)) {
                nanos = nanos * 10 + u32::from(byte - b'0');
            }
            for _ in count.min(9)..9 {
                nanos *= 10;
            }
            self.0 = &self.0[count..];
        }
        Some((hour, minute, second, nanos))
    }

    fn zone(&mut self) -> Option<&'a [u8]> {
        let value = self.0;
        if value.len() < 3 {
            return None;
        }
        let count = if value.starts_with(b"UTC") {
            3
        } else if value.starts_with(b"GMT") {
            3 + signed_zone(&value[3..]).unwrap_or(0)
        } else if value.starts_with(b"ChST") || value.starts_with(b"MeST") {
            4
        } else if matches!(value.first(), Some(b'+' | b'-')) {
            signed_zone(value)?
        } else {
            let count = value
                .iter()
                .take(6)
                .take_while(|byte| byte.is_ascii_uppercase())
                .count();
            match count {
                3 => count,
                4 if value[3] == b'T' || value.starts_with(b"WITA") => count,
                5 if value[4] == b'T' => count,
                _ => return None,
            }
        };
        self.0 = &value[count..];
        Some(&value[..count])
    }
}

fn signed_zone(value: &[u8]) -> Option<usize> {
    if !matches!(value.first(), Some(b'+' | b'-')) {
        return None;
    }
    let mut count = 1;
    let mut number = 0_i64;
    for byte in value[1..].iter().take_while(|byte| byte.is_ascii_digit()) {
        number = number
            .checked_mul(10)?
            .checked_add(i64::from(byte - b'0'))?;
        count += 1;
    }
    (count > 1 && number <= 23).then_some(count)
}

pub(super) fn parse(raw: &[u8]) -> Option<SystemTime> {
    (0..3).find_map(|layout| parse_layout(raw, layout))
}

fn parse_layout(raw: &[u8], layout: u8) -> Option<SystemTime> {
    let mut cursor = Cursor(raw);
    cursor.word(if layout == 1 { LONG_DAYS } else { SHORT_DAYS })?;
    let (year, month, day, clock, zone) = if layout == 2 {
        cursor.literal(b" ")?;
        let month = cursor.word(MONTHS)? as i64 + 1;
        cursor.literal(b" ")?;
        // The literal space already consumes the optional _2 padding.
        let day = cursor.number(2, false)?;
        cursor.literal(b" ")?;
        let clock = cursor.clock()?;
        cursor.literal(b" ")?;
        (cursor.year(false)?, month, day, clock, None)
    } else {
        cursor.literal(b", ")?;
        let day = cursor.number(2, true)?;
        cursor.literal(if layout == 1 { b"-" } else { b" " })?;
        let month = cursor.word(MONTHS)? as i64 + 1;
        cursor.literal(if layout == 1 { b"-" } else { b" " })?;
        let year = cursor.year(layout == 1)?;
        cursor.literal(b" ")?;
        let clock = cursor.clock()?;
        cursor.literal(b" ")?;
        let zone = if layout == 0 {
            cursor.literal(b"GMT")?;
            None
        } else {
            Some(cursor.zone()?)
        };
        (year, month, day, clock, zone)
    };
    if !cursor.0.is_empty() || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let (hour, minute, second, nanos) = clock;
    let mut seconds =
        days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    if let Some(zone) = zone {
        if zone != b"UTC" {
            if let Some(offset) = local::lookup_name(zone, seconds) {
                seconds -= i64::from(offset);
            }
        }
    }
    // Fabricated zones, including GMT+N, only change Go's location metadata;
    // absent a Local match they leave this already-UTC instant unchanged.
    let total = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    let absolute = total.unsigned_abs();
    let duration = Duration::new(
        (absolute / 1_000_000_000).try_into().ok()?,
        (absolute % 1_000_000_000) as u32,
    );
    if total < 0 {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
}

pub(super) fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

pub(super) fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 => {
            if leap(year) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub(super) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * month + 2) / 5 + day - 1 - 719468
}

pub(super) fn year_at(seconds: i64) -> i64 {
    let days = seconds.div_euclid(86400) + 719468;
    let era = days.div_euclid(146097);
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month = (5 * doy + 2) / 153;
    year + i64::from(month >= 10)
}
