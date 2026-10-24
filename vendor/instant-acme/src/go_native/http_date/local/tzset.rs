// Copyright 2011 The Go Authors. All rights reserved.
// Go 1.26.9 time/zoneinfo.go tzset and rule helpers; see LICENSE-GO.

use super::super::{days_from_civil, days_in_month, leap, year_at};

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn name(&mut self) -> Option<&'a [u8]> {
        let value = self.0;
        if value.first() == Some(&b'<') {
            let end = value.iter().position(|byte| *byte == b'>')?;
            self.0 = &value[end + 1..];
            return Some(&value[1..end]);
        }
        let end = value
            .iter()
            .position(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'-' | b'+'))
            .unwrap_or(value.len());
        if end < 3 {
            return None;
        }
        self.0 = &value[end..];
        Some(&value[..end])
    }

    fn number(&mut self, minimum: i64, maximum: i64) -> Option<i64> {
        let mut count = 0;
        let mut number = 0;
        for byte in self.0.iter().take_while(|byte| byte.is_ascii_digit()) {
            number = number * 10 + i64::from(byte - b'0');
            if number > maximum {
                return None;
            }
            count += 1;
        }
        if count == 0 || number < minimum {
            return None;
        }
        self.0 = &self.0[count..];
        Some(number)
    }

    fn byte(&mut self, expected: u8) -> Option<()> {
        if self.0.first() != Some(&expected) {
            return None;
        }
        self.0 = &self.0[1..];
        Some(())
    }

    fn offset(&mut self) -> Option<i64> {
        let sign = match self.0.first() {
            Some(b'+') => {
                self.0 = &self.0[1..];
                1
            }
            Some(b'-') => {
                self.0 = &self.0[1..];
                -1
            }
            _ => 1,
        };
        let mut offset = self.number(0, 24 * 7)? * 3600;
        if self.0.first() == Some(&b':') {
            self.0 = &self.0[1..];
            offset += self.number(0, 59)? * 60;
            if self.0.first() == Some(&b':') {
                self.0 = &self.0[1..];
                offset += self.number(0, 59)?;
            }
        }
        Some(sign * offset)
    }

    fn rule(&mut self) -> Option<Rule> {
        let kind = match self.0.first() {
            Some(b'J') => {
                self.0 = &self.0[1..];
                Kind::Julian(self.number(1, 365)?)
            }
            Some(b'M') => {
                self.0 = &self.0[1..];
                let month = self.number(1, 12)?;
                self.byte(b'.')?;
                let week = self.number(1, 5)?;
                self.byte(b'.')?;
                Kind::MonthWeekDay(month, week, self.number(0, 6)?)
            }
            _ => Kind::DayOfYear(self.number(0, 365)?),
        };
        let time = if self.0.first() == Some(&b'/') {
            self.0 = &self.0[1..];
            self.offset()?
        } else {
            7200
        };
        Some(Rule { kind, time })
    }
}

enum Kind {
    Julian(i64),
    DayOfYear(i64),
    MonthWeekDay(i64, i64, i64),
}
struct Rule {
    kind: Kind,
    time: i64,
}

impl Rule {
    fn seconds(&self, year: i64, offset: i64) -> i64 {
        let day = match self.kind {
            Kind::Julian(day) => day - 1 + i64::from(leap(year) && day >= 60),
            Kind::DayOfYear(day) => day,
            Kind::MonthWeekDay(month, week, weekday) => {
                // Keep Go's signed Zeller arithmetic for years around zero.
                let m1 = (month + 9) % 12 + 1;
                let yy0 = year - i64::from(month <= 2);
                let yy1 = yy0 / 100;
                let yy2 = yy0 % 100;
                let mut first = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
                if first < 0 {
                    first += 7;
                }
                let mut day = weekday - first;
                if day < 0 {
                    day += 7;
                }
                for _ in 1..week {
                    if day + 7 >= days_in_month(year, month) {
                        break;
                    }
                    day += 7;
                }
                day + days_from_civil(year, month, 1) - days_from_civil(year, 1, 1)
            }
        };
        day * 86400 + self.time - offset
    }
}

pub(super) fn lookup(text: &[u8], seconds: i64) -> Option<(&[u8], i32)> {
    let mut cursor = Cursor(text);
    let mut standard_name = cursor.name()?;
    let mut standard_offset = -cursor.offset()?;
    if cursor.0.is_empty() || cursor.0.first() == Some(&b',') {
        return Some((standard_name, standard_offset as i32));
    }
    let mut daylight_name = cursor.name()?;
    let mut daylight_offset = if cursor.0.is_empty() || cursor.0.first() == Some(&b',') {
        standard_offset + 3600
    } else {
        -cursor.offset()?
    };
    if cursor.0.is_empty() {
        cursor.0 = b",M3.2.0,M11.1.0";
    }
    if !matches!(cursor.0.first(), Some(b',' | b';')) {
        return None;
    }
    cursor.0 = &cursor.0[1..];
    let start = cursor.rule()?;
    cursor.byte(b',')?;
    let end = cursor.rule()?;
    if !cursor.0.is_empty() {
        return None;
    }
    let year = year_at(seconds);
    // Selected tzset uses Go's signed remainder, not Euclidean modulo, here.
    let yday = seconds.div_euclid(86400) - days_from_civil(year, 1, 1);
    let ysec = yday * 86400 + seconds % 86400;
    let mut start = start.seconds(year, standard_offset);
    let mut end = end.seconds(year, daylight_offset);
    if end < start {
        std::mem::swap(&mut start, &mut end);
        std::mem::swap(&mut standard_name, &mut daylight_name);
        std::mem::swap(&mut standard_offset, &mut daylight_offset);
    }
    if ysec < start || ysec >= end {
        Some((standard_name, standard_offset as i32))
    } else {
        Some((daylight_name, daylight_offset as i32))
    }
}
