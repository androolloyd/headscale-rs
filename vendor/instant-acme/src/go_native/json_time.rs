// Copyright 2009 The Go Authors. All rights reserved.
// time.Time.UnmarshalJSON and selected RFC3339 parsing; see LICENSE-GO.

//! Validate the JSON time fields before later resource members are assigned.
//! Go's selected strict-parser fallback still accepts a one-digit hour, comma
//! fractions and numeric-zone 24/60 endpoints. JSON escapes are not unquoted by
//! Time.UnmarshalJSON. The resource view retains the validated original text.

pub(super) fn assign(target: &mut Option<String>, raw: &[u8]) -> Result<(), String> {
    if raw == b"null" {
        return Ok(());
    }
    if raw.len() < 2 || raw.first() != Some(&b'"') || raw.last() != Some(&b'"') {
        return Err("Time.UnmarshalJSON: input is not a JSON string".into());
    }
    let value = &raw[1..raw.len() - 1];
    let mut parser = Parser { value, at: 0 };
    let year = parser.number(4, true, b"2006")?;
    parser.literal(b"-")?;
    let month = parser.number(2, true, b"01")?;
    if !(1..=12).contains(&month) {
        return Err(parser.range("month"));
    }
    parser.literal(b"-")?;
    let day = parser.number(2, true, b"02")?;
    parser.literal(b"T")?;
    let hour = parser.number(2, false, b"15")?;
    if hour >= 24 {
        return Err(parser.range("hour"));
    }
    parser.literal(b":")?;
    if parser.number(2, true, b"04")? >= 60 {
        return Err(parser.range("minute"));
    }
    parser.literal(b":")?;
    if parser.number(2, true, b"05")? >= 60 {
        return Err(parser.range("second"));
    }
    if matches!(parser.peek(), Some(b'.' | b','))
        && value.get(parser.at + 1).is_some_and(u8::is_ascii_digit)
    {
        parser.at += 1;
        while parser.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            parser.at += 1;
        }
    }
    parser.zone()?;
    if parser.at != value.len() {
        return Err(format!(
            "parsing time {}: extra text: {}",
            quote(value),
            quote(&value[parser.at..])
        ));
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > maximum {
        return Err(parser.range("day"));
    }
    *target = Some(String::from_utf8(value.to_vec()).map_err(|_| parser.expected(b"2006"))?);
    Ok(())
}

struct Parser<'a> {
    value: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.value.get(self.at).copied()
    }
    fn expected(&self, layout: &[u8]) -> String {
        self.expected_at(layout, self.at)
    }
    fn expected_at(&self, layout: &[u8], at: usize) -> String {
        format!(
            "parsing time {} as {}: cannot parse {} as {}",
            quote(self.value),
            quote(b"2006-01-02T15:04:05Z07:00"),
            quote(&self.value[at..]),
            quote(layout)
        )
    }
    fn range(&self, field: &str) -> String {
        format!("parsing time {}: {field} out of range", quote(self.value))
    }
    fn zone(&mut self) -> Result<(), String> {
        if self.peek() == Some(b'Z') {
            self.at += 1;
            return Ok(());
        }
        // RFC3339's Z07:00 is one standard-layout token, not a sequence of
        // sign/digits/literal tokens. Go saves the original suffix as hold,
        // then consumes all six bytes before numeric/sign validation.
        let hold = self.at;
        let Some(zone) = self.value.get(hold..).and_then(|value| value.get(..6)) else {
            return Err(self.expected_at(b"Z07:00", hold));
        };
        if zone[3] != b':' {
            return Err(self.expected_at(b"Z07:00", hold));
        }
        self.at += 6;
        let hour = two_digits(&zone[1..3]);
        // Go parses minute only when the hour's getnum succeeded. Failed
        // numeric assignments leave zero; range errors precede lexical/sign
        // errors, and a minute range error overwrites an hour range error.
        let minute = hour.and_then(|_| two_digits(&zone[4..6]));
        let mut range = None;
        if hour.is_some_and(|value| value > 24) {
            range = Some("time zone offset hour");
        }
        if minute.is_some_and(|value| value > 60) {
            range = Some("time zone offset minute");
        }
        if let Some(field) = range {
            return Err(self.range(field));
        }
        if hour.is_none() || minute.is_none() || !matches!(zone[0], b'+' | b'-') {
            return Err(self.expected_at(b"Z07:00", hold));
        }
        Ok(())
    }
    fn literal(&mut self, literal: &[u8]) -> Result<(), String> {
        for byte in literal {
            if self.peek() != Some(*byte) {
                return Err(self.expected(literal));
            }
            self.at += 1;
        }
        Ok(())
    }
    fn number(&mut self, maximum: usize, fixed: bool, layout: &[u8]) -> Result<i64, String> {
        let count = self.value[self.at..]
            .iter()
            .take(maximum)
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if count == 0 || fixed && count != maximum {
            return Err(self.expected(layout));
        }
        let mut value = 0;
        for byte in &self.value[self.at..self.at + count] {
            value = value * 10 + i64::from(byte - b'0');
        }
        self.at += count;
        Ok(value)
    }
}

fn two_digits(raw: &[u8]) -> Option<u8> {
    if raw.len() != 2 || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((raw[0] - b'0') * 10 + raw[1] - b'0')
}

fn quote(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::from("\"");
    for &byte in value {
        if byte < b' ' || !byte.is_ascii() {
            let _ = write!(output, "\\x{byte:02x}");
        } else {
            if matches!(byte, b'"' | b'\\') {
                output.push('\\');
            }
            output.push(char::from(byte));
        }
    }
    output.push('"');
    output
}
