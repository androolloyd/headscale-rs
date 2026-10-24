// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//! Admission-only adaptation of Go 1.26.9 net/mail.ParseAddress.
//! The caller stores the original accepted claim, so display-name/address
//! construction and formatting are intentionally not part of this parser.

use base64::Engine as _;

pub(super) fn valid_address(value: &str) -> bool {
    let mut parser = Parser {
        input: value.as_bytes(),
        offset: 0,
    };
    parser
        .address(true)
        .is_ok_and(|count| parser.cfws() && parser.empty() && count == 1)
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

type Parsed<T = ()> = Result<T, ()>;

impl Parser<'_> {
    fn rest(&self) -> &[u8] {
        &self.input[self.offset..]
    }
    fn empty(&self) -> bool {
        self.offset == self.input.len()
    }
    fn peek(&self) -> Option<u8> {
        self.rest().first().copied()
    }
    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.offset += 1;
        }
    }

    fn address(&mut self, group: bool) -> Parsed<usize> {
        self.space();
        if self.empty() {
            return Err(());
        }
        if self.spec().is_ok() {
            self.space();
            if self.consume(b'(') {
                let comment = self.comment()?;
                // A bare addr-spec's first comment supplies its display name;
                // only this comment runs WordDecoder. Later CFWS does not.
                for word in comment
                    .split(|byte| matches!(byte, b' ' | b'\t'))
                    .filter(|word| !word.is_empty())
                {
                    encoded_word(word)?;
                }
            }
            return Ok(1);
        }
        if self.peek() != Some(b'<') {
            self.phrase()?;
        }
        self.space();
        if group && self.consume(b':') {
            return self.group();
        }
        if !self.consume(b'<') {
            return Err(());
        }
        self.spec()?;
        if !self.consume(b'>') {
            return Err(());
        }
        Ok(1)
    }

    fn group(&mut self) -> Parsed<usize> {
        self.space();
        if self.consume(b';') {
            return if self.cfws() { Ok(0) } else { Err(()) };
        }
        let mut count = 0usize;
        loop {
            self.space();
            count = count.checked_add(self.address(false)?).ok_or(())?;
            if !self.cfws() {
                return Err(());
            }
            if self.consume(b';') {
                return if self.cfws() { Ok(count) } else { Err(()) };
            }
            if !self.consume(b',') {
                return Err(());
            }
        }
    }

    fn spec(&mut self) -> Parsed {
        let original = self.offset;
        let result = self.spec_inner();
        if result.is_err() {
            self.offset = original;
        }
        result
    }

    fn spec_inner(&mut self) -> Parsed {
        self.space();
        if self.peek() == Some(b'"') {
            if self.quoted()?.is_empty() {
                return Err(());
            }
        } else {
            self.atom(false)?;
        }
        // There is no CFWS allowance before '@' in selected consumeAddrSpec.
        if !self.consume(b'@') {
            return Err(());
        }
        self.space();
        if self.consume(b'[') {
            let start = self.offset;
            while self.peek() != Some(b']') {
                let (ch, width) = rune(self.rest()).ok_or(())?;
                if matches!(ch, '[' | ']' | '\\') || !vchar(ch) {
                    return Err(());
                }
                self.offset += width;
            }
            let literal = std::str::from_utf8(&self.input[start..self.offset]).map_err(|_| ())?;
            if literal.parse::<std::net::IpAddr>().is_err() {
                return Err(());
            }
            self.offset += 1;
        } else {
            self.atom(false)?;
        }
        Ok(())
    }

    fn phrase(&mut self) -> Parsed {
        let mut words = 0usize;
        loop {
            if words > 0 && !self.cfws() {
                return Err(());
            }
            self.space();
            if self.empty() {
                break;
            }
            let word = if self.peek() == Some(b'"') {
                self.quoted().map(|_| ())
            } else {
                self.atom(true).and_then(encoded_word)
            };
            if word.is_err() {
                // consumePhrase ignores a later error after at least one word.
                return if words == 0 { Err(()) } else { Ok(()) };
            }
            words += 1;
        }
        if words == 0 { Err(()) } else { Ok(()) }
    }

    fn quoted(&mut self) -> Parsed<Vec<u8>> {
        let original = self.offset;
        let result = self.quoted_inner();
        if result.is_err() {
            self.offset = original;
        }
        result
    }

    fn quoted_inner(&mut self) -> Parsed<Vec<u8>> {
        if !self.consume(b'"') {
            return Err(());
        }
        let mut value = Vec::new();
        let mut escaped = false;
        loop {
            let (ch, width) = rune(self.rest()).ok_or(())?;
            self.offset += width;
            if escaped {
                if !vchar(ch) && !matches!(ch, ' ' | '\t') {
                    return Err(());
                }
                value.extend_from_slice(&self.input[self.offset - width..self.offset]);
                escaped = false;
            } else if ch == '"' {
                return Ok(value);
            } else if ch == '\\' {
                escaped = true;
            } else if vchar(ch) || matches!(ch, ' ' | '\t') {
                value.extend_from_slice(&self.input[self.offset - width..self.offset]);
            } else {
                return Err(());
            }
        }
    }

    fn atom(&mut self, permissive: bool) -> Parsed<&[u8]> {
        let start = self.offset;
        while let Some((ch, width)) = rune(self.rest()) {
            if !atext(ch) {
                break;
            }
            self.offset += width;
        }
        let atom = &self.input[start..self.offset];
        if atom.is_empty()
            || !permissive
                && (atom.starts_with(b".")
                    || atom.ends_with(b".")
                    || atom.windows(2).any(|pair| pair == b".."))
        {
            return Err(());
        }
        Ok(atom)
    }

    fn cfws(&mut self) -> bool {
        self.space();
        while self.consume(b'(') {
            if self.comment().is_err() {
                return false;
            }
            self.space();
        }
        true
    }

    fn comment(&mut self) -> Parsed<Vec<u8>> {
        let mut depth = 1usize;
        let mut comment = Vec::new();
        while !self.empty() && depth > 0 {
            if self.peek() == Some(b'\\') && self.rest().len() > 1 {
                self.offset += 1;
            } else if self.peek() == Some(b'(') {
                depth = depth.checked_add(1).ok_or(())?;
            } else if self.peek() == Some(b')') {
                depth -= 1;
            }
            if depth > 0 {
                comment.push(self.input[self.offset]);
            }
            self.offset += 1;
        }
        if depth == 0 { Ok(comment) } else { Err(()) }
    }
}

fn rune(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    let width = match first {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let text = std::str::from_utf8(bytes.get(..width)?).ok()?;
    Some((text.chars().next()?, width))
}

fn vchar(ch: char) -> bool {
    ('!'..='~').contains(&ch) || ch as u32 >= 128
}
fn atext(ch: char) -> bool {
    !matches!(
        ch,
        '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"'
    ) && vchar(ch)
}

// net/mail ignores malformed encoded-word errors. A successfully decoded
// encoded-word with an unsupported charset is the one admission error.
fn encoded_word(word: &[u8]) -> Parsed {
    if word.len() < 8
        || !word.starts_with(b"=?")
        || !word.ends_with(b"?=")
        // Four question marks split the word into five fields.
        || word.split(|byte| *byte == b'?').count() != 5
    {
        return Ok(());
    }
    let mut parts = word[2..word.len() - 2].split(|byte| *byte == b'?');
    let charset = parts.next().unwrap_or_default();
    let encoding = parts.next().unwrap_or_default();
    let text = parts.next().unwrap_or_default();
    if charset.is_empty() || encoding.len() != 1 {
        return Ok(());
    }
    let decoded = match encoding[0] {
        b'B' | b'b' => {
            // Go's non-strict StdEncoding ignores CR/LF and permits trailing
            // pad bits. The decoded display text is not stored by this helper.
            let clean: Vec<_> = text
                .iter()
                .copied()
                .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                .collect();
            let engine = base64::engine::general_purpose::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::general_purpose::PAD.with_decode_allow_trailing_bits(true),
            );
            engine.decode(clean).is_ok()
        }
        b'Q' | b'q' => {
            let mut at = 0;
            let mut valid = true;
            while at < text.len() {
                if text[at] == b'=' {
                    if !text
                        .get(at + 1..at + 3)
                        .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                    {
                        valid = false;
                        break;
                    }
                    at += 3;
                } else if (b' '..=b'~').contains(&text[at])
                    || matches!(text[at], b'\r' | b'\n' | b'\t')
                {
                    at += 1;
                } else {
                    valid = false;
                    break;
                }
            }
            valid
        }
        _ => false,
    };
    let supported = std::str::from_utf8(charset).is_ok_and(|charset| {
        ["utf-8", "iso-8859-1", "us-ascii"]
            .iter()
            .any(|known| headscale_api_acl::go_unicode::equal_fold(charset, known))
    });
    if !decoded || supported {
        Ok(())
    } else {
        Err(())
    }
}
