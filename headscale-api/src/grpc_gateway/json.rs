// Copyright 2018 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Protobuf v1.36.11 JSON-token compatibility; see LICENSE-PROTOBUF-GO.

//! Private request projection of protobuf's token decoder. Numeric tokens keep
//! their original spelling, including exponent tokens accepted by that lexer.
//! Known fields and repeated elements are validated as tokens arrive, before
//! later names or malformed trailing input can replace an earlier type error.
//! Only the outer object and its immediate values need materialized children;
//! deeper containers are validated iteratively and retained as kind markers.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use headscale_api_acl::go_strconv::{quote, quote_rune};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FieldKind {
    String,
    Bool,
    Uint64,
    StringList,
    Timestamp,
}

pub(super) enum Value {
    Null,
    Bool(bool),
    Number(String),
    String { decoded: String, raw: String },
    Object(Vec<(String, Self)>),
    Array(Vec<Self>),
}

impl Value {
    pub(super) fn get(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.iter().find(|(key, _)| key == name).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(super) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub(super) fn raw_token(&self) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Number(raw) | Self::String { raw, .. } => raw.clone(),
            Self::Object(_) => "{".into(),
            Self::Array(_) => "[".into(),
        }
    }
}

enum TokenKind {
    Scalar(Value),
    ObjectOpen,
    ObjectClose,
    ArrayOpen,
    ArrayClose,
    Comma,
    Eof,
}

struct Token {
    kind: TokenKind,
    pos: usize,
    raw: String,
}

struct Lexer<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl Lexer<'_> {
    fn skip_space(&mut self) {
        while matches!(
            self.input.get(self.cursor),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.cursor += 1;
        }
    }

    fn position(&self, pos: usize) -> (usize, usize) {
        let prefix = &self.input[..pos];
        // `split` yields one more segment than there are newlines, and the
        // last segment is the text after the final newline.
        let line = prefix.split(|byte| *byte == b'\n').count();
        let current_line = prefix
            .rsplit(|byte| *byte == b'\n')
            .next()
            .unwrap_or(prefix);
        let column = String::from_utf8_lossy(current_line).chars().count() + 1;
        (line, column)
    }

    fn syntax(&self, pos: usize, message: impl std::fmt::Display) -> String {
        let (line, column) = self.position(pos);
        format!("syntax error (line {line}:{column}): {message}")
    }

    fn unexpected(&self, token: &Token) -> String {
        if matches!(token.kind, TokenKind::Eof) {
            "unexpected EOF".into()
        } else {
            self.syntax(token.pos, format_args!("unexpected token {}", token.raw))
        }
    }

    fn validate_field(
        &self,
        token: &Token,
        aliases: &[&str],
        kind: FieldKind,
        element: bool,
    ) -> Result<(), String> {
        // Invalid structural sequences are rejected by the state machine
        // before protobuf invokes a scalar/message decoder.
        if !matches!(
            token.kind,
            TokenKind::Scalar(_) | TokenKind::ObjectOpen | TokenKind::ArrayOpen
        ) {
            return Ok(());
        }
        if !element && matches!(token.kind, TokenKind::Scalar(Value::Null)) {
            return Ok(());
        }
        let kind = if element { FieldKind::String } else { kind };
        let valid = match (kind, &token.kind) {
            (FieldKind::String, TokenKind::Scalar(Value::String { .. }))
            | (FieldKind::Bool, TokenKind::Scalar(Value::Bool(_)))
            | (FieldKind::StringList, TokenKind::ArrayOpen) => true,
            (FieldKind::Uint64, TokenKind::Scalar(Value::Number(raw))) => {
                super::protojson_u64(raw, true).is_some()
            }
            (FieldKind::Uint64, TokenKind::Scalar(Value::String { decoded, .. })) => {
                super::protojson_u64(decoded, false).is_some()
            }
            (FieldKind::Timestamp, TokenKind::Scalar(Value::String { decoded, raw })) => {
                return super::validate_body_timestamp_string(decoded, raw).map_err(|error| {
                    let (line, column) = self.position(token.pos);
                    format!("(line {line}:{column}): {error}")
                });
            }
            _ => false,
        };
        if valid {
            return Ok(());
        }
        if matches!(kind, FieldKind::StringList | FieldKind::Timestamp) {
            return Err(self.unexpected(token));
        }
        let name = match kind {
            FieldKind::String => "string",
            FieldKind::Bool => "bool",
            FieldKind::Uint64 => "uint64",
            _ => unreachable!("container/message kinds returned above"),
        };
        let (line, column) = self.position(token.pos);
        Err(format!(
            "(line {line}:{column}): invalid value for {name} field {}: {}",
            aliases[0], token.raw
        ))
    }

    fn next(&mut self) -> Result<Token, String> {
        self.skip_space();
        let pos = self.cursor;
        let Some(&first) = self.input.get(pos) else {
            return Ok(Token {
                kind: TokenKind::Eof,
                pos,
                raw: String::new(),
            });
        };
        let kind = match first {
            b'{' => TokenKind::ObjectOpen,
            b'}' => TokenKind::ObjectClose,
            b'[' => TokenKind::ArrayOpen,
            b']' => TokenKind::ArrayClose,
            b',' => TokenKind::Comma,
            b'"' => {
                let decoded = self.string()?;
                let raw = String::from_utf8(self.input[pos..self.cursor].to_vec())
                    .expect("string lexer validated UTF-8");
                return Ok(Token {
                    kind: TokenKind::Scalar(Value::String {
                        decoded,
                        raw: raw.clone(),
                    }),
                    pos,
                    raw,
                });
            }
            b'n' if self.literal(b"null") => {
                self.cursor += 4;
                return Ok(Token {
                    kind: TokenKind::Scalar(Value::Null),
                    pos,
                    raw: "null".into(),
                });
            }
            b't' if self.literal(b"true") => {
                self.cursor += 4;
                return Ok(Token {
                    kind: TokenKind::Scalar(Value::Bool(true)),
                    pos,
                    raw: "true".into(),
                });
            }
            b'f' if self.literal(b"false") => {
                self.cursor += 5;
                return Ok(Token {
                    kind: TokenKind::Scalar(Value::Bool(false)),
                    pos,
                    raw: "false".into(),
                });
            }
            b'-' | b'0'..=b'9' => {
                if let Some(length) = number_length(&self.input[pos..]) {
                    self.cursor += length;
                    let raw = String::from_utf8(self.input[pos..self.cursor].to_vec())
                        .expect("number lexer accepts ASCII only");
                    return Ok(Token {
                        kind: TokenKind::Scalar(Value::Number(raw.clone())),
                        pos,
                        raw,
                    });
                }
                return Err(self.invalid_value(pos));
            }
            _ => return Err(self.invalid_value(pos)),
        };
        self.cursor += 1;
        Ok(Token {
            kind,
            pos,
            raw: char::from(first).to_string(),
        })
    }

    fn literal(&self, literal: &[u8]) -> bool {
        let rest = &self.input[self.cursor..];
        rest.starts_with(literal)
            && rest
                .get(literal.len())
                .is_none_or(|byte| !not_delimiter(*byte))
    }

    fn invalid_value(&self, pos: usize) -> String {
        let rest = &self.input[pos..];
        let ascii_len = rest
            .iter()
            .take(32)
            .take_while(|byte| not_delimiter(**byte))
            .count();
        let text = String::from_utf8_lossy(rest);
        let length = if ascii_len == 0 {
            text.chars().next().map_or(0, char::len_utf8)
        } else {
            ascii_len
        };
        let token = text.get(..length).unwrap_or(&text);
        self.syntax(pos, format_args!("invalid value {token}"))
    }

    fn string(&mut self) -> Result<String, String> {
        let pos = self.cursor;
        self.cursor += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.input.get(self.cursor) else {
                return Err("unexpected EOF".into());
            };
            match byte {
                b'"' => {
                    self.cursor += 1;
                    return Ok(out);
                }
                0..=0x1f => {
                    return Err(self.syntax(
                        pos,
                        format_args!(
                            "invalid character {} in string",
                            quote_rune(char::from(byte))
                        ),
                    ));
                }
                b'\\' => {
                    let start = self.cursor;
                    let Some(&escape) = self.input.get(start + 1) else {
                        return Err("unexpected EOF".into());
                    };
                    match escape {
                        b'"' | b'\\' | b'/' => out.push(char::from(escape)),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.input.len() - start < 6 {
                                return Err("unexpected EOF".into());
                            }
                            let Some(first) = hex16(&self.input[start + 2..start + 6]) else {
                                return Err(self.bad_escape(pos, &self.input[start..start + 6]));
                            };
                            self.cursor += 6;
                            let rune = if (0xd800..=0xdfff).contains(&first) {
                                let next = self.cursor;
                                if self.input.len() - next < 6 {
                                    return Err("unexpected EOF".into());
                                }
                                let second = hex16(&self.input[next + 2..next + 6]);
                                let Some(second) = second.filter(|second| {
                                    (0xd800..=0xdbff).contains(&first)
                                        && (0xdc00..=0xdfff).contains(second)
                                        && self.input[next..next + 2] == *b"\\u"
                                }) else {
                                    return Err(self.bad_escape(pos, &self.input[next..next + 6]));
                                };
                                self.cursor += 6;
                                0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second)
                                    - 0xdc00
                            } else {
                                u32::from(first)
                            };
                            out.push(char::from_u32(rune).expect("validated Unicode scalar"));
                            continue;
                        }
                        _ => return Err(self.bad_escape(pos, &self.input[start..start + 2])),
                    }
                    self.cursor += 2;
                }
                _ => {
                    let start = self.cursor;
                    while self
                        .input
                        .get(self.cursor)
                        .is_some_and(|byte| *byte >= 0x20 && !matches!(byte, b'"' | b'\\'))
                    {
                        self.cursor += 1;
                    }
                    let text = std::str::from_utf8(&self.input[start..self.cursor])
                        .map_err(|_| self.syntax(pos, "invalid UTF-8 in string"))?;
                    out.push_str(text);
                }
            }
        }
    }

    fn bad_escape(&self, pos: usize, raw: &[u8]) -> String {
        self.syntax(
            pos,
            format_args!("invalid escape code {} in string", quote_bytes(raw)),
        )
    }
}

fn quote_bytes(mut bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                let quoted = quote(text);
                out.push_str(&quoted[1..quoted.len() - 1]);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                let quoted = quote(std::str::from_utf8(&bytes[..valid]).expect("validated prefix"));
                out.push_str(&quoted[1..quoted.len() - 1]);
                let bad = error.error_len().unwrap_or(bytes.len() - valid);
                for byte in &bytes[valid..valid + bad] {
                    let _ = write!(out, "\\x{byte:02x}");
                }
                bytes = &bytes[valid + bad..];
            }
        }
    }
    out.push('"');
    out
}

fn hex16(bytes: &[u8]) -> Option<u16> {
    bytes.iter().try_fold(0u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        Some((value << 4) | u16::from(digit))
    })
}

fn not_delimiter(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'+' | b'.' | b'_')
}

/// parseNumber permits an exponent marker followed by a delimiter without
/// digits. Keep the token instead of routing it through a stricter JSON parser.
fn number_length(bytes: &[u8]) -> Option<usize> {
    let mut cursor = usize::from(bytes.first() == Some(&b'-'));
    match bytes.get(cursor)? {
        b'0' => cursor += 1,
        b'1'..=b'9' => {
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
        }
        _ => return None,
    }
    if bytes.get(cursor) == Some(&b'.') && bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit) {
        cursor += 2;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) && cursor + 1 < bytes.len() {
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
            if cursor == bytes.len() {
                return None;
            }
        }
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
    }
    bytes
        .get(cursor)
        .is_none_or(|byte| !not_delimiter(*byte))
        .then_some(cursor)
}

#[derive(Clone, Copy)]
enum State {
    ObjectFirst,
    ObjectName,
    ObjectValue,
    ObjectNext,
    ArrayFirst,
    ArrayValue,
    ArrayNext,
}

struct Frame {
    state: State,
    value: Value,
    name: Option<String>,
    retain: bool,
    field: Option<usize>,
    elements: Option<usize>,
}

fn append(frames: &mut [Frame], value: Value) {
    let frame = frames.last_mut().expect("value has a parent frame");
    match &mut frame.value {
        Value::Object(fields) => {
            let name = frame.name.take().expect("object value follows a name");
            if frame.retain {
                fields.push((name, value));
            }
            frame.state = State::ObjectNext;
        }
        Value::Array(values) => {
            if frame.retain {
                values.push(value);
            }
            frame.state = State::ArrayNext;
        }
        _ => unreachable!("frames are containers"),
    }
}

pub(super) fn parse(input: &[u8], fields: &[(&[&str], FieldKind)]) -> Result<Value, String> {
    let mut lexer = Lexer { input, cursor: 0 };
    let first = lexer.next()?;
    if !matches!(first.kind, TokenKind::ObjectOpen) {
        return Err(lexer.unexpected(&first));
    }
    let mut frames = vec![Frame {
        state: State::ObjectFirst,
        value: Value::Object(Vec::new()),
        name: None,
        retain: true,
        field: None,
        elements: None,
    }];
    let mut seen = BTreeSet::new();
    loop {
        let state = frames.last().expect("root is completed by return").state;
        let token = lexer.next()?;
        let closing = match state {
            State::ObjectFirst | State::ObjectName => {
                if matches!(token.kind, TokenKind::ObjectClose)
                    && matches!(state, State::ObjectFirst)
                {
                    true
                } else {
                    let TokenKind::Scalar(Value::String { decoded, .. }) = &token.kind else {
                        return Err(lexer.unexpected(&token));
                    };
                    lexer.skip_space();
                    let Some(&next) = input.get(lexer.cursor) else {
                        return Err("unexpected EOF".into());
                    };
                    if next != b':' {
                        return Err(lexer.syntax(
                            lexer.cursor,
                            format_args!(
                                "unexpected character {}, missing \":\" after field name",
                                char::from(next)
                            ),
                        ));
                    }
                    lexer.cursor += 1;
                    let mut selected = None;
                    if frames.len() == 1
                        && let Some(number) = fields
                            .iter()
                            .position(|(aliases, _)| aliases.contains(&decoded.as_str()))
                    {
                        if !seen.insert(number) {
                            let (line, column) = lexer.position(token.pos);
                            return Err(format!(
                                "(line {line}:{column}): duplicate field {}",
                                token.raw
                            ));
                        }
                        selected = Some(number);
                    }
                    let frame = frames.last_mut().unwrap();
                    frame.name = Some(decoded.clone());
                    frame.field = selected;
                    frame.state = State::ObjectValue;
                    false
                }
            }
            State::ObjectNext | State::ArrayNext => match (&token.kind, state) {
                (TokenKind::ObjectClose, State::ObjectNext)
                | (TokenKind::ArrayClose, State::ArrayNext) => true,
                (TokenKind::Comma, _) => {
                    frames.last_mut().unwrap().state = if matches!(state, State::ObjectNext) {
                        State::ObjectName
                    } else {
                        State::ArrayValue
                    };
                    false
                }
                _ => return Err(lexer.unexpected(&token)),
            },
            State::ArrayFirst if matches!(token.kind, TokenKind::ArrayClose) => true,
            State::ObjectValue | State::ArrayFirst | State::ArrayValue => {
                let frame = frames.last().unwrap();
                let selected = if frames.len() == 1 {
                    frame.field.map(|field| (field, false))
                } else {
                    frame.elements.map(|field| (field, true))
                };
                if let Some((field, element)) = selected {
                    let (aliases, kind) = fields[field];
                    lexer.validate_field(&token, aliases, kind, element)?;
                }
                match token.kind {
                    TokenKind::ObjectOpen | TokenKind::ArrayOpen => {
                        // A message consumes one of protobuf's default 10000
                        // recursion levels; skipped subtrees may use 9999.
                        if frames.len() >= 10000 {
                            return Err("exceeded max recursion depth".into());
                        }
                        let object = matches!(token.kind, TokenKind::ObjectOpen);
                        let retain = frames.len() <= 1;
                        let elements = selected
                            .filter(|(field, element)| {
                                !*element && fields[*field].1 == FieldKind::StringList
                            })
                            .map(|(field, _)| field);
                        frames.push(Frame {
                            state: if object {
                                State::ObjectFirst
                            } else {
                                State::ArrayFirst
                            },
                            value: if object {
                                Value::Object(Vec::new())
                            } else {
                                Value::Array(Vec::new())
                            },
                            name: None,
                            retain,
                            field: None,
                            elements,
                        });
                    }
                    TokenKind::Scalar(value) => append(&mut frames, value),
                    _ => return Err(lexer.unexpected(&token)),
                }
                false
            }
        };
        if closing {
            let frame = frames.pop().unwrap();
            if frames.is_empty() {
                let trailing = lexer.next()?;
                if !matches!(trailing.kind, TokenKind::Eof) {
                    return Err(lexer.unexpected(&trailing));
                }
                return Ok(frame.value);
            }
            append(&mut frames, frame.value);
        }
    }
}
