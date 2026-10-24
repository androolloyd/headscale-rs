// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Adapted from Go 1.26.9 encoding/json/scanner.go. Original terms and source
// provenance are retained in LICENSE-GO and UPSTREAM.md.

//! Iterative scanner for Go JSON syntax diagnostics, including EOF transitions.

use super::super::quote as go_strconv;

#[derive(Clone, Copy, Default)]
enum State {
    #[default]
    BeginValue,
    BeginValueOrEmpty,
    BeginString,
    BeginStringOrEmpty,
    InString,
    Escape,
    Unicode(u8),
    Negative,
    Zero,
    Integer,
    Dot,
    Fraction,
    Exponent,
    ExponentSign,
    ExponentDigits,
    Literal(&'static str, usize),
    EndValue,
    EndTop,
}

#[derive(Clone, Copy)]
enum Frame {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

#[derive(Default)]
struct Scanner {
    state: State,
    frames: Vec<Frame>,
    end_top: bool,
}

pub fn check_valid(bytes: &[u8]) -> Result<(), String> {
    let mut scanner = Scanner::default();
    for &byte in bytes {
        scanner.step(byte)?;
    }
    if !scanner.end_top {
        // Go eof feeds a space into the current state before deciding whether
        // the final literal ended or the input ended inside a container/string.
        scanner.step(b' ')?;
        if !scanner.end_top {
            return Err("unexpected end of JSON input".into());
        }
    }
    Ok(())
}

/// Scan one encoding/json.Decoder RawMessage without decoding its contents.
/// Leading whitespace is omitted from the raw value; trailing bytes belong to
/// the next Decode call and are not validated. Clean whitespace-only EOF is
/// distinct from a truncated value's io.ErrUnexpectedEOF.
pub fn first_raw_value(bytes: &[u8]) -> Result<Option<&[u8]>, String> {
    let Some(start) = bytes.iter().position(|byte| !space(*byte)) else {
        return Ok(None);
    };
    let mut scanner = Scanner::default();
    for (index, &byte) in bytes.iter().enumerate().skip(start) {
        let inside_container = !scanner.frames.is_empty();
        let result = scanner.step(byte);
        if scanner.end_top {
            // Object/array closes finish with their own byte. Scalar finishes
            // are delayed until the following byte, which Decoder.readValue
            // leaves unread even if stateEndTop recorded a trailing error.
            let end = if inside_container { index + 1 } else { index };
            return Ok(Some(&bytes[start..end]));
        }
        result?;
    }
    // readValue supplies a space after the reader reports EOF. Its scanner
    // error on that invented byte is surfaced as io.ErrUnexpectedEOF rather
    // than as an invalid-character error from a byte absent from the stream.
    let _ = scanner.step(b' ');
    if scanner.end_top {
        Ok(Some(&bytes[start..]))
    } else {
        Err("unexpected EOF".into())
    }
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn error(byte: u8, context: &str) -> String {
    let character = match byte {
        b'\'' => "'\\''".to_owned(),
        b'"' => "'\\\"'".to_owned(),
        _ => {
            let quoted = go_strconv::quote(&char::from(byte).to_string());
            format!("'{}'", &quoted[1..quoted.len() - 1])
        }
    };
    format!("invalid character {character} {context}")
}

impl Scanner {
    fn push(&mut self, byte: u8, frame: Frame) -> Result<(), String> {
        self.frames.push(frame);
        if self.frames.len() > 10_000 {
            return Err(error(byte, "exceeded max depth"));
        }
        Ok(())
    }

    fn pop(&mut self) {
        let _ = self.frames.pop();
        if self.frames.is_empty() {
            self.state = State::EndTop;
            self.end_top = true;
        } else {
            self.state = State::EndValue;
        }
    }

    fn step(&mut self, byte: u8) -> Result<(), String> {
        // Continue means the same byte is considered by the next state. State
        // transitions consume at most one byte; the frame stack is heap-owned.
        loop {
            match self.state {
                State::BeginValueOrEmpty => {
                    if space(byte) {
                        return Ok(());
                    }
                    self.state = if byte == b']' {
                        State::EndValue
                    } else {
                        State::BeginValue
                    };
                }
                State::BeginValue => {
                    if space(byte) {
                        return Ok(());
                    }
                    self.state = match byte {
                        b'{' => {
                            self.push(byte, Frame::ObjectKey)?;
                            State::BeginStringOrEmpty
                        }
                        b'[' => {
                            self.push(byte, Frame::ArrayValue)?;
                            State::BeginValueOrEmpty
                        }
                        b'"' => State::InString,
                        b'-' => State::Negative,
                        b'0' => State::Zero,
                        b'1'..=b'9' => State::Integer,
                        b't' => State::Literal("true", 1),
                        b'f' => State::Literal("false", 1),
                        b'n' => State::Literal("null", 1),
                        _ => return Err(error(byte, "looking for beginning of value")),
                    };
                    return Ok(());
                }
                State::BeginStringOrEmpty => {
                    if space(byte) {
                        return Ok(());
                    }
                    if byte == b'}' {
                        *self.frames.last_mut().expect("open object") = Frame::ObjectValue;
                        self.state = State::EndValue;
                    } else {
                        self.state = State::BeginString;
                    }
                }
                State::BeginString => {
                    if space(byte) {
                        return Ok(());
                    }
                    if byte != b'"' {
                        return Err(error(byte, "looking for beginning of object key string"));
                    }
                    self.state = State::InString;
                    return Ok(());
                }
                State::InString => {
                    match byte {
                        b'"' => self.state = State::EndValue,
                        b'\\' => self.state = State::Escape,
                        0..=0x1f => return Err(error(byte, "in string literal")),
                        _ => {}
                    }
                    return Ok(());
                }
                State::Escape => {
                    self.state = match byte {
                        b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => State::InString,
                        b'u' => State::Unicode(4),
                        _ => return Err(error(byte, "in string escape code")),
                    };
                    return Ok(());
                }
                State::Unicode(remaining) => {
                    if !byte.is_ascii_hexdigit() {
                        return Err(error(byte, "in \\u hexadecimal character escape"));
                    }
                    self.state = if remaining == 1 {
                        State::InString
                    } else {
                        State::Unicode(remaining - 1)
                    };
                    return Ok(());
                }
                State::Negative => {
                    self.state = match byte {
                        b'0' => State::Zero,
                        b'1'..=b'9' => State::Integer,
                        _ => return Err(error(byte, "in numeric literal")),
                    };
                    return Ok(());
                }
                State::Integer => {
                    if byte.is_ascii_digit() {
                        return Ok(());
                    }
                    self.state = State::Zero;
                }
                State::Zero => {
                    self.state = match byte {
                        b'.' => State::Dot,
                        b'e' | b'E' => State::Exponent,
                        _ => {
                            self.state = State::EndValue;
                            continue;
                        }
                    };
                    return Ok(());
                }
                State::Dot => {
                    if !byte.is_ascii_digit() {
                        return Err(error(byte, "after decimal point in numeric literal"));
                    }
                    self.state = State::Fraction;
                    return Ok(());
                }
                State::Fraction => {
                    if byte.is_ascii_digit() {
                        return Ok(());
                    }
                    if matches!(byte, b'e' | b'E') {
                        self.state = State::Exponent;
                        return Ok(());
                    }
                    self.state = State::EndValue;
                }
                State::Exponent => {
                    self.state = State::ExponentSign;
                    if matches!(byte, b'+' | b'-') {
                        return Ok(());
                    }
                }
                State::ExponentSign => {
                    if !byte.is_ascii_digit() {
                        return Err(error(byte, "in exponent of numeric literal"));
                    }
                    self.state = State::ExponentDigits;
                    return Ok(());
                }
                State::ExponentDigits => {
                    if byte.is_ascii_digit() {
                        return Ok(());
                    }
                    self.state = State::EndValue;
                }
                State::Literal(literal, next) => {
                    let expected = literal.as_bytes()[next];
                    if byte != expected {
                        return Err(error(
                            byte,
                            &format!(
                                "in literal {literal} (expecting '{}')",
                                char::from(expected)
                            ),
                        ));
                    }
                    self.state = if next + 1 == literal.len() {
                        State::EndValue
                    } else {
                        State::Literal(literal, next + 1)
                    };
                    return Ok(());
                }
                State::EndValue => {
                    let Some(frame) = self.frames.last().copied() else {
                        self.state = State::EndTop;
                        self.end_top = true;
                        continue;
                    };
                    if space(byte) {
                        return Ok(());
                    }
                    match frame {
                        Frame::ObjectKey if byte == b':' => {
                            *self.frames.last_mut().expect("open object") = Frame::ObjectValue;
                            self.state = State::BeginValue;
                        }
                        Frame::ObjectKey => return Err(error(byte, "after object key")),
                        Frame::ObjectValue if byte == b',' => {
                            *self.frames.last_mut().expect("open object") = Frame::ObjectKey;
                            self.state = State::BeginString;
                        }
                        Frame::ObjectValue if byte == b'}' => self.pop(),
                        Frame::ObjectValue => {
                            return Err(error(byte, "after object key:value pair"));
                        }
                        Frame::ArrayValue if byte == b',' => self.state = State::BeginValue,
                        Frame::ArrayValue if byte == b']' => self.pop(),
                        Frame::ArrayValue => return Err(error(byte, "after array element")),
                    }
                    return Ok(());
                }
                State::EndTop => {
                    return if space(byte) {
                        Ok(())
                    } else {
                        Err(error(byte, "after top-level value"))
                    };
                }
            }
        }
    }
}
