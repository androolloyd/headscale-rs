// Copyright 2010 The Go Authors. All rights reserved.
// Boundary states adapt Go encoding/json scanner.go and stream.go; see
// LICENSE-GO and LICENSE-GO-NOTICE. Typed decoding remains with serde_json.

//! Incremental first-value framing, including JSON grammar before the boundary.
//! Invalid input is returned immediately to the typed decoder for diagnostics.

#[derive(Clone, Copy)]
enum Context {
    Key,
    Value,
    Array,
}

#[derive(Clone, Copy)]
enum State {
    Value,
    ArrayEmpty,
    ObjectEmpty,
    Key,
    End,
    String,
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
    Literal(&'static [u8], usize),
}

enum Step {
    More,
    // Root composites include their closer; scalar completion looks ahead.
    End(bool),
    Invalid,
}

pub(crate) struct Scanner {
    state: State,
    stack: Vec<Context>,
    depth_error_byte: Option<u8>,
    invalid: bool,
}

impl Scanner {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Value,
            stack: Vec::new(),
            depth_error_byte: None,
            invalid: false,
        }
    }

    pub(crate) fn depth_error_byte(&self) -> Option<u8> {
        self.depth_error_byte
    }

    pub(crate) fn invalid(&self) -> bool {
        self.invalid
    }

    pub(crate) fn complete_at_eof(&mut self) -> bool {
        // stream.readValue uses one invented space only at EOF. An open
        // string/container remains incomplete; scalar final states terminate.
        self.feed(b" ") == Some(0) && !self.invalid
    }

    /// Return the prefix length to retain when the first value ends or errors.
    /// None means another body chunk (or EOF) is required. Each byte is visited
    /// once, without reparsing prior chunks or recursively walking containers.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Option<usize> {
        for (index, &byte) in bytes.iter().enumerate() {
            match self.step(byte) {
                Step::More => {}
                Step::End(include) => return Some(index + usize::from(include)),
                Step::Invalid => {
                    self.invalid = true;
                    return Some(index + 1);
                }
            }
        }
        None
    }

    fn push(&mut self, context: Context, state: State) -> Step {
        // This is the selected Go decoder's nesting limit, not a body-size cap.
        if self.stack.len() == 10_000 {
            self.depth_error_byte = Some(match context {
                Context::Key => b'{',
                _ => b'[',
            });
            return Step::Invalid;
        }
        self.stack.push(context);
        self.state = state;
        Step::More
    }

    fn begin(&mut self, byte: u8) -> Step {
        if space(byte) {
            return Step::More;
        }
        self.state = match byte {
            b'{' => return self.push(Context::Key, State::ObjectEmpty),
            b'[' => return self.push(Context::Array, State::ArrayEmpty),
            b'"' => State::String,
            b'-' => State::Negative,
            b'0' => State::Zero,
            b'1'..=b'9' => State::Integer,
            b't' => State::Literal(b"true", 1),
            b'f' => State::Literal(b"false", 1),
            b'n' => State::Literal(b"null", 1),
            _ => return Step::Invalid,
        };
        Step::More
    }

    fn end(&mut self, byte: u8) -> Step {
        let Some(context) = self.stack.last().copied() else {
            // Go scanEnd is delayed one byte even for a non-space suffix.
            return Step::End(false);
        };
        if space(byte) {
            self.state = State::End;
            return Step::More;
        }
        match (context, byte) {
            (Context::Key, b':') => {
                *self.stack.last_mut().unwrap() = Context::Value;
                self.state = State::Value;
            }
            (Context::Value, b',') => {
                *self.stack.last_mut().unwrap() = Context::Key;
                self.state = State::Key;
            }
            (Context::Array, b',') => self.state = State::Value,
            (Context::Value, b'}') | (Context::Array, b']') => {
                self.stack.pop();
                self.state = State::End;
                if self.stack.is_empty() {
                    // stream.readValue invents a space after root closers so
                    // it never waits for an extra byte from a blocked reader.
                    return Step::End(true);
                }
            }
            _ => return Step::Invalid,
        }
        Step::More
    }

    fn step(&mut self, byte: u8) -> Step {
        match self.state {
            State::Value => return self.begin(byte),
            State::ArrayEmpty => {
                if byte == b']' {
                    return self.end(byte);
                }
                return self.begin(byte);
            }
            State::ObjectEmpty if byte == b'}' => {
                *self.stack.last_mut().unwrap() = Context::Value;
                return self.end(byte);
            }
            State::ObjectEmpty | State::Key => {
                if space(byte) {
                    return Step::More;
                }
                if byte != b'"' {
                    return Step::Invalid;
                }
                self.state = State::String;
            }
            State::End => return self.end(byte),
            State::String => match byte {
                b'"' => self.state = State::End,
                b'\\' => self.state = State::Escape,
                0..=0x1f => return Step::Invalid,
                _ => {}
            },
            State::Escape => {
                self.state = match byte {
                    b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => State::String,
                    b'u' => State::Unicode(4),
                    _ => return Step::Invalid,
                };
            }
            State::Unicode(left) => {
                if !byte.is_ascii_hexdigit() {
                    return Step::Invalid;
                }
                self.state = if left == 1 {
                    State::String
                } else {
                    State::Unicode(left - 1)
                };
            }
            State::Negative => {
                self.state = match byte {
                    b'0' => State::Zero,
                    b'1'..=b'9' => State::Integer,
                    _ => return Step::Invalid,
                };
            }
            State::Integer if byte.is_ascii_digit() => {}
            State::Zero | State::Integer => {
                self.state = match byte {
                    b'.' => State::Dot,
                    b'e' | b'E' => State::Exponent,
                    _ => return self.end(byte),
                };
            }
            State::Dot => {
                if !byte.is_ascii_digit() {
                    return Step::Invalid;
                }
                self.state = State::Fraction;
            }
            State::Fraction if byte.is_ascii_digit() => {}
            State::Fraction => {
                if matches!(byte, b'e' | b'E') {
                    self.state = State::Exponent;
                } else {
                    return self.end(byte);
                }
            }
            State::Exponent if matches!(byte, b'+' | b'-') => self.state = State::ExponentSign,
            State::Exponent | State::ExponentSign => {
                if !byte.is_ascii_digit() {
                    return Step::Invalid;
                }
                self.state = State::ExponentDigits;
            }
            State::ExponentDigits if byte.is_ascii_digit() => {}
            State::ExponentDigits => return self.end(byte),
            State::Literal(literal, index) => {
                if byte != literal[index] {
                    return Step::Invalid;
                }
                self.state = if index + 1 == literal.len() {
                    State::End
                } else {
                    State::Literal(literal, index + 1)
                };
            }
        }
        Step::More
    }
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
