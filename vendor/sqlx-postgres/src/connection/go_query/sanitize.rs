//! Parameter substitution from pgx v5.10.0 internal/sanitize.
//! Copyright (c) 2013-2021 Jack Christensen
//! MIT license and permission notice: LICENSE-GO-PGX in this vendor directory.

use crate::error::Error;

#[derive(Clone, Copy)]
enum State {
    Raw,
    Quote { delimiter: u8, escape: bool },
    LineComment,
    BlockComment(usize),
}

pub(super) fn query(sql: &str, arguments: &[Option<String>]) -> Result<String, Error> {
    let bytes = sql.as_bytes();
    let mut output = String::new();
    let mut used = vec![false; arguments.len()];
    let mut state = State::Raw;
    let mut position = 0;
    let mut start = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        position += 1;
        match state {
            State::Raw => match byte {
                b'e' | b'E' if bytes.get(position) == Some(&b'\'') => {
                    position += 1;
                    state = State::Quote {
                        delimiter: b'\'',
                        escape: true,
                    };
                }
                b'\'' | b'"' => {
                    state = State::Quote {
                        delimiter: byte,
                        escape: false,
                    }
                }
                b'-' if bytes.get(position) == Some(&b'-') => {
                    position += 1;
                    state = State::LineComment;
                }
                b'/' if bytes.get(position) == Some(&b'*') => {
                    position += 1;
                    state = State::BlockComment(0);
                }
                b'$' if bytes.get(position).is_some_and(u8::is_ascii_digit) => {
                    output.push_str(&sql[start..position - 1]);
                    let mut number = 0_u32;
                    while let Some(byte) = bytes.get(position).filter(|byte| byte.is_ascii_digit())
                    {
                        number = if number > (i32::MAX.unsigned_abs() - 9) / 10 {
                            i32::MAX.unsigned_abs()
                        } else {
                            number * 10 + u32::from(*byte - b'0')
                        };
                        position += 1;
                    }
                    let index = number
                        .checked_sub(1)
                        .ok_or_else(|| err_protocol!("first sql argument must be > 0"))?;
                    let index = usize::try_from(index).map_err(Error::protocol)?;
                    let argument = arguments
                        .get(index)
                        .ok_or_else(|| err_protocol!("insufficient arguments"))?;
                    // Match pgx's protection against creating a line comment
                    // at the boundary of a substituted argument.
                    output.push(' ');
                    if let Some(argument) = argument {
                        output.push('\'');
                        for character in argument.chars() {
                            if character == '\'' {
                                output.push('\'');
                            }
                            output.push(character);
                        }
                        output.push('\'');
                    } else {
                        output.push_str("null");
                    }
                    output.push(' ');
                    used[index] = true;
                    start = position;
                }
                b'$' => {
                    let tag_start = position;
                    let mut end = position;
                    while let Some(byte) = bytes.get(end) {
                        if *byte == b'$' {
                            break;
                        }
                        let allowed = byte.is_ascii_alphabetic()
                            || *byte == b'_'
                            || (*byte >= 0x80)
                            || (end != tag_start && byte.is_ascii_digit());
                        if !allowed {
                            break;
                        }
                        end += 1;
                    }
                    if bytes.get(end) == Some(&b'$') && !sql[tag_start..end].contains('\u{fffd}') {
                        let closer = &bytes[position - 1..end + 1];
                        position = match memchr::memmem::find(&bytes[end + 1..], closer) {
                            Some(offset) => end + 1 + offset + closer.len(),
                            None => bytes.len(),
                        };
                    }
                }
                _ => {}
            },
            State::Quote { delimiter, escape } => {
                if byte == b'\\' && escape {
                    if let Some(character) = sql[position..].chars().next() {
                        position += character.len_utf8();
                    }
                } else if byte == delimiter {
                    if bytes.get(position) == Some(&delimiter) {
                        position += 1;
                    } else {
                        state = State::Raw;
                    }
                }
            }
            State::LineComment => {
                if byte == b'\\' {
                    if let Some(character) = sql[position..].chars().next() {
                        position += character.len_utf8();
                    }
                } else if matches!(byte, b'\n' | b'\r') {
                    state = State::Raw;
                }
            }
            State::BlockComment(depth) => {
                if byte == b'/' && bytes.get(position) == Some(&b'*') {
                    position += 1;
                    state = State::BlockComment(depth + 1);
                } else if byte == b'*' && bytes.get(position) == Some(&b'/') {
                    position += 1;
                    state = if depth == 0 {
                        State::Raw
                    } else {
                        State::BlockComment(depth - 1)
                    };
                }
            }
        }
    }
    output.push_str(&sql[start..]);
    if let Some(index) = used.iter().position(|used| !used) {
        return Err(err_protocol!("unused argument: {index}"));
    }
    Ok(output)
}
