//! Build public JSON values without serde's private-number map convention.
//!
//! With `arbitrary_precision`, serde_json's generic Value visitor interprets
//! a literal `$serde_json::private::Number` object member as number transport.
//! Capability payload objects must retain that member as ordinary JSON data.

use serde_json::{Map, Number, Value};

use crate::go_json::{self, Cursor};

#[derive(Clone, Copy)]
enum Mode {
    Exact,
    StrictAny,
    LegacyExact,
    LegacyStrictAny,
}

impl Mode {
    fn unique_names(self) -> bool {
        matches!(self, Self::StrictAny | Self::LegacyStrictAny)
    }

    fn string(self, bytes: &[u8]) -> Result<String, String> {
        match self {
            Self::LegacyExact | Self::LegacyStrictAny => go_json::unquote(bytes),
            Self::Exact | Self::StrictAny => {
                serde_json::from_slice::<String>(bytes).map_err(|error| error.to_string())
            }
        }
    }
}

enum Frame {
    Array(Vec<Value>),
    Object {
        values: Map<String, Value>,
        key: Option<String>,
    },
}

enum Drain {
    Array(std::vec::IntoIter<Value>),
    Object(serde_json::map::IntoIter),
}

impl Drain {
    fn next(&mut self) -> Option<Value> {
        match self {
            Self::Array(values) => values.next(),
            Self::Object(values) => values.next().map(|(_, value)| value),
        }
    }
}

/// Dispose of parser-owned trees without recursively dropping nested Values.
/// Owning iterators keep the scratch stack proportional to nesting, rather
/// than moving every sibling into a second breadth-sized allocation.
fn discard(value: Value) {
    let mut parents = Vec::<Drain>::new();
    let mut current = Some(value);
    loop {
        if let Some(value) = current.take() {
            match value {
                Value::Array(values) => parents.push(Drain::Array(values.into_iter())),
                Value::Object(values) => parents.push(Drain::Object(values.into_iter())),
                _ => {}
            }
        }
        let Some(parent) = parents.last_mut() else {
            break;
        };
        current = parent.next();
        if current.is_none() {
            let _ = parents.pop();
        }
    }
}

impl Frame {
    fn append(&mut self, value: Value) -> Result<(), String> {
        match self {
            Self::Array(values) => values.push(value),
            Self::Object { values, key } => {
                let Some(key) = key.take() else {
                    discard(value);
                    return Err("invalid JSON".to_owned());
                };
                // Policy preparation checks duplicate names before this
                // projection. Keep ordinary JSON map assembly independent
                // of serde's internal numeric transport object handling.
                if let Some(replaced) = values.insert(key, value) {
                    discard(replaced);
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> Value {
        match self {
            Self::Array(values) => Value::Array(values),
            Self::Object { values, .. } => Value::Object(values),
        }
    }
}

#[derive(Default)]
struct Assembly {
    frames: Vec<Frame>,
    completed: Option<Value>,
}

impl Drop for Assembly {
    fn drop(&mut self) {
        if let Some(value) = self.completed.take() {
            discard(value);
        }
        while let Some(frame) = self.frames.pop() {
            discard(frame.finish());
        }
    }
}

/// Project prepared JSON into the existing public Value representation.
///
/// Container parsing and parser-owned error/replacement cleanup are iterative,
/// with the Go scanner and Cursor's 10,000-container grammar limit. Number
/// parsing is separate from object construction, so arbitrary numeric literals
/// and literal private-number member names remain distinct. Ordinary duplicate
/// object members retain the last value; policy preparation rejects them before
/// this projection. This does not make a returned Value's cloning, equality,
/// serialization, or drop iterative, or retain original number spelling.
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    parse_with_mode(bytes, Mode::Exact)
}

/// go-jose's default generic decoder rejects duplicate decoded names and
/// converts numbers using strconv.ParseFloat(..., 64), rejecting overflow.
pub(crate) fn strict_any(bytes: &[u8]) -> Result<Value, String> {
    parse_with_mode(bytes, Mode::StrictAny)
}

/// Legacy Go string replacement with the exact-number map projection.
pub(crate) fn legacy(bytes: &[u8]) -> Result<Value, String> {
    parse_with_mode(bytes, Mode::LegacyExact)
}

/// go-jose's generic decoder combines legacy string replacement, unique
/// decoded names, and finite binary64 numbers.
pub(crate) fn legacy_strict_any(bytes: &[u8]) -> Result<Value, String> {
    parse_with_mode(bytes, Mode::LegacyStrictAny)
}

fn parse_with_mode(bytes: &[u8], mode: Mode) -> Result<Value, String> {
    go_json::check_valid(bytes)?;
    let mut cursor = Cursor::new(bytes);
    let mut assembly = Assembly::default();
    let mut pending = true;
    loop {
        cursor.space();
        if pending {
            match cursor.peek() {
                Some(b'[') => {
                    cursor.take(b'[')?;
                    assembly.frames.push(Frame::Array(Vec::new()));
                }
                Some(b'{') => {
                    cursor.take(b'{')?;
                    assembly.frames.push(Frame::Object {
                        values: Map::new(),
                        key: None,
                    });
                }
                Some(b'"') => {
                    let raw = cursor.quoted()?;
                    // Decode only the string scalar, preserving the selected
                    // strict/legacy rules without invoking ValueVisitor.
                    assembly.completed = Some(Value::String(mode.string(raw.get())?));
                }
                _ => {
                    let raw = cursor.value()?;
                    assembly.completed = Some(match raw.get() {
                        b"null" => Value::Null,
                        b"true" => Value::Bool(true),
                        b"false" => Value::Bool(false),
                        bytes => {
                            let text =
                                std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
                            let number = match mode {
                                Mode::Exact | Mode::LegacyExact => {
                                    text.parse::<Number>().map_err(|error| error.to_string())?
                                }
                                Mode::StrictAny | Mode::LegacyStrictAny => Number::from_f64(
                                    text.parse::<f64>().map_err(|error| error.to_string())?,
                                )
                                .ok_or_else(|| "JSON number out of float64 range".to_owned())?,
                            };
                            Value::Number(number)
                        }
                    });
                }
            }
            pending = false;
        }
        if assembly.frames.is_empty() && assembly.completed.is_some() {
            // Leave ownership with the cleanup guard until the final cursor
            // check succeeds, including on a future grammar-pass change.
            cursor.done()?;
            return assembly
                .completed
                .take()
                .ok_or_else(|| "invalid JSON".to_owned());
        }
        if let Some(value) = assembly.completed.take() {
            if let Some(frame) = assembly.frames.last_mut() {
                frame.append(value)?;
            } else {
                discard(value);
                return Err("invalid JSON".to_owned());
            }
        }
        cursor.space();
        let frame = assembly
            .frames
            .last_mut()
            .ok_or_else(|| "invalid JSON".to_owned())?;
        let close = match frame {
            Frame::Array(_) => b']',
            Frame::Object { .. } => b'}',
        };
        if cursor.peek() == Some(close) {
            cursor.take(close)?;
            assembly.completed = Some(
                assembly
                    .frames
                    .pop()
                    .ok_or_else(|| "invalid JSON".to_owned())?
                    .finish(),
            );
            continue;
        }
        if cursor.peek() == Some(b',') {
            cursor.take(b',')?;
            cursor.space();
        }
        if let Frame::Object { values, key } = frame {
            let raw = cursor.quoted()?;
            let name = mode.string(raw.get())?;
            if mode.unique_names() && values.contains_key(&name) {
                return Err(format!("json: duplicate key '{name}' in object"));
            }
            *key = Some(name);
            cursor.space();
            cursor.take(b':')?;
        }
        pending = true;
    }
}
