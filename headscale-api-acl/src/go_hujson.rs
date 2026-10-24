// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// hujson v0.0.0-20260302212456-ecc657c15afd
// parse.go, standard.go, pack.go, types.go.

//! Byte-oriented HuJSON parsing without a recursive AST. Literal validity uses
//! JSON v1 grammar (including its permissive string UTF-8); comments require
//! valid UTF-8 before metadata removal. Whitespace offsets are preserved.

use std::fmt::Write as _;

#[derive(Clone, Copy)]
enum Task {
    Value { name: bool },
    Finish { start: usize, kind: u8, name: bool },
    ObjectNext(Option<usize>),
    ObjectColon,
    ObjectAfter,
    ArrayNext(Option<usize>),
    ArrayAfter,
    End,
}

struct Parser<'a> {
    raw: &'a [u8],
    out: Vec<u8>,
    at: usize,
}

impl Parser<'_> {
    fn error(&self, at: usize, message: &str) -> String {
        // Diagnostic path only; a naive count is fine and avoids a dependency.
        #[allow(clippy::naive_bytecount)]
        let line = 1 + self.raw[..at].iter().filter(|&&byte| byte == b'\n').count();
        let column = at
            - self.raw[..at]
                .iter()
                .rposition(|&byte| byte == b'\n')
                .map_or(0, |at| at + 1)
            + 1;
        format!("hujson: line {line}, column {column}: {message}")
    }

    fn invalid(&self, at: usize, context: &str) -> String {
        let bytes = &self.raw[at..];
        let character = match std::str::from_utf8(bytes) {
            Ok(text) => text.chars().next(),
            Err(error) if error.valid_up_to() > 0 => {
                std::str::from_utf8(&bytes[..error.valid_up_to()])
                    .ok()
                    .and_then(|text| text.chars().next())
            }
            _ => None,
        };
        let quoted = character.map_or_else(
            || format!("'\\x{:02x}'", bytes[0]),
            |ch| {
                let quoted = crate::go_strconv::quote_rune(ch);
                // HuJSON spells every non-printing rune with a Unicode escape,
                // including ASCII controls otherwise abbreviated by strconv.
                if ch.is_ascii_control() {
                    format!("'\\u{:04x}'", u32::from(ch))
                } else {
                    quoted
                }
            },
        );
        self.error(at, &format!("invalid character {quoted} {context}"))
    }

    fn extra(&mut self) -> Result<(), String> {
        loop {
            match self.raw.get(self.at) {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.at += 1,
                Some(b'/') if matches!(self.raw.get(self.at + 1), Some(b'/' | b'*')) => {
                    let start = self.at;
                    let line = self.raw[self.at + 1] == b'/';
                    let body = &self.raw[self.at + 2..];
                    let end = if line {
                        body.iter()
                            .position(|&byte| byte == b'\n')
                            .map(|at| self.at + 2 + at + 1)
                    } else {
                        body.windows(2)
                            .position(|bytes| bytes == b"*/")
                            .map(|at| self.at + 2 + at + 2)
                    }
                    .ok_or_else(|| self.error(start, "parsing comment: unexpected EOF"))?;
                    if std::str::from_utf8(&self.raw[start..end]).is_err() {
                        return Err(self.error(start, "invalid UTF-8 in comment"));
                    }
                    for byte in &mut self.out[start..end] {
                        if !matches!(*byte, b' ' | b'\t' | b'\r' | b'\n') {
                            *byte = b' ';
                        }
                    }
                    self.at = end;
                }
                _ => return Ok(()),
            }
        }
    }

    fn literal(&mut self, start: usize, string: bool) -> Result<(), String> {
        if string {
            self.at += 1;
            let mut escaped = false;
            loop {
                let Some(&byte) = self.raw.get(self.at) else {
                    return Err(self.error(self.at, "parsing string: unexpected EOF"));
                };
                self.at += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
        } else {
            while self.raw.get(self.at).is_some_and(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'+' | b'.')
            }) {
                self.at += 1;
            }
            if self.at == start {
                return Err(self.invalid(start, "at start of value"));
            }
        }
        if crate::go_json::check_valid(&self.raw[start..self.at]).is_err() {
            // Error strings cannot contain arbitrary raw bytes. Valid UTF-8
            // literal diagnostics are exact; invalid byte literals are escaped.
            let text = std::str::from_utf8(&self.raw[start..self.at]).map_or_else(
                |_| {
                    self.raw[start..self.at]
                        .iter()
                        .fold(String::new(), |mut text, byte| {
                            let _ = write!(text, "\\x{byte:02x}");
                            text
                        })
                },
                str::to_owned,
            );
            return Err(self.error(start, &format!("invalid literal: {text}")));
        }
        Ok(())
    }
}

pub(crate) fn standardize(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut parser = Parser {
        raw,
        out: raw.to_vec(),
        at: 0,
    };
    let mut tasks = vec![Task::End, Task::Value { name: false }];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Value { name } => {
                parser.extra()?;
                let start = parser.at;
                let Some(&kind) = raw.get(start) else {
                    return Err(parser.error(start, "parsing value: unexpected EOF"));
                };
                tasks.push(Task::Finish { start, kind, name });
                match kind {
                    b'{' => {
                        parser.at += 1;
                        tasks.push(Task::ObjectNext(None));
                    }
                    b'[' => {
                        parser.at += 1;
                        tasks.push(Task::ArrayNext(None));
                    }
                    b'}' | b']' => return Err(parser.invalid(start, "at start of value")),
                    b'"' => parser.literal(start, true)?,
                    _ => parser.literal(start, false)?,
                }
            }
            Task::Finish { start, kind, name } => {
                parser.extra()?;
                if name && kind != b'"' {
                    return Err(parser.invalid(start, "at start of object name"));
                }
            }
            Task::ObjectNext(comma) => {
                parser.extra()?;
                if raw.get(parser.at) == Some(&b'}') {
                    if let Some(comma) = comma {
                        parser.out[comma] = b' ';
                    }
                    parser.at += 1;
                } else {
                    tasks.push(Task::ObjectColon);
                    tasks.push(Task::Value { name: true });
                }
            }
            Task::ObjectColon => {
                if parser.at == raw.len() {
                    return Err(
                        parser.error(parser.at, "parsing object after name: unexpected EOF")
                    );
                }
                if raw[parser.at] != b':' {
                    return Err(parser.invalid(parser.at, "after object name"));
                }
                parser.at += 1;
                tasks.push(Task::ObjectAfter);
                tasks.push(Task::Value { name: false });
            }
            Task::ObjectAfter | Task::ArrayAfter => {
                let object = matches!(task, Task::ObjectAfter);
                if parser.at == raw.len() {
                    return Err(parser.error(
                        parser.at,
                        if object {
                            "parsing object after value: unexpected EOF"
                        } else {
                            "parsing array after value: unexpected EOF"
                        },
                    ));
                }
                let close = if object { b'}' } else { b']' };
                if raw[parser.at] == b',' {
                    let comma = parser.at;
                    parser.at += 1;
                    tasks.push(if object {
                        Task::ObjectNext(Some(comma))
                    } else {
                        Task::ArrayNext(Some(comma))
                    });
                } else if raw[parser.at] == close {
                    parser.at += 1;
                } else {
                    return Err(parser.invalid(
                        parser.at,
                        if object {
                            "after object value (expecting ',' or '}')"
                        } else {
                            "after array value (expecting ',' or ']')"
                        },
                    ));
                }
            }
            Task::ArrayNext(comma) => {
                parser.extra()?;
                if raw.get(parser.at) == Some(&b']') {
                    if let Some(comma) = comma {
                        parser.out[comma] = b' ';
                    }
                    parser.at += 1;
                } else {
                    tasks.push(Task::ArrayAfter);
                    tasks.push(Task::Value { name: false });
                }
            }
            Task::End if parser.at < raw.len() => {
                return Err(parser.invalid(parser.at, "after top-level value"));
            }
            Task::End => {}
        }
    }
    Ok(parser.out)
}

/// Match stripMetadataMembers -> Standardize -> Pack without a recursive AST.
/// Original spans retain HuJSON's ownership of whitespace and comments; in
/// particular, a removed member does not donate its extras to its neighbors.
pub(crate) fn prepare_metadata(raw: &[u8]) -> Result<Vec<u8>, String> {
    type Span = std::ops::Range<usize>;
    enum Kind {
        Pending,
        Literal(Span),
        Object {
            members: Vec<(usize, usize)>,
            after: Span,
        },
        Array {
            elements: Vec<usize>,
            after: Span,
        },
    }
    struct Value {
        before: Span,
        // HuJSON distinguishes nil from a non-nil empty AfterExtra: the latter
        // is also the marker for an original trailing comma.
        after: Option<Span>,
        kind: Kind,
    }
    fn allocate(values: &mut Vec<Value>) -> usize {
        let id = values.len();
        values.push(Value {
            before: 0..0,
            after: None,
            kind: Kind::Pending,
        });
        id
    }
    enum Parse {
        Value(usize),
        Finish(usize),
        ObjectNext(usize),
        Colon,
        ObjectAfter(usize, usize),
        ArrayNext(usize),
        ArrayAfter(usize, usize),
    }

    // Validation still precedes metadata removal, including invalid comments
    // inside removed members. Standardize is length preserving; its output can
    // supply standardized extras while the original bytes supply punctuation
    // and the original trailing-comma/AfterExtra ownership.
    let mut parser = Parser {
        raw,
        out: standardize(raw)?,
        at: 0,
    };
    let mut values = Vec::new();
    let root = allocate(&mut values);
    let mut tasks = vec![Parse::Value(root)];
    while let Some(task) = tasks.pop() {
        match task {
            Parse::Value(id) => {
                let before = parser.at;
                parser.extra()?;
                values[id].before = before..parser.at;
                let start = parser.at;
                let Some(&byte) = raw.get(start) else {
                    return Err(parser.error(start, "parsing value: unexpected EOF"));
                };
                tasks.push(Parse::Finish(id));
                match byte {
                    b'{' => {
                        parser.at += 1;
                        values[id].kind = Kind::Object {
                            members: Vec::new(),
                            after: 0..0,
                        };
                        tasks.push(Parse::ObjectNext(id));
                    }
                    b'[' => {
                        parser.at += 1;
                        values[id].kind = Kind::Array {
                            elements: Vec::new(),
                            after: 0..0,
                        };
                        tasks.push(Parse::ArrayNext(id));
                    }
                    _ => {
                        parser.literal(start, byte == b'"')?;
                        values[id].kind = Kind::Literal(start..parser.at);
                    }
                }
            }
            Parse::Finish(id) => {
                let start = parser.at;
                parser.extra()?;
                values[id].after = (start < parser.at).then_some(start..parser.at);
            }
            Parse::ObjectNext(id) => {
                let before = parser.at;
                parser.extra()?;
                if raw.get(parser.at) == Some(&b'}') {
                    let last = match &values[id].kind {
                        Kind::Object { members, .. } => members.last().map(|member| member.1),
                        _ => unreachable!("object parse task"),
                    };
                    if let Some(last) = last {
                        values[last].after.get_or_insert(parser.at..parser.at);
                    }
                    if let Kind::Object { after, .. } = &mut values[id].kind {
                        *after = before..parser.at;
                    }
                    parser.at += 1;
                } else {
                    // parseNext owns these extras on the following name.
                    parser.at = before;
                    let name = allocate(&mut values);
                    let value = allocate(&mut values);
                    if let Kind::Object { members, .. } = &mut values[id].kind {
                        members.push((name, value));
                    }
                    tasks.push(Parse::ObjectAfter(id, value));
                    tasks.push(Parse::Value(value));
                    tasks.push(Parse::Colon);
                    tasks.push(Parse::Value(name));
                }
            }
            Parse::Colon => {
                if raw.get(parser.at) != Some(&b':') {
                    return Err(
                        parser.error(parser.at, "parsing object after name: unexpected EOF")
                    );
                }
                parser.at += 1;
            }
            Parse::ObjectAfter(id, value) => match raw.get(parser.at) {
                Some(b',') => {
                    parser.at += 1;
                    tasks.push(Parse::ObjectNext(id));
                }
                Some(b'}') => {
                    // Without a trailing comma, parseNextTrimmed moves the
                    // final value's extras to the object's own AfterExtra.
                    let extra = values[value].after.take().unwrap_or(parser.at..parser.at);
                    if let Kind::Object { after, .. } = &mut values[id].kind {
                        *after = extra;
                    }
                    parser.at += 1;
                }
                _ => {
                    return Err(
                        parser.error(parser.at, "parsing object after value: unexpected EOF")
                    );
                }
            },
            Parse::ArrayNext(id) => {
                let before = parser.at;
                parser.extra()?;
                if raw.get(parser.at) == Some(&b']') {
                    let last = match &values[id].kind {
                        Kind::Array { elements, .. } => elements.last().copied(),
                        _ => unreachable!("array parse task"),
                    };
                    if let Some(last) = last {
                        values[last].after.get_or_insert(parser.at..parser.at);
                    }
                    if let Kind::Array { after, .. } = &mut values[id].kind {
                        *after = before..parser.at;
                    }
                    parser.at += 1;
                } else {
                    parser.at = before;
                    let value = allocate(&mut values);
                    if let Kind::Array { elements, .. } = &mut values[id].kind {
                        elements.push(value);
                    }
                    tasks.push(Parse::ArrayAfter(id, value));
                    tasks.push(Parse::Value(value));
                }
            }
            Parse::ArrayAfter(id, value) => match raw.get(parser.at) {
                Some(b',') => {
                    parser.at += 1;
                    tasks.push(Parse::ArrayNext(id));
                }
                Some(b']') => {
                    let extra = values[value].after.take().unwrap_or(parser.at..parser.at);
                    if let Kind::Array { after, .. } = &mut values[id].kind {
                        *after = extra;
                    }
                    parser.at += 1;
                }
                _ => {
                    return Err(
                        parser.error(parser.at, "parsing array after value: unexpected EOF")
                    );
                }
            },
        }
    }
    if parser.at < raw.len() {
        return Err(parser.invalid(parser.at, "after top-level value"));
    }

    enum Pack {
        Value(usize, bool),
        Extra(Span),
        Byte(u8),
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut tasks = vec![Pack::Value(root, true)];
    while let Some(task) = tasks.pop() {
        match task {
            Pack::Extra(span) => out.extend_from_slice(&parser.out[span]),
            Pack::Byte(byte) => out.push(byte),
            Pack::Value(id, strip) => {
                let value = &values[id];
                out.extend_from_slice(&parser.out[value.before.clone()]);
                if let Some(after) = &value.after {
                    tasks.push(Pack::Extra(after.clone()));
                }
                match &value.kind {
                    Kind::Literal(span) => out.extend_from_slice(&raw[span.clone()]),
                    Kind::Object { members, after } => {
                        let mut kept = Vec::new();
                        for &(name, child) in members {
                            let child_strip = if strip {
                                let Kind::Literal(span) = &values[name].kind else {
                                    unreachable!("validated object name")
                                };
                                // Literal.String uses legacy JSON replacement
                                // for invalid UTF-8 and unpaired surrogates.
                                let name = crate::go_json::unquote(&raw[span.clone()])?;
                                if name.starts_with('#') {
                                    continue;
                                }
                                name != "app"
                            } else {
                                false
                            };
                            kept.push((name, child, child_strip));
                        }
                        out.push(b'{');
                        tasks.push(Pack::Byte(b'}'));
                        tasks.push(Pack::Extra(after.clone()));
                        if kept
                            .last()
                            .is_some_and(|(_, child, _)| values[*child].after.is_some())
                        {
                            // Standardize moves non-nil last.AfterExtra and a
                            // blank comma into the composite's AfterExtra. The
                            // byte order is identical when emitted separately.
                            tasks.push(Pack::Byte(b' '));
                        }
                        for (index, &(name, child, child_strip)) in kept.iter().enumerate().rev() {
                            if index + 1 < kept.len() {
                                tasks.push(Pack::Byte(b','));
                            }
                            tasks.push(Pack::Value(child, child_strip));
                            tasks.push(Pack::Byte(b':'));
                            tasks.push(Pack::Value(name, false));
                        }
                    }
                    Kind::Array { elements, after } => {
                        out.push(b'[');
                        tasks.push(Pack::Byte(b']'));
                        tasks.push(Pack::Extra(after.clone()));
                        if elements
                            .last()
                            .is_some_and(|child| values[*child].after.is_some())
                        {
                            tasks.push(Pack::Byte(b' '));
                        }
                        for (index, &child) in elements.iter().enumerate().rev() {
                            if index + 1 < elements.len() {
                                tasks.push(Pack::Byte(b','));
                            }
                            tasks.push(Pack::Value(child, strip));
                        }
                    }
                    Kind::Pending => unreachable!("completed HuJSON parse"),
                }
            }
        }
    }
    Ok(out)
}
