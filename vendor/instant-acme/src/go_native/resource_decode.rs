// Copyright 2010, 2013, 2015, 2018 The Go Authors. All rights reserved.
// encoding/json field assignment and ACME wire resources; see LICENSE-GO.

//! Finite typed assignment over ordered raw spans. Repeated fields are visited
//! in order; scalar null is a no-op, pointer null clears, and slices retain the
//! backing slots needed by later duplicate fields. Unknown values are skipped.

use super::{
    NativeAuthorization, NativeChallenge, NativeIdentifier, NativeOrderResource, NativeProblem,
    NativeSubproblem, json_time, legacy_json as json, native_error,
    response_error::{ProblemState, decode_problem_into},
};
use crate::Error;

pub(super) trait NativeDecode: Sized {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Default)]
struct Saved(Option<String>);

// decodeState keeps the nearest containing struct separately from its complete
// canonical field stack. Slice elements do not add an index to that stack.
#[derive(Default)]
struct Context {
    structure: &'static str,
    path: String,
}

impl Context {
    fn field(&self, structure: &'static str, name: &str) -> Self {
        Self {
            structure,
            path: if self.path.is_empty() {
                name.to_owned()
            } else {
                format!("{}.{name}", self.path)
            },
        }
    }
}

impl Saved {
    fn error(&mut self, error: String) {
        if self.0.is_none() {
            self.0 = Some(error);
        }
    }
    fn mismatch(&mut self, raw: &[u8], context: &Context, expected: &str) {
        self.error(type_error(raw, context.structure, &context.path, expected));
    }
    fn finish<T>(self, value: T) -> Result<T, Error> {
        match self.0 {
            Some(error) => Err(native_error(error)),
            None => Ok(value),
        }
    }
}

/// Selected UnmarshalTypeError.Error formatting, shared by finite anonymous
/// directory/account response structs without exposing their assignment state.
pub(super) fn type_error(raw: &[u8], structure: &str, path: &str, expected: &str) -> String {
    let value = match json::trim(raw).first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        Some(b'n') => "null",
        _ => "number",
    };
    // Only failed numeric conversions include the original literal.
    // A number assigned to a string, bool, slice or struct says "number".
    let value = if value == "number" && expected == "int" {
        format!("number {}", String::from_utf8_lossy(json::trim(raw)))
    } else {
        value.to_owned()
    };
    if structure.is_empty() && path.is_empty() {
        format!("json: cannot unmarshal {value} into Go value of type {expected}")
    } else {
        format!(
            "json: cannot unmarshal {value} into Go struct field {structure}.{path} of type {expected}"
        )
    }
}

#[derive(Default)]
struct Backing<T> {
    slots: Vec<T>,
    len: usize,
}

impl<T: Default> Backing<T> {
    fn assign(
        &mut self,
        raw: &[u8],
        saved: &mut Saved,
        context: &Context,
        kind: &str,
        mut element: impl FnMut(&mut T, &[u8], &mut Saved) -> Result<(), String>,
    ) -> Result<(), String> {
        if json::trim(raw) == b"null" {
            self.slots.clear();
            self.len = 0;
            return Ok(());
        }
        let Some(values) = json::array(raw) else {
            saved.mismatch(raw, context, kind);
            return Ok(());
        };
        if values.is_empty() {
            self.slots.clear();
            self.len = 0;
            return Ok(());
        }
        self.len = values.len();
        for (index, value) in values.into_iter().enumerate() {
            if index == self.slots.len() {
                self.slots.push(T::default());
            }
            element(&mut self.slots[index], value.get(), saved)?;
        }
        Ok(())
    }
    fn finish(mut self) -> Vec<T> {
        self.slots.truncate(self.len);
        self.slots
    }
}

fn fields<'a>(
    raw: &'a [u8],
    saved: &mut Saved,
    context: &Context,
    kind: &str,
) -> Option<Vec<(String, json::Raw<'a>)>> {
    if json::trim(raw) == b"null" {
        return None;
    }
    match json::object(raw) {
        Some(fields) => Some(fields),
        None => {
            saved.mismatch(raw, context, kind);
            None
        }
    }
}

fn string(target: &mut String, raw: &[u8], saved: &mut Saved, context: &Context) {
    if json::trim(raw) == b"null" {
        return;
    }
    match json::unquote(raw) {
        Some(value) => *target = value,
        None => saved.mismatch(raw, context, "string"),
    }
}

fn optional_string(target: &mut Option<String>, raw: &[u8], saved: &mut Saved, context: &Context) {
    // The Go wire field is a scalar string. Option is only the SDK's view.
    if json::trim(raw) == b"null" {
        return;
    }
    match json::unquote(raw) {
        Some(value) => *target = Some(value),
        None => saved.mismatch(raw, context, "string"),
    }
}

fn identifier(target: &mut NativeIdentifier, raw: &[u8], saved: &mut Saved, context: &Context) {
    let Some(fields) = fields(raw, saved, context, "acme.wireAuthzID") else {
        return;
    };
    for (name, value) in fields {
        if json::field(&name, "Type") {
            string(
                &mut target.kind,
                value.get(),
                saved,
                &context.field("wireAuthzID", "type"),
            );
        } else if json::field(&name, "Value") {
            string(
                &mut target.value,
                value.get(),
                saved,
                &context.field("wireAuthzID", "value"),
            );
        }
    }
}

fn problem(target: &mut Option<ProblemState>, raw: &[u8], saved: &mut Saved, context: &Context) {
    if json::trim(raw) == b"null" {
        *target = None;
        return;
    }
    let target = target.get_or_insert_with(ProblemState::default);
    if let Err(error) = decode_problem_into(target, raw) {
        let mut diagnostic = Saved::default();
        problem_diagnostic(raw, &mut diagnostic, context);
        saved.error(diagnostic.0.unwrap_or(error));
    }
}

fn string_diagnostic(raw: &[u8], saved: &mut Saved, context: &Context) {
    let raw = json::trim(raw);
    if raw != b"null" && raw.first() != Some(&b'"') {
        saved.mismatch(raw, context, "string");
    }
}

// Assignment remains in the shared wireError decoder. This finite walk only
// reconstructs its first saved UnmarshalTypeError's field context; no unknown
// payload is recursively decoded and no array index enters the field stack.
fn problem_diagnostic(raw: &[u8], saved: &mut Saved, context: &Context) {
    let Some(members) = fields(raw, saved, context, "acme.wireError") else {
        return;
    };
    for (name, value) in members {
        let raw = value.get();
        if json::field(&name, "Status") {
            if json::trim(raw) != b"null" && json::integer(raw).is_none() {
                saved.mismatch(raw, &context.field("wireError", "Status"), "int");
            }
        } else if let Some(name) = ["Type", "Detail", "Instance"]
            .into_iter()
            .find(|field| json::field(&name, field))
        {
            string_diagnostic(raw, saved, &context.field("wireError", name));
        } else if json::field(&name, "Subproblems") && json::trim(raw) != b"null" {
            let context = context.field("wireError", "Subproblems");
            match json::array(raw) {
                Some(values) => {
                    for value in values {
                        subproblem_diagnostic(value.get(), saved, &context);
                    }
                }
                None => saved.mismatch(raw, &context, "[]acme.Subproblem"),
            }
        }
    }
}

fn subproblem_diagnostic(raw: &[u8], saved: &mut Saved, context: &Context) {
    let Some(members) = fields(raw, saved, context, "acme.Subproblem") else {
        return;
    };
    for (name, value) in members {
        let raw = value.get();
        if let Some(name) = ["Type", "Detail", "Instance"]
            .into_iter()
            .find(|field| json::field(&name, field))
        {
            string_diagnostic(raw, saved, &context.field("Subproblem", name));
        } else if json::field(&name, "Identifier") {
            let context = context.field("Subproblem", "Identifier");
            let Some(members) = fields(raw, saved, &context, "acme.AuthzID") else {
                continue;
            };
            for (name, value) in members {
                if let Some(name) = ["Type", "Value"]
                    .into_iter()
                    .find(|field| json::field(&name, field))
                {
                    string_diagnostic(value.get(), saved, &context.field("AuthzID", name));
                }
            }
        }
    }
}

fn finish_problem(state: Option<ProblemState>) -> Option<NativeProblem> {
    state.map(|state| {
        let (status, kind, detail, instance, subproblems) = state.into_parts();
        NativeProblem {
            kind: Some(kind),
            detail: Some(detail),
            instance: Some(instance),
            status: Some(status),
            subproblems: subproblems
                .into_iter()
                .map(|problem| NativeSubproblem {
                    identifier: problem.identifier,
                    kind: Some(problem.problem_type),
                    detail: Some(problem.detail),
                    instance: Some(problem.instance),
                })
                .collect(),
        }
    })
}

#[derive(Default)]
struct Challenge {
    value: NativeChallenge,
    problem: Option<ProblemState>,
}

impl Challenge {
    fn assign(&mut self, raw: &[u8], saved: &mut Saved, context: &Context) -> Result<(), String> {
        let Some(fields) = fields(raw, saved, context, "acme.wireChallenge") else {
            return Ok(());
        };
        for (name, value) in fields {
            let raw = value.get();
            if json::field(&name, "URL") {
                string(
                    &mut self.value.url,
                    raw,
                    saved,
                    &context.field("wireChallenge", "url"),
                );
            } else if json::field(&name, "URI") {
                string(
                    &mut self.value.uri,
                    raw,
                    saved,
                    &context.field("wireChallenge", "uri"),
                );
            } else if json::field(&name, "Type") {
                string(
                    &mut self.value.kind,
                    raw,
                    saved,
                    &context.field("wireChallenge", "Type"),
                );
            } else if json::field(&name, "Token") {
                string(
                    &mut self.value.token,
                    raw,
                    saved,
                    &context.field("wireChallenge", "Token"),
                );
            } else if json::field(&name, "Status") {
                string(
                    &mut self.value.status,
                    raw,
                    saved,
                    &context.field("wireChallenge", "Status"),
                );
            } else if json::field(&name, "Validated") {
                json_time::assign(&mut self.value.validated, raw)?;
            } else if json::field(&name, "Error") {
                problem(
                    &mut self.problem,
                    raw,
                    saved,
                    &context.field("wireChallenge", "Error"),
                );
            }
        }
        Ok(())
    }
    fn finish(mut self) -> NativeChallenge {
        self.value.error = finish_problem(self.problem);
        self.value
    }
}

#[derive(Default)]
struct Authorization {
    value: NativeAuthorization,
    challenges: Backing<Challenge>,
    combinations: Backing<Backing<i64>>,
    problem: Option<ProblemState>,
}

impl Authorization {
    fn assign(&mut self, raw: &[u8], saved: &mut Saved, context: &Context) -> Result<(), String> {
        let Some(fields) = fields(raw, saved, context, "acme.wireAuthz") else {
            return Ok(());
        };
        for (name, value) in fields {
            let raw = value.get();
            if json::field(&name, "Status") {
                string(
                    &mut self.value.status,
                    raw,
                    saved,
                    &context.field("wireAuthz", "Status"),
                );
            } else if json::field(&name, "Identifier") {
                // Identifier is a Go value struct, so null retains it.
                identifier(
                    self.value
                        .identifier
                        .get_or_insert_with(NativeIdentifier::default),
                    raw,
                    saved,
                    &context.field("wireAuthz", "Identifier"),
                );
            } else if json::field(&name, "Wildcard") {
                match json::trim(raw) {
                    b"null" => {}
                    b"true" => self.value.wildcard = Some(true),
                    b"false" => self.value.wildcard = Some(false),
                    _ => saved.mismatch(raw, &context.field("wireAuthz", "Wildcard"), "bool"),
                }
            } else if json::field(&name, "Expires") {
                json_time::assign(&mut self.value.expires, raw)?;
            } else if json::field(&name, "Error") {
                problem(
                    &mut self.problem,
                    raw,
                    saved,
                    &context.field("wireAuthz", "Error"),
                );
            } else if json::field(&name, "Challenges") {
                self.challenges.assign(
                    raw,
                    saved,
                    &context.field("wireAuthz", "Challenges"),
                    "[]acme.wireChallenge",
                    |challenge, raw, saved| {
                        challenge.assign(raw, saved, &context.field("wireAuthz", "Challenges"))
                    },
                )?;
            } else if json::field(&name, "Combinations") {
                self.combinations.assign(
                    raw,
                    saved,
                    &context.field("wireAuthz", "Combinations"),
                    "[][]int",
                    |inner, raw, saved| {
                        inner.assign(
                            raw,
                            saved,
                            &context.field("wireAuthz", "Combinations"),
                            "[]int",
                            |target, raw, saved| {
                                if json::trim(raw) != b"null" {
                                    match json::integer(raw) {
                                        Some(value) => *target = value,
                                        None => saved.mismatch(
                                            raw,
                                            &context.field("wireAuthz", "Combinations"),
                                            "int",
                                        ),
                                    }
                                }
                                Ok(())
                            },
                        )
                    },
                )?;
            }
        }
        Ok(())
    }
    fn finish(mut self) -> NativeAuthorization {
        self.value.challenges = self
            .challenges
            .finish()
            .into_iter()
            .map(Challenge::finish)
            .collect();
        self.value.combinations = self
            .combinations
            .finish()
            .into_iter()
            .map(Backing::finish)
            .collect();
        self.value.error = finish_problem(self.problem);
        self.value
    }
}

#[derive(Default)]
struct Order {
    value: NativeOrderResource,
    authorizations: Backing<String>,
    identifiers: Backing<NativeIdentifier>,
    problem: Option<ProblemState>,
}

impl Order {
    fn assign(&mut self, raw: &[u8], saved: &mut Saved, context: &Context) -> Result<(), String> {
        let Some(fields) = fields(
            raw,
            saved,
            context,
            "struct { Status string; Expires time.Time; Identifiers []acme.wireAuthzID; NotBefore time.Time; NotAfter time.Time; Error *acme.wireError; Authorizations []string; Finalize string; Certificate string }",
        ) else {
            return Ok(());
        };
        for (name, value) in fields {
            let raw = value.get();
            if json::field(&name, "Status") {
                string(
                    &mut self.value.status,
                    raw,
                    saved,
                    &context.field("", "Status"),
                );
            } else if json::field(&name, "Finalize") {
                string(
                    &mut self.value.finalize,
                    raw,
                    saved,
                    &context.field("", "Finalize"),
                );
            } else if json::field(&name, "Certificate") {
                optional_string(
                    &mut self.value.certificate,
                    raw,
                    saved,
                    &context.field("", "Certificate"),
                );
            } else if json::field(&name, "Expires") {
                json_time::assign(&mut self.value.expires, raw)?;
            } else if json::field(&name, "NotBefore") {
                json_time::assign(&mut self.value.not_before, raw)?;
            } else if json::field(&name, "NotAfter") {
                json_time::assign(&mut self.value.not_after, raw)?;
            } else if json::field(&name, "Error") {
                problem(&mut self.problem, raw, saved, &context.field("", "Error"));
            } else if json::field(&name, "Authorizations") {
                self.authorizations.assign(
                    raw,
                    saved,
                    &context.field("", "Authorizations"),
                    "[]string",
                    |target, raw, saved| {
                        string(target, raw, saved, &context.field("", "Authorizations"));
                        Ok(())
                    },
                )?;
            } else if json::field(&name, "Identifiers") {
                self.identifiers.assign(
                    raw,
                    saved,
                    &context.field("", "Identifiers"),
                    "[]acme.wireAuthzID",
                    |target, raw, saved| {
                        identifier(target, raw, saved, &context.field("", "Identifiers"));
                        Ok(())
                    },
                )?;
            }
        }
        Ok(())
    }
    fn finish(mut self) -> NativeOrderResource {
        self.value.authorizations = self.authorizations.finish();
        self.value.identifiers = self.identifiers.finish();
        self.value.error = finish_problem(self.problem);
        self.value
    }
}

impl NativeDecode for Option<NativeOrderResource> {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error> {
        if json::trim(bytes) == b"null" {
            return Ok(None);
        }
        let mut target = Order::default();
        let mut saved = Saved::default();
        target
            .assign(bytes, &mut saved, &Context::default())
            .map_err(native_error)?;
        saved.finish(Some(target.finish()))
    }
}

impl NativeDecode for Option<NativeAuthorization> {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error> {
        if json::trim(bytes) == b"null" {
            return Ok(None);
        }
        let mut target = Authorization::default();
        let mut saved = Saved::default();
        target
            .assign(bytes, &mut saved, &Context::default())
            .map_err(native_error)?;
        saved.finish(Some(target.finish()))
    }
}

impl NativeDecode for Option<NativeChallenge> {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error> {
        if json::trim(bytes) == b"null" {
            return Ok(None);
        }
        let mut target = Challenge::default();
        let mut saved = Saved::default();
        target
            .assign(bytes, &mut saved, &Context::default())
            .map_err(native_error)?;
        saved.finish(Some(target.finish()))
    }
}
