// Copyright 2010, 2018 The Go Authors. All rights reserved.
// Go encoding/json saved assignments and x/crypto/acme.responseError;
// see LICENSE-GO and LICENSE-GO-NOTICE.

use std::fmt::Write as _;

use http::{HeaderMap, StatusCode};

use super::{NativeIdentifier, legacy_json as json};
use crate::{Error, limits::bounded_display};

/// Complete native HTTP error metadata, without narrowing status or identifiers
/// into the SDK's RFC problem representation.
///
/// The fields keep the response in full (up to the client's body bound);
/// `Display` and `Debug` render only a short prefix of the remote-controlled
/// text, so formatting an error never copies a whole response body.
#[derive(Clone)]
#[non_exhaustive]
pub struct NativeResponseError {
    /// Original HTTP status, independent of a JSON status assignment.
    pub http_status: StatusCode,
    /// Go's signed platform-integer problem status after partial assignments.
    pub status: i64,
    /// Decoded problem type, including assignments before a saved type error.
    pub problem_type: String,
    /// Decoded detail, or UTF8 projection of the fallback response bytes.
    pub detail: String,
    /// Decoded instance URL.
    pub instance: String,
    /// Partially assigned native subproblems in source order.
    pub subproblems: Vec<NativeResponseSubproblem>,
    /// Original body bytes, retained even when fallback detail is invalid UTF8.
    pub body: Vec<u8>,
    /// Whether responseError replaced detail after an Unmarshal error.
    pub fallback_detail: bool,
    /// Original response headers when supplied by the transport caller.
    pub headers: Option<HeaderMap>,
}

/// A native subproblem, retaining fields not represented by the SDK enum.
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct NativeResponseSubproblem {
    /// Decoded subproblem type.
    pub problem_type: String,
    /// Decoded subproblem detail.
    pub detail: String,
    /// Decoded instance URL.
    pub instance: String,
    /// Optional pointer-valued identifier, including unknown type strings.
    pub identifier: Option<NativeIdentifier>,
}

impl NativeResponseError {
    pub(super) fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = Some(headers);
        self
    }

    pub(super) fn problem_type(&self) -> &str {
        &self.problem_type
    }

    pub(super) fn is_bad_nonce(&self) -> bool {
        // Every character in the suffix has only its ASCII upper/lowercase
        // partners in Go's lowercase mapping; non-ASCII prefix text is opaque.
        self.problem_type()
            .to_ascii_lowercase()
            .ends_with(":badnonce")
    }

    /// Exact detail bytes, including an invalid-UTF8 response fallback.
    pub fn detail_bytes(&self) -> &[u8] {
        if self.fallback_detail && !self.body.is_empty() {
            &self.body
        } else {
            self.detail.as_bytes()
        }
    }

    pub(super) fn into_error(self) -> Error {
        Error::Other(Box::new(self))
    }
}

impl std::fmt::Display for NativeResponseSubproblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bounded_display(formatter, |out| {
            write!(out, "{}: ", self.problem_type)?;
            if let Some(identifier) = &self.identifier {
                write!(out, "[{}: {}] ", identifier.kind, identifier.value)?;
            }
            out.write_str(&self.detail)
        })
    }
}

impl std::fmt::Display for NativeResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rust formatters require UTF8; detail_bytes preserves any Go raw
        // string bytes that cannot be emitted through this interface. The
        // whole rendering shares one ERROR_DISPLAY_LIMIT budget.
        bounded_display(formatter, |out| {
            write!(
                out,
                "{} {}: {}",
                self.status, self.problem_type, self.detail
            )?;
            if !self.subproblems.is_empty() {
                out.write_str("; subproblems:")?;
                for problem in &self.subproblems {
                    if out.is_cut() {
                        break;
                    }
                    write!(out, "\n\t{problem}")?;
                }
            }
            Ok(())
        })
    }
}

impl std::fmt::Debug for NativeResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derived Debug would print `body` as a list of decimal bytes, which
        // is several times the size of an already large response. Show the
        // sizes plus the bounded Display text instead.
        formatter
            .debug_struct("NativeResponseError")
            .field("http_status", &self.http_status)
            .field("status", &self.status)
            .field("message", &format_args!("{self}"))
            .field("body_len", &self.body.len())
            .field("subproblems", &self.subproblems.len())
            .field("fallback_detail", &self.fallback_detail)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for NativeResponseError {}

// Keep backing entries after a shorter duplicate array, as Go's []Subproblem
// decoder reslices existing capacity and can observe those entries again.
#[derive(Clone, Default, Debug)]
struct Subproblems {
    items: Vec<NativeResponseSubproblem>,
    length: usize,
}

/// Reusable wireError assignment state. Hidden slice backing slots survive
/// successive duplicate pointer-object decodes, just as Go's slice capacity.
#[derive(Clone, Default, Debug)]
pub(super) struct ProblemState {
    pub(super) status: i64,
    pub(super) problem_type: String,
    pub(super) detail: String,
    pub(super) instance: String,
    problems: Subproblems,
}

impl ProblemState {
    pub(super) fn into_parts(self) -> (i64, String, String, String, Vec<NativeResponseSubproblem>) {
        let mut problems = self.problems.items;
        problems.truncate(self.problems.length);
        (
            self.status,
            self.problem_type,
            self.detail,
            self.instance,
            problems,
        )
    }
}

fn string(target: &mut String, raw: &[u8], failed: &mut bool) {
    if json::trim(raw) == b"null" {
        return;
    }
    match json::unquote(raw) {
        Some(value) => *target = value,
        None => *failed = true,
    }
}

fn identifier(target: &mut Option<NativeIdentifier>, raw: &[u8], failed: &mut bool) {
    if json::trim(raw) == b"null" {
        *target = None;
        return;
    }
    // indirect allocates a nil pointer before reporting a non-null wrong type.
    let target = target.get_or_insert_with(NativeIdentifier::default);
    let Some(fields) = json::object(raw) else {
        *failed = true;
        return;
    };
    for (name, value) in fields {
        if json::field(&name, "Type") {
            string(&mut target.kind, value.get(), failed);
        } else if json::field(&name, "Value") {
            string(&mut target.value, value.get(), failed);
        }
    }
}

fn subproblem(target: &mut NativeResponseSubproblem, raw: &[u8], failed: &mut bool) {
    if json::trim(raw) == b"null" {
        return;
    }
    let Some(fields) = json::object(raw) else {
        *failed = true;
        return;
    };
    for (name, value) in fields {
        if json::field(&name, "Type") {
            string(&mut target.problem_type, value.get(), failed);
        } else if json::field(&name, "Detail") {
            string(&mut target.detail, value.get(), failed);
        } else if json::field(&name, "Instance") {
            string(&mut target.instance, value.get(), failed);
        } else if json::field(&name, "Identifier") {
            identifier(&mut target.identifier, value.get(), failed);
        }
    }
}

fn subproblems(target: &mut Subproblems, raw: &[u8], failed: &mut bool) {
    if json::trim(raw) == b"null" {
        *target = Subproblems::default();
        return;
    }
    let Some(values) = json::array(raw) else {
        *failed = true;
        return;
    };
    if values.is_empty() {
        *target = Subproblems::default();
        return;
    }
    target.length = values.len();
    for (index, value) in values.into_iter().enumerate() {
        if index >= target.items.len() {
            target.items.push(NativeResponseSubproblem::default());
        }
        subproblem(&mut target.items[index], value.get(), failed);
    }
}

/// Return a saved type error after retaining every valid sibling assignment.
/// Syntax failure happens before any assignment, as with json.Unmarshal.
pub(super) fn decode_problem_into(target: &mut ProblemState, raw: &[u8]) -> Result<(), String> {
    if !json::check_valid(raw) {
        return Err("invalid JSON problem".into());
    }
    if json::trim(raw) == b"null" {
        return Ok(());
    }
    let fields = json::object(raw).ok_or_else(|| "problem must be an object".to_owned())?;
    let mut failed = false;
    for (name, value) in fields {
        let raw = value.get();
        if json::field(&name, "Status") {
            if json::trim(raw) != b"null" {
                match json::integer(raw) {
                    Some(value) => target.status = value,
                    None => failed = true,
                }
            }
        } else if json::field(&name, "Type") {
            string(&mut target.problem_type, raw, &mut failed);
        } else if json::field(&name, "Detail") {
            string(&mut target.detail, raw, &mut failed);
        } else if json::field(&name, "Instance") {
            string(&mut target.instance, raw, &mut failed);
        } else if json::field(&name, "Subproblems") {
            subproblems(&mut target.problems, raw, &mut failed);
        }
    }
    if failed {
        Err("invalid problem field type".into())
    } else {
        Ok(())
    }
}

pub(super) fn parse(status: StatusCode, body: &[u8]) -> NativeResponseError {
    let mut state = ProblemState {
        status: i64::from(status.as_u16()),
        ..ProblemState::default()
    };
    let failed = decode_problem_into(&mut state, body).is_err();
    let (problem_status, problem_type, detail, instance, subproblems) = state.into_parts();
    let mut output = NativeResponseError {
        http_status: status,
        status: problem_status,
        problem_type,
        detail,
        instance,
        subproblems,
        body: body.to_vec(),
        fallback_detail: failed,
        headers: None,
    };
    if failed {
        output.fallback_detail = true;
        output.detail = if body.is_empty() {
            format!(
                "{} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or_default()
            )
        } else {
            json::lossy(body)
        };
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::ERROR_DISPLAY_LIMIT;

    const MARKER: &str = "... (truncated)";

    #[test]
    fn display_and_debug_embed_only_a_bounded_prefix_of_the_body() {
        // The measured case: a huge non-JSON error body became the error text.
        let body = vec![b'<'; 5 * 1024 * 1024];
        let error = parse(StatusCode::BAD_GATEWAY, &body);
        assert!(error.fallback_detail);
        let text = error.to_string();
        assert!(
            text.len() <= ERROR_DISPLAY_LIMIT + MARKER.len(),
            "{}",
            text.len()
        );
        assert!(text.ends_with(MARKER));
        let debug = format!("{error:?}");
        assert!(debug.len() <= ERROR_DISPLAY_LIMIT + 512, "{}", debug.len());
        // Structured access still sees the whole response.
        assert_eq!(error.body.len(), body.len());
        assert_eq!(error.detail_bytes().len(), body.len());
    }

    #[test]
    fn problem_document_display_shares_one_budget_with_its_subproblems() {
        let subproblems = (0..2000)
            .map(|index| {
                serde_json::json!({
                    "type": "urn:ietf:params:acme:error:dns",
                    "detail": "d".repeat(256),
                    "identifier": {"type": "dns", "value": format!("h{index}.example.com")},
                })
            })
            .collect::<Vec<_>>();
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "x".repeat(1024 * 1024),
            "subproblems": subproblems,
        }))
        .unwrap();
        let error = parse(StatusCode::BAD_REQUEST, &body);
        assert!(!error.fallback_detail);
        assert_eq!(error.subproblems.len(), 2000);
        let text = error.to_string();
        assert!(
            text.len() <= ERROR_DISPLAY_LIMIT + MARKER.len(),
            "{}",
            text.len()
        );
        assert!(text.ends_with(MARKER));
    }

    #[test]
    fn realistic_error_is_rendered_in_full() {
        let body = br#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-01 00:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/","status":429,"subproblems":[{"type":"urn:ietf:params:acme:error:dns","detail":"DNS problem: NXDOMAIN looking up A for a.example.com","identifier":{"type":"dns","value":"a.example.com"}}]}"#;
        let text = parse(StatusCode::TOO_MANY_REQUESTS, body).to_string();
        assert!(!text.ends_with(MARKER), "{text}");
        assert!(text.contains("see https://letsencrypt.org/docs/rate-limits/"));
        assert!(text.contains("NXDOMAIN looking up A for a.example.com"));
    }
}
