//! Admin-panel auth surface.
//!
//! Three concerns, deliberately small:
//!
//! 1. **Bearer-token check.** For CLI / scripting — `Authorization:
//!    Bearer <HEADSCALE_ADMIN_TOKEN>`. The token is a fixed string the
//!    operator configures at startup; we constant-time compare it
//!    against the presented value.
//! 2. **Session cookie.** For browser UX — set by `POST /admin/login`
//!    after a valid bearer-token submission, carried thereafter by the
//!    browser. The cookie payload is `<expires_unix>.<hmac_hex>` where
//!    the HMAC is taken over the expiry bytes with the per-process
//!    secret. 8-hour TTL by default. Cookie attributes:
//!    `HttpOnly; Secure; SameSite=Lax; Path=/admin`.
//! 3. **CSRF token.** A hidden form field on every `POST` page. Token
//!    = HMAC over the session cookie expiry; the server re-derives and
//!    compares constant-time. Tokens issued at render time live for as
//!    long as the cookie they're paired with.
//!
//! ## Why no `cookie` crate?
//!
//! The cookie surface we need is one `Set-Cookie` header on login + one
//! `Cookie:` header parsed at request time. Adding the
//! `cookie`/`tower-cookies` deps for that is overkill; we inline the
//! formatting and use `hmac` + `sha2` which are already in the
//! transitive dep tree.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    response::{IntoResponse, Redirect},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Cookie name carried by the browser after a successful login.
pub const SESSION_COOKIE: &str = "octra_admin_session";

/// Default session TTL: 8 hours. Matches the spec deliverable.
pub const SESSION_TTL_SECS: u64 = 8 * 3600;

/// Per-process admin auth config. Cheap to clone (everything is `Arc`
/// or `Copy`).
#[derive(Clone)]
pub struct AdminAuth {
    /// Operator-configured bearer token. Required to be non-empty;
    /// constructing with an empty token disables admin access entirely
    /// (see [`AdminAuth::new`]).
    pub(crate) bearer: std::sync::Arc<String>,
    /// 32-byte HMAC secret used for both the session cookie and the
    /// CSRF token. Generated at startup with `getrandom` (via
    /// `rand_core`); never persisted.
    pub(crate) secret: std::sync::Arc<[u8; 32]>,
}

impl AdminAuth {
    /// Build a fresh auth state.
    ///
    /// `bearer` is the operator-configured token. If empty, the admin
    /// surface returns 503 on every request (locking the panel until
    /// an operator wires up a real token); this avoids accidentally
    /// shipping an unauthenticated admin panel.
    pub fn new(bearer: impl Into<String>) -> Self {
        use rand_core::RngCore;
        let mut secret = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret);
        Self {
            bearer: std::sync::Arc::new(bearer.into()),
            secret: std::sync::Arc::new(secret),
        }
    }

    /// Test-only constructor that pins the HMAC secret to a known value
    /// so tests can pre-compute cookie payloads.
    #[cfg(test)]
    pub(crate) fn new_with_secret(bearer: impl Into<String>, secret: [u8; 32]) -> Self {
        Self {
            bearer: std::sync::Arc::new(bearer.into()),
            secret: std::sync::Arc::new(secret),
        }
    }

    /// Returns `true` if `presented` matches the configured bearer.
    /// Constant-time. An empty configured bearer always returns false.
    pub(crate) fn verify_bearer(&self, presented: &str) -> bool {
        if self.bearer.is_empty() || presented.is_empty() {
            return false;
        }
        // subtle::ConstantTimeEq isn't in the workspace deps; roll a
        // simple constant-time compare instead. Length-leak is fine
        // (the token length is operator-chosen and not secret).
        if self.bearer.len() != presented.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.bearer.as_bytes().iter().zip(presented.as_bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Mint a session-cookie payload tied to `expires_unix`. Format:
    /// `<expires>.<hmac_hex>`.
    pub(crate) fn mint_session(&self, expires_unix: u64) -> String {
        let mut mac =
            HmacSha256::new_from_slice(self.secret.as_ref()).expect("HMAC accepts any 32B key");
        mac.update(expires_unix.to_string().as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{expires_unix}.{}", hex::encode(tag))
    }

    /// Validate a session-cookie payload. Returns the expiry in unix
    /// seconds if valid AND unexpired, or `None` otherwise.
    pub(crate) fn verify_session(&self, payload: &str) -> Option<u64> {
        let (exp_str, tag_hex) = payload.split_once('.')?;
        let expires: u64 = exp_str.parse().ok()?;
        let tag = hex::decode(tag_hex).ok()?;
        let mut mac =
            HmacSha256::new_from_slice(self.secret.as_ref()).expect("HMAC accepts any 32B key");
        mac.update(exp_str.as_bytes());
        mac.verify_slice(&tag).ok()?;
        if expires <= now_unix() {
            return None;
        }
        Some(expires)
    }

    /// Format the `Set-Cookie` header value for a freshly minted session.
    ///
    /// Associated fn (no `&self`): the header is fully derived from the
    /// session payload + constants. Kept on `AdminAuth` for call-site
    /// locality (`s.auth.cookie_header(...)`).
    pub(crate) fn cookie_header(payload: &str, max_age_secs: u64) -> String {
        // `Secure` is included unconditionally; operators are expected
        // to terminate TLS in front of the admin port (or use an SSH
        // port-forward). Modern browsers tolerate `Secure` on localhost.
        format!(
            "{SESSION_COOKIE}={payload}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}"
        )
    }

    /// `Set-Cookie` value that deletes the session cookie.
    pub(crate) fn cookie_clear_header() -> String {
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
    }

    /// Derive a CSRF token bound to the supplied session payload. The
    /// token is `hmac(secret, "csrf:" || payload)`, hex-encoded.
    pub(crate) fn csrf_for(&self, session_payload: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(self.secret.as_ref()).expect("HMAC accepts any 32B key");
        mac.update(b"csrf:");
        mac.update(session_payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Constant-time CSRF verification against the live session.
    pub(crate) fn csrf_valid(&self, session_payload: &str, supplied_hex: &str) -> bool {
        let Ok(supplied) = hex::decode(supplied_hex) else {
            return false;
        };
        let mut mac =
            HmacSha256::new_from_slice(self.secret.as_ref()).expect("HMAC accepts any 32B key");
        mac.update(b"csrf:");
        mac.update(session_payload.as_bytes());
        mac.verify_slice(&supplied).is_ok()
    }
}

/// Outcome of evaluating the auth state of an incoming request.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Request carried a valid bearer token (API / CLI client).
    Bearer,
    /// Request carried a valid session cookie. `payload` is the raw
    /// cookie value; handlers thread it back into `csrf_for` when
    /// rendering forms.
    Session { payload: String },
    /// Neither credential present (or both invalid). Handlers decide
    /// whether to redirect (HTML) or 401 (API).
    Anonymous,
}

impl AuthOutcome {
    /// True for both [`Self::Bearer`] and [`Self::Session`].
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Bearer | Self::Session { .. })
    }

    /// If the caller authenticated via a session cookie, return the
    /// CSRF token bound to that session. Bearer-token clients don't
    /// need CSRF (they're not browser-driven) so this returns `None`
    /// for them — form-bearing pages skip CSRF rendering in that case.
    pub fn csrf_token(&self, auth: &AdminAuth) -> Option<String> {
        match self {
            Self::Session { payload } => Some(auth.csrf_for(payload)),
            _ => None,
        }
    }
}

/// Evaluate auth purely off the request headers. Centralised so the
/// per-route guards can decide redirect vs. 401 themselves.
pub(crate) fn evaluate_headers(headers: &HeaderMap, auth: &AdminAuth) -> AuthOutcome {
    // 1. Bearer header.
    if let Some(tok) = bearer_token(headers)
        && auth.verify_bearer(tok)
    {
        return AuthOutcome::Bearer;
    }
    // 2. Session cookie.
    let prefix = format!("{SESSION_COOKIE}=");
    if let Some(s) = headers
        .get(header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
    {
        for piece in s.split(';') {
            let piece = piece.trim();
            if let Some(payload) = piece.strip_prefix(prefix.as_str())
                && auth.verify_session(payload).is_some()
            {
                return AuthOutcome::Session {
                    payload: payload.to_string(),
                };
            }
        }
    }
    AuthOutcome::Anonymous
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Build the redirect response browser clients see when they hit an
/// `/admin/*` page without auth.
pub(crate) fn redirect_to_login() -> Response<Body> {
    Redirect::to("/admin/login").into_response()
}

/// Build the 401 response API clients see when they hit
/// `/api/v1/*` without auth.
pub(crate) fn api_unauthorized() -> Response<Body> {
    let mut r = (
        StatusCode::UNAUTHORIZED,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        r#"{"error":"unauthorized"}"#,
    )
        .into_response();
    // Hint to clients that bearer auth is expected.
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Bearer realm="octra-admin""#),
    );
    r
}

/// Unix-seconds now, saturating at 0.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_compare_is_constant_time_shape() {
        let a = AdminAuth::new_with_secret("right-token", [7u8; 32]);
        assert!(a.verify_bearer("right-token"));
        assert!(!a.verify_bearer("wrong-token"));
        assert!(!a.verify_bearer(""));
        assert!(!a.verify_bearer("right-tokenX"));
    }

    #[test]
    fn empty_bearer_rejects_everything() {
        let a = AdminAuth::new_with_secret("", [7u8; 32]);
        assert!(!a.verify_bearer(""));
        assert!(!a.verify_bearer("anything"));
    }

    #[test]
    fn session_roundtrip() {
        let a = AdminAuth::new_with_secret("tok", [9u8; 32]);
        let exp = now_unix() + 1000;
        let payload = a.mint_session(exp);
        assert_eq!(a.verify_session(&payload), Some(exp));
    }

    #[test]
    fn expired_session_rejected() {
        let a = AdminAuth::new_with_secret("tok", [9u8; 32]);
        let payload = a.mint_session(1); // way in the past
        assert_eq!(a.verify_session(&payload), None);
    }

    #[test]
    fn tampered_session_rejected() {
        let a = AdminAuth::new_with_secret("tok", [9u8; 32]);
        let exp = now_unix() + 1000;
        let payload = a.mint_session(exp);
        // Bump the expiry without re-signing.
        let (exp_str, tag) = payload.split_once('.').unwrap();
        let bigger: u64 = exp_str.parse::<u64>().unwrap() + 10;
        let tampered = format!("{bigger}.{tag}");
        assert_eq!(a.verify_session(&tampered), None);
    }

    #[test]
    fn csrf_roundtrip() {
        let a = AdminAuth::new_with_secret("tok", [3u8; 32]);
        let payload = a.mint_session(now_unix() + 1000);
        let token = a.csrf_for(&payload);
        assert!(a.csrf_valid(&payload, &token));
        assert!(!a.csrf_valid(&payload, "deadbeef"));
        assert!(!a.csrf_valid("other-session", &token));
    }
}
