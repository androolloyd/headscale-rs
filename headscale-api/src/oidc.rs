//! OIDC helpers that mirror headscale-go's auth-provider behavior.
//!
//! The full token-exchange callback flow is still wired separately. This
//! module keeps both the pure pieces and the auth-code start path testable
//! against upstream semantics: claim authorization, issuer/subject
//! identifiers, UserInfo merging, node-expiry selection, state/nonce cookies,
//! PKCE challenge generation, and auth URL construction.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use rand_core::RngCore;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub const REGISTER_METHOD_OIDC: &str = "oidc";
const REGISTRATION_ID_LENGTH: usize = 24;
const OIDC_CSRF_TOKEN_LEN: usize = 64;
const OIDC_COOKIE_MAX_AGE_SECS: u64 = 60 * 60;
const DEFAULT_OIDC_AUTH_CACHE_EXPIRY: StdDuration = StdDuration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPolicyConfig {
    pub allowed_domains: Vec<String>,
    pub allowed_users: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub email_verified_required: bool,
    pub expiry: Duration,
    pub use_expiry_from_token: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcPkceMethod {
    Plain,
    S256,
}

impl OidcPkceMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPkceConfig {
    pub enabled: bool,
    pub method: OidcPkceMethod,
}

impl Default for OidcPkceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            method: OidcPkceMethod::S256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcAuthConfig {
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub extra_params: BTreeMap<String, String>,
    pub pkce: OidcPkceConfig,
}

#[derive(Debug, Clone)]
pub struct OidcAuthRuntime {
    config: Arc<OidcAuthConfig>,
    registrations: Arc<OidcRegistrationCache>,
}

impl OidcAuthRuntime {
    pub fn new(config: OidcAuthConfig) -> Self {
        Self {
            config: Arc::new(config),
            registrations: Arc::new(OidcRegistrationCache::new(DEFAULT_OIDC_AUTH_CACHE_EXPIRY)),
        }
    }

    pub fn with_registration_cache(
        config: OidcAuthConfig,
        registrations: Arc<OidcRegistrationCache>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            registrations,
        }
    }

    pub fn registration(&self, state: &str) -> Option<OidcRegistrationInfo> {
        self.registrations.get(state)
    }

    fn begin_registration(
        &self,
        registration_id: String,
    ) -> Result<OidcAuthStart, OidcRuntimeError> {
        if registration_id.len() != REGISTRATION_ID_LENGTH {
            return Err(OidcRuntimeError::InvalidRegistrationId);
        }

        let state = random_urlsafe(OIDC_CSRF_TOKEN_LEN);
        let nonce = random_urlsafe(OIDC_CSRF_TOKEN_LEN);
        let verifier = self.config.pkce.enabled.then(|| random_urlsafe(64));
        let challenge = verifier
            .as_ref()
            .map(|verifier| pkce_challenge(verifier, self.config.pkce.method));
        let auth_url = build_auth_url(
            &self.config,
            &state,
            &nonce,
            challenge.as_deref(),
            self.config.pkce.enabled.then_some(self.config.pkce.method),
        );

        self.registrations.insert(
            state.clone(),
            OidcRegistrationInfo {
                registration_id,
                verifier,
            },
        );

        Ok(OidcAuthStart {
            auth_url,
            state,
            nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRegistrationInfo {
    pub registration_id: String,
    pub verifier: Option<String>,
}

#[derive(Debug)]
pub struct OidcRegistrationCache {
    inner: RwLock<BTreeMap<String, OidcRegistrationEntry>>,
    expiry: StdDuration,
}

#[derive(Debug, Clone)]
struct OidcRegistrationEntry {
    info: OidcRegistrationInfo,
    expires_at: Instant,
}

impl OidcRegistrationCache {
    pub fn new(expiry: StdDuration) -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
            expiry,
        }
    }

    pub fn insert(&self, state: String, info: OidcRegistrationInfo) {
        self.prune_expired();
        self.inner.write().insert(
            state,
            OidcRegistrationEntry {
                info,
                expires_at: Instant::now() + self.expiry,
            },
        );
    }

    pub fn get(&self, state: &str) -> Option<OidcRegistrationInfo> {
        self.prune_expired();
        self.inner.read().get(state).map(|entry| entry.info.clone())
    }

    pub fn remove(&self, state: &str) -> Option<OidcRegistrationInfo> {
        self.prune_expired();
        self.inner.write().remove(state).map(|entry| entry.info)
    }

    pub fn len(&self) -> usize {
        self.prune_expired();
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let expired = self
            .inner
            .read()
            .iter()
            .filter_map(|(state, entry)| (now >= entry.expires_at).then(|| state.clone()))
            .collect::<Vec<_>>();
        let mut inner = self.inner.write();
        let mut removed = 0;
        for state in expired {
            if inner.remove(&state).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OidcAuthStart {
    auth_url: String,
    state: String,
    nonce: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcRuntimeError {
    #[error("invalid registration id")]
    InvalidRegistrationId,
    #[error("missing code or state parameter")]
    MissingCodeOrState,
    #[error("state not found")]
    StateCookieMissing,
    #[error("state did not match")]
    StateCookieMismatch,
    #[error("registration not found")]
    RegistrationNotFound,
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub state: String,
}

impl Default for OidcPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            allowed_users: Vec::new(),
            allowed_groups: Vec::new(),
            email_verified_required: true,
            expiry: Duration::days(180),
            use_expiry_from_token: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcClaims {
    #[serde(default, rename = "sub")]
    pub sub: String,
    #[serde(default, rename = "iss")]
    pub iss: String,
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "groups")]
    pub groups: Vec<String>,
    #[serde(default, rename = "email")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(default, rename = "picture")]
    pub profile_picture_url: String,
    #[serde(default, rename = "preferred_username")]
    pub username: String,
}

impl OidcClaims {
    pub fn identifier(&self) -> String {
        if self.iss.is_empty() && self.sub.is_empty() {
            return String::new();
        }
        if self.iss.is_empty() {
            return clean_identifier(&self.sub);
        }
        if self.sub.is_empty() {
            return clean_identifier(&self.iss);
        }

        let issuer = self.iss.trim_end_matches('/');
        let subject = self.sub.trim_start_matches('/');
        clean_identifier(&format!("{issuer}/{subject}"))
    }

    pub fn provider_identifier(&self) -> String {
        let identifier = self.identifier();
        if self.iss.is_empty() && !identifier.starts_with('/') {
            format!("/{identifier}")
        } else {
            identifier
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcUserInfo {
    #[serde(default, rename = "sub")]
    pub sub: String,
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "given_name")]
    pub given_name: String,
    #[serde(default, rename = "family_name")]
    pub family_name: String,
    #[serde(default, rename = "preferred_username")]
    pub preferred_username: String,
    #[serde(default, rename = "email")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(default, rename = "groups")]
    pub groups: Option<Vec<String>>,
    #[serde(default, rename = "picture")]
    pub picture: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcUserProfile {
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: String,
    pub provider: String,
    pub profile_pic_url: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcAuthorizationError {
    #[error("unauthorised domain")]
    UnauthorisedDomain,
    #[error("unauthorised group")]
    UnauthorisedGroup,
    #[error("unauthorised user")]
    UnauthorisedUser,
    #[error("unverified email")]
    UnverifiedEmail,
}

pub fn authorize_claims(
    cfg: &OidcPolicyConfig,
    claims: &OidcClaims,
) -> Result<(), OidcAuthorizationError> {
    if !cfg.allowed_groups.is_empty()
        && !cfg
            .allowed_groups
            .iter()
            .any(|group| claims.groups.iter().any(|claim| claim == group))
    {
        return Err(OidcAuthorizationError::UnauthorisedGroup);
    }

    let trust_email = !cfg.email_verified_required || claims.email_verified;
    let has_email_tests = !cfg.allowed_domains.is_empty() || !cfg.allowed_users.is_empty();
    if !trust_email && has_email_tests {
        return Err(OidcAuthorizationError::UnverifiedEmail);
    }

    if !cfg.allowed_domains.is_empty() {
        let Some((_, domain)) = claims.email.rsplit_once('@') else {
            return Err(OidcAuthorizationError::UnauthorisedDomain);
        };
        if !cfg.allowed_domains.iter().any(|allowed| allowed == domain) {
            return Err(OidcAuthorizationError::UnauthorisedDomain);
        }
    }

    if !cfg.allowed_users.is_empty()
        && !cfg
            .allowed_users
            .iter()
            .any(|allowed| allowed == &claims.email)
    {
        return Err(OidcAuthorizationError::UnauthorisedUser);
    }

    Ok(())
}

pub fn merge_userinfo_claims(claims: &mut OidcClaims, userinfo: Option<&OidcUserInfo>) {
    let Some(userinfo) = userinfo else {
        return;
    };
    if userinfo.sub != claims.sub {
        return;
    }

    if !userinfo.email.is_empty() {
        claims.email.clone_from(&userinfo.email);
    }
    claims.email_verified = userinfo.email_verified || claims.email_verified;
    if !userinfo.preferred_username.is_empty() {
        claims.username.clone_from(&userinfo.preferred_username);
    }
    if !userinfo.name.is_empty() {
        claims.name.clone_from(&userinfo.name);
    }
    if !userinfo.picture.is_empty() {
        claims.profile_picture_url.clone_from(&userinfo.picture);
    }
    if let Some(groups) = &userinfo.groups {
        claims.groups.clone_from(groups);
    }
}

pub fn determine_node_expiry(
    cfg: &OidcPolicyConfig,
    id_token_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    if cfg.use_expiry_from_token {
        id_token_expiry
    } else {
        now + cfg.expiry
    }
}

pub fn user_profile_from_claims(
    claims: &OidcClaims,
    email_verified_required: bool,
) -> OidcUserProfile {
    OidcUserProfile {
        name: if is_valid_oidc_username(&claims.username) {
            claims.username.clone()
        } else {
            String::new()
        },
        display_name: claims.name.clone(),
        email: if (!email_verified_required || claims.email_verified)
            && looks_like_email_address(&claims.email)
        {
            claims.email.clone()
        } else {
            String::new()
        },
        provider_identifier: claims.provider_identifier(),
        provider: REGISTER_METHOD_OIDC.to_string(),
        profile_pic_url: claims.profile_picture_url.clone(),
    }
}

pub async fn handle_register(runtime: OidcAuthRuntime, registration_id: String) -> Response {
    let start = match runtime.begin_registration(registration_id) {
        Ok(start) => start,
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), err.to_string()),
    };

    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    append_cookie(response.headers_mut(), csrf_cookie("state", &start.state));
    append_cookie(response.headers_mut(), csrf_cookie("nonce", &start.nonce));
    response
}

pub async fn handle_callback(
    runtime: OidcAuthRuntime,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    if query.code.is_empty() || query.state.is_empty() {
        return oidc_error_response(
            status_for_runtime_error(&OidcRuntimeError::MissingCodeOrState),
            OidcRuntimeError::MissingCodeOrState.to_string(),
        );
    }

    match validate_state_cookie(&headers, &query.state) {
        Ok(()) => {}
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), err.to_string()),
    }

    if runtime.registration(&query.state).is_none() {
        return oidc_error_response(
            status_for_runtime_error(&OidcRuntimeError::RegistrationNotFound),
            OidcRuntimeError::RegistrationNotFound.to_string(),
        );
    }

    oidc_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "OIDC token exchange is not implemented".to_string(),
    )
}

pub fn clean_identifier(identifier: &str) -> String {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return String::new();
    }

    if let Some((scheme, rest)) = identifier.split_once("://")
        && !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        let (authority_and_path, suffix) = split_url_suffix(rest);
        let (authority, path) = authority_and_path
            .split_once('/')
            .map_or((authority_and_path, ""), |(authority, path)| {
                (authority, path)
            });
        let path = clean_slash_path(path);
        if path.is_empty() {
            return format!("{}://{}{}", scheme.to_ascii_lowercase(), authority, suffix);
        }
        return format!(
            "{}://{}/{}{}",
            scheme.to_ascii_lowercase(),
            authority,
            path,
            suffix
        );
    }

    clean_slash_path(identifier)
}

fn build_auth_url(
    cfg: &OidcAuthConfig,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    pkce_method: Option<OidcPkceMethod>,
) -> String {
    let mut params = vec![
        ("client_id".to_string(), cfg.client_id.clone()),
        ("redirect_uri".to_string(), cfg.redirect_url.clone()),
        ("response_type".to_string(), "code".to_string()),
        ("scope".to_string(), scope_value(&cfg.scopes)),
        ("state".to_string(), state.to_string()),
    ];

    if let (Some(challenge), Some(method)) = (code_challenge, pkce_method) {
        params.push(("access_type".to_string(), "offline".to_string()));
        params.push((
            "code_challenge_method".to_string(),
            method.as_str().to_string(),
        ));
        params.push(("code_challenge".to_string(), challenge.to_string()));
    }

    for (key, value) in &cfg.extra_params {
        params.push((key.clone(), value.clone()));
    }
    params.push(("nonce".to_string(), nonce.to_string()));

    let query = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_encode(&key), form_encode(&value)))
        .collect::<Vec<_>>()
        .join("&");

    if cfg.authorization_endpoint.contains('?') {
        format!("{}&{}", cfg.authorization_endpoint, query)
    } else {
        format!("{}?{}", cfg.authorization_endpoint, query)
    }
}

fn scope_value(scopes: &[String]) -> String {
    scopes.join(" ")
}

fn csrf_cookie(base_name: &str, value: &str) -> String {
    format!(
        "{}={}; Path=/oidc/callback; Max-Age={OIDC_COOKIE_MAX_AGE_SECS}; HttpOnly",
        cookie_name(base_name, value),
        value
    )
}

fn append_cookie(headers: &mut HeaderMap, cookie: String) {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

fn cookie_name(base_name: &str, value: &str) -> String {
    format!(
        "{}_{}",
        base_name,
        value.chars().take(6).collect::<String>()
    )
}

fn validate_state_cookie(headers: &HeaderMap, state: &str) -> Result<(), OidcRuntimeError> {
    let expected_name = cookie_name("state", state);
    let Some(actual) = cookie_value(headers, &expected_name) else {
        return Err(OidcRuntimeError::StateCookieMissing);
    };
    if actual == state {
        Ok(())
    } else {
        Err(OidcRuntimeError::StateCookieMismatch)
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
}

fn status_for_runtime_error(err: &OidcRuntimeError) -> StatusCode {
    match err {
        OidcRuntimeError::InvalidRegistrationId
        | OidcRuntimeError::MissingCodeOrState
        | OidcRuntimeError::StateCookieMissing => StatusCode::BAD_REQUEST,
        OidcRuntimeError::StateCookieMismatch => StatusCode::FORBIDDEN,
        OidcRuntimeError::RegistrationNotFound => StatusCode::NOT_FOUND,
    }
}

fn oidc_error_response(status: StatusCode, message: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        message,
    )
        .into_response()
}

fn pkce_challenge(verifier: &str, method: OidcPkceMethod) -> String {
    match method {
        OidcPkceMethod::Plain => verifier.to_string(),
        OidcPkceMethod::S256 => {
            let digest = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
    }
}

fn random_urlsafe(len: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut raw = vec![0_u8; len];
    rand_core::OsRng.fill_bytes(&mut raw);
    raw.into_iter()
        .map(|byte| ALPHABET[(byte as usize) & 0x3f] as char)
        .collect()
}

fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn split_url_suffix(rest: &str) -> (&str, &str) {
    let query = rest.find('?');
    let fragment = rest.find('#');
    let idx = match (query, fragment) {
        (Some(q), Some(f)) => q.min(f),
        (Some(q), None) => q,
        (None, Some(f)) => f,
        (None, None) => return (rest, ""),
    };
    rest.split_at(idx)
}

fn clean_slash_path(path: &str) -> String {
    path.split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_valid_oidc_username(username: &str) -> bool {
    if username.len() < 2 {
        return false;
    }

    let Some(first) = username.chars().next() else {
        return false;
    };
    if !first.is_alphabetic() {
        return false;
    }

    let mut at_count = 0;
    for ch in username.chars() {
        match ch {
            ch if ch.is_alphabetic() || ch.is_numeric() => {}
            '-' | '.' | '_' => {}
            '@' => {
                at_count += 1;
                if at_count > 1 {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn looks_like_email_address(email: &str) -> bool {
    looks_like_simple_email_address(email)
        || email
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .is_some_and(|(address, trailing)| {
                trailing.trim().is_empty() && looks_like_simple_email_address(address)
            })
}

fn looks_like_simple_email_address(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !email.chars().any(char::is_whitespace)
}

fn deserialize_flexible_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexibleBool {
        Bool(bool),
        String(String),
    }

    match Option::<FlexibleBool>::deserialize(deserializer)? {
        Some(FlexibleBool::Bool(value)) => Ok(value),
        Some(FlexibleBool::String(value)) => value.parse().map_err(serde::de::Error::custom),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, header};
    use chrono::TimeZone;

    fn cfg() -> OidcPolicyConfig {
        OidcPolicyConfig {
            email_verified_required: true,
            ..OidcPolicyConfig::default()
        }
    }

    fn claims(email: &str, email_verified: bool) -> OidcClaims {
        OidcClaims {
            email: email.to_string(),
            email_verified,
            ..OidcClaims::default()
        }
    }

    fn auth_config(pkce: OidcPkceConfig) -> OidcAuthConfig {
        OidcAuthConfig {
            authorization_endpoint: "https://issuer.example/oauth2/auth".into(),
            client_id: "headscale-rs".into(),
            redirect_url: "https://headscale.example/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            extra_params: BTreeMap::from([("domain_hint".into(), "example.com".into())]),
            pkce,
        }
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        url.split_once('?')
            .map(|(_, query)| query)
            .into_iter()
            .flat_map(|query| query.split('&'))
            .filter_map(|part| part.split_once('='))
            .find_map(|(part_key, value)| (part_key == key).then(|| value.to_string()))
    }

    #[test]
    fn oidc_authorization_matches_upstream_matrix() {
        let cases = [
            (
                "verified email domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", true),
                Ok(()),
            ),
            (
                "verified email user",
                OidcPolicyConfig {
                    allowed_users: vec!["user@test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", true),
                Ok(()),
            ),
            (
                "unverified email domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", false),
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "group member",
                OidcPolicyConfig {
                    allowed_groups: vec!["test".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test".into()],
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "non group member",
                OidcPolicyConfig {
                    allowed_groups: vec!["nope".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["testo".into()],
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnauthorisedGroup),
            ),
            (
                "group member but bad domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["user@good.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "bad@bad.com".into(),
                    email_verified: true,
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnauthorisedDomain),
            ),
            (
                "all checks pass",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: true,
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "all checks pass with unverified email",
                OidcPolicyConfig {
                    email_verified_required: false,
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..OidcPolicyConfig::default()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: false,
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "fail on unverified email",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: false,
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "unverified email user only",
                OidcPolicyConfig {
                    allowed_users: vec!["user@test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", false),
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "no filters configured",
                cfg(),
                claims("anyone@anywhere.com", false),
                Ok(()),
            ),
            (
                "multiple allowed groups second matches",
                OidcPolicyConfig {
                    allowed_groups: vec!["group1".into(), "group2".into(), "group3".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["group2".into()],
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
        ];

        for (name, cfg, claims, expected) in cases {
            assert_eq!(authorize_claims(&cfg, &claims), expected, "{name}");
        }
    }

    #[test]
    fn oidc_auth_start_builds_upstream_auth_url_and_state_cache() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig {
            enabled: true,
            method: OidcPkceMethod::S256,
        }));
        let start = runtime.begin_registration("r".repeat(24)).unwrap();

        assert!(
            start
                .auth_url
                .starts_with("https://issuer.example/oauth2/auth?")
        );
        assert_eq!(
            query_param(&start.auth_url, "client_id").as_deref(),
            Some("headscale-rs")
        );
        assert_eq!(
            query_param(&start.auth_url, "redirect_uri").as_deref(),
            Some("https%3A%2F%2Fheadscale.example%2Foidc%2Fcallback")
        );
        assert_eq!(
            query_param(&start.auth_url, "scope").as_deref(),
            Some("openid+profile+email")
        );
        assert_eq!(
            query_param(&start.auth_url, "state"),
            Some(start.state.clone())
        );
        assert_eq!(
            query_param(&start.auth_url, "nonce"),
            Some(start.nonce.clone())
        );
        assert_eq!(
            query_param(&start.auth_url, "code_challenge_method").as_deref(),
            Some("S256")
        );
        assert!(query_param(&start.auth_url, "code_challenge").is_some());
        assert_eq!(
            query_param(&start.auth_url, "access_type").as_deref(),
            Some("offline")
        );
        assert_eq!(
            query_param(&start.auth_url, "domain_hint").as_deref(),
            Some("example.com")
        );

        let cached = runtime.registration(&start.state).unwrap();
        assert_eq!(cached.registration_id, "r".repeat(24));
        assert!(cached.verifier.is_some());
    }

    #[test]
    fn oidc_auth_start_uses_plain_pkce_when_configured() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig {
            enabled: true,
            method: OidcPkceMethod::Plain,
        }));
        let start = runtime.begin_registration("r".repeat(24)).unwrap();
        let cached = runtime.registration(&start.state).unwrap();

        assert_eq!(
            query_param(&start.auth_url, "code_challenge_method").as_deref(),
            Some("plain")
        );
        assert_eq!(
            query_param(&start.auth_url, "code_challenge"),
            cached.verifier
        );
    }

    #[tokio::test]
    async fn oidc_register_handler_sets_state_nonce_cookies_and_redirects() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let response = handle_register(runtime.clone(), "r".repeat(24)).await;

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let state = query_param(&location, "state").unwrap();
        assert!(runtime.registration(&state).is_some());

        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with(&cookie_name("state", &state)))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.contains("Path=/oidc/callback"))
        );
    }

    #[tokio::test]
    async fn oidc_callback_preflight_rejects_missing_or_mismatched_state() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let response = handle_callback(
            runtime.clone(),
            HeaderMap::new(),
            Query(OidcCallbackQuery {
                code: String::new(),
                state: String::new(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let start = runtime.begin_registration("r".repeat(24)).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}=wrong", cookie_name("state", &start.state))
                .parse()
                .unwrap(),
        );
        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "code".into(),
                state: start.state,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn oidc_claim_identifier_matches_headscale_go_cleanup() {
        for (input, expected) in [
            ("", ""),
            ("oidc/sub", "oidc/sub"),
            ("oidc//sub", "oidc/sub"),
            ("oidc/sub/", "oidc/sub"),
            ("oidc//sub///id//", "oidc/sub/id"),
            ("http://example.com/path", "http://example.com/path"),
            (
                "http://example.com//path///resource",
                "http://example.com/path/resource",
            ),
            ("https://example.com///path//", "https://example.com/path"),
            (
                "https://login.microsoftonline.com//v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
                "https://login.microsoftonline.com/v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
            ),
            (
                "ftp://example.com//resource//",
                "ftp://example.com/resource",
            ),
            ("///", ""),
            ("/path//to///resource", "path/to/resource"),
            (
                "ldap://example.org//path//to//resource",
                "ldap://example.org/path/to/resource",
            ),
            ("HTTPS://example.com//Path", "https://example.com/Path"),
        ] {
            assert_eq!(clean_identifier(input), expected, "{input}");
        }

        assert_eq!(
            clean_identifier("  https://issuer.example//tenant / /alice  "),
            "https://issuer.example/tenant/alice"
        );
        assert_eq!(
            clean_identifier("oidc// tenant / alice "),
            "oidc/tenant/alice"
        );
        assert_eq!(clean_identifier("///"), "");
        assert_eq!(
            OidcClaims {
                iss: "https://issuer.example/root/".into(),
                sub: "/subject".into(),
                ..OidcClaims::default()
            }
            .identifier(),
            "https://issuer.example/root/subject"
        );
        assert_eq!(
            OidcClaims {
                sub: "subject".into(),
                ..OidcClaims::default()
            }
            .provider_identifier(),
            "/subject"
        );
    }

    #[test]
    fn oidc_userinfo_merge_only_when_subject_matches() {
        let mut claims = OidcClaims {
            sub: "sub".into(),
            email: "id@example.com".into(),
            email_verified: false,
            username: "iduser".into(),
            name: "ID User".into(),
            profile_picture_url: "https://example.com/id.png".into(),
            groups: vec!["id-group".into()],
            ..OidcClaims::default()
        };

        merge_userinfo_claims(
            &mut claims,
            Some(&OidcUserInfo {
                sub: "other".into(),
                email: "ignored@example.com".into(),
                groups: Some(vec!["ignored".into()]),
                ..OidcUserInfo::default()
            }),
        );
        assert_eq!(claims.email, "id@example.com");
        assert_eq!(claims.groups, vec!["id-group"]);

        merge_userinfo_claims(
            &mut claims,
            Some(&OidcUserInfo {
                sub: "sub".into(),
                email: "user@example.com".into(),
                email_verified: true,
                preferred_username: "userinfo".into(),
                name: "User Info".into(),
                picture: "https://example.com/user.png".into(),
                groups: Some(vec!["userinfo-group".into()]),
                ..OidcUserInfo::default()
            }),
        );

        assert_eq!(claims.email, "user@example.com");
        assert!(claims.email_verified);
        assert_eq!(claims.username, "userinfo");
        assert_eq!(claims.name, "User Info");
        assert_eq!(claims.profile_picture_url, "https://example.com/user.png");
        assert_eq!(claims.groups, vec!["userinfo-group"]);
    }

    #[test]
    fn oidc_expiry_uses_token_or_config_like_upstream() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let token_expiry = Utc.timestamp_opt(1_700_003_600, 0).unwrap();
        let cfg = OidcPolicyConfig {
            expiry: Duration::days(180),
            ..OidcPolicyConfig::default()
        };
        assert_eq!(
            determine_node_expiry(&cfg, token_expiry, now),
            now + cfg.expiry
        );

        let cfg = OidcPolicyConfig {
            use_expiry_from_token: true,
            ..cfg
        };
        assert_eq!(determine_node_expiry(&cfg, token_expiry, now), token_expiry);
    }

    #[test]
    fn user_profile_from_claims_matches_oidc_provider_fields() {
        let profile = user_profile_from_claims(
            &OidcClaims {
                iss: "https://issuer.example".into(),
                sub: "subject".into(),
                username: "alice".into(),
                name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                email_verified: true,
                profile_picture_url: "https://example.com/alice.png".into(),
                ..OidcClaims::default()
            },
            true,
        );

        assert_eq!(profile.name, "alice");
        assert_eq!(profile.display_name, "Alice Smith");
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(
            profile.provider_identifier,
            "https://issuer.example/subject"
        );
        assert_eq!(profile.provider, REGISTER_METHOD_OIDC);
        assert_eq!(profile.profile_pic_url, "https://example.com/alice.png");
    }

    #[test]
    fn user_profile_accepts_upstream_oidc_username_edges() {
        let profile = user_profile_from_claims(
            &OidcClaims {
                iss: "https://sso.company.com/oauth2/default".into(),
                sub: "00u7dr4qp7xxxxxxxxxx".into(),
                username: "tim.horton@company.com".into(),
                name: "Tim Horton".into(),
                email: "tim.horton@company.com".into(),
                email_verified: false,
                ..OidcClaims::default()
            },
            true,
        );
        assert_eq!(profile.name, "tim.horton@company.com");
        assert_eq!(profile.display_name, "Tim Horton");
        assert_eq!(profile.email, "");
        assert_eq!(
            profile.provider_identifier,
            "https://sso.company.com/oauth2/default/00u7dr4qp7xxxxxxxxxx"
        );

        let invalid = user_profile_from_claims(
            &OidcClaims {
                username: "1alice".into(),
                ..OidcClaims::default()
            },
            true,
        );
        assert_eq!(invalid.name, "");
    }

    #[test]
    fn oidc_claims_accept_flexible_email_verified_json() {
        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":"true"}"#,
        )
        .unwrap();
        assert_eq!(parsed.sub, "test");
        assert!(parsed.email_verified);

        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":"false"}"#,
        )
        .unwrap();
        assert!(!parsed.email_verified);

        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":true}"#,
        )
        .unwrap();
        assert!(parsed.email_verified);
    }
}
