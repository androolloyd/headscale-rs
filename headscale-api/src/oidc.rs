//! OIDC helpers that mirror headscale-go's auth-provider behavior.
//!
//! The final user/node handoff is still wired separately. This module keeps
//! both the pure pieces and the auth-code path testable against upstream
//! semantics: claim authorization, issuer/subject identifiers, UserInfo
//! merging, node-expiry selection, state/nonce cookies, PKCE challenge
//! generation, auth URL construction, token exchange, and ID-token validation.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
#[cfg(feature = "full")]
use std::sync::atomic::AtomicU8;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration as StdDuration, Instant};

use axum::body::Bytes;
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
mod browser_html;
#[cfg(feature = "full")]
mod claim_maps;
#[cfg(feature = "full")]
mod discovery;
mod error_html;
mod form;
#[cfg(feature = "full")]
mod json;
#[cfg(feature = "full")]
mod jwk;
mod mailbox;
#[cfg(feature = "full")]
mod rsa;
#[cfg(feature = "full")]
mod userinfo_json;
mod username;
const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const REGISTRATION_ID_LENGTH: usize = 24;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + REGISTRATION_ID_LENGTH;
const OIDC_CSRF_TOKEN_LEN: usize = 64;
const OIDC_COOKIE_NAME_PREFIX_LEN: usize = 6;
const OIDC_COOKIE_MAX_AGE_SECS: u64 = 60 * 60;
const DEFAULT_OIDC_AUTH_CACHE_EXPIRY: StdDuration = StdDuration::from_secs(15 * 60);
const DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES: usize = 1024;
/// Pending OIDC states one registration id may hold at once. A redirect adds a
/// state and nothing removes it before the callback, so without a cap a single
/// pending registration (anyone can create one, see the registration cache's
/// per-source quota) could repeat the redirect until the global LRU dropped
/// other users' in-flight sign-ins. 16 leaves room for several browser tabs
/// and retries; going past it drops that registration's own oldest states.
const OIDC_MAX_PENDING_STATES_PER_REGISTRATION: usize = 16;
// headscale-go v0.29.5 NewHeadscale gives provider initialization a
// 30-second context. Include response-body decoding in the same deadline.
#[cfg(feature = "full")]
const OIDC_DISCOVERY_TIMEOUT: StdDuration = StdDuration::from_secs(30);
#[cfg(feature = "full")]
const OIDC_PROVIDER_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// Most bytes read from any one OIDC provider response (discovery document,
/// JWKS, token endpoint, userinfo), counted as received after any
/// decompression and enforced while streaming, never after buffering.
///
/// The token endpoint value is Go's own: golang.org/x/oauth2
/// `internal/token.go` reads `io.LimitReader(r.Body, 1<<20)`. go-oidc v3.18.0
/// reads the discovery document, JWKS and userinfo with an unbounded
/// `io.ReadAll` (oidc.go, jwks.go), which a hostile or compromised issuer can
/// turn into an allocation bomb; this client applies the same 1 MiB to them.
/// Real responses are far smaller (a discovery document is a few KiB, a JWKS
/// with dozens of RSA keys tens of KiB), so 1 MiB is generous.
#[cfg(feature = "full")]
const OIDC_PROVIDER_BODY_LIMIT: usize = 1024 * 1024;
/// Most bytes of a remote-controlled value (a response body, a discovery
/// `issuer`, a Content-Type) that an error string or log line may embed. The
/// complete value is bounded by `OIDC_PROVIDER_BODY_LIMIT`, but a diagnostic
/// needs only the start of it: Go's go-oidc and oauth2 error strings carry the
/// whole body, which for a hostile server is a megabyte per log line.
const OIDC_ERROR_BODY_PREFIX: usize = 256;
#[cfg(feature = "full")]
const MAX_PENDING_OIDC_CALLBACKS: usize = 128;
#[cfg(feature = "full")]
static OIDC_CRYPTO_WORKERS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        let workers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .clamp(1, 8);
        Arc::new(tokio::sync::Semaphore::new(workers))
    });
const OIDC_SIGNING_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
];
const REGISTER_CONFIRM_CSRF_COOKIE: &str = "headscale_register_confirm";
const REGISTER_CONFIRM_BODY_LIMIT: usize = 4 * 1024;

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

#[derive(Clone, PartialEq, Eq)]
pub struct OidcAuthConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub extra_params: BTreeMap<String, String>,
    pub pkce: OidcPkceConfig,
    pub policy: OidcPolicyConfig,
}

impl fmt::Debug for OidcAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("pkce", &self.pkce)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcProviderMetadata {
    #[serde(default, deserialize_with = "deserialize_go_string")]
    pub issuer: String,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    pub authorization_endpoint: String,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    pub jwks_uri: String,
    #[serde(default, deserialize_with = "deserialize_go_string_list")]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone)]
pub struct OidcAuthRuntime {
    config: Arc<OidcAuthConfig>,
    signing_algorithms: Arc<Vec<String>>,
    #[cfg(feature = "full")]
    provider_client: reqwest::Client,
    #[cfg(feature = "full")]
    token_auth_style: Arc<AtomicU8>,
    #[cfg(feature = "full")]
    jwks: Arc<OidcJwksCache>,
    #[cfg(feature = "full")]
    pending_callbacks: Arc<tokio::sync::Semaphore>,
    registrations: Arc<OidcRegistrationCache>,
    confirmations: Arc<OidcRegistrationConfirmationCache>,
    users: Option<Arc<dyn OidcUserStore>>,
    registration_handler: Option<Arc<dyn OidcRegistrationHandler>>,
}

impl fmt::Debug for OidcAuthRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthRuntime")
            .field("config", &self.config)
            .field("signing_algorithms", &self.signing_algorithms)
            .field("registrations", &self.registrations)
            .field("confirmations", &self.confirmations)
            .field("users", &self.users.as_ref().map(|_| "<configured>"))
            .field(
                "registration_handler",
                &self.registration_handler.as_ref().map(|_| "<configured>"),
            )
            .finish_non_exhaustive()
    }
}

impl OidcAuthRuntime {
    pub fn new(config: OidcAuthConfig) -> Self {
        Self {
            config: Arc::new(config),
            signing_algorithms: Arc::new(vec!["RS256".into()]),
            #[cfg(feature = "full")]
            provider_client: reqwest::Client::new(),
            #[cfg(feature = "full")]
            token_auth_style: Arc::new(AtomicU8::new(0)),
            #[cfg(feature = "full")]
            jwks: Arc::new(OidcJwksCache::default()),
            #[cfg(feature = "full")]
            pending_callbacks: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_OIDC_CALLBACKS)),
            registrations: Arc::new(OidcRegistrationCache::new(DEFAULT_OIDC_AUTH_CACHE_EXPIRY)),
            confirmations: Arc::new(OidcRegistrationConfirmationCache::new(
                DEFAULT_OIDC_AUTH_CACHE_EXPIRY,
            )),
            users: None,
            registration_handler: None,
        }
    }

    pub fn with_registration_cache(
        config: OidcAuthConfig,
        registrations: Arc<OidcRegistrationCache>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            signing_algorithms: Arc::new(vec!["RS256".into()]),
            #[cfg(feature = "full")]
            provider_client: reqwest::Client::new(),
            #[cfg(feature = "full")]
            token_auth_style: Arc::new(AtomicU8::new(0)),
            #[cfg(feature = "full")]
            jwks: Arc::new(OidcJwksCache::default()),
            #[cfg(feature = "full")]
            pending_callbacks: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_OIDC_CALLBACKS)),
            registrations,
            confirmations: Arc::new(OidcRegistrationConfirmationCache::new(
                DEFAULT_OIDC_AUTH_CACHE_EXPIRY,
            )),
            users: None,
            registration_handler: None,
        }
    }

    pub fn with_user_store(mut self, users: Arc<dyn OidcUserStore>) -> Self {
        self.users = Some(users);
        self
    }

    /// Mirror go-oidc's discovery allowlist. Empty or unsupported-only
    /// metadata falls back to the mandatory RS256 algorithm.
    pub fn with_provider_signing_algorithms(mut self, algorithms: Vec<String>) -> Self {
        let algorithms: Vec<_> = algorithms
            .into_iter()
            .filter(|alg| OIDC_SIGNING_ALGORITHMS.contains(&alg.as_str()))
            .collect();
        self.signing_algorithms = Arc::new(if algorithms.is_empty() {
            vec!["RS256".into()]
        } else {
            algorithms
        });
        self
    }

    pub fn with_registration_handler(
        mut self,
        registration_handler: Arc<dyn OidcRegistrationHandler>,
    ) -> Self {
        self.registration_handler = Some(registration_handler);
        self
    }

    pub fn with_registration_handler_if_unset(
        mut self,
        registration_handler: Arc<dyn OidcRegistrationHandler>,
    ) -> Self {
        if self.registration_handler.is_none() {
            self.registration_handler = Some(registration_handler);
        }
        self
    }

    pub fn registration(&self, state: &str) -> Option<OidcRegistrationInfo> {
        self.registrations.get(state)
    }

    pub fn pending_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<OidcPendingRegistrationConfirmation> {
        self.registration_handler
            .as_ref()
            .and_then(|handler| handler.oidc_pending_registration_confirmation(registration_id))
            .or_else(|| self.confirmations.get(registration_id))
    }

    fn begin_registration(&self, registration_id: &str) -> Result<OidcAuthStart, OidcRuntimeError> {
        self.begin_auth_flow(registration_id, true)
    }

    fn begin_auth(&self, auth_id: &str) -> Result<OidcAuthStart, OidcRuntimeError> {
        self.begin_auth_flow(auth_id, false)
    }

    fn begin_auth_flow(
        &self,
        auth_id: &str,
        registration: bool,
    ) -> Result<OidcAuthStart, OidcRuntimeError> {
        let registration_id = if registration {
            registration_id_from_register_path(auth_id)
                .ok_or(OidcRuntimeError::InvalidRegistrationId)?
        } else {
            registration_id_from_auth_path(auth_id).ok_or(OidcRuntimeError::InvalidAuthId)?
        }
        .to_owned();

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
                registration,
            },
        );

        tracing::debug!("redirecting to {} for authentication", auth_url);

        Ok(OidcAuthStart {
            auth_url,
            state,
            nonce,
        })
    }
}

fn registration_id_from_register_path(segment: &str) -> Option<&str> {
    let rest = segment.strip_prefix(AUTH_ID_PREFIX)?;
    (segment.len() == AUTH_ID_LENGTH && rest.len() == REGISTRATION_ID_LENGTH).then_some(rest)
}

fn registration_id_from_auth_path(segment: &str) -> Option<&str> {
    let rest = segment.strip_prefix(AUTH_ID_PREFIX)?;
    (segment.len() == AUTH_ID_LENGTH && rest.len() == REGISTRATION_ID_LENGTH).then_some(rest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRegistrationInfo {
    pub registration_id: String,
    pub verifier: Option<String>,
    pub registration: bool,
}

#[derive(Debug)]
pub struct OidcRegistrationCache {
    inner: RwLock<BTreeMap<String, OidcRegistrationEntry>>,
    expiry: StdDuration,
    max_entries: usize,
    access_counter: AtomicU64,
}

#[derive(Debug, Clone)]
struct OidcRegistrationEntry {
    info: OidcRegistrationInfo,
    expires_at: Instant,
    last_used: u64,
}

impl OidcRegistrationCache {
    pub fn new(expiry: StdDuration) -> Self {
        Self::with_max_entries(expiry, DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES)
    }

    pub fn with_max_entries(expiry: StdDuration, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
            expiry,
            max_entries: nonzero_cache_max_entries(max_entries),
            access_counter: AtomicU64::new(0),
        }
    }

    pub fn insert(&self, state: String, info: OidcRegistrationInfo) {
        self.prune_expired();
        let entry = OidcRegistrationEntry {
            info,
            expires_at: Instant::now() + self.expiry,
            last_used: self.next_access(),
        };
        let registration_id = entry.info.registration_id.clone();
        let mut inner = self.inner.write();
        inner.insert(state, entry);
        prune_registration_states(&mut inner, &registration_id);
        prune_lru(&mut inner, self.max_entries);
    }

    pub fn get(&self, state: &str) -> Option<OidcRegistrationInfo> {
        self.prune_expired();
        let mut inner = self.inner.write();
        let entry = inner.get_mut(state)?;
        entry.last_used = self.next_access();
        Some(entry.info.clone())
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

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let expired = self
            .inner
            .read()
            .iter()
            .filter(|&(_state, entry)| now >= entry.expires_at)
            .map(|(state, _entry)| state.clone())
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

    fn next_access(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcRegistrationConfirmInfo {
    pub hostname: String,
    pub os: String,
    pub machine_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPendingRegistrationConfirmation {
    pub registration_id: String,
    pub user: OidcStoredUser,
    pub node_expiry: Option<DateTime<Utc>>,
    pub csrf: String,
    pub device: OidcRegistrationConfirmInfo,
}

#[derive(Debug)]
pub struct OidcRegistrationConfirmationCache {
    inner: RwLock<BTreeMap<String, OidcRegistrationConfirmationEntry>>,
    expiry: StdDuration,
    max_entries: usize,
    access_counter: AtomicU64,
}

#[derive(Debug, Clone)]
struct OidcRegistrationConfirmationEntry {
    pending: OidcPendingRegistrationConfirmation,
    expires_at: Instant,
    last_used: u64,
}

impl OidcRegistrationConfirmationCache {
    fn new(expiry: StdDuration) -> Self {
        Self::with_max_entries(expiry, DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES)
    }

    fn with_max_entries(expiry: StdDuration, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
            expiry,
            max_entries: nonzero_cache_max_entries(max_entries),
            access_counter: AtomicU64::new(0),
        }
    }

    #[cfg_attr(not(feature = "full"), allow(dead_code))]
    fn insert(&self, pending: OidcPendingRegistrationConfirmation) {
        self.prune_expired();
        let entry = OidcRegistrationConfirmationEntry {
            pending,
            expires_at: Instant::now() + self.expiry,
            last_used: self.next_access(),
        };
        let mut inner = self.inner.write();
        inner.insert(entry.pending.registration_id.clone(), entry);
        prune_lru(&mut inner, self.max_entries);
    }

    fn get(&self, registration_id: &str) -> Option<OidcPendingRegistrationConfirmation> {
        self.prune_expired();
        let mut inner = self.inner.write();
        let entry = inner.get_mut(registration_id)?;
        entry.last_used = self.next_access();
        Some(entry.pending.clone())
    }

    fn remove(&self, registration_id: &str) -> Option<OidcPendingRegistrationConfirmation> {
        self.prune_expired();
        self.inner
            .write()
            .remove(registration_id)
            .map(|entry| entry.pending)
    }

    fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let expired = self
            .inner
            .read()
            .iter()
            .filter(|&(_registration_id, entry)| now >= entry.expires_at)
            .map(|(registration_id, _entry)| registration_id.clone())
            .collect::<Vec<_>>();
        let mut inner = self.inner.write();
        let mut removed = 0;
        for registration_id in expired {
            if inner.remove(&registration_id).is_some() {
                removed += 1;
            }
        }
        removed
    }

    fn next_access(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

trait LruCacheEntry {
    fn last_used(&self) -> u64;
}

impl LruCacheEntry for OidcRegistrationEntry {
    fn last_used(&self) -> u64 {
        self.last_used
    }
}

impl LruCacheEntry for OidcRegistrationConfirmationEntry {
    fn last_used(&self) -> u64 {
        self.last_used
    }
}

fn nonzero_cache_max_entries(max_entries: usize) -> usize {
    if max_entries == 0 {
        DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES
    } else {
        max_entries
    }
}

/// Drops the least recently used states of `registration_id` beyond
/// [`OIDC_MAX_PENDING_STATES_PER_REGISTRATION`]; other registrations' states
/// are never touched.
fn prune_registration_states(
    inner: &mut BTreeMap<String, OidcRegistrationEntry>,
    registration_id: &str,
) {
    let mut owned = inner
        .iter()
        .filter(|(_state, entry)| entry.info.registration_id == registration_id)
        .map(|(state, entry)| (entry.last_used, state.clone()))
        .collect::<Vec<_>>();
    if owned.len() <= OIDC_MAX_PENDING_STATES_PER_REGISTRATION {
        return;
    }
    owned.sort_unstable();
    let excess = owned.len() - OIDC_MAX_PENDING_STATES_PER_REGISTRATION;
    for (_last_used, state) in owned.into_iter().take(excess) {
        inner.remove(&state);
    }
}

fn prune_lru<T: LruCacheEntry>(inner: &mut BTreeMap<String, T>, max_entries: usize) {
    while inner.len() > max_entries {
        let Some(evict_key) = inner
            .iter()
            .min_by_key(|(_key, entry)| entry.last_used())
            .map(|(key, _entry)| key.clone())
        else {
            break;
        };
        inner.remove(&evict_key);
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
    #[error("invalid auth id")]
    InvalidAuthId,
    #[error("missing code or state parameter")]
    MissingCodeOrState,
    #[error("invalid state parameter")]
    InvalidStateParameter,
    #[error("state not found")]
    StateCookieMissing,
    #[error("state did not match")]
    StateCookieMismatch,
    #[error("registration not found")]
    RegistrationNotFound,
    #[error("registration session expired")]
    RegistrationSessionExpired,
    #[error("registration not OIDC-authorized")]
    RegistrationNotOidcAuthorized,
    #[error("auth session is not for node registration")]
    AuthSessionNotRegistration,
    #[error("invalid form")]
    InvalidForm,
    #[error("missing csrf token")]
    MissingCsrfToken,
    #[error("missing csrf cookie")]
    MissingCsrfCookie,
    #[error("csrf token mismatch")]
    CsrfTokenMismatch,
    #[error("csrf token does not match cached registration")]
    CsrfTokenCacheMismatch,
    #[error("invalid code")]
    InvalidCode,
    #[error("no id_token")]
    MissingIdToken,
    #[error("failed to verify id_token")]
    IdTokenVerificationFailed,
    #[error("nonce not found in IDToken")]
    NonceMissingInToken,
    #[error("nonce not found")]
    NonceCookieMissing,
    #[error("nonce did not match")]
    NonceCookieMismatch,
    #[error(transparent)]
    Authorization(#[from] OidcAuthorizationError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcDiscoveryError {
    #[error("oidc issuer is empty")]
    EmptyIssuer,
    #[error("{message}")]
    Fetch { url: String, message: String },
    #[error("oidc: failed to decode provider discovery object: {message}")]
    Decode { url: String, message: String },
    #[error("{status}: {body}")]
    HttpStatus { status: String, body: String },
    #[error("OIDC discovery metadata is missing {field}")]
    MissingField { field: &'static str },
    #[error(
        "oidc: issuer URL provided to client ({}) did not match the issuer URL returned by provider ({})",
        headscale_api_acl::go_strconv::quote(.expected),
        headscale_api_acl::go_strconv::quote(&bounded_remote_text(.actual.as_bytes()))
    )]
    IssuerMismatch { expected: String, actual: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcRuntimeBuildError {
    #[error("creating OIDC provider from issuer config: {0}")]
    Discovery(#[from] OidcDiscoveryError),
    #[error("unsupported OIDC PKCE method {method:?}")]
    InvalidPkceMethod { method: String },
}

impl OidcProviderMetadata {
    pub fn validate_for_issuer(&self, issuer: &str) -> Result<(), OidcDiscoveryError> {
        if issuer.is_empty() {
            return Err(OidcDiscoveryError::EmptyIssuer);
        }
        // NewProvider checks issuer identity at discovery. Missing endpoints
        // fail only when the corresponding OAuth/JWKS operation is attempted.
        if self.issuer != issuer {
            return Err(OidcDiscoveryError::IssuerMismatch {
                expected: issuer.to_string(),
                actual: self.issuer.clone(),
            });
        }

        Ok(())
    }
}

/// Lossy text of at most `OIDC_ERROR_BODY_PREFIX` leading bytes of a remote
/// value, cut on a char boundary, noting the full size when it was cut.
fn bounded_remote_text(value: &[u8]) -> String {
    if value.len() <= OIDC_ERROR_BODY_PREFIX {
        return String::from_utf8_lossy(value).into_owned();
    }
    let mut end = OIDC_ERROR_BODY_PREFIX;
    // Step back over UTF-8 continuation bytes so a character is not split.
    while end > 0 && value[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    format!(
        "{}... ({} bytes total)",
        String::from_utf8_lossy(&value[..end]),
        value.len()
    )
}

pub fn oidc_discovery_url(issuer: &str) -> Result<String, OidcDiscoveryError> {
    Ok(format!(
        "{}/.well-known/openid-configuration",
        normalize_issuer(issuer)?
    ))
}

#[cfg(feature = "full")]
pub async fn discover_oidc_metadata(
    issuer: &str,
) -> Result<OidcProviderMetadata, OidcDiscoveryError> {
    let client = reqwest::Client::new();
    discover_oidc_metadata_with_client(&client, issuer).await
}

#[cfg(feature = "full")]
pub async fn discover_oidc_metadata_with_client(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<OidcProviderMetadata, OidcDiscoveryError> {
    let url = oidc_discovery_url(issuer)?;
    let response = client
        .get(&url)
        .timeout(OIDC_DISCOVERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| OidcDiscoveryError::Fetch {
            url: url.clone(),
            message: err.to_string(),
        })?;

    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map_or_else(Vec::new, |value| value.as_bytes().to_vec());
    let body = oidc_response_body(response)
        .await
        .map_err(|message| OidcDiscoveryError::Fetch {
            url: url.clone(),
            message: format!("unable to read response body: {message}"),
        })?;
    if status != StatusCode::OK {
        return Err(OidcDiscoveryError::HttpStatus {
            status: status.to_string(),
            body: bounded_remote_text(&body),
        });
    }

    let metadata = discovery::decode(&body).map_err(|err| OidcDiscoveryError::Decode {
        url: url.clone(),
        message: if discovery::has_json_content_type(&content_type) {
            format!("got Content-Type = application/json, but could not unmarshal as JSON: {err}")
        } else {
            format!(
                "expected Content-Type = application/json, got {}: {err}",
                form::quote_bytes(&content_type[..content_type.len().min(OIDC_ERROR_BODY_PREFIX)])
            )
        },
    })?;
    metadata.validate_for_issuer(issuer)?;
    Ok(metadata)
}

#[cfg(feature = "full")]
pub fn auth_config_from_core_oidc(
    oidc: &headscale_core::config::OidcConfig,
    server_url: &str,
    metadata: OidcProviderMetadata,
) -> Result<OidcAuthConfig, OidcRuntimeBuildError> {
    metadata.validate_for_issuer(&oidc.issuer)?;

    Ok(OidcAuthConfig {
        issuer: metadata.issuer,
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        userinfo_endpoint: metadata.userinfo_endpoint,
        jwks_uri: metadata.jwks_uri,
        client_id: oidc.client_id.clone(),
        client_secret: oidc.client_secret.clone(),
        redirect_url: oidc_redirect_url(server_url),
        scopes: oidc.scope.clone(),
        extra_params: oidc.extra_params.clone(),
        pkce: OidcPkceConfig {
            enabled: oidc.pkce.enabled,
            method: oidc_pkce_method_from_str(&oidc.pkce.method)?,
        },
        policy: OidcPolicyConfig {
            allowed_domains: oidc.allowed_domains.clone(),
            allowed_users: oidc.allowed_users.clone(),
            allowed_groups: oidc.allowed_groups.clone(),
            email_verified_required: oidc.email_verified_required,
            expiry: chrono::Duration::from_std(oidc.expiry).unwrap_or(chrono::Duration::MAX),
            use_expiry_from_token: oidc.use_expiry_from_token,
        },
    })
}

#[cfg(feature = "full")]
pub async fn runtime_from_core_oidc(
    oidc: &headscale_core::config::OidcConfig,
    server_url: &str,
) -> Result<Option<OidcAuthRuntime>, OidcRuntimeBuildError> {
    if oidc.issuer.is_empty() {
        return Ok(None);
    }

    let metadata = match discover_oidc_metadata(&oidc.issuer).await {
        Ok(metadata) => metadata,
        Err(err) if !oidc.only_start_if_oidc_is_available => {
            let err = OidcRuntimeBuildError::Discovery(err);
            tracing::warn!(
                error = %err,
                "failed to set up OIDC provider, falling back to CLI based authentication"
            );
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };

    let algorithms = metadata.id_token_signing_alg_values_supported.clone();
    Ok(Some(
        OidcAuthRuntime::new(auth_config_from_core_oidc(oidc, server_url, metadata)?)
            .with_provider_signing_algorithms(algorithms),
    ))
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
    #[serde(default, rename = "sub", deserialize_with = "deserialize_go_string")]
    pub sub: String,
    #[serde(default, rename = "iss", deserialize_with = "deserialize_go_string")]
    pub iss: String,
    #[serde(default, rename = "name", deserialize_with = "deserialize_go_string")]
    pub name: String,
    #[serde(
        default,
        rename = "groups",
        deserialize_with = "deserialize_flexible_string_vec_default"
    )]
    pub groups: Vec<String>,
    #[serde(default, rename = "email", deserialize_with = "deserialize_go_string")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(
        default,
        rename = "picture",
        deserialize_with = "deserialize_go_string"
    )]
    pub profile_picture_url: String,
    #[serde(
        default,
        rename = "preferred_username",
        deserialize_with = "deserialize_go_string"
    )]
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

        let issuer = self.iss.strip_suffix('/').unwrap_or(&self.iss);
        let subject = self.sub.strip_prefix('/').unwrap_or(&self.sub);
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
    #[serde(default, rename = "sub", deserialize_with = "deserialize_go_string")]
    pub sub: String,
    #[serde(default, rename = "name", deserialize_with = "deserialize_go_string")]
    pub name: String,
    #[serde(
        default,
        rename = "given_name",
        deserialize_with = "deserialize_go_string"
    )]
    pub given_name: String,
    #[serde(
        default,
        rename = "family_name",
        deserialize_with = "deserialize_go_string"
    )]
    pub family_name: String,
    #[serde(
        default,
        rename = "preferred_username",
        deserialize_with = "deserialize_go_string"
    )]
    pub preferred_username: String,
    #[serde(default, rename = "email", deserialize_with = "deserialize_go_string")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(
        default,
        rename = "groups",
        deserialize_with = "deserialize_optional_flexible_string_vec"
    )]
    pub groups: Option<Vec<String>>,
    #[serde(
        default,
        rename = "picture",
        deserialize_with = "deserialize_go_string"
    )]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcStoredUser {
    pub id: u64,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: String,
    pub provider: String,
    pub profile_pic_url: String,
}

impl OidcStoredUser {
    pub fn username(&self) -> String {
        if !self.email.is_empty() {
            self.email.clone()
        } else if !self.name.is_empty() {
            self.name.clone()
        } else if !self.provider_identifier.is_empty() {
            self.provider_identifier.clone()
        } else {
            self.id.to_string()
        }
    }
}

#[async_trait::async_trait]
pub trait OidcUserStore: Send + Sync {
    async fn create_or_update_oidc_user(
        &self,
        profile: OidcUserProfile,
    ) -> Result<OidcStoredUser, String>;

    /// Reload the pending account before confirmation. Legacy/custom stores
    /// retain their cached profile by default; native stores resolve its ID.
    async fn refresh_oidc_user(&self, user: &OidcStoredUser) -> Result<OidcStoredUser, String> {
        Ok(user.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRegistrationResult {
    pub new_node: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcAuthRequestKind {
    Registration,
    SshCheck,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcRegistrationError {
    #[error("login session expired, try again")]
    SessionExpired,
    #[error("{0}")]
    Store(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcAuthError {
    #[error("login session expired, try again")]
    SessionExpired,
    #[error("auth session is not for SSH check")]
    NotSshCheck,
    #[error("src node no longer exists")]
    SourceNodeMissing,
    #[error("src node has no user owner")]
    SourceNodeNoUserOwner,
    #[error("OIDC user is not the owner of the SSH source node")]
    UserNotSourceOwner,
    #[error("OIDC auth request completion is not implemented")]
    NotImplemented,
    #[error("{0}")]
    Store(String),
}

#[async_trait::async_trait]
pub trait OidcRegistrationHandler: Send + Sync {
    async fn complete_oidc_registration(
        &self,
        registration_id: &str,
        user: &OidcStoredUser,
        node_expiry: Option<DateTime<Utc>>,
    ) -> Result<OidcRegistrationResult, OidcRegistrationError>;

    async fn complete_oidc_auth_request(
        &self,
        auth_id: &str,
        user: &OidcStoredUser,
    ) -> Result<(), OidcAuthError> {
        let _ = (auth_id, user);
        Err(OidcAuthError::NotImplemented)
    }

    fn oidc_registration_exists(&self, _registration_id: &str) -> bool {
        false
    }

    fn oidc_auth_request_kind(&self, auth_id: &str) -> Option<OidcAuthRequestKind> {
        self.oidc_registration_exists(auth_id)
            .then_some(OidcAuthRequestKind::Registration)
    }

    fn oidc_registration_confirmation_info(
        &self,
        _registration_id: &str,
    ) -> Option<OidcRegistrationConfirmInfo> {
        None
    }

    fn store_oidc_registration_confirmation(
        &self,
        _pending: OidcPendingRegistrationConfirmation,
    ) -> bool {
        false
    }

    fn oidc_pending_registration_confirmation(
        &self,
        _registration_id: &str,
    ) -> Option<OidcPendingRegistrationConfirmation> {
        None
    }

    fn remove_oidc_registration_confirmation(
        &self,
        _registration_id: &str,
    ) -> Option<OidcPendingRegistrationConfirmation> {
        None
    }
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
    _now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if cfg.use_expiry_from_token {
        Some(id_token_expiry)
    } else {
        None
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
    handle_register_with_request_security(runtime, registration_id, false).await
}

pub async fn handle_register_with_request_security(
    runtime: OidcAuthRuntime,
    registration_id: String,
    request_is_tls: bool,
) -> Response {
    let start = match runtime.begin_registration(&registration_id) {
        Ok(start) => start,
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), &err.to_string()),
    };

    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    let secure = runtime.config.redirect_url.starts_with("https://") || request_is_tls;
    append_cookie(
        response.headers_mut(),
        &csrf_cookie(
            "state",
            &start.state,
            secure,
            &callback_cookie_path(&runtime.config.redirect_url),
        ),
    );
    append_cookie(
        response.headers_mut(),
        &csrf_cookie(
            "nonce",
            &start.nonce,
            secure,
            &callback_cookie_path(&runtime.config.redirect_url),
        ),
    );
    response
}

pub async fn handle_auth(runtime: OidcAuthRuntime, auth_id: String) -> Response {
    handle_auth_with_request_security(runtime, auth_id, false).await
}

pub async fn handle_auth_with_request_security(
    runtime: OidcAuthRuntime,
    auth_id: String,
    request_is_tls: bool,
) -> Response {
    let start = match runtime.begin_auth(&auth_id) {
        Ok(start) => start,
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), &err.to_string()),
    };

    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    let secure = runtime.config.redirect_url.starts_with("https://") || request_is_tls;
    append_cookie(
        response.headers_mut(),
        &csrf_cookie(
            "state",
            &start.state,
            secure,
            &callback_cookie_path(&runtime.config.redirect_url),
        ),
    );
    append_cookie(
        response.headers_mut(),
        &csrf_cookie(
            "nonce",
            &start.nonce,
            secure,
            &callback_cookie_path(&runtime.config.redirect_url),
        ),
    );
    response
}

pub async fn handle_register_confirm(
    runtime: OidcAuthRuntime,
    auth_id: String,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    handle_register_confirm_with_request_security(runtime, auth_id, headers, raw, false).await
}

/// Render the confirmation on a reloadable URL, after the callback has
/// consumed the one-time OAuth code. The browser must present the CSRF cookie
/// that the callback issued; knowing the auth ID alone is insufficient.
pub fn handle_register_confirm_get(
    runtime: &OidcAuthRuntime,
    auth_id: &str,
    headers: &HeaderMap,
) -> Response {
    match registration_confirmation_for_get(runtime, auth_id, headers) {
        Ok(pending) => registration_confirmation_response(runtime, auth_id, &pending),
        Err(response) => response,
    }
}

/// Native HTTP entry point reloads the account after validating the browser
/// cookie, matching Headscale's confirmation-time GetUserByID boundary.
pub async fn handle_register_confirm_get_with_user_refresh(
    runtime: &OidcAuthRuntime,
    auth_id: &str,
    headers: &HeaderMap,
) -> Response {
    let mut pending = match registration_confirmation_for_get(runtime, auth_id, headers) {
        Ok(pending) => pending,
        Err(response) => return response,
    };
    if let Some(users) = &runtime.users {
        pending.user = match users.refresh_oidc_user(&pending.user).await {
            Ok(user) => user,
            Err(error) => {
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("looking up user: {error}"),
                );
            }
        };
    }
    registration_confirmation_response(runtime, auth_id, &pending)
}

fn registration_confirmation_for_get(
    runtime: &OidcAuthRuntime,
    auth_id: &str,
    headers: &HeaderMap,
) -> Result<OidcPendingRegistrationConfirmation, Response> {
    let Some(registration_id) = registration_id_from_register_path(auth_id) else {
        return Err(oidc_error_response(
            StatusCode::BAD_REQUEST,
            &OidcRuntimeError::InvalidRegistrationId.to_string(),
        ));
    };
    let Some(pending) = runtime.pending_confirmation(registration_id) else {
        let err = match runtime
            .registration_handler
            .as_ref()
            .and_then(|handler| handler.oidc_auth_request_kind(registration_id))
        {
            Some(_) => OidcRuntimeError::RegistrationNotOidcAuthorized,
            None => return Err(registration_link_spent_response()),
        };
        return Err(oidc_error_response(
            status_for_runtime_error(&err),
            &err.to_string(),
        ));
    };
    let Some(cookie_csrf) = cookie_value(headers, REGISTER_CONFIRM_CSRF_COOKIE) else {
        return Err(oidc_error_response(
            StatusCode::FORBIDDEN,
            &OidcRuntimeError::MissingCsrfCookie.to_string(),
        ));
    };
    if cookie_csrf != pending.csrf {
        return Err(oidc_error_response(
            StatusCode::FORBIDDEN,
            &OidcRuntimeError::CsrfTokenMismatch.to_string(),
        ));
    }
    Ok(pending)
}

fn registration_confirmation_response(
    runtime: &OidcAuthRuntime,
    auth_id: &str,
    pending: &OidcPendingRegistrationConfirmation,
) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        oidc_registration_confirm_html(
            pending,
            &register_confirm_url(&runtime.config.redirect_url, auth_id),
        ),
    )
        .into_response()
}

pub async fn handle_register_confirm_with_request_security(
    runtime: OidcAuthRuntime,
    auth_id: String,
    headers: HeaderMap,
    raw: Bytes,
    secure_cookies: bool,
) -> Response {
    handle_register_confirm_with_request_security_and_query(
        runtime,
        auth_id,
        headers,
        raw,
        secure_cookies,
        None,
    )
    .await
}

/// Native ParseForm also validates URL-query syntax. Query values never
/// provide the POST-only CSRF field used to authorize confirmation.
pub async fn handle_register_confirm_with_request_security_and_query(
    runtime: OidcAuthRuntime,
    auth_id: String,
    headers: HeaderMap,
    raw: Bytes,
    secure_cookies: bool,
    query: Option<&str>,
) -> Response {
    let Some(registration_id) = registration_id_from_register_path(&auth_id).map(str::to_string)
    else {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            &OidcRuntimeError::InvalidRegistrationId.to_string(),
        );
    };

    let form_csrf = match form::decode_confirmation_form(&headers, &raw, query) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                &OidcRuntimeError::MissingCsrfToken.to_string(),
            );
        }
        Err(error) => {
            return oidc_error_response(StatusCode::BAD_REQUEST, &format!("invalid form: {error}"));
        }
    };

    let Some(cookie_csrf) = cookie_value(&headers, REGISTER_CONFIRM_CSRF_COOKIE) else {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            &OidcRuntimeError::MissingCsrfCookie.to_string(),
        );
    };
    if cookie_csrf != form_csrf {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            &OidcRuntimeError::CsrfTokenMismatch.to_string(),
        );
    }

    let Some(registration_handler) = &runtime.registration_handler else {
        return oidc_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "OIDC callback completion is not implemented",
        );
    };

    let Some(mut pending) = registration_handler
        .oidc_pending_registration_confirmation(&registration_id)
        .or_else(|| runtime.confirmations.get(&registration_id))
    else {
        let err = match registration_handler.oidc_auth_request_kind(&registration_id) {
            Some(_) => OidcRuntimeError::RegistrationNotOidcAuthorized,
            None => return registration_link_spent_response(),
        };
        return oidc_error_response(status_for_runtime_error(&err), &err.to_string());
    };

    if pending.csrf != cookie_csrf {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            &OidcRuntimeError::CsrfTokenCacheMismatch.to_string(),
        );
    }

    if let Some(users) = &runtime.users {
        pending.user = match users.refresh_oidc_user(&pending.user).await {
            Ok(user) => user,
            Err(error) => {
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("looking up user: {error}"),
                );
            }
        };
    }

    match registration_handler
        .complete_oidc_registration(&pending.registration_id, &pending.user, pending.node_expiry)
        .await
    {
        Ok(result) => {
            registration_handler.remove_oidc_registration_confirmation(&registration_id);
            runtime.confirmations.remove(&registration_id);
            let mut response = oidc_registration_success_response(&pending.user, result.new_node);
            clear_register_confirm_cookie(
                response.headers_mut(),
                &register_confirm_path(&runtime.config.redirect_url, &auth_id),
                runtime.config.redirect_url.starts_with("https://") || secure_cookies,
            );
            response
        }
        Err(OidcRegistrationError::SessionExpired) => registration_link_spent_response(),
        Err(OidcRegistrationError::Store(err)) => {
            oidc_error_response(StatusCode::INTERNAL_SERVER_ERROR, &err)
        }
    }
}

pub async fn handle_callback(
    runtime: OidcAuthRuntime,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    handle_callback_with_request_security(runtime, headers, Query(query), false).await
}

pub async fn handle_callback_with_request_security(
    runtime: OidcAuthRuntime,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
    secure_cookies: bool,
) -> Response {
    handle_callback_bytes(
        runtime,
        headers,
        query.code.into_bytes(),
        query.state.into_bytes(),
        secure_cookies,
    )
    .await
}

/// Native URL.Query().Get keeps the first successfully decoded byte value,
/// including an empty value, despite malformed unrelated query pairs.
pub(crate) async fn handle_callback_with_raw_query(
    runtime: OidcAuthRuntime,
    headers: HeaderMap,
    query: Option<String>,
    secure_cookies: bool,
) -> Response {
    let query = query.as_deref().unwrap_or_default().as_bytes();
    handle_callback_bytes(
        runtime,
        headers,
        form::query_first_value(query, b"code").unwrap_or_default(),
        form::query_first_value(query, b"state").unwrap_or_default(),
        secure_cookies,
    )
    .await
}

async fn handle_callback_bytes(
    runtime: OidcAuthRuntime,
    headers: HeaderMap,
    code: Vec<u8>,
    state: Vec<u8>,
    secure_cookies: bool,
) -> Response {
    if code.is_empty() || state.is_empty() {
        return oidc_error_response(
            status_for_runtime_error(&OidcRuntimeError::MissingCodeOrState),
            &OidcRuntimeError::MissingCodeOrState.to_string(),
        );
    }

    match validate_state_cookie_bytes(&headers, &state) {
        Ok(()) => {}
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), &err.to_string()),
    }

    // A matching Cookie value contains only ASCII cookie-octets, so this
    // conversion follows exact byte equality instead of a lossy projection.
    let state = String::from_utf8(state).expect("validated state cookie is ASCII");

    let registration = runtime.registration(&state);
    #[cfg(not(feature = "full"))]
    let _ = (registration, secure_cookies);

    #[cfg(feature = "full")]
    {
        // Upstream needs cached state before the exchange only for PKCE.
        // Otherwise code/core/nonce/application validation runs before the
        // state is consumed, preserving provider errors and callback cleanup.
        if runtime.config.pkce.enabled && registration.is_none() {
            return oidc_error_response(StatusCode::NOT_FOUND, "registration not found");
        }
        let Ok(_callback) = Arc::clone(&runtime.pending_callbacks).try_acquire_owned() else {
            return oidc_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many pending OIDC callbacks",
            );
        };
        let verifier = runtime
            .config
            .pkce
            .enabled
            .then(|| {
                registration
                    .as_ref()
                    .and_then(|info| info.verifier.as_deref())
            })
            .flatten();
        let token = match exchange_oauth2_token(&runtime, &code, verifier).await {
            Ok(token) => token,
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), &err.to_string());
            }
        };

        let id_token = match verify_id_token(&runtime, &token.id_token).await {
            Ok(id_token) => id_token,
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), &err.to_string());
            }
        };

        match validate_nonce_cookie(&headers, &id_token.nonce) {
            Ok(()) => {}
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), &err.to_string());
            }
        }

        // Every outcome after nonce binding expires both browser cookies,
        // including application-claims failures and later store errors.
        let mut response = async {
            let node_expiry =
                determine_node_expiry(&runtime.config.policy, id_token.expiry, Utc::now());
            let mut claims = match json::application_claims(&id_token.payload) {
                Ok(claims) => claims,
                Err(error) => {
                    return oidc_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("decoding ID token claims: {error}"),
                    );
                }
            };
            let userinfo = fetch_userinfo(&runtime, &token).await;
            if userinfo
                .as_ref()
                .is_some_and(|userinfo| userinfo.sub != claims.sub)
            {
                tracing::error!("could not get userinfo; only using claims from id token");
            }
            merge_userinfo_claims(&mut claims, userinfo.as_ref());
            if let Err(err) = authorize_claims(&runtime.config.policy, &claims) {
                let err = OidcRuntimeError::Authorization(err);
                return oidc_error_response(status_for_runtime_error(&err), &err.to_string());
            }
            let profile =
                user_profile_from_claims(&claims, runtime.config.policy.email_verified_required);
            let user = if let Some(users) = &runtime.users {
                match users.create_or_update_oidc_user(profile).await {
                    Ok(user) => user,
                    Err(_) => {
                        return oidc_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "could not create or update user",
                        );
                    }
                }
            } else {
                stored_user_from_profile(profile)
            };

            // The verified callback state is single-use. Consume it atomically
            // before completing registration or SSH approval so concurrent or
            // replayed callbacks cannot resolve the same auth request twice.
            let Some(registration) = runtime.registrations.remove(&state) else {
                tracing::debug!(
                    state = %state,
                    "state not found in cache, login session may have expired"
                );
                return oidc_error_response(
                    StatusCode::GONE,
                    "login session expired, try again",
                );
            };

            if let Some(registration_handler) = &runtime.registration_handler {
                if registration.registration {
                    match registration_handler.oidc_auth_request_kind(&registration.registration_id)
                    {
                        Some(OidcAuthRequestKind::Registration) => {}
                        Some(OidcAuthRequestKind::SshCheck) => {
                            tracing::warn!(
                                auth_id = %format_args!("{AUTH_ID_PREFIX}{}", registration.registration_id),
                                "OIDC callback hit registration path with auth request that is not a node registration"
                            );
                            let err = OidcRuntimeError::AuthSessionNotRegistration;
                            return oidc_error_response(
                                status_for_runtime_error(&err),
                                &err.to_string(),
                            );
                        }
                        None => {
                            tracing::debug!(
                                auth_id = %format_args!("{AUTH_ID_PREFIX}{}", registration.registration_id),
                                "registration session expired before authorization completed"
                            );
                            return oidc_error_response(
                                StatusCode::GONE,
                                "login session expired, try again",
                            );
                        }
                    }
                    let csrf = random_urlsafe(32);
                    let device = registration_handler
                        .oidc_registration_confirmation_info(&registration.registration_id)
                        .unwrap_or_default();
                    let pending = OidcPendingRegistrationConfirmation {
                        registration_id: registration.registration_id.clone(),
                        user: user.clone(),
                        node_expiry,
                        csrf,
                        device,
                    };
                    if !registration_handler.store_oidc_registration_confirmation(pending.clone()) {
                        runtime.confirmations.insert(pending.clone());
                    }
                    return oidc_registration_confirm_redirect(
                        &runtime.config.redirect_url,
                        &pending,
                        runtime.config.redirect_url.starts_with("https://") || secure_cookies,
                    );
                }

                match registration_handler
                    .complete_oidc_auth_request(&registration.registration_id, &user)
                    .await
                {
                    Ok(()) => return oidc_ssh_success_response(&user),
                    Err(err) => {
                        return oidc_error_response(status_for_auth_error(&err), &err.to_string());
                    }
                }
            }
            oidc_error_response(
                StatusCode::NOT_IMPLEMENTED,
                "OIDC callback completion is not implemented",
            )
        }
        .await;
        // Upstream deletes both callback cookies right after the nonce check,
        // before a later step (the register-confirm redirect) sets its own
        // cookie, so the deletions lead the Set-Cookie headers.
        let later_cookies: Vec<HeaderValue> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .cloned()
            .collect();
        response.headers_mut().remove(header::SET_COOKIE);
        clear_callback_cookies(
            response.headers_mut(),
            &runtime.config.redirect_url,
            &state,
            &id_token.nonce,
        );
        for cookie in later_cookies {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        response
    }

    #[cfg(not(feature = "full"))]
    {
        oidc_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "OIDC callback completion is not implemented",
        )
    }
}

#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
struct OidcTokenResponse {
    #[serde(default, deserialize_with = "deserialize_go_string")]
    access_token: String,
    #[serde(default, deserialize_with = "deserialize_token_extra")]
    id_token: String,
    // Extra("id_token").(string) distinguishes an empty string from an
    // absent/non-string JSON value. Verification handles empty strings.
    #[serde(skip)]
    id_token_is_string: bool,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    token_type: String,
    #[serde(default, rename = "error", deserialize_with = "deserialize_go_string")]
    error_code: String,
    #[serde(
        default,
        rename = "error_description",
        deserialize_with = "deserialize_go_string"
    )]
    _error_description: String,
    #[serde(
        default,
        rename = "error_uri",
        deserialize_with = "deserialize_go_string"
    )]
    _error_uri: String,
    #[serde(
        default,
        rename = "refresh_token",
        deserialize_with = "deserialize_go_string"
    )]
    _refresh_token: String,
    #[serde(
        default,
        rename = "expires_in",
        deserialize_with = "deserialize_oauth_expiry"
    )]
    _expires_in: Option<i64>,
}

#[cfg(feature = "full")]
async fn exchange_oauth2_token(
    runtime: &OidcAuthRuntime,
    code: &[u8],
    verifier: Option<&str>,
) -> Result<OidcTokenResponse, OidcRuntimeError> {
    let cfg = &runtime.config;
    let client = &runtime.provider_client;

    // oauth2 caches the first successful style per endpoint/client ID.
    // Both are immutable in this runtime, so its shared byte is sufficient.
    let cached_style = runtime.token_auth_style.load(Ordering::Relaxed);
    let styles: &[u8] = match cached_style {
        1 => &[1],
        2 => &[2],
        _ => &[1, 2],
    };
    for (attempt, style) in styles.iter().copied().enumerate() {
        let auth_in_header = style == 1;
        let can_retry = attempt + 1 < styles.len();
        let mut form = BTreeMap::from([
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), String::new()),
        ]);
        if !cfg.redirect_url.is_empty() {
            form.insert("redirect_uri".to_string(), cfg.redirect_url.clone());
        }
        if let Some(verifier) = verifier {
            form.insert("code_verifier".to_string(), verifier.to_string());
        }
        if !auth_in_header {
            if !cfg.client_id.is_empty() {
                form.insert("client_id".to_string(), cfg.client_id.clone());
            }
            if !cfg.client_secret.is_empty() {
                form.insert("client_secret".to_string(), cfg.client_secret.clone());
            }
        }

        let request = client
            .post(&cfg.token_endpoint)
            .timeout(OIDC_PROVIDER_TIMEOUT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(
                form.iter()
                    .map(|(key, value)| {
                        let value = if key == "code" {
                            code
                        } else {
                            value.as_bytes()
                        };
                        format!("{}={}", form_encode(key), form_encode_bytes(value))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        let request = if auth_in_header {
            request.header(
                reqwest::header::AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!(
                        "{}:{}",
                        form_encode(&cfg.client_id),
                        form_encode(&cfg.client_secret)
                    ))
                ),
            )
        } else {
            request
        };

        let response = match request.send().await {
            Ok(response) => response,
            Err(_) if can_retry => continue,
            Err(_) => return Err(OidcRuntimeError::InvalidCode),
        };
        let token = match parse_oauth2_token_response(response).await {
            Ok(token) => token,
            Err(_) if can_retry => continue,
            Err(_) => return Err(OidcRuntimeError::InvalidCode),
        };
        if cached_style == 0 {
            runtime.token_auth_style.store(style, Ordering::Relaxed);
        }
        if !token.id_token_is_string {
            return Err(OidcRuntimeError::MissingIdToken);
        }
        return Ok(token);
    }

    Err(OidcRuntimeError::InvalidCode)
}

#[cfg(feature = "full")]
async fn parse_oauth2_token_response(
    response: reqwest::Response,
) -> Result<OidcTokenResponse, String> {
    let success = response.status().is_success();
    let content_type = oidc_response_media_type(&response).0;
    let body = oidc_oauth_response_body(response).await?;
    let token = if matches!(
        content_type.as_str(),
        "application/x-www-form-urlencoded" | "text/plain"
    ) {
        let mut values = form::decode_token_form(&body)?;
        OidcTokenResponse {
            id_token_is_string: json::form_id_token_is_string(
                values.get("id_token").map_or("", String::as_str),
            ),
            access_token: values.remove("access_token").unwrap_or_default(),
            id_token: values.remove("id_token").unwrap_or_default(),
            token_type: values.remove("token_type").unwrap_or_default(),
            error_code: values.remove("error").unwrap_or_default(),
            ..Default::default()
        }
    } else {
        json::token_response(&body)?
    };
    if !success || !token.error_code.is_empty() || token.access_token.is_empty() {
        return Err("invalid token response".into());
    }
    Ok(token)
}

#[cfg(feature = "full")]
fn deserialize_token_extra<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(serde_json::Value::deserialize(deserializer)?
        .as_str()
        .unwrap_or_default()
        .to_string())
}

#[cfg(feature = "full")]
fn deserialize_oauth_expiry<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let seconds = match value {
        serde_json::Value::Null => return Ok(None),
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(number) => {
            oidc_json_number(&number).and_then(|number| number.as_i64())
        }
        _ => None,
    };
    seconds
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("invalid expires_in"))
}

#[cfg(feature = "full")]
fn log_userinfo_provider_error(error: impl fmt::Display) {
    // Pinned callback logs the failed Provider.UserInfo result, then reaches
    // its failed merge branch and logs the same provider error a second time.
    tracing::error!(error = %error, "could not get userinfo; only using claims from id token");
    tracing::error!(error = %error, "could not get userinfo; only using claims from id token");
}

#[cfg(feature = "full")]
fn userinfo_transport_error(endpoint: &str, error: reqwest::Error) -> String {
    // net/http.Client.Do wraps transport failures in url.Error with the
    // original Get operation and a quoted URL whose password is replaced.
    // Preserve native transport causes: reqwest's outer Display omits them.
    let request_error = !error.is_builder();
    let mut url = error
        .url()
        .cloned()
        .or_else(|| reqwest::Url::parse(endpoint).ok());
    if let Some(url) = &mut url
        && url.password().is_some()
    {
        let _ = url.set_password(Some("***"));
    }
    let error = error.without_url();
    let cause = oidc_transport_causes(&error);
    if request_error {
        let url = url.as_ref().map_or(endpoint, |url| url.as_str());
        format!("Get {}: {cause}", form::quote_bytes(url.as_bytes()))
    } else {
        // Native request construction and header errors retain their actual
        // cause instead of pretending they came from Client.Do.
        cause
    }
}

#[cfg(feature = "full")]
fn oidc_transport_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        let _ = write!(message, ": {error}");
        cause = error.source();
    }
    message
}

#[cfg(feature = "full")]
fn userinfo_response_status(response: &reqwest::Response) -> String {
    let status = response.status();
    let reason = response
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map(|reason| bounded_remote_text(reason.as_bytes()));
    format!(
        "{} {}",
        status.as_str(),
        reason
            .as_deref()
            .unwrap_or_else(|| status.canonical_reason().unwrap_or_default())
    )
}

#[cfg(feature = "full")]
async fn fetch_userinfo(
    runtime: &OidcAuthRuntime,
    token: &OidcTokenResponse,
) -> Option<OidcUserInfo> {
    let cfg = &runtime.config;
    let Some(endpoint) = cfg
        .userinfo_endpoint
        .as_ref()
        .filter(|endpoint| !endpoint.is_empty())
    else {
        log_userinfo_provider_error("oidc: user info endpoint is not supported by this provider");
        return None;
    };
    let token_type = if token.token_type.is_empty()
        || headscale_api_acl::go_unicode::equal_fold(&token.token_type, "bearer")
    {
        "Bearer"
    } else if headscale_api_acl::go_unicode::equal_fold(&token.token_type, "basic") {
        "Basic"
    } else if headscale_api_acl::go_unicode::equal_fold(&token.token_type, "mac") {
        "MAC"
    } else {
        token.token_type.as_str()
    };

    let response = match runtime
        .provider_client
        .get(endpoint)
        .timeout(OIDC_PROVIDER_TIMEOUT)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("{token_type} {}", token.access_token),
        )
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            log_userinfo_provider_error(userinfo_transport_error(endpoint, err));
            return None;
        }
    };

    let success = response.status() == StatusCode::OK;
    let status = userinfo_response_status(&response);
    let (content_type, media_error) = oidc_response_media_type(&response);
    let body = match oidc_response_body(response).await {
        Ok(body) => body,
        Err(error) => {
            log_userinfo_provider_error(error);
            return None;
        }
    };
    // Provider.UserInfo reads the response body before checking its status.
    // Keep the existing explicit resource bound on both success and error
    // bodies; a read/size error therefore takes precedence over HTTP status.
    if !success {
        log_userinfo_provider_error(format!("{status}: {}", bounded_remote_text(&body)));
        return None;
    }
    let body = if media_error.is_none() && content_type == "application/jwt" {
        let raw = match std::str::from_utf8(&body) {
            Ok(raw) => raw,
            Err(error) => {
                log_userinfo_provider_error(format!(
                    "oidc: invalid userinfo jwt signature {error}"
                ));
                return None;
            }
        };
        match verify_oidc_signed_payload(runtime, raw, None).await {
            Ok(payload) => payload,
            Err(error) => {
                log_userinfo_provider_error(format!(
                    "oidc: invalid userinfo jwt signature {error}"
                ));
                return None;
            }
        }
    } else {
        body
    };
    match userinfo_json::parse(&body) {
        Ok(userinfo) => Some(userinfo),
        Err(userinfo_json::DecodeError::Provider(error)) => {
            log_userinfo_provider_error(error);
            None
        }
        Err(userinfo_json::DecodeError::Claims) => {
            // A successful Provider.UserInfo left err=nil in the pinned
            // callback, so a later Claims failure logs no error field.
            tracing::error!("could not get userinfo; only using claims from id token");
            None
        }
    }
}

#[cfg(feature = "full")]
fn oidc_response_media_type(response: &reqwest::Response) -> (String, Option<String>) {
    // Keep raw parameter bytes for Go MIME duplicate comparison; HTTP
    // HeaderValue need not be UTF-8. oauth2 ignores the error but UserInfo
    // requires full parse success before interpreting a signed JWT body.
    let value = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map_or(&[][..], |value| value.as_bytes());
    form::media_type_bytes(value)
}

#[cfg(feature = "full")]
async fn oidc_crypto_work<T, F>(work: F) -> Result<T, OidcRuntimeError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = OIDC_CRYPTO_WORKERS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)?;
    tokio::task::spawn_blocking(move || {
        // Cancellation of the caller must not release a still-running job's
        // permit and allow more work into the blocking pool.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)
}

#[cfg(feature = "full")]
async fn oidc_oauth_response_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    // oauth2 reads io.LimitReader(body, 1<<20), not an oversize rejection.
    // It closes after that prefix, so bytes/errors beyond it are unobserved.
    let mut body = Vec::new();
    while body.len() < OIDC_PROVIDER_BODY_LIMIT {
        let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? else {
            break;
        };
        let remaining = OIDC_PROVIDER_BODY_LIMIT - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Ok(body)
}

#[cfg(feature = "full")]
async fn oidc_response_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|len| len > OIDC_PROVIDER_BODY_LIMIT as u64)
    {
        return Err("OIDC provider response exceeds 1 MiB".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| oidc_transport_causes(&err))?
    {
        if chunk.len() > OIDC_PROVIDER_BODY_LIMIT.saturating_sub(body.len()) {
            return Err("OIDC provider response exceeds 1 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "full")]
#[derive(Debug)]
struct OidcJwks {
    keys: Vec<OidcJwk>,
}

#[cfg(feature = "full")]
#[derive(Debug, Clone, Deserialize)]
struct OidcJwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    crv: String,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    x: String,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    y: String,
    #[serde(skip)]
    private_key: bool,
}

#[cfg(feature = "full")]
#[derive(Default)]
struct OidcJwksCache {
    keys: RwLock<Arc<Vec<OidcJwk>>>,
    generation: AtomicU64,
    refresh: tokio::sync::Mutex<()>,
}

#[cfg(feature = "full")]
struct OidcJwsHeader {
    alg: String,
    kid: String,
}

#[cfg(feature = "full")]
struct OidcSignedPayload {
    header: OidcJwsHeader,
    input: Vec<u8>,
    signature: String,
    payload: Vec<u8>,
}

#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
struct OidcJsonSignature {
    protected: Option<String>,
    header: Option<serde_json::Map<String, serde_json::Value>>,
    signature: Option<String>,
}

#[cfg(feature = "full")]
#[derive(Deserialize)]
struct OidcJsonJws {
    payload: Option<String>,
    signatures: Option<Vec<OidcJsonSignature>>,
    #[serde(flatten)]
    flattened: OidcJsonSignature,
}

#[cfg(feature = "full")]
fn decode_oidc_base64(value: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    // Go's RawURLEncoding accepts CR/LF and non-zero unused trailing bits.
    let value = value.replace(['\r', '\n'], "");
    engine.decode(value).ok()
}

#[cfg(feature = "full")]
fn oidc_header_string(
    header: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<String> {
    match header.get(name) {
        None | Some(serde_json::Value::Null) => Some(String::new()),
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        _ => None,
    }
}

#[cfg(feature = "full")]
fn parse_oidc_signed_payload(raw: &str) -> Option<OidcSignedPayload> {
    // ParseSigned strips Unicode whitespace before selecting a serialization.
    let raw: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    let (protected, unprotected, payload, signature, general) = if raw.starts_with('{') {
        let jws = json::signed_json(raw.as_bytes())?;
        let payload = jws.payload?;
        let mut signatures = jws.signatures.unwrap_or_default();
        if signatures.len() > 1 {
            return None;
        }
        let general = !signatures.is_empty();
        let signature = signatures.pop().unwrap_or(jws.flattened);
        (
            signature.protected,
            signature.header.unwrap_or_default(),
            payload,
            signature.signature?,
            general,
        )
    } else {
        let mut parts = raw.split('.');
        let protected = parts.next()?.to_string();
        let payload = parts.next()?.to_string();
        let signature = parts.next()?.to_string();
        if parts.next().is_some() {
            return None;
        }
        (
            Some(protected),
            serde_json::Map::new(),
            payload,
            signature,
            false,
        )
    };
    let protected_bytes = match protected.as_deref() {
        Some(encoded) => Some(decode_oidc_base64(encoded)?),
        None => None,
    };
    let protected_header = match &protected_bytes {
        Some(bytes) => json::header(bytes)?,
        None => serde_json::Map::new(),
    };
    if unprotected.contains_key("crit")
        || !oidc_header_string(&unprotected, "nonce")
            .unwrap_or_default()
            .is_empty()
    {
        return None;
    }
    let critical: Vec<String> = match protected_header.get("crit") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(value) => serde_json::from_value::<Vec<Option<String>>>(value.clone())
            .ok()?
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect(),
    };
    if critical.iter().any(|name| name != "b64") {
        return None;
    }
    let mut merged = protected_header.clone();
    for (name, value) in &unprotected {
        let present = merged
            .get(name)
            .is_some_and(|value| !value.is_null() && value.as_str() != Some(""));
        if !present {
            merged.insert(name.clone(), value.clone());
        }
    }
    // Pinned go-jose's general form builds the exposed header from protected
    // fields before attaching the unprotected map. Its kid lookup follows that
    // exposed header; flattened form uses the merged header instead.
    let selected = if general { &protected_header } else { &merged };
    validate_oidc_jws_header(&protected_header, false)?;
    if !general {
        validate_oidc_jws_header(&unprotected, false)?;
    }
    validate_oidc_jws_header(selected, true)?;
    let header = OidcJwsHeader {
        alg: oidc_header_string(selected, "alg")?,
        kid: oidc_header_string(selected, "kid")?,
    };
    let payload = decode_oidc_base64(&payload)?;
    let signature = decode_oidc_base64(&signature)?;
    if signature.is_empty() {
        return None;
    }
    // Go reconstructs auth data from decoded buffers, not the original base64
    // spelling. Its b64 flag controls auth data; serialized payload stays base64.
    let mut input = protected_bytes
        .as_ref()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default()
        .into_bytes();
    input.push(b'.');
    if protected_header
        .get("b64")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
    {
        input.extend_from_slice(URL_SAFE_NO_PAD.encode(&payload).as_bytes());
    } else {
        input.extend_from_slice(&payload);
    }
    Some(OidcSignedPayload {
        header,
        input,
        signature: URL_SAFE_NO_PAD.encode(signature),
        payload,
    })
}

#[cfg(feature = "full")]
fn oidc_certificate_chain(value: Option<&serde_json::Value>) -> Option<Vec<Vec<u8>>> {
    let encoded = match value {
        None | Some(serde_json::Value::Null) => return Some(Vec::new()),
        Some(value) => serde_json::from_value::<Vec<Option<String>>>(value.clone()).ok()?,
    };
    let mut certificates = Vec::with_capacity(encoded.len());
    for certificate in encoded {
        let certificate = certificate.unwrap_or_default().replace(['\r', '\n'], "");
        let engine = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::PAD.with_decode_allow_trailing_bits(true),
        );
        let certificate = engine.decode(certificate).ok()?;
        let (remaining, _) = x509_parser::parse_x509_certificate(&certificate).ok()?;
        if !remaining.is_empty() {
            return None;
        }
        certificates.push(certificate);
    }
    Some(certificates)
}

#[cfg(feature = "full")]
fn validate_oidc_jws_header(
    header: &serde_json::Map<String, serde_json::Value>,
    require_public_jwk: bool,
) -> Option<()> {
    for name in ["alg", "kid", "nonce"] {
        oidc_header_string(header, name)?;
    }
    oidc_certificate_chain(header.get("x5c"))?;
    if let Some(jwk) = header.get("jwk").filter(|jwk| !jwk.is_null()) {
        let key = self::jwk::parse(jwk).ok()?;
        if require_public_jwk
            && (key.private_key
                || key.kty == "oct"
                || (key.kty == "RSA"
                    && key
                        .e
                        .as_deref()
                        .and_then(decode_oidc_base64)
                        .is_none_or(|value| oidc_rsa_exponent(&value) == 0)))
        {
            return None;
        }
    }
    Some(())
}

#[cfg(feature = "full")]
fn oidc_integer_bytes(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

#[cfg(feature = "full")]
fn oidc_rsa_exponent(bytes: &[u8]) -> i64 {
    let bytes = &bytes[bytes.len().saturating_sub(8)..];
    let mut word = [0; 8];
    word[8 - bytes.len()..].copy_from_slice(bytes);
    i64::from_be_bytes(word)
}

#[cfg(feature = "full")]
#[derive(Debug, Deserialize)]
struct OidcIdTokenClaims {
    #[serde(flatten)]
    claims: OidcClaims,
    #[serde(default, deserialize_with = "deserialize_go_string")]
    nonce: String,
    #[serde(default)]
    exp: serde_json::Value,
    #[serde(default)]
    aud: serde_json::Value,
    nbf: Option<serde_json::Value>,
    // Missing iat is Go's zero time; explicit null invokes jsonTime's decoder
    // and fails. Option<Value> alone would incorrectly collapse both cases.
    #[serde(default, deserialize_with = "deserialize_present_json_value")]
    iat: Option<serde_json::Value>,
    #[serde(
        default,
        rename = "at_hash",
        deserialize_with = "deserialize_go_string"
    )]
    _at_hash: String,
    #[serde(
        default,
        rename = "_claim_names",
        deserialize_with = "deserialize_claim_names"
    )]
    claim_names: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "_claim_sources",
        deserialize_with = "deserialize_claim_sources"
    )]
    claim_sources: BTreeMap<String, Option<OidcClaimSource>>,
}

#[cfg(feature = "full")]
#[derive(Debug, Default, Deserialize)]
struct OidcClaimSource {
    #[serde(
        default,
        rename = "endpoint",
        deserialize_with = "deserialize_go_string"
    )]
    _endpoint: String,
    #[serde(
        default,
        rename = "access_token",
        deserialize_with = "deserialize_go_string"
    )]
    _access_token: String,
}

#[cfg(feature = "full")]
fn deserialize_present_json_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

#[cfg(feature = "full")]
fn deserialize_claim_names<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        Option::<BTreeMap<String, Option<String>>>::deserialize(deserializer)?
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| (name, value.unwrap_or_default()))
            .collect(),
    )
}

#[cfg(feature = "full")]
fn deserialize_claim_sources<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Option<OidcClaimSource>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        Option::<BTreeMap<String, Option<OidcClaimSource>>>::deserialize(deserializer)?
            .unwrap_or_default(),
    )
}

#[cfg(feature = "full")]
#[derive(Debug)]
struct VerifiedOidcIdToken {
    payload: Vec<u8>,
    nonce: String,
    #[allow(dead_code)]
    expiry: DateTime<Utc>,
}

#[cfg(feature = "full")]
async fn verify_id_token(
    runtime: &OidcAuthRuntime,
    raw_id_token: &str,
) -> Result<VerifiedOidcIdToken, OidcRuntimeError> {
    let payload = verify_oidc_signed_payload(
        runtime,
        raw_id_token,
        Some(runtime.signing_algorithms.as_slice()),
    )
    .await?;
    verify_id_token_claims(runtime, &payload)
}

#[cfg(feature = "full")]
async fn verify_oidc_signed_payload(
    runtime: &OidcAuthRuntime,
    raw_jws: &str,
    algorithms: Option<&[String]>,
) -> Result<Vec<u8>, OidcRuntimeError> {
    let invalid = || OidcRuntimeError::IdTokenVerificationFailed;
    let raw_jws = raw_jws.to_owned();
    let mut signed = oidc_crypto_work(move || parse_oidc_signed_payload(&raw_jws))
        .await?
        .ok_or_else(invalid)?;
    let payload = std::mem::take(&mut signed.payload);
    let signed = Arc::new(signed);
    let header = &signed.header;
    let algorithm_allowed = algorithms.map_or_else(
        || OIDC_SIGNING_ALGORITHMS.contains(&header.alg.as_str()),
        |algorithms| algorithms.contains(&header.alg),
    );
    if !algorithm_allowed {
        return Err(invalid());
    }

    // Match go-oidc: try every matching key, retain the successful key set,
    // and refresh on a miss. Serialize/coalesce refreshes so concurrent
    // logins do not each fetch the provider's signing keys.
    let generation = runtime.jwks.generation.load(Ordering::Acquire);
    let keys = runtime.jwks.keys.read().clone();
    let cached = oidc_verify_with_keys(keys, signed.clone()).await?;
    if !cached {
        let _refresh = runtime.jwks.refresh.lock().await;
        let changed = generation != runtime.jwks.generation.load(Ordering::Acquire);
        let keys = runtime.jwks.keys.read().clone();
        let matched = oidc_verify_with_keys(keys, signed.clone()).await?;
        if !matched {
            if changed {
                return Err(invalid());
            }
            let fetched = fetch_oidc_jwks(runtime).await;
            // Failed refreshes must also wake queued callers with the same
            // result instead of serially retrying a stalled provider.
            runtime.jwks.generation.fetch_add(1, Ordering::Release);
            let jwks = fetched?;
            let keys = Arc::new(jwks.keys);
            let matched = oidc_verify_with_keys(keys.clone(), signed.clone()).await?;
            *runtime.jwks.keys.write() = keys;
            if !matched {
                return Err(invalid());
            }
        }
    }

    // Return claim bytes only after signature and algorithm verification.
    Ok(payload)
}

#[cfg(feature = "full")]
async fn oidc_verify_with_keys(
    keys: Arc<Vec<OidcJwk>>,
    signed: Arc<OidcSignedPayload>,
) -> Result<bool, OidcRuntimeError> {
    oidc_crypto_work(move || {
        oidc_signature_matches(&keys, &signed.header, &signed.input, &signed.signature)
    })
    .await
}

#[cfg(feature = "full")]
fn verify_id_token_claims(
    runtime: &OidcAuthRuntime,
    payload: &[u8],
) -> Result<VerifiedOidcIdToken, OidcRuntimeError> {
    // go-oidc has no expiry grace period, but permits five minutes for nbf.
    let invalid = || OidcRuntimeError::IdTokenVerificationFailed;
    let token = json::id_token_claims(payload).ok_or_else(invalid)?;
    let cfg = &runtime.config;
    let valid_issuer = token.claims.iss == cfg.issuer
        || (cfg.issuer == "https://accounts.google.com"
            && token.claims.iss == "accounts.google.com");
    let valid_audience = token.aud.as_str() == Some(cfg.client_id.as_str())
        || token.aud.as_array().is_some_and(|audiences| {
            audiences.iter().all(|aud| aud.is_string() || aud.is_null())
                && audiences
                    .iter()
                    .any(|aud| aud.as_str() == Some(cfg.client_id.as_str()))
        });
    let expiry = oidc_numeric_date(&token.exp).ok_or_else(invalid)?;
    let now = Utc::now();
    if !valid_issuer || cfg.client_id.is_empty() || !valid_audience || expiry < now {
        return Err(invalid());
    }
    if let Some(nbf) = &token.nbf
        && oidc_numeric_date(nbf).ok_or_else(invalid)? > now + Duration::minutes(5)
    {
        return Err(invalid());
    }
    if token
        .iat
        .as_ref()
        .is_some_and(|iat| !oidc_valid_json_time(iat))
        || token
            .claim_names
            .values()
            .any(|source| source.is_empty() || !token.claim_sources.contains_key(source))
    {
        return Err(invalid());
    }
    if token.nonce.is_empty() {
        return Err(OidcRuntimeError::NonceMissingInToken);
    }
    Ok(VerifiedOidcIdToken {
        payload: payload.to_vec(),
        nonce: token.nonce,
        expiry,
    })
}

#[cfg(feature = "full")]
async fn fetch_oidc_jwks(runtime: &OidcAuthRuntime) -> Result<OidcJwks, OidcRuntimeError> {
    let invalid = || OidcRuntimeError::IdTokenVerificationFailed;
    let response = runtime
        .provider_client
        .get(&runtime.config.jwks_uri)
        .timeout(OIDC_PROVIDER_TIMEOUT)
        .send()
        .await
        .map_err(|_| invalid())?;
    if response.status() != StatusCode::OK {
        return Err(invalid());
    }
    let body = oidc_response_body(response).await.map_err(|_| invalid())?;
    oidc_crypto_work(move || jwk::decode(&body))
        .await?
        .map_err(|_| invalid())
}

#[cfg(feature = "full")]
fn oidc_json_number(text: &str) -> Option<serde_json::Number> {
    let bytes = text.as_bytes();
    // Number's serde visitor recognizes an internal object transport in
    // arbitrary-precision mode. json.Number accepts only numeric grammar.
    if !matches!(bytes.first(), Some(b'-' | b'0'..=b'9'))
        || headscale_api_acl::go_json::trim(bytes) != bytes
    {
        return None;
    }
    headscale_api_acl::go_json::check_valid(bytes).ok()?;
    text.parse().ok()
}

#[cfg(feature = "full")]
fn oidc_valid_json_time(value: &serde_json::Value) -> bool {
    // IssuedAt is parsed but never date-compared by go-oidc. jsonTime accepts
    // Int64 or finite Float64 even when Chrono cannot represent the timestamp.
    let valid = |number: &serde_json::Number| {
        number.as_i64().is_some() || number.as_f64().is_some_and(f64::is_finite)
    };
    match value {
        serde_json::Value::Number(number) => valid(number),
        serde_json::Value::String(text) => oidc_json_number(text).as_ref().is_some_and(valid),
        _ => false,
    }
}

#[cfg(feature = "full")]
fn oidc_numeric_date(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    // Go's float64(math.MinInt64) and float64(math.MaxInt64): -2^63 is exact
    // and MaxInt64 rounds up to 2^63, so the upper bound is exclusive.
    const I64_MIN_AS_F64: f64 = -9_223_372_036_854_775_808.0;
    const I64_MAX_AS_F64: f64 = 9_223_372_036_854_775_808.0;
    // jsonTime attempts Int64 before Float64, for both JSON and quoted numbers.
    let quoted;
    let number = match value {
        serde_json::Value::Number(number) => number,
        serde_json::Value::String(text) => {
            quoted = oidc_json_number(text)?;
            &quoted
        }
        _ => return None,
    };
    let seconds = if let Some(integer) = number.as_i64() {
        integer
    } else {
        let number = number.as_f64()?;
        if !number.is_finite() || !(I64_MIN_AS_F64..I64_MAX_AS_F64).contains(&number) {
            return None;
        }
        number.trunc() as i64
    };
    DateTime::from_timestamp(seconds, 0)
}

#[cfg(feature = "full")]
fn oidc_signature_matches(
    keys: &[OidcJwk],
    header: &OidcJwsHeader,
    input: &[u8],
    signature: &str,
) -> bool {
    keys.iter()
        .filter(|key| !key.private_key)
        .filter(|key| header.kid.is_empty() || key.kid.as_deref() == Some(header.kid.as_str()))
        .any(|key| oidc_verify_signature(key, &header.alg, input, signature))
}

#[cfg(feature = "full")]
fn oidc_verify_signature(key: &OidcJwk, alg: &str, input: &[u8], signature: &str) -> bool {
    use jsonwebtoken::{Algorithm, DecodingKey};

    if matches!(
        alg,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
    ) {
        if key.kty != "RSA" {
            return false;
        }
        let Some((n, e)) = key
            .n
            .as_deref()
            .and_then(decode_oidc_base64)
            .zip(key.e.as_deref().and_then(decode_oidc_base64))
        else {
            return false;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        return self::rsa::verify(alg, &n, &e, input, &signature);
    }
    if alg == "ES512" {
        if key.kty != "EC" || key.crv != "P-521" {
            return false;
        }
        let Some(point) = oidc_ec_public_key(key, 66) else {
            return false;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        return aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P521_SHA512_FIXED,
            point,
        )
        .verify(input, &signature)
        .is_ok();
    }
    let Ok(algorithm) = alg.parse::<Algorithm>() else {
        return false;
    };
    let key = match algorithm {
        Algorithm::ES256 if key.kty == "EC" && key.crv == "P-256" => {
            oidc_ec_public_key(key, 32).map(|point| DecodingKey::from_ec_der(&point))
        }
        Algorithm::ES384 if key.kty == "EC" && key.crv == "P-384" => {
            oidc_ec_public_key(key, 48).map(|point| DecodingKey::from_ec_der(&point))
        }
        Algorithm::EdDSA if key.kty == "OKP" && key.crv == "Ed25519" => decode_oidc_base64(&key.x)
            .and_then(|public| {
                DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(public)).ok()
            }),
        _ => None,
    };
    key.is_some_and(|key| {
        jsonwebtoken::crypto::verify(signature, input, &key, algorithm).unwrap_or(false)
    })
}

#[cfg(feature = "full")]
fn oidc_ec_public_key(key: &OidcJwk, size: usize) -> Option<Vec<u8>> {
    let x = decode_oidc_base64(&key.x)?;
    let y = decode_oidc_base64(&key.y)?;
    if x.len() != size || y.len() != size {
        return None;
    }
    let mut point = vec![0; 1 + 2 * size];
    point[0] = 4;
    point[1..=size].copy_from_slice(&x);
    point[1 + size..].copy_from_slice(&y);
    Some(point)
}

pub fn clean_identifier(identifier: &str) -> String {
    let identifier = headscale_api_acl::go_unicode::trim_space(identifier);
    if identifier.is_empty() {
        return String::new();
    }
    if let Ok(mut url) = crate::go_url::Url::parse(identifier)
        && !url.scheme().is_empty()
    {
        let mut path = Vec::new();
        for part in url
            .path()
            .split(|byte| *byte == b'/')
            .map(trim_identifier_segment)
            .filter(|part| !part.is_empty())
        {
            path.push(b'/');
            path.extend_from_slice(part);
        }
        // Go changes Path without clearing RawPath: String uses the old raw
        // spelling only if it still decodes to exactly the cleaned Path.
        url.set_decoded_path(path);
        return String::from_utf8(url.as_bytes()).expect("serialized identifier is UTF-8");
    }
    clean_slash_path(identifier)
}

fn trim_identifier_segment(mut bytes: &[u8]) -> &[u8] {
    // Go TrimSpace preserves invalid UTF-8 bytes in URL.Path; percent decoding
    // must not create replacement runes or a different account identity.
    const SPACE: &[&[u8]] = &[
        b"\t",
        b"\n",
        b"\x0b",
        b"\x0c",
        b"\r",
        b" ",
        "\u{85}".as_bytes(),
        "\u{a0}".as_bytes(),
        "\u{1680}".as_bytes(),
        "\u{2000}".as_bytes(),
        "\u{2001}".as_bytes(),
        "\u{2002}".as_bytes(),
        "\u{2003}".as_bytes(),
        "\u{2004}".as_bytes(),
        "\u{2005}".as_bytes(),
        "\u{2006}".as_bytes(),
        "\u{2007}".as_bytes(),
        "\u{2008}".as_bytes(),
        "\u{2009}".as_bytes(),
        "\u{200a}".as_bytes(),
        "\u{2028}".as_bytes(),
        "\u{2029}".as_bytes(),
        "\u{202f}".as_bytes(),
        "\u{205f}".as_bytes(),
        "\u{3000}".as_bytes(),
    ];
    while let Some(prefix) = SPACE.iter().find(|space| bytes.starts_with(space)) {
        bytes = &bytes[prefix.len()..];
    }
    while let Some(suffix) = SPACE.iter().find(|space| bytes.ends_with(space)) {
        bytes = &bytes[..bytes.len() - suffix.len()];
    }
    bytes
}

fn normalize_issuer(issuer: &str) -> Result<String, OidcDiscoveryError> {
    if issuer.is_empty() {
        return Err(OidcDiscoveryError::EmptyIssuer);
    }
    Ok(issuer.strip_suffix('/').unwrap_or(issuer).to_string())
}

fn deserialize_go_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_go_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<Option<String>>>::deserialize(deserializer)?
        .unwrap_or_default()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect())
}

#[cfg(feature = "full")]
fn oidc_redirect_url(server_url: &str) -> String {
    format!(
        "{}/oidc/callback",
        server_url.strip_suffix('/').unwrap_or(server_url)
    )
}

#[cfg(feature = "full")]
fn oidc_pkce_method_from_str(method: &str) -> Result<OidcPkceMethod, OidcRuntimeBuildError> {
    match method {
        "plain" => Ok(OidcPkceMethod::Plain),
        "S256" => Ok(OidcPkceMethod::S256),
        _ => Err(OidcRuntimeBuildError::InvalidPkceMethod {
            method: method.to_string(),
        }),
    }
}

fn build_auth_url(
    cfg: &OidcAuthConfig,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    pkce_method: Option<OidcPkceMethod>,
) -> String {
    let mut params = BTreeMap::from([
        ("client_id".to_string(), cfg.client_id.clone()),
        ("response_type".to_string(), "code".to_string()),
    ]);
    if !cfg.redirect_url.is_empty() {
        params.insert("redirect_uri".to_string(), cfg.redirect_url.clone());
    }
    if !cfg.scopes.is_empty() {
        params.insert("scope".to_string(), scope_value(&cfg.scopes));
    }
    if !state.is_empty() {
        params.insert("state".to_string(), state.to_string());
    }

    if let (Some(challenge), Some(method)) = (code_challenge, pkce_method) {
        params.insert("access_type".to_string(), "offline".to_string());
        params.insert(
            "code_challenge_method".to_string(),
            method.as_str().to_string(),
        );
        params.insert("code_challenge".to_string(), challenge.to_string());
    }

    for (key, value) in &cfg.extra_params {
        params.insert(key.clone(), value.clone());
    }
    params.insert("nonce".to_string(), nonce.to_string());

    let query = encode_form_values(&params);

    if cfg.authorization_endpoint.contains('?') {
        format!("{}&{}", cfg.authorization_endpoint, query)
    } else {
        format!("{}?{}", cfg.authorization_endpoint, query)
    }
}

fn scope_value(scopes: &[String]) -> String {
    scopes.join(" ")
}

fn csrf_cookie(base_name: &str, value: &str, secure: bool, path: &str) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path={path}; Max-Age={OIDC_COOKIE_MAX_AGE_SECS}; HttpOnly{secure}; SameSite=Lax",
        cookie_name(base_name, value),
        value
    )
}

fn callback_cookie_path(redirect_url: &str) -> String {
    sanitize_cookie_path(&decoded_url_path(redirect_url))
}

fn decoded_url_path(url: &str) -> String {
    // Go url.URL.Path is percent-decoded. Keep display/form URL paths
    // separate from the byte sanitization performed by Cookie.String.
    let authority = url.find("://").map_or(0, |index| index + 3);
    let start = url[authority..].find('/').map(|index| authority + index);
    let Some(start) = start else {
        return "/oidc/callback".to_owned();
    };
    let path = url[start..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .as_bytes();
    let mut decoded = Vec::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        let value = if path[index] == b'%' && index + 2 < path.len() {
            let digit = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
            if let (Some(high), Some(low)) = (digit(path[index + 1]), digit(path[index + 2])) {
                index += 2;
                high * 16 + low
            } else {
                path[index]
            }
        } else {
            path[index]
        };
        decoded.push(value);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn sanitize_cookie_path(path: &str) -> String {
    // Go drops non-ASCII/control/semicolon bytes from a cookie Path.
    let bytes: Vec<u8> = path
        .bytes()
        .filter(|&byte| (0x20..0x7f).contains(&byte) && byte != b';')
        .collect();
    String::from_utf8(bytes).expect("cookie path is ASCII")
}

#[cfg(feature = "full")]
fn clear_callback_cookies(headers: &mut HeaderMap, redirect_url: &str, state: &str, nonce: &str) {
    let path = callback_cookie_path(redirect_url);
    for (base, value) in [("state", state), ("nonce", nonce)] {
        append_cookie(
            headers,
            &format!("{}=; Path={path}; Max-Age=0", cookie_name(base, value)),
        );
    }
}

fn append_cookie(headers: &mut HeaderMap, cookie: &str) {
    if !cookie
        .split_once('=')
        .is_some_and(|(name, _)| valid_cookie_name(name))
    {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

fn cookie_name(base_name: &str, value: &str) -> String {
    // Go prefixes bytes, and a non-ASCII/broken UTF-8 prefix cannot be a
    // valid cookie name. The name validator below rejects either spelling.
    let prefix = &value.as_bytes()[..value.len().min(OIDC_COOKIE_NAME_PREFIX_LEN)];
    format!("{base_name}_{}", String::from_utf8_lossy(prefix))
}

fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_state_cookie_bytes(headers: &HeaderMap, state: &[u8]) -> Result<(), OidcRuntimeError> {
    if state.len() < OIDC_COOKIE_NAME_PREFIX_LEN {
        return Err(OidcRuntimeError::InvalidStateParameter);
    }
    let prefix = std::str::from_utf8(&state[..OIDC_COOKIE_NAME_PREFIX_LEN])
        .map_err(|_| OidcRuntimeError::StateCookieMissing)?;
    let name = format!("state_{prefix}");
    let actual = cookie_value(headers, &name).ok_or(OidcRuntimeError::StateCookieMissing)?;
    if actual.as_bytes() == state {
        Ok(())
    } else {
        Err(OidcRuntimeError::StateCookieMismatch)
    }
}

#[cfg(feature = "full")]
fn validate_nonce_cookie(headers: &HeaderMap, nonce: &str) -> Result<(), OidcRuntimeError> {
    if nonce.is_empty() {
        return Err(OidcRuntimeError::NonceMissingInToken);
    }

    let expected_name = cookie_name("nonce", nonce);
    let Some(actual) = cookie_value(headers, &expected_name) else {
        return Err(OidcRuntimeError::NonceCookieMissing);
    };
    if actual == nonce {
        Ok(())
    } else {
        Err(OidcRuntimeError::NonceCookieMismatch)
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    if !valid_cookie_name(name) {
        return None;
    }
    let lines = headers.get_all(header::COOKIE);
    // Go counts candidate parts before filtering names or malformed values.
    let count = lines.iter().try_fold(0usize, |count, line| {
        count.checked_add(line.as_bytes().split(|&byte| byte == b';').count())
    })?;
    if !cookie_count_within_limit(count) {
        return None;
    }
    fn trim(mut value: &[u8]) -> &[u8] {
        while matches!(value.first(), Some(b' ' | b'\t')) {
            value = &value[1..];
        }
        while matches!(value.last(), Some(b' ' | b'\t')) {
            value = &value[..value.len() - 1];
        }
        value
    }
    for line in &lines {
        // Invalid parts do not erase a valid cookie later in the same header.
        for part in line.as_bytes().split(|&byte| byte == b';') {
            let part = trim(part);
            let (key, value) = match part.iter().position(|&byte| byte == b'=') {
                Some(index) => (&part[..index], &part[index + 1..]),
                None => (part, &b""[..]),
            };
            if trim(key) != name.as_bytes() {
                continue;
            }
            let value =
                if value.len() > 1 && value.first() == Some(&b'"') && value.last() == Some(&b'"') {
                    &value[1..value.len() - 1]
                } else {
                    value
                };
            if value
                .iter()
                .all(|&byte| (0x20..0x7f).contains(&byte) && !matches!(byte, b'"' | b';' | b'\\'))
            {
                return Some(String::from_utf8(value.to_vec()).expect("cookie value is ASCII"));
            }
        }
    }
    None
}

fn cookie_count_within_limit(count: usize) -> bool {
    let default = count <= 3000;
    let Some(settings) = std::env::var_os("GODEBUG") else {
        return default;
    };
    // internal/godebug scans backwards: the last assigned value wins, even
    // when that value is empty/invalid. Names and arguments are untrimmed.
    let Some(value) = settings
        .as_encoded_bytes()
        .split(|&byte| byte == b',')
        .rev()
        .find_map(|entry| {
            let equals = entry.iter().position(|&byte| byte == b'=')?;
            (&entry[..equals] == b"httpcookiemaxnum").then_some(&entry[equals + 1..])
        })
    else {
        return default;
    };
    // Go's optional #pattern is a Go-stack bisect facility. No equivalent
    // Rust call stack is available; leave patterned settings at the default.
    if value.contains(&b'#') {
        return default;
    }
    let Ok(value) = std::str::from_utf8(value) else {
        return default;
    };
    let Ok(limit) = value.parse::<isize>() else {
        return default;
    };
    limit == 0 || (limit > 0 && count <= limit as usize)
}

fn status_for_runtime_error(err: &OidcRuntimeError) -> StatusCode {
    match err {
        OidcRuntimeError::InvalidRegistrationId
        | OidcRuntimeError::InvalidAuthId
        | OidcRuntimeError::MissingCodeOrState
        | OidcRuntimeError::InvalidStateParameter
        | OidcRuntimeError::AuthSessionNotRegistration
        | OidcRuntimeError::InvalidForm
        | OidcRuntimeError::MissingCsrfToken
        | OidcRuntimeError::StateCookieMissing
        | OidcRuntimeError::MissingIdToken
        | OidcRuntimeError::NonceMissingInToken
        | OidcRuntimeError::NonceCookieMissing => StatusCode::BAD_REQUEST,
        OidcRuntimeError::StateCookieMismatch
        | OidcRuntimeError::MissingCsrfCookie
        | OidcRuntimeError::CsrfTokenMismatch
        | OidcRuntimeError::CsrfTokenCacheMismatch
        | OidcRuntimeError::RegistrationNotOidcAuthorized
        | OidcRuntimeError::InvalidCode
        | OidcRuntimeError::IdTokenVerificationFailed
        | OidcRuntimeError::NonceCookieMismatch => StatusCode::FORBIDDEN,
        OidcRuntimeError::RegistrationNotFound => StatusCode::NOT_FOUND,
        OidcRuntimeError::RegistrationSessionExpired => StatusCode::GONE,
        OidcRuntimeError::Authorization(_) => StatusCode::UNAUTHORIZED,
    }
}

#[cfg(feature = "full")]
fn status_for_auth_error(err: &OidcAuthError) -> StatusCode {
    match err {
        OidcAuthError::SessionExpired | OidcAuthError::SourceNodeMissing => StatusCode::GONE,
        OidcAuthError::NotSshCheck => StatusCode::BAD_REQUEST,
        OidcAuthError::SourceNodeNoUserOwner | OidcAuthError::UserNotSourceOwner => {
            StatusCode::FORBIDDEN
        }
        OidcAuthError::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        OidcAuthError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn oidc_error_response(status: StatusCode, message: &str) -> Response {
    // Browser pages expose the status-derived actionable message; technical
    // details stay in the server log, as httpUserError does upstream.
    tracing::error!(status = status.as_u16(), error = %message, "OIDC browser error");
    error_html::response(status)
}

fn registration_link_spent_response() -> Response {
    tracing::error!(
        status = 410,
        error = "registration link already used or expired",
        "OIDC browser error"
    );
    error_html::response_with_message(
        StatusCode::GONE,
        "This link has already been used or has expired. If your device is connected you are done; otherwise start the login again.",
    )
}

#[cfg(feature = "full")]
fn oidc_registration_confirm_redirect(
    redirect_url: &str,
    pending: &OidcPendingRegistrationConfirmation,
    secure_cookie: bool,
) -> Response {
    let auth_id = format!("{}{}", AUTH_ID_PREFIX, pending.registration_id);
    let destination = register_confirm_url(redirect_url, &auth_id);
    let cookie = register_confirm_cookie(
        &register_confirm_path(redirect_url, &auth_id),
        &pending.csrf,
        secure_cookie,
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&destination).expect("validated OIDC redirect URL"),
    );
    append_cookie(response.headers_mut(), &cookie);
    response
}

#[cfg(feature = "full")]
fn register_confirm_cookie(path: &str, csrf: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    let path = sanitize_cookie_path(path);
    format!(
        "{REGISTER_CONFIRM_CSRF_COOKIE}={csrf}; Path={path}; Max-Age={}; HttpOnly{secure}; SameSite=Lax",
        DEFAULT_OIDC_AUTH_CACHE_EXPIRY.as_secs(),
    )
}

fn register_confirm_url(redirect_url: &str, auth_id: &str) -> String {
    let base = redirect_url
        .strip_suffix("/oidc/callback")
        .expect("validated OIDC callback URL");
    format!("{base}/register/confirm/{auth_id}")
}

fn register_confirm_path(redirect_url: &str, auth_id: &str) -> String {
    let url = register_confirm_url(redirect_url, auth_id);
    decoded_url_path(&url)
}

fn clear_register_confirm_cookie(headers: &mut HeaderMap, path: &str, secure: bool) {
    let secure = if secure { "; Secure" } else { "" };
    let path = sanitize_cookie_path(path);
    append_cookie(
        headers,
        &format!(
            "{REGISTER_CONFIRM_CSRF_COOKIE}=; Path={path}; Max-Age=0; HttpOnly{secure}; SameSite=Lax"
        ),
    );
}

fn oidc_registration_confirm_html(
    pending: &OidcPendingRegistrationConfirmation,
    action_url: &str,
) -> String {
    browser_html::register_confirm(
        &user_display_name(&pending.user),
        &pending.device.hostname,
        &pending.device.os,
        &pending.device.machine_key,
        action_url,
        REGISTER_CONFIRM_CSRF_COOKIE,
        &pending.csrf,
    )
}

fn oidc_registration_success_response(user: &OidcStoredUser, new_node: bool) -> Response {
    let (title, heading, verb) = if new_node {
        (
            "Headscale - Node Registered",
            "Node registered",
            "Registered",
        )
    } else {
        (
            "Headscale - Node Reauthenticated",
            "Node reauthenticated",
            "Reauthenticated",
        )
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        oidc_registration_success_html(title, heading, verb, &user_display_name(user)),
    )
        .into_response()
}

#[cfg(feature = "full")]
fn oidc_ssh_success_response(user: &OidcStoredUser) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        oidc_ssh_success_html(&user_display_name(user)),
    )
        .into_response()
}

fn oidc_registration_success_html(title: &str, heading: &str, verb: &str, user: &str) -> String {
    browser_html::auth_success(title, heading, verb, user, "You can now close this window.")
}

#[cfg(feature = "full")]
fn oidc_ssh_success_html(user: &str) -> String {
    browser_html::auth_success(
        "Headscale - SSH Session Authorized",
        "SSH session authorized",
        "Authorized",
        user,
        "You may return to your terminal.",
    )
}

#[cfg(feature = "full")]
fn stored_user_from_profile(profile: OidcUserProfile) -> OidcStoredUser {
    let name = if !profile.email.is_empty() {
        profile.email.clone()
    } else if !profile.name.is_empty() {
        profile.name.clone()
    } else {
        profile.provider_identifier.clone()
    };

    OidcStoredUser {
        id: 0,
        name,
        display_name: profile.display_name,
        email: profile.email,
        provider_identifier: profile.provider_identifier,
        provider: profile.provider,
        profile_pic_url: profile.profile_pic_url,
    }
}

fn user_display_name(user: &OidcStoredUser) -> String {
    if !user.display_name.is_empty() {
        user.display_name.clone()
    } else if !user.email.is_empty() {
        user.email.clone()
    } else if !user.name.is_empty() {
        user.name.clone()
    } else if !user.provider_identifier.is_empty() {
        user.provider_identifier.clone()
    } else {
        user.id.to_string()
    }
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
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
    form_encode_bytes(value.as_bytes())
}

fn form_encode_bytes(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn encode_form_values(values: &BTreeMap<String, String>) -> String {
    // url.Values.Encode sorts keys and uses Go QueryEscape rather than the
    // WHATWG form safe set. Native auth options use Set, one value per key.
    values
        .iter()
        .map(|(key, value)| format!("{}={}", form_encode(key), form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn clean_slash_path(path: &str) -> String {
    path.split('/')
        .map(headscale_api_acl::go_unicode::trim_space)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_valid_oidc_username(username: &str) -> bool {
    username::valid_username(username)
}

fn looks_like_email_address(email: &str) -> bool {
    mailbox::valid_address(email)
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

    match FlexibleBool::deserialize(deserializer)? {
        FlexibleBool::Bool(value) => Ok(value),
        FlexibleBool::String(value) => match value.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
            "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
            _ => Err(serde::de::Error::custom("cannot parse boolean")),
        },
    }
}

fn deserialize_flexible_string_vec_default<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_optional_flexible_string_vec(deserializer).map(Option::unwrap_or_default)
}

fn deserialize_optional_flexible_string_vec<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexibleStringVec {
        Vec(Vec<Option<String>>),
        String(String),
    }

    match Option::<FlexibleStringVec>::deserialize(deserializer)? {
        Some(FlexibleStringVec::Vec(value)) => Ok(Some(
            value.into_iter().map(Option::unwrap_or_default).collect(),
        )),
        Some(FlexibleStringVec::String(value)) => Ok(Some(vec![value])),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, header};
    use chrono::TimeZone;

    #[derive(Debug, Default)]
    #[cfg(feature = "full")]
    struct MockOidcUserStore {
        profiles: RwLock<Vec<OidcUserProfile>>,
        fail: bool,
    }

    #[cfg(feature = "full")]
    type OidcRegistrationCall = (String, OidcStoredUser, Option<DateTime<Utc>>);
    #[cfg(feature = "full")]
    type OidcAuthCall = (String, OidcStoredUser);

    #[derive(Debug, Default)]
    #[cfg(feature = "full")]
    struct MockOidcRegistrationHandler {
        calls: RwLock<Vec<OidcRegistrationCall>>,
        auth_calls: RwLock<Vec<OidcAuthCall>>,
        confirmations: RwLock<BTreeMap<String, OidcPendingRegistrationConfirmation>>,
        fail_expired: bool,
        auth_kind: Option<OidcAuthRequestKind>,
    }

    #[async_trait::async_trait]
    #[cfg(feature = "full")]
    impl OidcUserStore for MockOidcUserStore {
        async fn create_or_update_oidc_user(
            &self,
            profile: OidcUserProfile,
        ) -> Result<OidcStoredUser, String> {
            if self.fail {
                return Err("store failed".to_string());
            }
            self.profiles.write().push(profile.clone());
            Ok(OidcStoredUser {
                id: 42,
                name: profile.name,
                display_name: profile.display_name,
                email: profile.email,
                provider_identifier: profile.provider_identifier,
                provider: profile.provider,
                profile_pic_url: profile.profile_pic_url,
            })
        }
    }

    #[async_trait::async_trait]
    #[cfg(feature = "full")]
    impl OidcRegistrationHandler for MockOidcRegistrationHandler {
        async fn complete_oidc_registration(
            &self,
            registration_id: &str,
            user: &OidcStoredUser,
            node_expiry: Option<DateTime<Utc>>,
        ) -> Result<OidcRegistrationResult, OidcRegistrationError> {
            if self.fail_expired {
                return Err(OidcRegistrationError::SessionExpired);
            }
            self.calls
                .write()
                .push((registration_id.to_string(), user.clone(), node_expiry));
            Ok(OidcRegistrationResult { new_node: true })
        }

        async fn complete_oidc_auth_request(
            &self,
            auth_id: &str,
            user: &OidcStoredUser,
        ) -> Result<(), OidcAuthError> {
            if self.fail_expired {
                return Err(OidcAuthError::SessionExpired);
            }
            self.auth_calls
                .write()
                .push((auth_id.to_string(), user.clone()));
            Ok(())
        }

        fn oidc_registration_exists(&self, registration_id: &str) -> bool {
            matches!(
                self.oidc_auth_request_kind(registration_id),
                Some(OidcAuthRequestKind::Registration)
            )
        }

        fn oidc_auth_request_kind(&self, _auth_id: &str) -> Option<OidcAuthRequestKind> {
            if self.fail_expired {
                None
            } else {
                Some(self.auth_kind.unwrap_or(OidcAuthRequestKind::Registration))
            }
        }

        fn oidc_registration_confirmation_info(
            &self,
            _registration_id: &str,
        ) -> Option<OidcRegistrationConfirmInfo> {
            Some(OidcRegistrationConfirmInfo {
                hostname: "oidc-client".into(),
                os: "linux".into(),
                machine_key: "[abcdef]".into(),
            })
        }

        fn store_oidc_registration_confirmation(
            &self,
            pending: OidcPendingRegistrationConfirmation,
        ) -> bool {
            self.confirmations
                .write()
                .insert(pending.registration_id.clone(), pending);
            true
        }

        fn oidc_pending_registration_confirmation(
            &self,
            registration_id: &str,
        ) -> Option<OidcPendingRegistrationConfirmation> {
            self.confirmations.read().get(registration_id).cloned()
        }

        fn remove_oidc_registration_confirmation(
            &self,
            registration_id: &str,
        ) -> Option<OidcPendingRegistrationConfirmation> {
            self.confirmations.write().remove(registration_id)
        }
    }

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
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/oauth2/auth".into(),
            token_endpoint: "https://issuer.example/oauth2/token".into(),
            userinfo_endpoint: Some("https://issuer.example/oauth2/userinfo".into()),
            jwks_uri: "https://issuer.example/oauth2/jwks".into(),
            client_id: "headscale-rs".into(),
            client_secret: "secret".into(),
            redirect_url: "https://headscale.example/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            extra_params: BTreeMap::from([("domain_hint".into(), "example.com".into())]),
            pkce,
            policy: OidcPolicyConfig::default(),
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

    fn cache_registration_info(registration_id: &str) -> OidcRegistrationInfo {
        OidcRegistrationInfo {
            registration_id: registration_id.to_string(),
            verifier: None,
            registration: true,
        }
    }

    fn cache_pending_confirmation(
        registration_id: &str,
        csrf: &str,
    ) -> OidcPendingRegistrationConfirmation {
        OidcPendingRegistrationConfirmation {
            registration_id: registration_id.to_string(),
            user: OidcStoredUser {
                id: 1,
                name: "alice@example.com".into(),
                display_name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                provider_identifier: "https://issuer.example/subject".into(),
                provider: REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
            node_expiry: None,
            csrf: csrf.to_string(),
            device: OidcRegistrationConfirmInfo::default(),
        }
    }

    fn provider_metadata() -> OidcProviderMetadata {
        OidcProviderMetadata {
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/oauth2/auth".into(),
            token_endpoint: "https://issuer.example/oauth2/token".into(),
            userinfo_endpoint: Some("https://issuer.example/oauth2/userinfo".into()),
            jwks_uri: "https://issuer.example/oauth2/jwks".into(),
            id_token_signing_alg_values_supported: vec!["RS256".into()],
        }
    }

    #[test]
    fn oidc_discovery_url_matches_issuer_path_rules() {
        assert_eq!(
            oidc_discovery_url("https://issuer.example/").unwrap(),
            "https://issuer.example/.well-known/openid-configuration"
        );
        assert_eq!(
            oidc_discovery_url("https://issuer.example/realms/headscale/").unwrap(),
            "https://issuer.example/realms/headscale/.well-known/openid-configuration"
        );
        assert_eq!(oidc_discovery_url(""), Err(OidcDiscoveryError::EmptyIssuer));
    }

    #[test]
    fn oidc_metadata_validates_issuer_and_defers_missing_endpoints() {
        let metadata = provider_metadata();
        assert_eq!(
            metadata.validate_for_issuer("https://issuer.example"),
            Ok(())
        );

        let mut missing_auth_endpoint = metadata.clone();
        missing_auth_endpoint.authorization_endpoint.clear();
        assert_eq!(
            missing_auth_endpoint.validate_for_issuer("https://issuer.example"),
            Ok(())
        );

        let mut mismatch = metadata;
        mismatch.issuer = "https://other.example".into();
        assert_eq!(
            mismatch.validate_for_issuer("https://issuer.example"),
            Err(OidcDiscoveryError::IssuerMismatch {
                expected: "https://issuer.example".into(),
                actual: "https://other.example".into(),
            })
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn oidc_core_config_builds_runtime_config_from_discovery() {
        let oidc = headscale_core::config::OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "client-id".into(),
            client_secret: "client-secret".into(),
            scope: vec!["openid".into(), "email".into()],
            extra_params: BTreeMap::from([("domain_hint".into(), "example.com".into())]),
            pkce: headscale_core::config::PkceConfig {
                enabled: true,
                method: "plain".into(),
            },
            ..headscale_core::config::OidcConfig::default()
        };

        let cfg =
            auth_config_from_core_oidc(&oidc, "https://headscale.example/", provider_metadata())
                .unwrap();

        assert_eq!(cfg.issuer, "https://issuer.example");
        assert_eq!(
            cfg.authorization_endpoint,
            "https://issuer.example/oauth2/auth"
        );
        assert_eq!(cfg.token_endpoint, "https://issuer.example/oauth2/token");
        assert_eq!(
            cfg.userinfo_endpoint.as_deref(),
            Some("https://issuer.example/oauth2/userinfo")
        );
        assert_eq!(cfg.jwks_uri, "https://issuer.example/oauth2/jwks");
        assert_eq!(cfg.client_id, "client-id");
        assert_eq!(cfg.client_secret, "client-secret");
        assert_eq!(cfg.redirect_url, "https://headscale.example/oidc/callback");
        assert_eq!(cfg.scopes, vec!["openid", "email"]);
        assert_eq!(
            cfg.extra_params.get("domain_hint").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            cfg.pkce,
            OidcPkceConfig {
                enabled: true,
                method: OidcPkceMethod::Plain,
            }
        );
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_discovery_fetches_provider_metadata() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}/issuer");
        let route_issuer = issuer.clone();
        let app = axum::Router::new().route(
            "/issuer/.well-known/openid-configuration",
            axum::routing::get(move || {
                let issuer = route_issuer.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/oauth2/auth"),
                        "token_endpoint": format!("{issuer}/oauth2/token"),
                        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
                        "jwks_uri": format!("{issuer}/oauth2/jwks"),
                    }))
                }
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let metadata = discover_oidc_metadata(&issuer).await.unwrap();
        assert_eq!(metadata.issuer, issuer);
        assert_eq!(
            metadata.authorization_endpoint,
            format!("{}/oauth2/auth", metadata.issuer)
        );
        assert_eq!(
            metadata.token_endpoint,
            format!("{}/oauth2/token", metadata.issuer)
        );
        assert_eq!(
            metadata.jwks_uri,
            format!("{}/oauth2/jwks", metadata.issuer)
        );

        handle.abort();
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
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();

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
        assert!(cached.registration);
    }

    #[test]
    fn oidc_registration_cache_is_bounded_lru_like_upstream() {
        let cache = OidcRegistrationCache::with_max_entries(StdDuration::from_secs(60), 2);
        cache.insert("state-1".into(), cache_registration_info("one"));
        cache.insert("state-2".into(), cache_registration_info("two"));

        assert_eq!(cache.max_entries(), 2);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("state-1").unwrap().registration_id, "one");

        cache.insert("state-3".into(), cache_registration_info("three"));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("state-1").unwrap().registration_id, "one");
        assert!(cache.get("state-2").is_none());
        assert_eq!(cache.get("state-3").unwrap().registration_id, "three");
    }

    #[test]
    fn one_registration_cannot_flood_other_registrations_out_of_the_state_cache() {
        // Every redirect for a registration id inserts a fresh state, so one
        // pending registration, which any unauthenticated client can create,
        // could repeat the redirect until the LRU dropped everyone else's
        // in-flight sign-in.
        let cache = OidcRegistrationCache::new(StdDuration::from_secs(60));
        cache.insert("victim-state".into(), cache_registration_info("victim"));

        let flood = DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES * 4;
        for n in 0..flood {
            cache.insert(format!("flood-{n}"), cache_registration_info("attacker"));
        }

        assert_eq!(
            cache.get("victim-state").unwrap().registration_id,
            "victim",
            "the flooded registration must not push another registration's state out"
        );
        let attacker_states = (0..flood)
            .filter(|n| cache.get(&format!("flood-{n}")).is_some())
            .count();
        assert_eq!(attacker_states, OIDC_MAX_PENDING_STATES_PER_REGISTRATION);
        // The newest states survive: the user's latest redirect still works.
        assert!(cache.get(&format!("flood-{}", flood - 1)).is_some());
    }

    #[test]
    fn state_cap_is_per_registration_and_keeps_two_tab_sign_ins_working() {
        let cache = OidcRegistrationCache::new(StdDuration::from_secs(60));
        for n in 0..OIDC_MAX_PENDING_STATES_PER_REGISTRATION {
            cache.insert(format!("tab-{n}"), cache_registration_info("one"));
        }
        for n in 0..OIDC_MAX_PENDING_STATES_PER_REGISTRATION {
            assert!(
                cache.get(&format!("tab-{n}")).is_some(),
                "state {n} within the cap"
            );
        }
        cache.insert("other".into(), cache_registration_info("two"));
        assert_eq!(cache.len(), OIDC_MAX_PENDING_STATES_PER_REGISTRATION + 1);
        // One more state for the same registration drops only its oldest.
        cache.insert("tab-new".into(), cache_registration_info("one"));
        assert!(cache.get("tab-0").is_none());
        assert!(cache.get("tab-1").is_some());
        assert!(cache.get("other").is_some());
    }

    #[test]
    fn oidc_confirmation_cache_is_bounded_lru_like_upstream() {
        let cache =
            OidcRegistrationConfirmationCache::with_max_entries(StdDuration::from_secs(60), 2);
        cache.insert(cache_pending_confirmation("registration-1", "csrf-1"));
        cache.insert(cache_pending_confirmation("registration-2", "csrf-2"));

        assert_eq!(cache.get("registration-1").unwrap().csrf, "csrf-1");
        cache.insert(cache_pending_confirmation("registration-3", "csrf-3"));

        assert_eq!(cache.get("registration-1").unwrap().csrf, "csrf-1");
        assert!(cache.get("registration-2").is_none());
        assert_eq!(cache.get("registration-3").unwrap().csrf, "csrf-3");
    }

    #[test]
    fn oidc_auth_start_for_ssh_check_requires_prefixed_auth_id() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let auth_id = format!("hskey-authreq-{}", "a".repeat(24));
        let start = runtime.begin_auth(&auth_id).unwrap();

        let cached = runtime.registration(&start.state).unwrap();
        assert_eq!(cached.registration_id, "a".repeat(24));
        assert!(!cached.registration);
        assert_eq!(
            runtime.begin_auth(&"a".repeat(24)).unwrap_err(),
            OidcRuntimeError::InvalidAuthId
        );
    }

    #[test]
    fn oidc_registration_start_requires_prefixed_auth_id() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let auth_id = format!("hskey-authreq-{}", "r".repeat(24));
        let start = runtime.begin_registration(&auth_id).unwrap();

        let cached = runtime.registration(&start.state).unwrap();
        assert_eq!(cached.registration_id, "r".repeat(24));
        assert!(cached.registration);
        assert_eq!(
            runtime.begin_registration(&"r".repeat(24)).unwrap_err(),
            OidcRuntimeError::InvalidRegistrationId
        );
    }

    #[test]
    fn oidc_auth_start_uses_plain_pkce_when_configured() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig {
            enabled: true,
            method: OidcPkceMethod::Plain,
        }));
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
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
        let response =
            handle_register(runtime.clone(), format!("hskey-authreq-{}", "r".repeat(24))).await;

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
        assert!(cookies.iter().all(|cookie| cookie.contains("; Secure")));
        assert!(cookies.iter().all(|cookie| cookie.contains("SameSite=Lax")));
    }

    #[tokio::test]
    async fn oidc_state_cookies_follow_server_url_and_direct_tls() {
        let mut config = auth_config(OidcPkceConfig::default());
        config.redirect_url = "http://headscale.example/oidc/callback".into();
        let runtime = OidcAuthRuntime::new(config);
        let auth_id = format!("hskey-authreq-{}", "s".repeat(24));

        let plain =
            handle_register_with_request_security(runtime.clone(), auth_id.clone(), false).await;
        assert!(
            plain
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .all(|value| {
                    let cookie = value.to_str().unwrap();
                    !cookie.contains("; Secure") && cookie.contains("SameSite=Lax")
                })
        );

        let tls = handle_auth_with_request_security(runtime, auth_id, true).await;
        assert!(
            tls.headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .all(|value| value.to_str().unwrap().contains("; Secure"))
        );
    }

    #[tokio::test]
    async fn oidc_auth_handler_sets_state_nonce_cookies_and_redirects() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let response =
            handle_auth(runtime.clone(), format!("hskey-authreq-{}", "a".repeat(24))).await;

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let state = query_param(&location, "state").unwrap();
        let cached = runtime.registration(&state).unwrap();
        assert_eq!(cached.registration_id, "a".repeat(24));
        assert!(!cached.registration);

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

        let response = handle_callback(
            runtime.clone(),
            HeaderMap::new(),
            Query(OidcCallbackQuery {
                code: "code".into(),
                state: "abc".into(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
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

    fn cookie_headers(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        headers
    }

    /// Upstream OIDCCallbackHandler checks the state cookie before any token
    /// exchange: a short state is "invalid state parameter" (400), a missing
    /// state cookie is "state not found" (400) and a differing value is
    /// "state did not match" (403).
    #[test]
    fn state_cookie_validation_follows_upstream_errors() {
        let state = "abcdefghijklmnopqrstuvwxyz012345";
        let name = cookie_name("state", state);
        assert_eq!(name, "state_abcdef");

        assert_eq!(
            validate_state_cookie_bytes(&HeaderMap::new(), b"abcde"),
            Err(OidcRuntimeError::InvalidStateParameter)
        );
        assert_eq!(
            validate_state_cookie_bytes(&HeaderMap::new(), state.as_bytes()),
            Err(OidcRuntimeError::StateCookieMissing)
        );
        // A cookie for a different state prefix does not satisfy the lookup.
        assert_eq!(
            validate_state_cookie_bytes(&cookie_headers("state_zzzzzz=whatever"), state.as_bytes()),
            Err(OidcRuntimeError::StateCookieMissing)
        );
        assert_eq!(
            validate_state_cookie_bytes(
                &cookie_headers(&format!("{name}=wrong")),
                state.as_bytes()
            ),
            Err(OidcRuntimeError::StateCookieMismatch)
        );
        // Same prefix, longer state: the whole value must match.
        assert_eq!(
            validate_state_cookie_bytes(
                &cookie_headers(&format!("{name}={}", &state[..state.len() - 1])),
                state.as_bytes()
            ),
            Err(OidcRuntimeError::StateCookieMismatch)
        );
        assert_eq!(
            validate_state_cookie_bytes(
                &cookie_headers(&format!("other=1; {name}={state}")),
                state.as_bytes()
            ),
            Ok(())
        );
    }

    #[tokio::test]
    async fn oidc_callback_state_cookie_failures_render_upstream_error_pages() {
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()));
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        let callback = |headers: HeaderMap| {
            handle_callback(
                runtime.clone(),
                headers,
                Query(OidcCallbackQuery {
                    code: "code".into(),
                    state: start.state.clone(),
                }),
            )
        };
        let body = |response: Response| async {
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        };

        // No state cookie at all: upstream 400, status-derived page message.
        let response = callback(HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let page = body(response).await;
        assert!(page.contains("Bad Request"), "{page}");
        assert!(
            page.contains("The request could not be processed. Please try again."),
            "{page}"
        );

        // Mismatched state cookie: upstream 403 "not authorized" page.
        let wrong = format!("{}=wrong", cookie_name("state", &start.state));
        let response = callback(cookie_headers(&wrong)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let page = body(response).await;
        assert!(page.contains("Forbidden"), "{page}");
        assert!(
            page.contains("You are not authorized. Please contact your administrator."),
            "{page}"
        );

        // Neither failure may consume the pending registration.
        assert!(runtime.registration(&start.state).is_some());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_exchanges_code_verifies_id_token_and_nonce_before_completion() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) =
            oidc_callback_fixture(token.clone(), captured_form.clone()).await;

        let mut config = auth_config(OidcPkceConfig {
            enabled: true,
            method: OidcPkceMethod::S256,
        });
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        let runtime = OidcAuthRuntime::new(config);
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        let verifier = runtime
            .registration(&start.state)
            .unwrap()
            .verifier
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers.clone(),
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state.clone(),
            }),
        )
        .await;

        // Rust-only: a runtime without a registration handler cannot finish
        // the flow; the error still uses upstream's browser error page.
        assert_go_error_page(
            response,
            StatusCode::NOT_IMPLEMENTED,
            GO_SERVER_ERROR_MSG,
            "OIDC callback completion is not implemented",
        )
        .await;
        let replay = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;
        // The first callback consumed the state. With PKCE enabled upstream
        // getOauth2Token needs the cached verifier before any code exchange,
        // so the replay stops there: 404 "registration not found"
        // (oidc.go:486-490).
        assert_go_error_page(
            replay,
            StatusCode::NOT_FOUND,
            GO_BAD_REQUEST_MSG,
            "registration not found",
        )
        .await;
        let form = captured_form.read();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
        assert_eq!(
            form.get("redirect_uri").map(String::as_str),
            Some("https://headscale.example/oidc/callback")
        );
        assert_eq!(
            form.get("code_verifier").map(String::as_str),
            Some(verifier.as_str())
        );
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_rejects_missing_nonce_cookie_after_verified_id_token() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        let runtime = OidcAuthRuntime::new(config);
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", cookie_name("state", &start.state), start.state)
                .parse()
                .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream oidc.go: missing nonce cookie -> 400 "nonce not found".
        assert_go_error_page(
            response,
            StatusCode::BAD_REQUEST,
            GO_BAD_REQUEST_MSG,
            "nonce not found",
        )
        .await;
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_rejects_unverified_id_token() {
        let token = Arc::new(RwLock::new("not-a-jwt".to_string()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token, captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        let runtime = OidcAuthRuntime::new(config);
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", cookie_name("state", &start.state), start.state)
                .parse()
                .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream oidc.go extractIDToken: 403 "failed to verify id_token".
        assert_go_error_page(
            response,
            StatusCode::FORBIDDEN,
            GO_UNAUTHORIZED_MSG,
            "failed to verify id_token",
        )
        .await;
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_fetches_userinfo_and_authorizes_merged_claims() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, userinfo_auth) =
            oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = Some(format!("{base_url}/userinfo"));
        config.policy = OidcPolicyConfig {
            allowed_groups: vec!["userinfo-group".into()],
            allowed_domains: vec!["example.com".into()],
            allowed_users: vec!["userinfo@example.com".into()],
            ..OidcPolicyConfig::default()
        };
        let runtime = OidcAuthRuntime::new(config);
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(userinfo_auth.read().as_deref(), Some("Bearer access-token"));
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_upserts_authorized_merged_profile_when_store_is_configured() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = Some(format!("{base_url}/userinfo"));
        config.policy = OidcPolicyConfig {
            allowed_groups: vec!["userinfo-group".into()],
            allowed_domains: vec!["example.com".into()],
            allowed_users: vec!["userinfo@example.com".into()],
            ..OidcPolicyConfig::default()
        };
        let store = Arc::new(MockOidcUserStore::default());
        let runtime = OidcAuthRuntime::new(config).with_user_store(store.clone());
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let profiles = store.profiles.read();
        assert_eq!(profiles.len(), 1);
        assert_eq!(
            profiles[0],
            OidcUserProfile {
                name: "userinfo".into(),
                display_name: "User Info Name".into(),
                email: "userinfo@example.com".into(),
                provider_identifier: "https://issuer.example/subject".into(),
                provider: REGISTER_METHOD_OIDC.into(),
                profile_pic_url: "https://example.com/userinfo.png".into(),
            }
        );
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_maps_user_store_failure_to_upstream_error_response() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        let runtime = OidcAuthRuntime::new(config).with_user_store(Arc::new(MockOidcUserStore {
            fail: true,
            ..MockOidcUserStore::default()
        }));
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream oidc.go: 500 "could not create or update user".
        assert_go_error_page(
            response,
            StatusCode::INTERNAL_SERVER_ERROR,
            GO_SERVER_ERROR_MSG,
            "could not create or update user",
        )
        .await;
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_renders_registration_confirmation_before_completion() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        config.policy.use_expiry_from_token = true;
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(config).with_registration_handler(registrations.clone());
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state.clone(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://headscale.example/register/confirm/hskey-authreq-rrrrrrrrrrrrrrrrrrrrrrrr"
        );
        // Upstream order (confirmed against the Go handler): the state and
        // nonce callback cookies are deleted first, then the register-confirm
        // CSRF cookie is set, scoped to the confirmation URL path.
        let set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(set_cookies.len(), 3, "{set_cookies:?}");
        assert_eq!(
            set_cookies[0],
            format!(
                "{}=; Path=/oidc/callback; Max-Age=0",
                cookie_name("state", &start.state)
            )
        );
        assert_eq!(
            set_cookies[1],
            format!(
                "{}=; Path=/oidc/callback; Max-Age=0",
                cookie_name("nonce", &start.nonce)
            )
        );
        let confirm_cookie = &set_cookies[2];
        assert!(confirm_cookie.starts_with("headscale_register_confirm="));
        assert!(confirm_cookie.ends_with(
            "; Path=/register/confirm/hskey-authreq-rrrrrrrrrrrrrrrrrrrrrrrr; Max-Age=900; HttpOnly; Secure; SameSite=Lax"
        ));
        let cookie_header = set_cookie_header(&response);
        assert!(cookie_header.starts_with("headscale_register_confirm="));
        assert!(!cookie_header.contains(';'), "{cookie_header}");
        let auth_id = format!("hskey-authreq-{}", "r".repeat(24));
        let unauthorized = handle_register_confirm_get(&runtime, &auth_id, &HeaderMap::new());
        assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
        let page =
            handle_register_confirm_get(&runtime, &auth_id, &confirm_headers(&cookie_header));
        assert_eq!(page.status(), StatusCode::OK);
        let body = response_body(page).await;
        let reload =
            handle_register_confirm_get(&runtime, &auth_id, &confirm_headers(&cookie_header));
        assert_eq!(reload.status(), StatusCode::OK);
        assert_eq!(response_body(reload).await, body);
        assert!(body.contains("Headscale - Confirm node registration"));
        assert!(body.contains("Confirm node registration"));
        assert!(body.contains("Confirm registration"));
        assert!(body.contains("Alice Smith"));
        assert!(body.contains("oidc-client"));
        assert!(body.contains("[abcdef]"));
        assert!(registrations.calls.read().is_empty());
        assert!(
            runtime.pending_confirmation(&"r".repeat(24)).is_some(),
            "callback should stage pending confirmation on the auth request"
        );

        let csrf = csrf_from_confirm_body(&body);
        let confirm = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{}", "r".repeat(24)),
            confirm_headers(&cookie_header),
            Bytes::from(format!("{REGISTER_CONFIRM_CSRF_COOKIE}={csrf}")),
        )
        .await;

        assert_eq!(confirm.status(), StatusCode::OK);
        let success_body = response_body(confirm).await;
        assert!(success_body.contains("Headscale - Node Registered"));
        assert!(success_body.contains("Node registered"));
        assert!(success_body.contains("Registered as"));
        assert!(success_body.contains("Alice Smith"));
        assert!(success_body.contains("You can now close this window"));

        let calls = registrations.calls.read();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "r".repeat(24));
        assert_eq!(calls[0].1.email, "alice@example.com");
        assert_eq!(calls[0].1.name, "alice@example.com");
        assert_eq!(
            calls[0].2,
            Some(Utc.timestamp_opt(4_102_444_800, 0).unwrap())
        );
        drop(calls);
        assert!(
            runtime.pending_confirmation(&"r".repeat(24)).is_none(),
            "successful confirmation should consume the staged auth-request confirmation"
        );
        let spent =
            handle_register_confirm_get(&runtime, &auth_id, &confirm_headers(&cookie_header));
        assert_eq!(spent.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn confirmation_url_and_cookie_path_keep_reverse_proxy_prefix() {
        let redirect = "https://control.example/hs/oidc/callback";
        let auth_id = "hskey-authreq-rrrrrrrrrrrrrrrrrrrrrrrr";
        assert_eq!(
            register_confirm_url(redirect, auth_id),
            "https://control.example/hs/register/confirm/hskey-authreq-rrrrrrrrrrrrrrrrrrrrrrrr"
        );
        assert_eq!(
            register_confirm_path(redirect, auth_id),
            "/hs/register/confirm/hskey-authreq-rrrrrrrrrrrrrrrrrrrrrrrr"
        );
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_completes_ssh_auth_and_renders_ssh_success_page() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(config).with_registration_handler(registrations.clone());
        let start = runtime
            .begin_auth(&format!("hskey-authreq-{}", "s".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state.clone(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = response_body(response).await;
        assert!(body.contains("Headscale - SSH Session Authorized"));
        assert!(body.contains("SSH session authorized"));
        assert!(body.contains("Authorized as"));
        assert!(body.contains("You may return to your terminal"));

        let calls = registrations.auth_calls.read();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "s".repeat(24));
        assert_eq!(calls[0].1.email, "alice@example.com");
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_without_token_expiry_passes_no_provider_expiry() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        config.policy.expiry = Duration::zero();
        config.policy.use_expiry_from_token = false;
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(config).with_registration_handler(registrations.clone());
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime.clone(),
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie_header = set_cookie_header(&response);
        let page = handle_register_confirm_get(
            &runtime,
            &format!("hskey-authreq-{}", "r".repeat(24)),
            &confirm_headers(&cookie_header),
        );
        assert_eq!(page.status(), StatusCode::OK);
        let body = response_body(page).await;
        let csrf = csrf_from_confirm_body(&body);
        assert!(registrations.calls.read().is_empty());

        let confirm = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{}", "r".repeat(24)),
            confirm_headers(&cookie_header),
            Bytes::from(format!("{REGISTER_CONFIRM_CSRF_COOKIE}={csrf}")),
        )
        .await;
        assert_eq!(confirm.status(), StatusCode::OK);
        let calls = registrations.calls.read();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, None);
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_registration_success_copy_matches_upstream_registered_and_reauth() {
        let user = OidcStoredUser {
            id: 42,
            name: "alice@example.com".into(),
            display_name: "Alice Smith".into(),
            email: "alice@example.com".into(),
            provider_identifier: "https://issuer.example/subject".into(),
            provider: REGISTER_METHOD_OIDC.into(),
            profile_pic_url: String::new(),
        };

        let registered = response_body(oidc_registration_success_response(&user, true)).await;
        assert!(registered.contains("Headscale - Node Registered"));
        assert!(registered.contains("Node registered"));
        assert!(registered.contains("Registered as"));
        assert!(registered.contains("Alice Smith"));

        let reauthenticated = response_body(oidc_registration_success_response(&user, false)).await;
        assert!(reauthenticated.contains("Headscale - Node Reauthenticated"));
        assert!(reauthenticated.contains("Node reauthenticated"));
        assert!(reauthenticated.contains("Reauthenticated as"));
        assert!(reauthenticated.contains("Alice Smith"));
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_csrf_cookie_form_mismatch() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);
        runtime
            .confirmations
            .insert(test_pending_confirmation(&registration_id, "expected-csrf"));

        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=expected-csrf"),
            Bytes::from("headscale_register_confirm=wrong-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler: 403 "csrf token mismatch".
        assert_go_error_page(
            response,
            StatusCode::FORBIDDEN,
            GO_UNAUTHORIZED_MSG,
            "csrf token mismatch",
        )
        .await;
        assert!(runtime.pending_confirmation(&registration_id).is_some());
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_without_pending_confirmation() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);

        let response = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=fake-csrf"),
            Bytes::from("headscale_register_confirm=fake-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler: no pending confirmation -> 403
        // "registration not OIDC-authorized".
        assert_go_error_page(
            response,
            StatusCode::FORBIDDEN,
            GO_UNAUTHORIZED_MSG,
            "registration not OIDC-authorized",
        )
        .await;
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_maps_missing_registration_to_gone() {
        let registrations = Arc::new(MockOidcRegistrationHandler {
            fail_expired: true,
            ..MockOidcRegistrationHandler::default()
        });
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);

        let response = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=fake-csrf"),
            Bytes::from("headscale_register_confirm=fake-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler: auth session gone ->
        // errRegistrationLinkSpent, a 410 carrying its own UserMsg.
        assert_go_error_page(
            response,
            StatusCode::GONE,
            GO_LINK_SPENT_MSG,
            "registration link already used or expired",
        )
        .await;
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_non_registration_auth_session() {
        let registrations = Arc::new(MockOidcRegistrationHandler {
            auth_kind: Some(OidcAuthRequestKind::SshCheck),
            ..MockOidcRegistrationHandler::default()
        });
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);

        let response = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=fake-csrf"),
            Bytes::from("headscale_register_confirm=fake-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler never checks IsRegistration: an SSH
        // check request carries no PendingConfirmation, so it is refused with
        // 403 "registration not OIDC-authorized" (oidc.go:936-940; confirmed
        // by running the Go handler on an SSH-check auth ID).
        assert_go_error_page(
            response,
            StatusCode::FORBIDDEN,
            GO_UNAUTHORIZED_MSG,
            "registration not OIDC-authorized",
        )
        .await;
        assert!(registrations.calls.read().is_empty());
        assert!(registrations.auth_calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_cached_csrf_mismatch() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);
        runtime
            .confirmations
            .insert(test_pending_confirmation(&registration_id, "cached-csrf"));

        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=posted-csrf"),
            Bytes::from("headscale_register_confirm=posted-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler: 403 "csrf token does not match
        // cached registration".
        assert_go_error_page(
            response,
            StatusCode::FORBIDDEN,
            GO_UNAUTHORIZED_MSG,
            "csrf token does not match cached registration",
        )
        .await;
        assert!(runtime.pending_confirmation(&registration_id).is_some());
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_malformed_urlencoded_form_like_upstream() {
        // The third column is Go's url.ParseQuery error, which upstream logs
        // with "user msg: invalid form" (captured from the Go handler).
        for (name, body, go_error) in [
            (
                "short percent escape",
                "headscale_register_confirm=%",
                "invalid URL escape \"%\"",
            ),
            (
                "non-hex percent escape",
                "headscale_register_confirm=%zz",
                "invalid URL escape \"%zz\"",
            ),
            (
                "semicolon separator",
                "headscale_register_confirm=expected-csrf;other=value",
                "invalid semicolon separator in query",
            ),
        ] {
            assert_eq!(
                form::decode_confirmation_form(
                    &confirm_headers("headscale_register_confirm=expected-csrf"),
                    body.as_bytes(),
                    None,
                ),
                Err(go_error.to_owned()),
                "{name}"
            );
            let registrations = Arc::new(MockOidcRegistrationHandler::default());
            let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
                .with_registration_handler(registrations.clone());
            let registration_id = "r".repeat(24);
            runtime
                .confirmations
                .insert(test_pending_confirmation(&registration_id, "expected-csrf"));

            let response = handle_register_confirm(
                runtime.clone(),
                format!("hskey-authreq-{registration_id}"),
                confirm_headers("headscale_register_confirm=expected-csrf"),
                Bytes::from(body),
            )
            .await;

            assert_go_error_page(
                response,
                StatusCode::BAD_REQUEST,
                GO_BAD_REQUEST_MSG,
                go_error,
            )
            .await;
            assert!(
                runtime.pending_confirmation(&registration_id).is_some(),
                "{name}: rejected POST must not clear pending confirmation"
            );
            assert!(registrations.calls.read().is_empty(), "{name}");
        }
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_oversized_urlencoded_form_like_upstream() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);
        runtime
            .confirmations
            .insert(test_pending_confirmation(&registration_id, "expected-csrf"));

        let body = format!("headscale_register_confirm={}", "x".repeat(4096));
        // Upstream http.MaxBytesReader(4 KiB) error, logged as "invalid form".
        assert_eq!(
            form::decode_confirmation_form(
                &confirm_headers("headscale_register_confirm=expected-csrf"),
                body.as_bytes(),
                None,
            ),
            Err("http: request body too large".to_owned())
        );
        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=expected-csrf"),
            Bytes::from(body),
        )
        .await;

        assert_go_error_page(
            response,
            StatusCode::BAD_REQUEST,
            GO_BAD_REQUEST_MSG,
            "request body too large",
        )
        .await;
        assert!(runtime.pending_confirmation(&registration_id).is_some());
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_requires_urlencoded_form_content_type() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);
        runtime
            .confirmations
            .insert(test_pending_confirmation(&registration_id, "expected-csrf"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "headscale_register_confirm=expected-csrf".parse().unwrap(),
        );

        // Go ParseForm treats a missing Content-Type as octet-stream and
        // leaves PostForm empty, so the token is "missing", not malformed.
        assert_eq!(
            form::decode_confirmation_form(
                &headers,
                b"headscale_register_confirm=expected-csrf",
                None
            ),
            Ok(None)
        );
        let response = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{registration_id}"),
            headers,
            Bytes::from("headscale_register_confirm=expected-csrf"),
        )
        .await;

        // Upstream RegisterConfirmHandler: 400 "missing csrf token".
        assert_go_error_page(
            response,
            StatusCode::BAD_REQUEST,
            GO_BAD_REQUEST_MSG,
            "missing csrf token",
        )
        .await;
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_ignores_oversized_non_form_body_like_upstream() {
        let registrations = Arc::new(MockOidcRegistrationHandler::default());
        let runtime = OidcAuthRuntime::new(auth_config(OidcPkceConfig::default()))
            .with_registration_handler(registrations.clone());
        let registration_id = "r".repeat(24);
        runtime
            .confirmations
            .insert(test_pending_confirmation(&registration_id, "expected-csrf"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "headscale_register_confirm=expected-csrf".parse().unwrap(),
        );

        // A non-form body is never read by Go's ParseForm, so its size does
        // not trip MaxBytesReader.
        assert_eq!(
            form::decode_confirmation_form(
                &headers,
                "x".repeat(REGISTER_CONFIRM_BODY_LIMIT + 1).as_bytes(),
                None
            ),
            Ok(None)
        );
        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            headers,
            Bytes::from("x".repeat(REGISTER_CONFIRM_BODY_LIMIT + 1)),
        )
        .await;

        // Upstream RegisterConfirmHandler: 400 "missing csrf token".
        assert_go_error_page(
            response,
            StatusCode::BAD_REQUEST,
            GO_BAD_REQUEST_MSG,
            "missing csrf token",
        )
        .await;
        assert!(runtime.pending_confirmation(&registration_id).is_some());
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_maps_expired_registration_to_upstream_gone_response() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        let runtime = OidcAuthRuntime::new(config).with_registration_handler(Arc::new(
            MockOidcRegistrationHandler {
                fail_expired: true,
                ..MockOidcRegistrationHandler::default()
            },
        ));
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream beginRegistrationConfirmation: auth session gone -> 410
        // "login session expired, try again".
        assert_go_error_page(
            response,
            StatusCode::GONE,
            GO_GONE_MSG,
            "login session expired, try again",
        )
        .await;
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_rejects_registration_flow_for_non_registration_auth_session() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        let registrations = Arc::new(MockOidcRegistrationHandler {
            auth_kind: Some(OidcAuthRequestKind::SshCheck),
            ..MockOidcRegistrationHandler::default()
        });
        let runtime = OidcAuthRuntime::new(config).with_registration_handler(registrations.clone());
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream beginRegistrationConfirmation: !IsRegistration -> 400
        // "auth session is not for node registration".
        assert_go_error_page(
            response,
            StatusCode::BAD_REQUEST,
            GO_BAD_REQUEST_MSG,
            "auth session is not for node registration",
        )
        .await;
        assert!(registrations.calls.read().is_empty());
        assert!(registrations.auth_calls.read().is_empty());
        assert!(registrations.confirmations.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_callback_rejects_claims_after_token_validation() {
        let token = Arc::new(RwLock::new(String::new()));
        let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
        let (_handle, base_url, _) = oidc_callback_fixture(token.clone(), captured_form).await;

        let mut config = auth_config(OidcPkceConfig::default());
        config.token_endpoint = format!("{base_url}/token");
        config.jwks_uri = format!("{base_url}/jwks");
        config.userinfo_endpoint = None;
        config.policy = OidcPolicyConfig {
            allowed_groups: vec!["missing-group".into()],
            ..OidcPolicyConfig::default()
        };
        let runtime = OidcAuthRuntime::new(config);
        let start = runtime
            .begin_registration(&format!("hskey-authreq-{}", "r".repeat(24)))
            .unwrap();
        *token.write() = signed_id_token(&start.nonce);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; {}={}",
                cookie_name("state", &start.state),
                start.state,
                cookie_name("nonce", &start.nonce),
                start.nonce
            )
            .parse()
            .unwrap(),
        );

        let response = handle_callback(
            runtime,
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        // Upstream validateOIDCAllowedGroups: 401 "unauthorised group".
        assert_go_error_page(
            response,
            StatusCode::UNAUTHORIZED,
            GO_UNAUTHORIZED_MSG,
            "unauthorised group",
        )
        .await;
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
    fn oidc_userinfo_and_claims_accept_single_group_string() {
        let mut claims: OidcClaims =
            serde_json::from_str(r#"{"sub":"sub","email":"id@example.com","groups":"id-group"}"#)
                .unwrap();
        assert_eq!(claims.groups, vec!["id-group"]);

        let userinfo: OidcUserInfo = serde_json::from_str(
            r#"{"sub":"sub","email":"user@example.com","groups":"userinfo-group"}"#,
        )
        .unwrap();
        merge_userinfo_claims(&mut claims, Some(&userinfo));
        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.groups, vec!["userinfo-group"]);
    }

    #[test]
    fn oidc_expiry_uses_only_token_when_configured_like_upstream() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let token_expiry = Utc.timestamp_opt(1_700_003_600, 0).unwrap();
        let cfg = OidcPolicyConfig {
            expiry: Duration::days(180),
            ..OidcPolicyConfig::default()
        };
        assert_eq!(determine_node_expiry(&cfg, token_expiry, now), None);

        let cfg = OidcPolicyConfig {
            use_expiry_from_token: true,
            ..cfg
        };
        assert_eq!(
            determine_node_expiry(&cfg, token_expiry, now),
            Some(token_expiry)
        );
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
    fn user_profile_from_json_matches_upstream_from_claim_cases() {
        for (name, json, email_verified_required, expected) in [
            (
                "string-bool-false",
                r#"{
                    "sub": "test3",
                    "email": "test3@test.no",
                    "email_verified": "false"
                }"#,
                true,
                OidcUserProfile {
                    name: String::new(),
                    display_name: String::new(),
                    email: String::new(),
                    provider_identifier: "/test3".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
            ),
            (
                "allow-unverified-email",
                r#"{
                    "sub": "test4",
                    "email": "test4@test.no",
                    "email_verified": "false"
                }"#,
                false,
                OidcUserProfile {
                    name: String::new(),
                    display_name: String::new(),
                    email: "test4@test.no".into(),
                    provider_identifier: "/test4".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
            ),
            (
                "azure-double-slash-issuer",
                r#"{
                    "iss": "https://login.microsoftonline.com//v2.0",
                    "email": "user@domain.com",
                    "name": "XXXXXX XXXX",
                    "preferred_username": "user@domain.com",
                    "sub": "I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ"
                }"#,
                true,
                OidcUserProfile {
                    name: "user@domain.com".into(),
                    display_name: "XXXXXX XXXX".into(),
                    email: String::new(),
                    provider_identifier: "https://login.microsoftonline.com/v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
            ),
            (
                "casbin-profile-picture-and-groups",
                r#"{
                    "sub": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "iss": "https://oidc.example.com/",
                    "preferred_username": "user001",
                    "name": "User001",
                    "email": "user001@example.com",
                    "email_verified": true,
                    "picture": "https://cdn.casbin.org/img/casbin.svg",
                    "groups": "org1/department1"
                }"#,
                true,
                OidcUserProfile {
                    name: "user001".into(),
                    display_name: "User001".into(),
                    email: "user001@example.com".into(),
                    provider_identifier: "https://oidc.example.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: "https://cdn.casbin.org/img/casbin.svg".into(),
                },
            ),
        ] {
            let claims: OidcClaims = serde_json::from_str(json).unwrap();
            assert_eq!(
                claims.groups.len(),
                usize::from(name == "casbin-profile-picture-and-groups")
            );
            assert_eq!(
                user_profile_from_claims(&claims, email_verified_required),
                expected,
                "{name}"
            );
        }
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

    #[cfg(feature = "full")]
    async fn oidc_callback_fixture(
        token: Arc<RwLock<String>>,
        captured_form: Arc<RwLock<BTreeMap<String, String>>>,
    ) -> (
        tokio::task::JoinHandle<()>,
        String,
        Arc<RwLock<Option<String>>>,
    ) {
        use axum::Json;
        use axum::extract::Form;
        use axum::routing::{get, post};

        let token_route = token.clone();
        let captured_route = captured_form.clone();
        let captured_userinfo_auth = Arc::new(RwLock::new(None));
        let captured_userinfo_auth_route = captured_userinfo_auth.clone();
        let app = axum::Router::new()
            .route(
                "/token",
                post(
                    move |headers: HeaderMap, Form(form): Form<BTreeMap<String, String>>| {
                        let token = token_route.clone();
                        let captured = captured_route.clone();
                        async move {
                            assert!(
                                headers
                                    .get(header::AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok())
                                    .is_some_and(|value| value.starts_with("Basic "))
                            );
                            *captured.write() = form;
                            Json(serde_json::json!({
                                "access_token": "access-token",
                                "token_type": "Bearer",
                                "id_token": token.read().clone(),
                            }))
                        }
                    },
                ),
            )
            .route(
                "/userinfo",
                get(move |headers: HeaderMap| {
                    let captured_userinfo_auth = captured_userinfo_auth_route.clone();
                    async move {
                        *captured_userinfo_auth.write() = headers
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .map(ToOwned::to_owned);
                        Json(serde_json::json!({
                            "sub": "subject",
                            "name": "User Info Name",
                            "preferred_username": "userinfo",
                            "email": "userinfo@example.com",
                            "email_verified": true,
                            "groups": ["userinfo-group"],
                            "picture": "https://example.com/userinfo.png",
                        }))
                    }
                }),
            )
            .route(
                "/jwks",
                get(|| async {
                    Json(serde_json::json!({
                        "keys": [{
                            "kty": "RSA",
                            "kid": "test-key",
                            "use": "sig",
                            "alg": "RS256",
                            "n": TEST_RSA_MODULUS,
                            "e": "AQAB",
                        }]
                    }))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (handle, base_url, captured_userinfo_auth)
    }

    #[cfg(feature = "full")]
    async fn response_body(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// Cookie header a browser jar would send back: deletions (Max-Age=0,
    /// such as the callback's state/nonce clears) are dropped, not replayed.
    #[cfg(feature = "full")]
    fn set_cookie_header(response: &Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter(|value| !value.contains("; Max-Age=0"))
            .filter_map(|value| value.split_once(';').map(|(cookie, _attrs)| cookie))
            .collect::<Vec<_>>()
            .join("; ")
    }

    // headscale-go v0.29.5 httpUserError (handlers.go) answers every
    // browser-facing OIDC error with the branded AuthError page: heading
    // http.StatusText(code), message HTTPError.UserMsg or
    // userMessageForStatusCode(code). HTTPError.Msg (the technical cause) is
    // only logged. Texts below are copied from the Go source and were
    // confirmed by running the Go handlers.
    #[cfg(feature = "full")]
    const GO_BAD_REQUEST_MSG: &str = "The request could not be processed. Please try again.";
    #[cfg(feature = "full")]
    const GO_UNAUTHORIZED_MSG: &str = "You are not authorized. Please contact your administrator.";
    #[cfg(feature = "full")]
    const GO_GONE_MSG: &str = "Your session has expired. Please try again.";
    #[cfg(feature = "full")]
    const GO_SERVER_ERROR_MSG: &str = "Something went wrong. Please try again later.";
    #[cfg(feature = "full")]
    const GO_LINK_SPENT_MSG: &str = "This link has already been used or has expired. If your device is connected you are done; otherwise start the login again.";

    /// Assert the upstream AuthError page for `status` with `message`, and
    /// that the technical cause (`hidden`) stays out of the page.
    #[cfg(feature = "full")]
    async fn assert_go_error_page(
        response: Response,
        status: StatusCode,
        message: &str,
        hidden: &str,
    ) {
        let heading = match status.as_u16() {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            410 => "Gone",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            other => panic!("no Go StatusText fixture for {other}"),
        };
        assert_eq!(response.status(), status, "{hidden}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = response_body(response).await;
        assert!(body.starts_with("<!DOCTYPE html>"), "{hidden}: {body}");
        assert!(
            body.contains("<title>Headscale - Error</title>"),
            "{hidden}"
        );
        assert!(
            body.contains(&format!(">{heading}</strong>{message}</div>")),
            "{hidden}: expected heading {heading:?} and message {message:?}"
        );
        assert!(
            !body.contains(hidden),
            "technical cause {hidden:?} must only be logged, like upstream"
        );
    }

    #[cfg(feature = "full")]
    fn confirm_headers(cookie_header: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie_header.parse().unwrap());
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers
    }

    #[cfg(feature = "full")]
    fn test_pending_confirmation(
        registration_id: &str,
        csrf: &str,
    ) -> OidcPendingRegistrationConfirmation {
        OidcPendingRegistrationConfirmation {
            registration_id: registration_id.to_string(),
            user: OidcStoredUser {
                id: 1,
                name: "alice@example.com".into(),
                display_name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                provider_identifier: "https://issuer.example/subject".into(),
                provider: REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
            node_expiry: None,
            csrf: csrf.to_string(),
            device: OidcRegistrationConfirmInfo {
                hostname: "oidc-client".into(),
                os: "linux".into(),
                machine_key: "[abcdef]".into(),
            },
        }
    }

    /// Mirrors upstream's oidc_test.go csrfInputRe,
    /// `name="headscale_register_confirm"[^>]*value="([^"]+)"`: elem-go sorts
    /// attributes, so `type="hidden"` sits between name and value.
    #[cfg(feature = "full")]
    fn csrf_from_confirm_body(body: &str) -> String {
        let marker = format!("name=\"{REGISTER_CONFIRM_CSRF_COOKIE}\"");
        let tag = body
            .split_once(&marker)
            .and_then(|(_before, after)| after.split_once('>'))
            .map(|(tag, _after)| tag)
            .expect("confirm form contains CSRF field");
        tag.split_once("value=\"")
            .and_then(|(_before, value)| value.split_once('"'))
            .map(|(csrf, _after)| csrf.to_string())
            .filter(|csrf| !csrf.is_empty())
            .expect("confirm form CSRF field has value")
    }

    #[cfg(feature = "full")]
    fn signed_id_token(nonce: &str) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            exp: i64,
            iat: i64,
            nonce: &'a str,
            name: &'a str,
            email: &'a str,
            email_verified: bool,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".into());
        encode(
            &header,
            &Claims {
                iss: "https://issuer.example",
                sub: "subject",
                aud: "headscale-rs",
                exp: 4_102_444_800,
                iat: 1_700_000_000,
                nonce,
                name: "Alice Smith",
                email: "alice@example.com",
                email_verified: true,
            },
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[cfg(feature = "full")]
    const TEST_RSA_MODULUS: &str = "13IZNgtofWGSQJkweQHBUDYhhX3bATj4ymKH5eDV5-clp8r411X8VnwjjxNwllYLL3o1KKoRHATXOyctIXBaMc4sUHdJVMbHdtNhm0GbxVxcRj5RtSmE8iuHWMdK8miq6drcduxdTaNCz407Ch0TF4MEipgIxqWQKmqvl8mGCh0He8GsgK2gbdQSE8g5iq3nRIn3mc_602YpMOiSxcVP3XfBeMYHdMJ0fQ83i79dclyIN5hqUjCIpXjt6nH8sRmeVubHon2Histd70SvyMChK68MUOQ_IT3y7-LKY-3hRHze5B-ap7F7v2Q99zCvEcdX8LCAFbiLG56dPax6rBQjoQ";

    #[cfg(feature = "full")]
    const TEST_RSA_PRIVATE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDXchk2C2h9YZJA\n\
mTB5AcFQNiGFfdsBOPjKYofl4NXn5yWnyvjXVfxWfCOPE3CWVgsvejUoqhEcBNc7\n\
Jy0hcFoxzixQd0lUxsd202GbQZvFXFxGPlG1KYTyK4dYx0ryaKrp2tx27F1No0LP\n\
jTsKHRMXgwSKmAjGpZAqaq+XyYYKHQd7wayAraBt1BITyDmKredEifeZz/rTZikw\n\
6JLFxU/dd8F4xgd0wnR9DzeLv11yXIg3mGpSMIileO3qcfyxGZ5W5seifYeKy13v\n\
RK/IwKErrwxQ5D8hPfLv4spj7eFEfN7kH5qnsXu/ZD33MK8Rx1fwsIAVuIsbnp09\n\
rHqsFCOhAgMBAAECggEAMmxzZxk7buDntHPGCwQ0pNvOc6pVmA8n92IhMVWyarDI\n\
OOHB5NAsm2c5gVKI7r6bppSBHY/UKk0dvKv6HZHoojCBYaHRiWRuqapmdUphNUtd\n\
E1mhkPdzNKSobEhUi7Cgk9QT9kdyvOmBiQcicscEQWP6K5/Sqf904uCOUUWqt/HO\n\
XizTA4LB9u2Y55qvPGz/9CG/7zShbX2Lw7YJUm2ndA3tZi473uOpszF61yFz14zW\n\
I4wienSEQQpZdcQSuC3Lk8tG9Kz+zWi+fHzSNx8NX9yXnzYNZFiiN7eP7iiUIh9q\n\
e0MkwhEUQ51cOO+c0TqbXwnCPyYlIhe8q7wTs7kSuQKBgQDzgjzxPtSg5FmjHzpd\n\
AQvjqD5+xLqY0p0GGFXi0eLvkfTEEOEB41A186bxH+pePVFkA0yyVSpU+2aQJWXv\n\
puWjg3z+LvtJ74cBv7ZyQh37SkquZw1Yg8iyDIuccJxEBemffJ18Arne1c2ZZh17\n\
ukeKgWa5MJhgmW59aNdQ/HhG7QKBgQDif1X/CcXhUzFiSuPica3B7t2GfEzCE8M/\n\
5hBe+0lltzsqRE8rYr0Y+m3fwCuRi5p2wU4ljG7x55kJwi8mesbsQQK/MisJHjMU\n\
TmkNM25bsde8qFyPq4kfM6PTdBUMsnQG+O0pLj7VBWZ6ZxoyopbEK1lpJg9c4ihm\n\
mx1KM5SlBQKBgQDr6BmoUglmUbMxX/iHz5K4G+9nmql3klsDY6IZGuMy2wD4za1e\n\
ydyUWBc8dIH2iIsITFYKUo2vRNsI/OIzeUnxzlnSWquh5kayAAv9x2YKY9/T9Awu\n\
24UcUSEUDtik4eGCXBSp5m4xnooPealIi5/xZAmjkZudwicTofUvBVh0xQKBgQDL\n\
4ngU9kUsSekgY+2y/0W8VzsOPoISChwuPvjppyYw67nUmFzz3xP9kiCp06DkiVho\n\
IiYoYrvUAfie8i/jYY4DSZohZhWbRZYRZ2vlODDVVcevyZZYtb7fWWrVg58XKOSN\n\
CjLiaQCiXRQchwbsIbO5rpPztRELOYHIq0S4cKoTyQKBgQCps8B1Im7HRiohw/Jh\n\
B7ur2garaZVSBJcYOXPGv+lrKYXrMlg/KZ4nQCvncqxHg9PvlxmpPmzIAthVYhki\n\
YFK5FWw3FdAIuCrN0K9IXMOWXByuJtgCHOttx4fu24fuyQ2t5N4q5CfQHUyJAgtQ\n\
Tg59Qj49HbnFm11JVyqd490zKQ==\n\
-----END PRIVATE KEY-----\n";

    /// Outbound reads from a misbehaving OIDC provider: every response is
    /// bounded while it streams, and no error or log line carries a whole body.
    #[cfg(feature = "full")]
    mod remote_body_limits {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};

        use axum::body::Body;
        use axum::routing::{get, post};

        use super::*;

        /// The documented bound, written out so these tests do not follow the
        /// production constant: golang.org/x/oauth2 reads `io.LimitReader(body, 1<<20)`.
        const LIMIT: usize = 1 << 20;

        #[test]
        fn provider_body_limit_is_the_oauth2_limit() {
            assert_eq!(OIDC_PROVIDER_BODY_LIMIT, LIMIT);
        }

        /// What an endless provider is willing to send before giving up; a client
        /// that stops at its bound drops the connection long before this.
        const ENDLESS: usize = 128 * 1024 * 1024;
        /// Loopback socket buffers absorb a few MiB after the client closes.
        const SERVER_WRITE_SLACK: usize = 24 * 1024 * 1024;

        /// A response body of 16 KiB `x` frames that counts what was pulled.
        struct Endless {
            pulled: Arc<AtomicUsize>,
            sent: usize,
        }

        impl http_body::Body for Endless {
            type Data = Bytes;
            type Error = std::convert::Infallible;

            fn poll_frame(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                if self.sent >= ENDLESS {
                    return Poll::Ready(None);
                }
                self.sent += 16 * 1024;
                self.pulled.fetch_add(16 * 1024, Ordering::Relaxed);
                Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_static(
                    &[b'x'; 16 * 1024],
                )))))
            }
        }

        fn endless(pulled: &Arc<AtomicUsize>) -> Response {
            let body = Body::new(Endless {
                pulled: pulled.clone(),
                sent: 0,
            });
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }

        async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handle = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (base, handle)
        }

        /// A runtime whose every provider endpoint is `base` plus a path.
        fn runtime_for(base: &str) -> OidcAuthRuntime {
            let mut config = auth_config(OidcPkceConfig::default());
            config.token_endpoint = format!("{base}/token");
            config.jwks_uri = format!("{base}/jwks");
            config.userinfo_endpoint = Some(format!("{base}/userinfo"));
            OidcAuthRuntime::new(config)
        }

        async fn settled(pulled: &AtomicUsize) -> usize {
            // A client that kept draining after giving up would keep growing this.
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            pulled.load(Ordering::Relaxed)
        }

        #[tokio::test]
        async fn discovery_abandons_an_endless_body_at_the_limit() {
            let pulled = Arc::new(AtomicUsize::new(0));
            let counter = pulled.clone();
            let (base, handle) = serve(axum::Router::new().route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let counter = counter.clone();
                    async move { endless(&counter) }
                }),
            ))
            .await;

            let error = discover_oidc_metadata(&format!("{base}/issuer"))
                .await
                .unwrap_err();
            let OidcDiscoveryError::Fetch { message, .. } = &error else {
                panic!("unexpected error: {error}");
            };
            assert_eq!(
                message,
                "unable to read response body: OIDC provider response exceeds 1 MiB"
            );
            let pulled = settled(&pulled).await;
            assert!(
                pulled < LIMIT + SERVER_WRITE_SLACK,
                "the provider was drained for {pulled} bytes"
            );
            handle.abort();
        }

        #[tokio::test]
        async fn jwks_abandons_an_endless_body_at_the_limit() {
            let pulled = Arc::new(AtomicUsize::new(0));
            let counter = pulled.clone();
            let (base, handle) = serve(axum::Router::new().route(
                "/jwks",
                get(move || {
                    let counter = counter.clone();
                    async move { endless(&counter) }
                }),
            ))
            .await;

            let result = fetch_oidc_jwks(&runtime_for(&base)).await;
            assert!(matches!(
                result,
                Err(OidcRuntimeError::IdTokenVerificationFailed)
            ));
            let pulled = settled(&pulled).await;
            assert!(
                pulled < LIMIT + SERVER_WRITE_SLACK,
                "the provider was drained for {pulled} bytes"
            );
            handle.abort();
        }

        #[tokio::test]
        async fn userinfo_abandons_an_endless_body_at_the_limit() {
            let pulled = Arc::new(AtomicUsize::new(0));
            let counter = pulled.clone();
            let (base, handle) = serve(axum::Router::new().route(
                "/userinfo",
                get(move || {
                    let counter = counter.clone();
                    async move { endless(&counter) }
                }),
            ))
            .await;

            let token = OidcTokenResponse {
                access_token: "access-token".into(),
                ..OidcTokenResponse::default()
            };
            assert!(fetch_userinfo(&runtime_for(&base), &token).await.is_none());
            let pulled = settled(&pulled).await;
            assert!(
                pulled < LIMIT + SERVER_WRITE_SLACK,
                "the provider was drained for {pulled} bytes"
            );
            handle.abort();
        }

        #[tokio::test]
        async fn token_endpoint_reads_at_most_the_oauth2_limit() {
            let pulled = Arc::new(AtomicUsize::new(0));
            let counter = pulled.clone();
            let (base, handle) = serve(axum::Router::new().route(
                "/token",
                post(move || {
                    let counter = counter.clone();
                    async move { endless(&counter) }
                }),
            ))
            .await;

            // oauth2 truncates at 1<<20 (it does not reject), then fails to
            // decode the prefix; both auth styles are tried, each bounded.
            let result = exchange_oauth2_token(&runtime_for(&base), b"code", None).await;
            assert!(matches!(result, Err(OidcRuntimeError::InvalidCode)));
            let pulled = settled(&pulled).await;
            assert!(
                pulled < 2 * LIMIT + SERVER_WRITE_SLACK,
                "the provider was drained for {pulled} bytes"
            );
            handle.abort();
        }

        #[tokio::test]
        async fn discovery_status_error_embeds_only_a_short_prefix() {
            // Under the read bound, so the whole body is received.
            let body = "e".repeat(900 * 1024);
            let (base, handle) = serve(axum::Router::new().route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let body = body.clone();
                    async move { (StatusCode::INTERNAL_SERVER_ERROR, body) }
                }),
            ))
            .await;

            let error = discover_oidc_metadata(&format!("{base}/issuer"))
                .await
                .unwrap_err();
            let text = error.to_string();
            assert!(text.len() < 400, "{} bytes", text.len());
            assert!(
                text.starts_with("500 Internal Server Error: eeee"),
                "{text:.80}"
            );
            assert!(text.ends_with("... (921600 bytes total)"), "{text}");
            handle.abort();
        }

        #[tokio::test]
        async fn issuer_mismatch_embeds_only_a_short_prefix_of_the_remote_issuer() {
            let hostile = format!("https://{}.example", "i".repeat(900 * 1024));
            let document = serde_json::json!({
                "issuer": hostile,
                "authorization_endpoint": "https://a.example/auth",
                "token_endpoint": "https://a.example/token",
                "jwks_uri": "https://a.example/jwks",
            })
            .to_string();
            let (base, handle) = serve(axum::Router::new().route(
                "/issuer/.well-known/openid-configuration",
                get(move || {
                    let document = document.clone();
                    async move { ([(header::CONTENT_TYPE, "application/json")], document) }
                }),
            ))
            .await;

            let error = discover_oidc_metadata(&format!("{base}/issuer"))
                .await
                .unwrap_err();
            let OidcDiscoveryError::IssuerMismatch { actual, .. } = &error else {
                panic!("unexpected error: {error}");
            };
            // The structured field keeps the remote value; only the text is cut.
            assert_eq!(actual, &hostile);
            let text = error.to_string();
            assert!(text.len() < 1024, "{} bytes", text.len());
            assert!(text.contains("bytes total)"), "{text}");
            handle.abort();
        }

        /// Collects the fields of every event logged on the current thread.
        struct Capture(Arc<RwLock<Vec<String>>>);

        impl tracing::Subscriber for Capture {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                // Only the error-level lines under test, not the HTTP stack's
                // debug chatter.
                *metadata.level() == tracing::Level::ERROR
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                struct Fields(String);
                impl tracing::field::Visit for Fields {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn fmt::Debug,
                    ) {
                        let _ = write!(self.0, "{}={value:?} ", field.name());
                    }
                }
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.write().push(fields.0);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        #[tokio::test]
        async fn userinfo_error_status_logs_only_a_short_prefix_of_the_body() {
            let body = "u".repeat(900 * 1024);
            let (base, handle) = serve(axum::Router::new().route(
                "/userinfo",
                get(move || {
                    let body = body.clone();
                    async move { (StatusCode::BAD_REQUEST, body) }
                }),
            ))
            .await;

            let logged = Arc::new(RwLock::new(Vec::new()));
            let guard = tracing::subscriber::set_default(Capture(logged.clone()));
            let token = OidcTokenResponse {
                access_token: "access-token".into(),
                ..OidcTokenResponse::default()
            };
            assert!(fetch_userinfo(&runtime_for(&base), &token).await.is_none());
            drop(guard);

            let logged = logged.read();
            // The pinned callback logs the provider error twice.
            assert_eq!(logged.len(), 2, "{logged:?}");
            for line in logged.iter() {
                assert!(line.len() < 600, "{} bytes: {line:.120}", line.len());
                assert!(line.contains("400 Bad Request: uuuu"), "{line:.120}");
                assert!(line.contains("(921600 bytes total)"), "{line:.120}");
            }
            handle.abort();
        }

        #[test]
        fn bounded_remote_text_cuts_on_a_char_boundary() {
            assert_eq!(bounded_remote_text(b"short"), "short");
            let exact = vec![b'a'; OIDC_ERROR_BODY_PREFIX];
            assert_eq!(bounded_remote_text(&exact).len(), OIDC_ERROR_BODY_PREFIX);

            // A 2-byte char straddling the cut must not be split or replaced.
            let mut text = "a".repeat(OIDC_ERROR_BODY_PREFIX - 1);
            text.push('\u{e9}');
            text.push_str(&"b".repeat(100));
            let bounded = bounded_remote_text(text.as_bytes());
            assert!(!bounded.contains('\u{fffd}'), "{bounded}");
            assert!(bounded.starts_with(&"a".repeat(OIDC_ERROR_BODY_PREFIX - 1)));
            assert!(bounded.ends_with(&format!("... ({} bytes total)", text.len())));

            // Invalid UTF-8 is replaced, not propagated.
            assert!(bounded_remote_text(&[0xff; 1000]).contains('\u{fffd}'));
        }
    }
}
