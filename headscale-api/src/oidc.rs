//! OIDC helpers that mirror headscale-go's auth-provider behavior.
//!
//! The final user/node handoff is still wired separately. This module keeps
//! both the pure pieces and the auth-code path testable against upstream
//! semantics: claim authorization, issuer/subject identifiers, UserInfo
//! merging, node-expiry selection, state/nonce cookies, PKCE challenge
//! generation, auth URL construction, token exchange, and ID-token validation.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
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
const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const REGISTRATION_ID_LENGTH: usize = 24;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + REGISTRATION_ID_LENGTH;
const OIDC_CSRF_TOKEN_LEN: usize = 64;
const OIDC_COOKIE_NAME_PREFIX_LEN: usize = 6;
const OIDC_COOKIE_MAX_AGE_SECS: u64 = 60 * 60;
const DEFAULT_OIDC_AUTH_CACHE_EXPIRY: StdDuration = StdDuration::from_secs(15 * 60);
const DEFAULT_OIDC_AUTH_CACHE_MAX_ENTRIES: usize = 1024;
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcProviderMetadata {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: String,
}

#[derive(Clone)]
pub struct OidcAuthRuntime {
    config: Arc<OidcAuthConfig>,
    registrations: Arc<OidcRegistrationCache>,
    confirmations: Arc<OidcRegistrationConfirmationCache>,
    users: Option<Arc<dyn OidcUserStore>>,
    registration_handler: Option<Arc<dyn OidcRegistrationHandler>>,
}

impl fmt::Debug for OidcAuthRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthRuntime")
            .field("config", &self.config)
            .field("registrations", &self.registrations)
            .field("confirmations", &self.confirmations)
            .field("users", &self.users.as_ref().map(|_| "<configured>"))
            .field(
                "registration_handler",
                &self.registration_handler.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

impl OidcAuthRuntime {
    pub fn new(config: OidcAuthConfig) -> Self {
        Self {
            config: Arc::new(config),
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
        let mut inner = self.inner.write();
        inner.insert(state, entry);
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
    #[error("failed to fetch OIDC discovery metadata from {url}: {message}")]
    Fetch { url: String, message: String },
    #[error("failed to decode OIDC discovery metadata from {url}: {message}")]
    Decode { url: String, message: String },
    #[error("OIDC discovery metadata is missing {field}")]
    MissingField { field: &'static str },
    #[error("OIDC discovery issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcRuntimeBuildError {
    #[error(transparent)]
    Discovery(#[from] OidcDiscoveryError),
    #[error("unsupported OIDC PKCE method {method:?}")]
    InvalidPkceMethod { method: String },
}

impl OidcProviderMetadata {
    pub fn validate_for_issuer(&self, issuer: &str) -> Result<(), OidcDiscoveryError> {
        let expected = normalize_issuer(issuer)?;
        let actual = require_oidc_field(&self.issuer, "issuer")?;
        require_oidc_field(&self.authorization_endpoint, "authorization_endpoint")?;
        require_oidc_field(&self.token_endpoint, "token_endpoint")?;
        require_oidc_field(&self.jwks_uri, "jwks_uri")?;

        if normalize_issuer(actual)? != expected {
            return Err(OidcDiscoveryError::IssuerMismatch {
                expected,
                actual: actual.to_string(),
            });
        }

        Ok(())
    }
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
        .send()
        .await
        .map_err(|err| OidcDiscoveryError::Fetch {
            url: url.clone(),
            message: err.to_string(),
        })?;

    let status = response.status();
    if !status.is_success() {
        return Err(OidcDiscoveryError::Fetch {
            url,
            message: format!("HTTP {status}"),
        });
    }

    let metadata = response
        .json::<OidcProviderMetadata>()
        .await
        .map_err(|err| OidcDiscoveryError::Decode {
            url: url.clone(),
            message: err.to_string(),
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
        issuer: normalize_issuer(&metadata.issuer)?,
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
    if oidc.issuer.trim().is_empty() {
        return Ok(None);
    }

    let metadata = match discover_oidc_metadata(&oidc.issuer).await {
        Ok(metadata) => metadata,
        Err(err) if !oidc.only_start_if_oidc_is_available => {
            tracing::warn!(
                error = %err,
                "OIDC provider discovery failed; continuing without OIDC because oidc.only_start_if_oidc_is_available=false"
            );
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };

    Ok(Some(OidcAuthRuntime::new(auth_config_from_core_oidc(
        oidc, server_url, metadata,
    )?)))
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
    #[serde(
        default,
        rename = "groups",
        deserialize_with = "deserialize_flexible_string_vec_default"
    )]
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
    #[serde(
        default,
        rename = "groups",
        deserialize_with = "deserialize_optional_flexible_string_vec"
    )]
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
        } else {
            self.provider_identifier.clone()
        }
    }
}

#[async_trait::async_trait]
pub trait OidcUserStore: Send + Sync {
    async fn create_or_update_oidc_user(
        &self,
        profile: OidcUserProfile,
    ) -> Result<OidcStoredUser, String>;
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
    let start = match runtime.begin_registration(&registration_id) {
        Ok(start) => start,
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), err.to_string()),
    };

    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    append_cookie(response.headers_mut(), &csrf_cookie("state", &start.state));
    append_cookie(response.headers_mut(), &csrf_cookie("nonce", &start.nonce));
    response
}

pub async fn handle_auth(runtime: OidcAuthRuntime, auth_id: String) -> Response {
    let start = match runtime.begin_auth(&auth_id) {
        Ok(start) => start,
        Err(err) => return oidc_error_response(status_for_runtime_error(&err), err.to_string()),
    };

    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    append_cookie(response.headers_mut(), &csrf_cookie("state", &start.state));
    append_cookie(response.headers_mut(), &csrf_cookie("nonce", &start.nonce));
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

pub async fn handle_register_confirm_with_request_security(
    runtime: OidcAuthRuntime,
    auth_id: String,
    headers: HeaderMap,
    raw: Bytes,
    secure_cookies: bool,
) -> Response {
    let Some(registration_id) = registration_id_from_register_path(&auth_id).map(str::to_string)
    else {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            OidcRuntimeError::InvalidRegistrationId.to_string(),
        );
    };

    if !is_form_urlencoded_content_type(&headers) {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            OidcRuntimeError::MissingCsrfToken.to_string(),
        );
    }

    if raw.len() > REGISTER_CONFIRM_BODY_LIMIT {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            OidcRuntimeError::InvalidForm.to_string(),
        );
    }

    if !is_strict_urlencoded_form(&raw) {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            OidcRuntimeError::InvalidForm.to_string(),
        );
    }

    let form_csrf = form_urlencoded::parse(&raw)
        .find_map(|(key, value)| (key == REGISTER_CONFIRM_CSRF_COOKIE).then(|| value.into_owned()))
        .filter(|value| !value.is_empty());
    let Some(form_csrf) = form_csrf else {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            OidcRuntimeError::MissingCsrfToken.to_string(),
        );
    };

    let Some(cookie_csrf) = cookie_value(&headers, REGISTER_CONFIRM_CSRF_COOKIE) else {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            OidcRuntimeError::MissingCsrfCookie.to_string(),
        );
    };
    if cookie_csrf != form_csrf {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            OidcRuntimeError::CsrfTokenMismatch.to_string(),
        );
    }

    let Some(registration_handler) = &runtime.registration_handler else {
        return oidc_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "OIDC callback completion is not implemented".to_string(),
        );
    };

    let Some(pending) = registration_handler
        .oidc_pending_registration_confirmation(&registration_id)
        .or_else(|| runtime.confirmations.get(&registration_id))
    else {
        let err = match registration_handler.oidc_auth_request_kind(&registration_id) {
            Some(OidcAuthRequestKind::Registration) => {
                OidcRuntimeError::RegistrationNotOidcAuthorized
            }
            Some(OidcAuthRequestKind::SshCheck) => OidcRuntimeError::AuthSessionNotRegistration,
            None => OidcRuntimeError::RegistrationSessionExpired,
        };
        return oidc_error_response(status_for_runtime_error(&err), err.to_string());
    };

    if pending.csrf != cookie_csrf {
        return oidc_error_response(
            StatusCode::FORBIDDEN,
            OidcRuntimeError::CsrfTokenCacheMismatch.to_string(),
        );
    }

    match registration_handler
        .complete_oidc_registration(&pending.registration_id, &pending.user, pending.node_expiry)
        .await
    {
        Ok(result) => {
            registration_handler.remove_oidc_registration_confirmation(&registration_id);
            runtime.confirmations.remove(&registration_id);
            let mut response = oidc_registration_success_response(&pending.user, result.new_node);
            clear_register_confirm_cookie(response.headers_mut(), &auth_id, secure_cookies);
            response
        }
        Err(OidcRegistrationError::SessionExpired) => {
            oidc_error_response(StatusCode::GONE, "registration session expired".to_string())
        }
        Err(OidcRegistrationError::Store(err)) => {
            oidc_error_response(StatusCode::INTERNAL_SERVER_ERROR, err)
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

    let Some(registration) = runtime.registration(&query.state) else {
        return oidc_error_response(
            status_for_runtime_error(&OidcRuntimeError::RegistrationNotFound),
            OidcRuntimeError::RegistrationNotFound.to_string(),
        );
    };
    #[cfg(not(feature = "full"))]
    let _ = (registration, secure_cookies);

    #[cfg(feature = "full")]
    {
        let token = match exchange_oauth2_token(
            &runtime.config,
            &query.code,
            registration.verifier.as_deref(),
        )
        .await
        {
            Ok(token) => token,
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), err.to_string());
            }
        };

        let id_token = match verify_id_token(&runtime.config, &token.id_token).await {
            Ok(id_token) => id_token,
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), err.to_string());
            }
        };

        match validate_nonce_cookie(&headers, &id_token.nonce) {
            Ok(()) => {}
            Err(err) => {
                return oidc_error_response(status_for_runtime_error(&err), err.to_string());
            }
        }

        let mut claims = id_token.claims;
        let userinfo = fetch_userinfo(&runtime.config, &token).await;
        merge_userinfo_claims(&mut claims, userinfo.as_ref());
        if let Err(err) = authorize_claims(&runtime.config.policy, &claims) {
            let err = OidcRuntimeError::Authorization(err);
            return oidc_error_response(status_for_runtime_error(&err), err.to_string());
        }
        let node_expiry =
            determine_node_expiry(&runtime.config.policy, id_token.expiry, Utc::now());
        let profile =
            user_profile_from_claims(&claims, runtime.config.policy.email_verified_required);
        let user = if let Some(users) = &runtime.users {
            match users.create_or_update_oidc_user(profile).await {
                Ok(user) => user,
                Err(_) => {
                    return oidc_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Could not create or update user".to_string(),
                    );
                }
            }
        } else {
            stored_user_from_profile(profile)
        };

        if let Some(registration_handler) = &runtime.registration_handler {
            if registration.registration {
                match registration_handler.oidc_auth_request_kind(&registration.registration_id) {
                    Some(OidcAuthRequestKind::Registration) => {}
                    Some(OidcAuthRequestKind::SshCheck) => {
                        let err = OidcRuntimeError::AuthSessionNotRegistration;
                        return oidc_error_response(
                            status_for_runtime_error(&err),
                            err.to_string(),
                        );
                    }
                    None => {
                        return oidc_error_response(
                            StatusCode::GONE,
                            "login session expired, try again".to_string(),
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
                return oidc_registration_confirm_response(&pending, secure_cookies);
            }

            match registration_handler
                .complete_oidc_auth_request(&registration.registration_id, &user)
                .await
            {
                Ok(()) => return oidc_ssh_success_response(&user),
                Err(err) => {
                    return oidc_error_response(status_for_auth_error(&err), err.to_string());
                }
            }
        }
    }

    oidc_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "OIDC callback completion is not implemented".to_string(),
    )
}

#[cfg(feature = "full")]
#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    id_token: String,
}

#[cfg(feature = "full")]
async fn exchange_oauth2_token(
    cfg: &OidcAuthConfig,
    code: &str,
    verifier: Option<&str>,
) -> Result<OidcTokenResponse, OidcRuntimeError> {
    let client = reqwest::Client::new();

    for auth_in_header in [true, false] {
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), cfg.redirect_url.clone()),
        ];
        if let Some(verifier) = verifier {
            form.push(("code_verifier".to_string(), verifier.to_string()));
        }
        if !auth_in_header {
            form.push(("client_id".to_string(), cfg.client_id.clone()));
            form.push(("client_secret".to_string(), cfg.client_secret.clone()));
        }

        let request = client.post(&cfg.token_endpoint).form(&form);
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

        let response = request
            .send()
            .await
            .map_err(|_| OidcRuntimeError::InvalidCode)?;
        if !response.status().is_success() {
            if auth_in_header {
                continue;
            }
            return Err(OidcRuntimeError::InvalidCode);
        }

        let token = response
            .json::<OidcTokenResponse>()
            .await
            .map_err(|_| OidcRuntimeError::InvalidCode)?;
        if token.id_token.is_empty() {
            return Err(OidcRuntimeError::MissingIdToken);
        }
        return Ok(token);
    }

    Err(OidcRuntimeError::InvalidCode)
}

#[cfg(feature = "full")]
async fn fetch_userinfo(cfg: &OidcAuthConfig, token: &OidcTokenResponse) -> Option<OidcUserInfo> {
    let endpoint = cfg.userinfo_endpoint.as_ref()?;
    if token.access_token.is_empty() {
        return None;
    }

    let response = match reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(&token.access_token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!(error = %err, "could not get OIDC userinfo; only using id_token claims");
            return None;
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "could not get OIDC userinfo; only using id_token claims"
        );
        return None;
    }

    match response.json::<OidcUserInfo>().await {
        Ok(userinfo) => Some(userinfo),
        Err(err) => {
            tracing::warn!(error = %err, "could not decode OIDC userinfo; only using id_token claims");
            None
        }
    }
}

#[cfg(feature = "full")]
#[derive(Debug, Deserialize)]
struct OidcJwks {
    #[serde(default)]
    keys: Vec<OidcJwk>,
}

#[cfg(feature = "full")]
#[derive(Debug, Deserialize)]
struct OidcJwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[cfg(feature = "full")]
#[derive(Debug, Deserialize)]
struct OidcIdTokenClaims {
    #[serde(flatten)]
    claims: OidcClaims,
    #[serde(default)]
    nonce: String,
    exp: i64,
}

#[cfg(feature = "full")]
#[derive(Debug)]
struct VerifiedOidcIdToken {
    #[allow(dead_code)]
    claims: OidcClaims,
    nonce: String,
    #[allow(dead_code)]
    expiry: DateTime<Utc>,
}

#[cfg(feature = "full")]
async fn verify_id_token(
    cfg: &OidcAuthConfig,
    raw_id_token: &str,
) -> Result<VerifiedOidcIdToken, OidcRuntimeError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header =
        decode_header(raw_id_token).map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)?;
    let jwks = reqwest::Client::new()
        .get(&cfg.jwks_uri)
        .send()
        .await
        .map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)?;
    if !jwks.status().is_success() {
        return Err(OidcRuntimeError::IdTokenVerificationFailed);
    }
    let jwks = jwks
        .json::<OidcJwks>()
        .await
        .map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)?;

    let key = jwks
        .keys
        .iter()
        .find(|key| {
            key.kty == "RSA"
                && match (&header.kid, &key.kid) {
                    (Some(expected), Some(actual)) => expected == actual,
                    (Some(_), None) => false,
                    (None, _) => true,
                }
        })
        .and_then(|key| Some((key.n.as_ref()?, key.e.as_ref()?)))
        .and_then(|(n, e)| DecodingKey::from_rsa_components(n, e).ok())
        .ok_or(OidcRuntimeError::IdTokenVerificationFailed)?;

    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    ) {
        return Err(OidcRuntimeError::IdTokenVerificationFailed);
    }

    let mut validation = Validation::new(header.alg);
    validation.set_audience(std::slice::from_ref(&cfg.client_id));
    validation.set_issuer(std::slice::from_ref(&cfg.issuer));

    let token = decode::<OidcIdTokenClaims>(raw_id_token, &key, &validation)
        .map_err(|_| OidcRuntimeError::IdTokenVerificationFailed)?;
    if token.claims.nonce.is_empty() {
        return Err(OidcRuntimeError::NonceMissingInToken);
    }

    let Some(expiry) = DateTime::<Utc>::from_timestamp(token.claims.exp, 0) else {
        return Err(OidcRuntimeError::IdTokenVerificationFailed);
    };

    Ok(VerifiedOidcIdToken {
        claims: token.claims.claims,
        nonce: token.claims.nonce,
        expiry,
    })
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

fn normalize_issuer(issuer: &str) -> Result<String, OidcDiscoveryError> {
    let issuer = issuer.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return Err(OidcDiscoveryError::EmptyIssuer);
    }
    Ok(issuer.to_string())
}

fn require_oidc_field<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, OidcDiscoveryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OidcDiscoveryError::MissingField { field });
    }
    Ok(value)
}

#[cfg(feature = "full")]
fn oidc_redirect_url(server_url: &str) -> String {
    format!("{}/oidc/callback", server_url.trim_end_matches('/'))
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

fn append_cookie(headers: &mut HeaderMap, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
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
    if state.len() < OIDC_COOKIE_NAME_PREFIX_LEN {
        return Err(OidcRuntimeError::InvalidStateParameter);
    }

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
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
}

fn is_form_urlencoded_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| {
            mime.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn is_strict_urlencoded_form(raw: &[u8]) -> bool {
    if raw.contains(&b';') {
        return false;
    }

    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            if index + 2 >= raw.len()
                || !raw[index + 1].is_ascii_hexdigit()
                || !raw[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }

    true
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

fn oidc_error_response(status: StatusCode, message: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        message,
    )
        .into_response()
}

#[cfg(feature = "full")]
fn oidc_registration_confirm_response(
    pending: &OidcPendingRegistrationConfirmation,
    secure_cookie: bool,
) -> Response {
    let auth_id = format!("{}{}", AUTH_ID_PREFIX, pending.registration_id);
    let cookie = register_confirm_cookie(&auth_id, &pending.csrf, secure_cookie);
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        oidc_registration_confirm_html(pending),
    )
        .into_response();
    append_cookie(response.headers_mut(), &cookie);
    response
}

#[cfg(feature = "full")]
fn register_confirm_cookie(auth_id: &str, csrf: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{REGISTER_CONFIRM_CSRF_COOKIE}={csrf}; Path=/register/confirm/{auth_id}; Max-Age={}{}; HttpOnly; SameSite=Strict",
        DEFAULT_OIDC_AUTH_CACHE_EXPIRY.as_secs(),
        secure,
    )
}

fn clear_register_confirm_cookie(headers: &mut HeaderMap, auth_id: &str, secure: bool) {
    let secure = if secure { "; Secure" } else { "" };
    append_cookie(
        headers,
        &format!(
            "{REGISTER_CONFIRM_CSRF_COOKIE}=; Path=/register/confirm/{auth_id}; Max-Age=0{secure}; HttpOnly; SameSite=Strict"
        ),
    );
}

#[cfg(feature = "full")]
fn oidc_registration_confirm_html(pending: &OidcPendingRegistrationConfirmation) -> String {
    let auth_id = format!("{}{}", AUTH_ID_PREFIX, pending.registration_id);
    let user = user_display_name(&pending.user);
    let hostname = display_or_unknown(&pending.device.hostname);
    let os = display_or_unknown(&pending.device.os);
    let machine_key = display_or_unknown(&pending.device.machine_key);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Headscale - Confirm node registration</title></head><body><main><h1>Confirm node registration</h1><p>A device is asking to be added to your tailnet. Please review the details below and confirm that this device is yours.</p><dl><dt>Hostname</dt><dd>{}</dd><dt>OS</dt><dd>{}</dd><dt>Machine key</dt><dd><code>{}</code></dd><dt>Registered to</dt><dd>{}</dd></dl><form method=\"POST\" action=\"/register/confirm/{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\"><button type=\"submit\">Confirm registration</button></form><p>If you do not recognise this device, close this window. The registration request will expire automatically.</p></main></body></html>",
        html_escape(&hostname),
        html_escape(&os),
        html_escape(&machine_key),
        html_escape(&user),
        html_escape(&auth_id),
        REGISTER_CONFIRM_CSRF_COOKIE,
        html_escape(&pending.csrf)
    )
}

#[cfg(feature = "full")]
fn display_or_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "unknown".to_string()
    } else {
        value.to_string()
    }
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
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>{}</title></head><body><main><h1>{}</h1><p>{} as <strong>{}</strong>. You can now close this window.</p></main></body></html>",
        html_escape(title),
        html_escape(heading),
        html_escape(verb),
        html_escape(user)
    )
}

#[cfg(feature = "full")]
fn oidc_ssh_success_html(user: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Headscale - SSH Session Authorized</title></head><body><main><h1>SSH session authorized</h1><p>Authorized as <strong>{}</strong>. You may return to your terminal.</p></main></body></html>",
        html_escape(user)
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
    } else {
        user.provider_identifier.clone()
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
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
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
        Vec(Vec<String>),
        String(String),
    }

    match Option::<FlexibleStringVec>::deserialize(deserializer)? {
        Some(FlexibleStringVec::Vec(value)) => Ok(Some(value)),
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
        }
    }

    #[test]
    fn oidc_discovery_url_matches_issuer_path_rules() {
        assert_eq!(
            oidc_discovery_url(" https://issuer.example/ ").unwrap(),
            "https://issuer.example/.well-known/openid-configuration"
        );
        assert_eq!(
            oidc_discovery_url("https://issuer.example/realms/headscale/").unwrap(),
            "https://issuer.example/realms/headscale/.well-known/openid-configuration"
        );
        assert_eq!(oidc_discovery_url(""), Err(OidcDiscoveryError::EmptyIssuer));
    }

    #[test]
    fn oidc_metadata_validates_required_fields_and_issuer() {
        let metadata = provider_metadata();
        assert_eq!(
            metadata.validate_for_issuer("https://issuer.example/"),
            Ok(())
        );

        let mut missing_auth_endpoint = metadata.clone();
        missing_auth_endpoint.authorization_endpoint.clear();
        assert_eq!(
            missing_auth_endpoint.validate_for_issuer("https://issuer.example"),
            Err(OidcDiscoveryError::MissingField {
                field: "authorization_endpoint"
            })
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
            issuer: "https://issuer.example/".into(),
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
            headers,
            Query(OidcCallbackQuery {
                code: "auth-code".into(),
                state: start.state,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            response_body(response).await,
            "OIDC callback completion is not implemented"
        );
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_body(response).await, "nonce not found");
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_body(response).await, "failed to verify id_token");
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

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response_body(response).await,
            "Could not create or update user"
        );
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

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let cookie_header = set_cookie_header(&response);
        let body = response_body(response).await;
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

        assert_eq!(response.status(), StatusCode::OK);
        let cookie_header = set_cookie_header(&response);
        let body = response_body(response).await;
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_body(response).await, "csrf token mismatch");
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_body(response).await,
            "registration not OIDC-authorized"
        );
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

        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response_body(response).await,
            "registration session expired"
        );
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_body(response).await,
            "auth session is not for node registration"
        );
        assert!(registrations.calls.read().is_empty());
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_body(response).await,
            "csrf token does not match cached registration"
        );
        assert!(runtime.pending_confirmation(&registration_id).is_some());
        assert!(registrations.calls.read().is_empty());
    }

    #[cfg(feature = "full")]
    #[tokio::test]
    async fn oidc_register_confirm_rejects_malformed_urlencoded_form_like_upstream() {
        for (name, body) in [
            ("short percent escape", "headscale_register_confirm=%"),
            ("non-hex percent escape", "headscale_register_confirm=%zz"),
            (
                "semicolon separator",
                "headscale_register_confirm=expected-csrf;other=value",
            ),
        ] {
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

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            assert_eq!(response_body(response).await, "invalid form", "{name}");
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
        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            confirm_headers("headscale_register_confirm=expected-csrf"),
            Bytes::from(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_body(response).await, "invalid form");
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

        let response = handle_register_confirm(
            runtime,
            format!("hskey-authreq-{registration_id}"),
            headers,
            Bytes::from("headscale_register_confirm=expected-csrf"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_body(response).await, "missing csrf token");
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

        let response = handle_register_confirm(
            runtime.clone(),
            format!("hskey-authreq-{registration_id}"),
            headers,
            Bytes::from("x".repeat(REGISTER_CONFIRM_BODY_LIMIT + 1)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_body(response).await, "missing csrf token");
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

        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response_body(response).await,
            "login session expired, try again"
        );
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_body(response).await,
            "auth session is not for node registration"
        );
        assert!(registrations.calls.read().is_empty());
        assert!(registrations.auth_calls.read().is_empty());
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

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_body(response).await, "unauthorised group");
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

    #[cfg(feature = "full")]
    fn set_cookie_header(response: &Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split_once(';').map(|(cookie, _attrs)| cookie))
            .collect::<Vec<_>>()
            .join("; ")
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

    #[cfg(feature = "full")]
    fn csrf_from_confirm_body(body: &str) -> String {
        let marker = format!("name=\"{REGISTER_CONFIRM_CSRF_COOKIE}\" value=\"");
        let rest = body
            .split_once(&marker)
            .map(|(_before, after)| after)
            .expect("confirm form contains CSRF field");
        rest.split_once('"')
            .map(|(csrf, _after)| csrf.to_string())
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
}
