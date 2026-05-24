use std::collections::{HashMap, VecDeque};
use std::env;
use std::num::IntErrorKind;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(2 * 60);
const KEY_ID: &str = "test-key";

pub async fn run() -> Result<()> {
    let config = MockOidcConfig::from_env()?;
    let listen_addr = format!("{}:{}", config.addr, config.port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("binding mock OIDC listener on {listen_addr}"))?;
    let issuer = format!("http://{}/oidc", listener.local_addr()?);
    let state = AppState::new(config, issuer.clone());

    tracing::info!("mock OIDC server listening on {}", listener.local_addr()?);
    tracing::info!("issuer: {issuer}");

    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    config: Arc<MockOidcConfig>,
    issuer: Arc<String>,
    sessions: Arc<Mutex<SessionStore>>,
}

impl AppState {
    fn new(config: MockOidcConfig, issuer: String) -> Self {
        let sessions = SessionStore::with_users(config.users.clone());
        Self {
            config: Arc::new(config),
            issuer: Arc::new(issuer),
            sessions: Arc::new(Mutex::new(sessions)),
        }
    }
}

#[derive(Clone)]
struct MockOidcConfig {
    addr: String,
    port: i64,
    client_id: String,
    client_secret: String,
    access_ttl: Duration,
    users: VecDeque<MockUser>,
}

impl MockOidcConfig {
    fn from_env() -> Result<Self> {
        let client_id = required_env("MOCKOIDC_CLIENT_ID")?;
        let client_secret = required_env("MOCKOIDC_CLIENT_SECRET")?;
        let addr = required_env_with_message("MOCKOIDC_ADDR", "MOCKOIDC_PORT not defined")?;
        let port = required_env("MOCKOIDC_PORT")?;
        let access_ttl = match env::var("MOCKOIDC_ACCESS_TTL") {
            Ok(value) if !value.trim().is_empty() => parse_go_duration(&value)?,
            _ => DEFAULT_ACCESS_TTL,
        };
        let users = required_env("MOCKOIDC_USERS")?;
        let users = serde_json::from_str::<Vec<MockUser>>(&users)
            .context("unmarshalling users")?
            .into();
        let port = parse_go_atoi(&port)?;

        Ok(Self {
            addr,
            port,
            client_id,
            client_secret,
            access_ttl,
            users,
        })
    }
}

fn required_env(name: &str) -> Result<String> {
    required_env_with_message(name, &format!("{name} not defined"))
}

fn required_env_with_message(name: &str, message: &str) -> Result<String> {
    let value = env::var(name).unwrap_or_default();
    if value.is_empty() {
        bail!("{message}");
    }
    Ok(value)
}

fn parse_go_atoi(value: &str) -> Result<i64> {
    match value.parse::<i64>() {
        Ok(port) => Ok(port),
        Err(err) => {
            let reason = match err.kind() {
                IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => "value out of range",
                _ => "invalid syntax",
            };
            bail!("strconv.Atoi: parsing {value:?}: {reason}");
        }
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/oidc/.well-known/openid-configuration", get(discovery))
        .route("/oidc/.well-known/jwks.json", get(jwks))
        .route("/oidc/authorize", get(authorize))
        .route("/oidc/token", post(token))
        .route("/oidc/userinfo", get(userinfo))
        .with_state(state)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MockUser {
    #[serde(default, alias = "sub", alias = "subject")]
    subject: String,
    #[serde(default, alias = "email")]
    email: String,
    #[serde(default, alias = "email_verified")]
    email_verified: bool,
    #[serde(default, alias = "preferred_username")]
    preferred_username: String,
    #[serde(default, alias = "phone", alias = "phone_number")]
    phone: String,
    #[serde(default, alias = "address")]
    address: String,
    #[serde(default, alias = "groups")]
    groups: Vec<String>,
}

impl MockUser {
    fn default_user() -> Self {
        Self {
            subject: "1234567890".into(),
            email: "jane.doe@example.com".into(),
            email_verified: true,
            preferred_username: "jane.doe".into(),
            phone: "555-987-6543".into(),
            address: "123 Main Street".into(),
            groups: vec!["engineering".into(), "design".into()],
        }
    }

    fn scoped_userinfo(&self, scopes: &[String]) -> serde_json::Value {
        let include = |scope: &str| scopes.iter().any(|value| value == scope);
        let mut value = serde_json::Map::new();
        if include("email") {
            value.insert("email".into(), json!(self.email));
            value.insert("email_verified".into(), json!(self.email_verified));
        }
        if include("profile") {
            value.insert("preferred_username".into(), json!(self.preferred_username));
            value.insert("phone_number".into(), json!(self.phone));
            value.insert("address".into(), json!(self.address));
        }
        if include("groups") {
            value.insert("groups".into(), json!(self.groups));
        }
        serde_json::Value::Object(value)
    }
}

#[derive(Default)]
struct SessionStore {
    users: VecDeque<MockUser>,
    by_code: HashMap<String, Session>,
    by_access_token: HashMap<String, Session>,
    by_refresh_token: HashMap<String, Session>,
}

#[derive(Clone)]
struct Session {
    user: MockUser,
    scopes: Vec<String>,
    nonce: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    granted: bool,
}

impl SessionStore {
    fn with_users(users: VecDeque<MockUser>) -> Self {
        Self {
            users,
            ..Self::default()
        }
    }

    fn pop_user(&mut self) -> MockUser {
        self.users
            .pop_front()
            .unwrap_or_else(MockUser::default_user)
    }
}

async fn discovery(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "issuer": state.issuer.as_str(),
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer),
        "userinfo_endpoint": format!("{}/userinfo", state.issuer),
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "groups", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": [
            "sub",
            "email",
            "email_verified",
            "preferred_username",
            "phone_number",
            "address",
            "groups",
            "iss",
            "aud"
        ],
        "code_challenge_methods_supported": ["plain", "S256"],
    }))
}

async fn jwks() -> Json<serde_json::Value> {
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "kid": KEY_ID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_RSA_MODULUS,
            "e": "AQAB",
        }]
    }))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    scope: String,
    state: String,
    client_id: String,
    response_type: String,
    redirect_uri: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

async fn authorize(State(state): State<AppState>, Query(query): Query<AuthorizeQuery>) -> Response {
    if query.client_id != state.config.client_id {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client id",
        );
    }
    if query.response_type != "code" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Invalid response type",
        );
    }
    if let Some(method) = query.code_challenge_method.as_deref()
        && !matches!(method, "plain" | "S256")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unsupported code challenge method",
        );
    }

    let code = random_urlsafe(32);
    let session = {
        let mut store = state.sessions.lock().expect("session store lock");
        let user = store.pop_user();
        let session = Session {
            user,
            scopes: query
                .scope
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect(),
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            granted: false,
        };
        store.by_code.insert(code.clone(), session);
        redirect_with_code(&query.redirect_uri, &code, &query.state)
    };

    match session {
        Ok(location) => Redirect::to(&location).into_response(),
        Err(err) => oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &err.to_string()),
    }
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(mut form): Form<TokenForm>,
) -> Response {
    apply_basic_auth(&headers, &mut form);
    if form.client_id != state.config.client_id {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client id",
        );
    }
    if form.client_secret != state.config.client_secret {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client secret",
        );
    }

    let session = {
        let mut store = state.sessions.lock().expect("session store lock");
        match form.grant_type.as_str() {
            "authorization_code" => {
                let Some(session) = store.by_code.get_mut(&form.code) else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_grant",
                        &format!("Invalid code: {}", form.code),
                    );
                };
                if session.granted {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_grant",
                        &format!("Invalid code: {}", form.code),
                    );
                }
                if let Err(err) = validate_pkce(session, &form.code_verifier) {
                    return oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant", &err);
                }
                session.granted = true;
                session.clone()
            }
            "refresh_token" => {
                let Some(session) = store.by_refresh_token.get(&form.refresh_token) else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_grant",
                        "Invalid refresh token",
                    );
                };
                session.clone()
            }
            _ => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("Invalid grant type: {}", form.grant_type),
                );
            }
        }
    };

    let access_token = random_urlsafe(32);
    let refresh_token = if form.grant_type == "refresh_token" {
        form.refresh_token
    } else {
        random_urlsafe(32)
    };
    let id_token = match signed_id_token(&state, &session) {
        Ok(token) => token,
        Err(err) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };

    {
        let mut store = state.sessions.lock().expect("session store lock");
        store
            .by_access_token
            .insert(access_token.clone(), session.clone());
        store
            .by_refresh_token
            .insert(refresh_token.clone(), session);
    }

    Json(json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": state.config.access_ttl.as_nanos(),
    }))
    .into_response()
}

async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "Missing bearer token",
        );
    };
    let session = {
        let store = state.sessions.lock().expect("session store lock");
        store.by_access_token.get(token).cloned()
    };
    match session {
        Some(session) => Json(session.user.scoped_userinfo(&session.scopes)).into_response(),
        None => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "Invalid access token",
        ),
    }
}

fn redirect_with_code(redirect_uri: &str, code: &str, state: &str) -> Result<String> {
    let mut redirect = reqwest::Url::parse(redirect_uri)
        .with_context(|| format!("parsing redirect_uri {redirect_uri:?}"))?;
    redirect
        .query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    Ok(redirect.to_string())
}

fn apply_basic_auth(headers: &HeaderMap, form: &mut TokenForm) {
    if !form.client_id.is_empty() && !form.client_secret.is_empty() {
        return;
    }
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return;
    };
    let Some((client_id, client_secret)) = decoded.split_once(':') else {
        return;
    };
    form.client_id = client_id.to_string();
    form.client_secret = client_secret.to_string();
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn validate_pkce(session: &Session, verifier: &str) -> Result<(), String> {
    let Some(challenge) = session.code_challenge.as_deref() else {
        return Ok(());
    };
    let method = session.code_challenge_method.as_deref().unwrap_or("plain");
    if verifier.is_empty() {
        return Err("Invalid code verifier. Expected code but client sent none.".into());
    }
    let actual = match method {
        "plain" => verifier.to_string(),
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        }
        other => {
            return Err(format!(
                "Invalid code verifier. unknown challenge method: {other}"
            ));
        }
    };
    if actual != challenge {
        return Err(
            "Invalid code verifier. Code challenge did not match hashed code verifier.".into(),
        );
    }
    Ok(())
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn signed_id_token(state: &AppState, session: &Session) -> Result<String> {
    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        nonce: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        email: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        email_verified: Option<bool>,
        #[serde(skip_serializing_if = "str::is_empty")]
        preferred_username: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        phone_number: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        address: &'a str,
        groups: &'a [String],
    }

    let include = |scope: &str| session.scopes.iter().any(|value| value == scope);
    let now = unix_now()?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.into());
    encode(
        &header,
        &Claims {
            iss: state.issuer.as_str(),
            sub: &session.user.subject,
            aud: &state.config.client_id,
            exp: now + state.config.access_ttl.as_secs() as i64,
            iat: now,
            nonce: &session.nonce,
            email: if include("email") {
                &session.user.email
            } else {
                ""
            },
            email_verified: include("email").then_some(session.user.email_verified),
            preferred_username: if include("profile") {
                &session.user.preferred_username
            } else {
                ""
            },
            phone_number: if include("profile") {
                &session.user.phone
            } else {
                ""
            },
            address: if include("profile") {
                &session.user.address
            } else {
                ""
            },
            groups: if include("groups") {
                &session.user.groups
            } else {
                &[]
            },
        },
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
            .context("loading mock OIDC RSA key")?,
    )
    .context("signing mock OIDC id_token")
}

fn unix_now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs() as i64)
}

fn random_urlsafe(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn parse_go_duration(value: &str) -> Result<Duration> {
    let mut rest = value.trim();
    if rest.is_empty() {
        bail!("empty duration");
    }
    let mut total = Duration::ZERO;
    while !rest.is_empty() {
        let digits = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            bail!("invalid duration {value:?}");
        }
        let amount = rest[..digits]
            .parse::<u64>()
            .with_context(|| format!("parsing duration {value:?}"))?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|ch: char| ch.is_ascii_digit())
            .unwrap_or(rest.len());
        if unit_len == 0 {
            bail!("missing duration unit in {value:?}");
        }
        let unit = &rest[..unit_len];
        rest = &rest[unit_len..];
        total += match unit {
            "h" => Duration::from_secs(amount * 60 * 60),
            "m" => Duration::from_secs(amount * 60),
            "s" => Duration::from_secs(amount),
            "ms" => Duration::from_millis(amount),
            other => return Err(anyhow!("unsupported duration unit {other:?} in {value:?}")),
        };
    }
    Ok(total)
}

const TEST_RSA_MODULUS: &str = "13IZNgtofWGSQJkweQHBUDYhhX3bATj4ymKH5eDV5-clp8r411X8VnwjjxNwllYLL3o1KKoRHATXOyctIXBaMc4sUHdJVMbHdtNhm0GbxVxcRj5RtSmE8iuHWMdK8miq6drcduxdTaNCz407Ch0TF4MEipgIxqWQKmqvl8mGCh0He8GsgK2gbdQSE8g5iq3nRIn3mc_602YpMOiSxcVP3XfBeMYHdMJ0fQ83i79dclyIN5hqUjCIpXjt6nH8sRmeVubHon2Histd70SvyMChK68MUOQ_IT3y7-LKY-3hRHze5B-ap7F7v2Q99zCvEcdX8LCAFbiLG56dPax6rBQjoQ";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_style_duration() {
        assert_eq!(parse_go_duration("2m0s").unwrap(), Duration::from_secs(120));
        assert_eq!(
            parse_go_duration("1h2m3s").unwrap(),
            Duration::from_secs(3_723)
        );
    }

    #[test]
    fn mock_user_accepts_go_json_field_names() {
        let users: Vec<MockUser> = serde_json::from_str(
            r#"[{"Subject":"alice","Email":"alice@example.com","EmailVerified":true,"PreferredUsername":"alice","Groups":["engineering"]}]"#,
        )
        .unwrap();
        assert_eq!(users[0].subject, "alice");
        assert_eq!(users[0].email, "alice@example.com");
        assert!(users[0].email_verified);
        assert_eq!(users[0].groups, ["engineering"]);
    }
}
