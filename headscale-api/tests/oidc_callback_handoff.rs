use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration as StdDuration};

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Form,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Duration as ChronoDuration;
use headscale_api::{
    dns::DnsStore,
    oidc::{OidcAuthConfig, OidcAuthRuntime, OidcPkceConfig, OidcPkceMethod, OidcPolicyConfig},
    policy::PolicyStore,
    tailscale_wire::{
        AllocError, DerpMap, IpAllocator, KnockConfig, MachineRegistry, PreauthRedeemer,
        RedeemError, RedeemOk, RegisterResponse, RegistrationCache, ServerNoiseKey, WireState,
        noise::NoisePeerMachineKey, register as wire_register_handlers, router_with_oidc,
    },
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

const TEST_MACHINE_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[tokio::test]
async fn oidc_callback_wakes_wire_followup_with_authorized_client_registration() {
    let provider = spawn_mock_oidc_provider().await;
    let (state, _dir) = wire_state();
    let oidc = oidc_runtime(&provider.base_url);
    let app = router_with_oidc(state.clone(), oidc.clone());
    let machine_app = wire_machine_router(state.clone());
    let node_key_hex = "ab".repeat(32);

    let initial = decode_register_response(
        machine_app
            .clone()
            .oneshot(register_request(&node_key_hex, None))
            .await
            .unwrap(),
    )
    .await;
    assert!(!initial.machine_authorized);
    assert!(
        initial
            .auth_url
            .starts_with("https://headscale.example/register/")
    );
    let registration_id = initial.auth_url.rsplit('/').next().unwrap();
    assert_eq!(registration_id.len(), 24);
    assert!(state.registration_cache.get(registration_id).is_some());

    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/register/{registration_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_response.status(), StatusCode::FOUND);
    let cookie_header = callback_cookie_header(start_response.headers());
    let location = start_response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(&format!("{}/authorize?", provider.base_url)));

    let auth_params = query_params(&location);
    assert_eq!(auth_params.get("client_id").unwrap(), "headscale-rs");
    assert_eq!(auth_params.get("response_type").unwrap(), "code");
    assert_eq!(auth_params.get("code_challenge_method").unwrap(), "S256");
    let oidc_state = auth_params.get("state").unwrap().clone();
    let nonce = auth_params.get("nonce").unwrap().clone();
    *provider.token_nonce.write() = nonce;

    let registration = oidc.registration(&oidc_state).unwrap();
    assert_eq!(registration.registration_id, registration_id);
    let verifier = registration.verifier.unwrap();

    let mut followup = tokio::spawn({
        let machine_app = machine_app.clone();
        let auth_url = initial.auth_url.clone();
        let node_key_hex = node_key_hex.clone();
        async move {
            machine_app
                .oneshot(register_request(&node_key_hex, Some(&auth_url)))
                .await
                .unwrap()
        }
    });

    tokio::select! {
        result = &mut followup => {
            let response = result.unwrap();
            panic!("follow-up register completed before OIDC callback with {}", response.status());
        }
        () = tokio::time::sleep(StdDuration::from_millis(50)) => {}
    }

    let callback_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/oidc/callback?code=callback-code&state={oidc_state}"
                ))
                .header(header::COOKIE, cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback_response.status(), StatusCode::OK);
    let callback_body = body_string(callback_response).await;
    assert!(callback_body.contains("Signed in successfully"));
    assert!(callback_body.contains("User Info Name"));

    let completed = decode_register_response(
        tokio::time::timeout(StdDuration::from_secs(2), followup)
            .await
            .expect("follow-up register should wake after OIDC callback")
            .expect("follow-up register task should not panic"),
    )
    .await;
    assert!(completed.machine_authorized);
    assert!(completed.auth_url.is_empty());
    assert!(!completed.node_key_expired);
    assert_eq!(completed.login.login_name, "userinfo@example.com");

    let registered = state.machines.get(&node_key_hex).unwrap();
    assert_eq!(registered.user, "userinfo@example.com");
    assert_eq!(registered.hostname, "oidc-client");
    assert_eq!(registered.register_method, 3);
    assert!(registered.expiry.is_some());
    assert!(state.registration_cache.is_empty());

    let captured_form = provider.captured_form.read();
    assert_eq!(
        captured_form.get("grant_type").unwrap(),
        "authorization_code"
    );
    assert_eq!(captured_form.get("code").unwrap(), "callback-code");
    assert_eq!(
        captured_form.get("redirect_uri").unwrap(),
        "https://headscale.example/oidc/callback"
    );
    assert_eq!(captured_form.get("code_verifier").unwrap(), &verifier);
    assert_eq!(
        provider.captured_userinfo_auth.read().as_deref(),
        Some("Bearer access-token")
    );

    provider.handle.abort();
}

struct RejectingPreauth;

#[async_trait]
impl PreauthRedeemer for RejectingPreauth {
    async fn redeem(&self, _key: &str) -> Result<RedeemOk, RedeemError> {
        Err(RedeemError::Unknown)
    }
}

struct FixedIpAllocator;

impl IpAllocator for FixedIpAllocator {
    fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 42))
    }
}

fn wire_state() -> (WireState, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
        preauth: Arc::new(RejectingPreauth),
        ip_allocator: Arc::new(FixedIpAllocator),
        machines: Arc::new(MachineRegistry::new()),
        registration_store: None,
        derp_map: Arc::new(DerpMap::default()),
        policy: Arc::new(PolicyStore::new()),
        knock: KnockConfig::disabled(),
        dns: Arc::new(DnsStore::new()),
        public_control_url: Some("https://headscale.example".into()),
        registration_cache: Arc::new(RegistrationCache::new()),
    };
    (state, dir)
}

fn oidc_runtime(issuer: &str) -> OidcAuthRuntime {
    OidcAuthRuntime::new(OidcAuthConfig {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        userinfo_endpoint: Some(format!("{issuer}/userinfo")),
        jwks_uri: format!("{issuer}/jwks"),
        client_id: "headscale-rs".into(),
        client_secret: "secret".into(),
        redirect_url: "https://headscale.example/oidc/callback".into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        extra_params: BTreeMap::new(),
        pkce: OidcPkceConfig {
            enabled: true,
            method: OidcPkceMethod::S256,
        },
        policy: OidcPolicyConfig {
            allowed_domains: vec!["example.com".into()],
            allowed_users: Vec::new(),
            allowed_groups: vec!["engineering".into()],
            email_verified_required: true,
            expiry: ChronoDuration::days(30),
            use_expiry_from_token: false,
        },
    })
}

fn register_request(node_key_hex: &str, followup: Option<&str>) -> Request<Body> {
    let mut body = json!({
        "NodeKey": format!("nodekey:{node_key_hex}"),
        "Hostinfo": {
            "Hostname": "oidc-client",
            "OS": "linux",
            "OSVersion": "6.8"
        }
    });
    if let Some(followup) = followup {
        body["Followup"] = json!(followup);
    }

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/machine/nodekey:{node_key_hex}/register"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(NoisePeerMachineKey(TEST_MACHINE_KEY_HEX.to_string()));
    req
}

fn wire_machine_router(state: WireState) -> Router {
    Router::new()
        .route(
            "/machine/:node_key/register",
            post(wire_register_handlers::handle_register),
        )
        .route(
            "/machine/register",
            post(wire_register_handlers::handle_register_flat),
        )
        .with_state(state)
}

async fn decode_register_response(response: Response) -> RegisterResponse {
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn body_string(response: Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

fn callback_cookie_header(headers: &HeaderMap) -> String {
    let cookies = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    cookies.join("; ")
}

fn query_params(location: &str) -> BTreeMap<String, String> {
    location
        .split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

struct MockOidcProvider {
    base_url: String,
    token_nonce: Arc<RwLock<String>>,
    captured_form: Arc<RwLock<BTreeMap<String, String>>>,
    captured_userinfo_auth: Arc<RwLock<Option<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn spawn_mock_oidc_provider() -> MockOidcProvider {
    let token_nonce = Arc::new(RwLock::new(String::new()));
    let captured_form = Arc::new(RwLock::new(BTreeMap::new()));
    let captured_userinfo_auth = Arc::new(RwLock::new(None));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let app = oidc_provider_router(
        &base_url,
        token_nonce.clone(),
        captured_form.clone(),
        captured_userinfo_auth.clone(),
    );
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    MockOidcProvider {
        base_url,
        token_nonce,
        captured_form,
        captured_userinfo_auth,
        handle,
    }
}

fn oidc_provider_router(
    issuer: &str,
    token_nonce: Arc<RwLock<String>>,
    captured_form: Arc<RwLock<BTreeMap<String, String>>>,
    captured_userinfo_auth: Arc<RwLock<Option<String>>>,
) -> Router {
    let token_issuer = issuer.to_string();
    let token_nonce_route = token_nonce;
    let captured_form_route = captured_form;
    let userinfo_auth_route = captured_userinfo_auth;

    Router::new()
        .route("/authorize", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/token",
            post(
                move |headers: HeaderMap, Form(form): Form<BTreeMap<String, String>>| {
                    let token_issuer = token_issuer.clone();
                    let token_nonce = token_nonce_route.clone();
                    let captured_form = captured_form_route.clone();
                    async move {
                        if !headers
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| value.starts_with("Basic "))
                        {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                        *captured_form.write() = form;
                        let nonce = token_nonce.read().clone();
                        if nonce.is_empty() {
                            return StatusCode::BAD_REQUEST.into_response();
                        }
                        Json(json!({
                            "access_token": "access-token",
                            "token_type": "Bearer",
                            "id_token": signed_id_token(&token_issuer, &nonce),
                        }))
                        .into_response()
                    }
                },
            ),
        )
        .route(
            "/userinfo",
            get(move |headers: HeaderMap| {
                let captured_userinfo_auth = userinfo_auth_route.clone();
                async move {
                    *captured_userinfo_auth.write() = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned);
                    Json(json!({
                        "sub": "subject",
                        "name": "User Info Name",
                        "preferred_username": "userinfo",
                        "email": "userinfo@example.com",
                        "email_verified": true,
                        "groups": ["engineering"],
                        "picture": "https://example.com/userinfo.png",
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async {
                Json(json!({
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
        )
}

fn signed_id_token(issuer: &str, nonce: &str) -> String {
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
        groups: [&'a str; 1],
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    encode(
        &header,
        &Claims {
            iss: issuer,
            sub: "subject",
            aud: "headscale-rs",
            exp: 4_102_444_800,
            iat: 1_700_000_000,
            nonce,
            name: "Alice Smith",
            email: "alice@example.com",
            email_verified: true,
            groups: ["engineering"],
        },
        &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
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
