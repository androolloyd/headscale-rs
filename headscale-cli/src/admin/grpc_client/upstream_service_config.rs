// Copyright 2017, 2023 gRPC authors.
// Licensed under the Apache License, Version 2.0. See LICENSE-GRPC-GO and
// NOTICE-GRPC-GO in the headscale-cli package for the license and notices.

//! DNS service configuration following grpc-go v1.81.1.
//!
//! Selection, method paths and duration rules follow the pinned resolver and
//! service_config.go sources. Parsed retry policies feed unary replay;
//! readiness and balancing are handled by the connection lifecycle.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use rand_core::{OsRng, RngCore};
use serde_json::Value;

mod json;

pub(super) type SharedConfig = Arc<Mutex<ConfigState>>;

#[derive(Debug, Default)]
pub(super) struct ConfigState {
    current: Option<Arc<ServiceConfig>>,
    throttler: Option<Arc<RetryThrottler>>,
}

impl ConfigState {
    pub(super) fn update(&mut self, update: Result<Option<ServiceConfig>, String>) -> bool {
        match update {
            Ok(Some(config)) => {
                if self
                    .current
                    .as_ref()
                    .is_none_or(|old| old.raw != config.raw)
                {
                    self.current = Some(Arc::new(config));
                }
                self.reset_throttler();
                true
            }
            Ok(None) => {
                self.current
                    .get_or_insert_with(|| Arc::new(ServiceConfig::default()));
                self.reset_throttler();
                true
            }
            Err(_) => false,
        }
    }

    pub(super) fn current(&self) -> Option<Arc<ServiceConfig>> {
        self.current.clone()
    }

    pub(super) fn throttler(&self) -> Option<Arc<RetryThrottler>> {
        self.throttler.clone()
    }

    fn reset_throttler(&mut self) {
        // grpc-go installs a fresh bucket whenever it applies a service
        // configuration, including a missing-config/default reapplication.
        self.throttler = self
            .current
            .as_ref()
            .and_then(|config| config.throttling)
            .map(|settings| {
                Arc::new(RetryThrottler {
                    settings,
                    tokens: Mutex::new(settings.maximum),
                })
            });
    }
}

#[derive(Debug, Default)]
pub(super) struct ServiceConfig {
    raw: Vec<u8>,
    methods: BTreeMap<String, MethodConfig>,
    pub(super) shuffle_addresses: bool,
    pub(super) balancing: Balancing,
    throttling: Option<ThrottleSettings>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Balancing {
    #[default]
    PickFirst,
    RoundRobin,
}

#[derive(Clone, Debug, Default)]
pub(super) struct MethodConfig {
    pub(super) timeout_nanos: Option<i64>,
    pub(super) max_request: Option<i64>,
    pub(super) max_response: Option<i64>,
    pub(super) retry: Option<RetryPolicy>,
    pub(super) wait_for_ready: Option<bool>,
}

#[derive(Clone, Debug)]
pub(super) struct RetryPolicy {
    pub(super) maximum_attempts: u32,
    pub(super) initial_nanos: i64,
    pub(super) maximum_nanos: i64,
    pub(super) multiplier: f64,
    pub(super) codes: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
struct ThrottleSettings {
    maximum: f64,
    ratio: f64,
}

#[derive(Debug)]
pub(super) struct RetryThrottler {
    settings: ThrottleSettings,
    tokens: Mutex<f64>,
}

impl RetryThrottler {
    pub(super) fn failed(&self) -> bool {
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *tokens = (*tokens - 1.0).max(0.0);
        *tokens <= self.settings.maximum / 2.0
    }

    pub(super) fn succeeded(&self) {
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *tokens = (*tokens + self.settings.ratio).min(self.settings.maximum);
    }
}

impl ServiceConfig {
    pub(super) fn method(&self, name: &str) -> MethodConfig {
        self.methods
            .get(&format!("/headscale.v1.HeadscaleService/{name}"))
            .or_else(|| self.methods.get("/headscale.v1.HeadscaleService/"))
            .or_else(|| self.methods.get(""))
            .cloned()
            .unwrap_or_default()
    }
}

pub(super) fn select(records: &[Vec<u8>]) -> Result<Option<ServiceConfig>, String> {
    let text = records.concat();
    let Some(source) = text.strip_prefix(b"grpc_config=") else {
        return Ok(None);
    };
    let choices = json::choices(source)?;
    let hostname = hostname::get().map_err(|_| invalid())?;
    let hostname = hostname.to_str().ok_or_else(invalid)?;
    for choice in choices {
        let value = &choice.value;
        if strings(field(value, "clientLanguage"))?.is_some_and(|values| !values.contains(&"GO")) {
            continue;
        }
        if let Some(percent) = integer(field(value, "percentage"))?
            && i64::try_from(random_below(100) + 1).map_err(|_| invalid())? > percent
        {
            continue;
        }
        if strings(field(value, "clientHostName"))?
            .is_some_and(|values| !values.contains(&hostname))
        {
            continue;
        }
        if let Some(raw) = choice.service_config {
            let value = json::config(&raw)?;
            return parse(&value, raw).map(Some);
        }
    }
    // Go passes an empty selected string to ParseServiceConfig in this case.
    Err("no JSON service config provided".into())
}

fn parse(value: &Value, raw: Vec<u8>) -> Result<ServiceConfig, String> {
    object(value)?;
    let (balancing, shuffle_addresses) = balancer(value)?;
    let mut methods = BTreeMap::new();
    let method_configs = array(field(value, "methodConfig"))?;
    // Typed decoding happens even when the subsequent range checks are skipped
    // by Go's early return for an absent methodConfig list.
    let throttling = field(value, "retryThrottling");
    if let Some(throttling) = throttling {
        object(throttling)?;
    }
    let tokens = number(throttling.and_then(|value| field(value, "maxTokens")))?.unwrap_or(0.0);
    let ratio = number(throttling.and_then(|value| field(value, "tokenRatio")))?.unwrap_or(0.0);
    if let Some(health) = field(value, "healthCheckConfig") {
        object(health)?;
        string(field(health, "serviceName"))?;
        // The pinned standalone Go binary imports health/grpc_health_v1 but
        // not grpc/health, whose init registers internal.HealthCheckFunc.
        // Go validates this field but does not send health Watch RPCs there.
    }
    if let Some(configs) = method_configs {
        for config in configs {
            object(config)?;
            let names = array(field(config, "name"))?;
            let method = MethodConfig {
                timeout_nanos: duration(field(config, "timeout"))?,
                max_request: integer(field(config, "maxRequestMessageBytes"))?,
                max_response: integer(field(config, "maxResponseMessageBytes"))?,
                wait_for_ready: boolean(field(config, "waitForReady"))?,
                retry: field(config, "retryPolicy")
                    .map(|retry| parse_retry(retry, names.is_some()))
                    .transpose()?
                    .flatten(),
            };
            let Some(names) = names else {
                continue;
            };
            for name in names {
                object(name)?;
                let service = string(field(name, "service"))?.unwrap_or("");
                let name = string(field(name, "method"))?.unwrap_or("");
                if service.is_empty() && !name.is_empty() {
                    return Err("cannot combine empty 'service' and non-empty 'method'".into());
                }
                let path = if service.is_empty() {
                    String::new()
                } else {
                    format!("/{service}/{name}")
                };
                if methods.insert(path, method.clone()).is_some() {
                    return Err("duplicated name".into());
                }
            }
        }
        if throttling.is_some() && (!(tokens > 0.0 && tokens <= 1000.0) || ratio <= 0.0) {
            return Err("invalid retry throttling config".into());
        }
    }
    Ok(ServiceConfig {
        raw,
        methods,
        shuffle_addresses,
        balancing,
        throttling: throttling.map(|_| ThrottleSettings {
            maximum: tokens,
            ratio,
        }),
    })
}

fn balancer(value: &Value) -> Result<(Balancing, bool), String> {
    let legacy = string(field(value, "loadBalancingPolicy"))?;
    if let Some(configs) = field(value, "loadBalancingConfig") {
        let configs = configs.as_array().ok_or_else(invalid)?;
        for config in configs {
            let config = config.as_object().ok_or_else(invalid)?;
            if config.len() != 1 {
                return Err("invalid loadBalancingConfig entry".into());
            }
            let (name, config) = config.iter().next().ok_or_else(invalid)?;
            let name = balancer_name(name);
            match name.as_str() {
                "pick_first" => {
                    object(config)?;
                    return Ok((
                        Balancing::PickFirst,
                        boolean(field(config, "shuffleAddressList"))?.unwrap_or(false),
                    ));
                }
                "round_robin" => return Ok((Balancing::RoundRobin, false)),
                _ => {}
            }
        }
        return Err("invalid loadBalancingConfig: no supported policies".into());
    }
    Ok((
        if legacy.map(balancer_name).as_deref() == Some("round_robin") {
            Balancing::RoundRobin
        } else {
            Balancing::PickFirst
        },
        false,
    ))
}

fn balancer_name(name: &str) -> String {
    static CASE_SENSITIVE: OnceLock<bool> = OnceLock::new();
    let case_sensitive = *CASE_SENSITIVE.get_or_init(|| {
        std::env::var("GRPC_GO_EXPERIMENTAL_CASE_SENSITIVE_BALANCER_REGISTRIES")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
    });
    if case_sensitive {
        name.to_owned()
    } else {
        name.to_ascii_lowercase()
    }
}

fn parse_retry(value: &Value, check_ranges: bool) -> Result<Option<RetryPolicy>, String> {
    object(value)?;
    let attempts = integer(field(value, "maxAttempts"))?.unwrap_or(0);
    let initial = duration(field(value, "initialBackoff"))?.unwrap_or(0);
    let maximum = duration(field(value, "maxBackoff"))?.unwrap_or(0);
    let multiplier = number(field(value, "backoffMultiplier"))?.unwrap_or(0.0);
    let codes = array(field(value, "retryableStatusCodes"))?.unwrap_or_default();
    let decoded_codes = codes
        .iter()
        .map(retry_code)
        .collect::<Result<Vec<_>, _>>()?;
    if check_ranges
        && (attempts <= 1 || initial <= 0 || maximum <= 0 || multiplier <= 0.0 || codes.is_empty())
    {
        return Err("invalid retry policy".into());
    }
    Ok(check_ranges.then_some(RetryPolicy {
        maximum_attempts: attempts.clamp(0, 5) as u32,
        initial_nanos: initial,
        maximum_nanos: maximum,
        multiplier,
        codes: decoded_codes,
    }))
}

fn retry_code(code: &Value) -> Result<u32, String> {
    if code.is_null() {
        return Ok(0);
    }
    if let Some(name) = code.as_str() {
        const NAMES: [&str; 17] = [
            "OK",
            "CANCELLED",
            "UNKNOWN",
            "INVALID_ARGUMENT",
            "DEADLINE_EXCEEDED",
            "NOT_FOUND",
            "ALREADY_EXISTS",
            "PERMISSION_DENIED",
            "RESOURCE_EXHAUSTED",
            "FAILED_PRECONDITION",
            "ABORTED",
            "OUT_OF_RANGE",
            "UNIMPLEMENTED",
            "INTERNAL",
            "UNAVAILABLE",
            "DATA_LOSS",
            "UNAUTHENTICATED",
        ];
        return NAMES
            .iter()
            .position(|candidate| *candidate == name)
            .map(|code| code as u32)
            .ok_or_else(|| "invalid retry status code".into());
    }
    code.as_u64()
        .filter(|code| *code <= 16)
        .map(|code| code as u32)
        .ok_or_else(|| "invalid retry status code".into())
}

fn duration(value: Option<&Value>) -> Result<Option<i64>, String> {
    string(value)?.map(duration_nanos).transpose()
}

fn duration_nanos(value: &str) -> Result<i64, String> {
    let value = value.strip_suffix('s').ok_or_else(invalid)?;
    let (negative, value) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let mut parts = value.split('.');
    let seconds = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || (seconds.is_empty() && fraction.is_none_or(str::is_empty)) {
        return Err(invalid());
    }
    let mut seconds = if seconds.is_empty() {
        0
    } else {
        seconds.parse::<i64>().map_err(|_| invalid())?
    };
    if seconds > 315_576_000_000 {
        return Err(invalid());
    }
    let mut nanos = 0_i64;
    if let Some(fraction) = fraction.filter(|fraction| !fraction.is_empty()) {
        if fraction.len() > 9 {
            return Err(invalid());
        }
        nanos = fraction.parse::<i64>().map_err(|_| invalid())?;
        for _ in fraction.len()..9 {
            nanos *= 10;
        }
    }
    if negative {
        seconds = seconds.wrapping_neg();
        nanos = nanos.wrapping_neg();
    }
    if seconds > i64::MAX / 1_000_000_000
        || (seconds == i64::MAX / 1_000_000_000 && nanos >= i64::MAX % 1_000_000_000)
    {
        Ok(i64::MAX)
    } else if seconds < i64::MIN / 1_000_000_000
        || (seconds == i64::MIN / 1_000_000_000 && nanos <= i64::MIN % 1_000_000_000)
    {
        Ok(i64::MIN)
    } else {
        Ok(seconds.wrapping_mul(1_000_000_000).wrapping_add(nanos))
    }
}

pub(super) fn shuffle<T>(values: &mut [T]) {
    for end in (1..values.len()).rev() {
        values.swap(end, random_below(end + 1));
    }
}

pub(super) fn random_below(bound: usize) -> usize {
    let bound = bound as u64;
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let value = OsRng.next_u64();
        if value >= threshold {
            return (value % bound) as usize;
        }
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .get(name)
        .filter(|value| !value.is_null())
}
fn object(value: &Value) -> Result<(), String> {
    if value.is_object() || value.is_null() {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn string(value: Option<&Value>) -> Result<Option<&str>, String> {
    value
        .map(|value| value.as_str().ok_or_else(invalid))
        .transpose()
}
fn integer(value: Option<&Value>) -> Result<Option<i64>, String> {
    value
        .map(|value| value.as_i64().ok_or_else(invalid))
        .transpose()
}
fn number(value: Option<&Value>) -> Result<Option<f64>, String> {
    value
        .map(|value| value.as_f64().ok_or_else(invalid))
        .transpose()
}
fn boolean(value: Option<&Value>) -> Result<Option<bool>, String> {
    value
        .map(|value| value.as_bool().ok_or_else(invalid))
        .transpose()
}
fn array(value: Option<&Value>) -> Result<Option<&[Value]>, String> {
    value
        .map(|value| value.as_array().map(Vec::as_slice).ok_or_else(invalid))
        .transpose()
}
fn strings(value: Option<&Value>) -> Result<Option<Vec<&str>>, String> {
    array(value)?
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    if value.is_null() {
                        Ok("")
                    } else {
                        value.as_str().ok_or_else(invalid)
                    }
                })
                .collect()
        })
        .transpose()
}
fn invalid() -> String {
    "invalid DNS gRPC service configuration".into()
}

pub(super) trait RpcMethod {
    const NAME: &'static str;
}
macro_rules! rpc_methods {
    ($($request:ident => $method:ident),* $(,)?) => { $(
        impl RpcMethod for headscale_api::generated::$request { const NAME: &'static str = stringify!($method); }
    )* };
}
rpc_methods! {
    CreateUserRequest => CreateUser, RenameUserRequest => RenameUser, DeleteUserRequest => DeleteUser,
    ListUsersRequest => ListUsers, CreateApiKeyRequest => CreateApiKey, ListApiKeysRequest => ListApiKeys,
    ExpireApiKeyRequest => ExpireApiKey, DeleteApiKeyRequest => DeleteApiKey,
    CreatePreAuthKeyRequest => CreatePreAuthKey, ListPreAuthKeysRequest => ListPreAuthKeys,
    ExpirePreAuthKeyRequest => ExpirePreAuthKey, DeletePreAuthKeyRequest => DeletePreAuthKey,
    GetPolicyRequest => GetPolicy, SetPolicyRequest => SetPolicy, CheckPolicyRequest => CheckPolicy,
    ListNodesRequest => ListNodes, GetNodeRequest => GetNode, RegisterNodeRequest => RegisterNode,
    AuthRegisterRequest => AuthRegister, AuthApproveRequest => AuthApprove, AuthRejectRequest => AuthReject,
    DebugCreateNodeRequest => DebugCreateNode, SetTagsRequest => SetTags, SetApprovedRoutesRequest => SetApprovedRoutes,
    ExpireNodeRequest => ExpireNode, RenameNodeRequest => RenameNode, DeleteNodeRequest => DeleteNode,
    BackfillNodeIPsRequest => BackfillNodeIPs, HealthRequest => Health,
}
