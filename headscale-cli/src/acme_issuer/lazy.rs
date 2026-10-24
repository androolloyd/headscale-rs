// Copyright 2016 The Go Authors. All rights reserved.
// Native lifecycle adapts x/crypto/acme/autocert and renewal.go; see
// LICENSE-GO-STDLIB. ACME requests use the existing instant-acme transport.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use headscale_api::tailscale_wire::{
    WireError,
    tls::{self, AcmeCertificateKind, AcmeCertificateProvider, AcmeHandshakeRequest, TlsMaterial},
};
use rand_core::RngCore;
use tokio::sync::watch;
use tokio_rustls::rustls::ServerConfig;

use super::{
    AcmeHttp01ChallengeStore, AcmeHttp01IssuerConfig, certificate_key,
    certificate_request_with_key, load_or_create_native_account as load_or_create_account,
    native_order, write_bytes_atomically,
};

#[derive(Clone)]
struct Ready {
    config: Arc<ServerConfig>,
    key_pem: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

type Outcome = Result<Ready, String>;

#[derive(Clone, Default)]
struct Progress {
    result: Option<Outcome>,
    finished: bool,
    state_created: bool,
}

#[derive(Default)]
struct Slot {
    ready: Option<Ready>,
    pending: Option<watch::Receiver<Progress>>,
    failed_until: Option<tokio::time::Instant>,
    renewal_started: bool,
}

struct Inner {
    config: AcmeHttp01IssuerConfig,
    initial: TlsMaterial,
    http01: Option<AcmeHttp01ChallengeStore>,
    slots: Mutex<HashMap<AcmeCertificateKind, Slot>>,
    // Load/create one account lazily, then clone it before network operations.
    account: tokio::sync::Mutex<Option<instant_acme::Account>>,
    stop: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) struct LazyAcmeProvider(Arc<Inner>);

struct StopOnDrop(watch::Sender<bool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

pub(crate) struct LazyAcmeShutdown {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl LazyAcmeShutdown {
    pub(crate) fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.task.abort_handle()
    }
}

impl Drop for LazyAcmeShutdown {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.task.abort();
    }
}

impl LazyAcmeProvider {
    pub(crate) fn new(
        config: AcmeHttp01IssuerConfig,
        http01: Option<AcmeHttp01ChallengeStore>,
    ) -> Result<(Arc<Self>, LazyAcmeShutdown), WireError> {
        let initial = tls::load_lazy_acme_material(&config.cache_dir, &config.hostname)?;
        let (stop, _) = watch::channel(false);
        let on_drop = StopOnDrop(stop.clone());
        let task = tokio::spawn(async move {
            let _on_drop = on_drop;
            std::future::pending::<()>().await;
        });
        let shutdown = LazyAcmeShutdown {
            stop: stop.clone(),
            task,
        };
        Ok((
            Arc::new(Self(Arc::new(Inner {
                config,
                initial,
                http01,
                slots: Mutex::new(HashMap::new()),
                account: tokio::sync::Mutex::new(None),
                stop,
            }))),
            shutdown,
        ))
    }
}

impl AcmeCertificateProvider for LazyAcmeProvider {
    fn initial_material(&self) -> Result<TlsMaterial, WireError> {
        Ok(self.0.initial.clone())
    }

    fn prepare(
        &self,
        request: AcmeHandshakeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<ServerConfig>, WireError>> + Send + 'static>> {
        let inner = self.0.clone();
        Box::pin(async move {
            if *inner.stop.borrow() {
                return Err(wire("ACME manager is stopped"));
            }
            // Go applies HostPolicy before normal memory/cache lookup; token
            // handshakes use only the bound challenge resolver and never issue.
            if !request.allowed_for_hostname(&inner.config.hostname) {
                return Err(wire(format!(
                    "acme/autocert: host {} not configured in HostWhitelist",
                    headscale_api_acl::go_strconv::quote(&request.hostname)
                )));
            }
            if request.token {
                return Ok(inner.initial.server_config.clone());
            }
            let ready = obtain(inner, request.kind, false).await.map_err(wire)?;
            Ok(ready.config)
        })
    }
}

fn wire(message: impl Into<String>) -> WireError {
    WireError::Internal(message.into())
}

fn obtain(
    inner: Arc<Inner>,
    kind: AcmeCertificateKind,
    renewal: bool,
) -> Pin<Box<dyn Future<Output = Outcome> + Send>> {
    Box::pin(async move {
        let mut stop = inner.stop.subscribe();
        if *stop.borrow() {
            return Err("ACME manager is stopped".into());
        }
        let (mut receiver, is_owner) = {
            let mut slots = inner
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = slots.entry(kind).or_default();
            if !renewal {
                // Existing manager state is intentionally reused even after
                // NotAfter; only the renewal owner replaces it.
                if let Some(ready) = &slot.ready {
                    return Ok(ready.clone());
                }
                if slot
                    .failed_until
                    .is_some_and(|deadline| deadline > tokio::time::Instant::now())
                {
                    return Err("acme/autocert: missing certificate".into());
                }
            }
            if let Some(receiver) = &slot.pending {
                (receiver.clone(), false)
            } else {
                let (sender, receiver) = watch::channel(Progress::default());
                slot.pending = Some(receiver.clone());
                let old = slot.ready.clone();
                let owner = inner.clone();
                tokio::spawn(async move {
                    let mut stopping = owner.stop.subscribe();
                    let budget = if renewal { 600 } else { 300 };
                    let state_created = AtomicBool::new(false);
                    let result = if *stopping.borrow() {
                        Err("ACME manager is stopped".into())
                    } else {
                        tokio::select! {
                            biased;
                            _ = stopping.changed() => Err("ACME manager is stopped".into()),
                            result = tokio::time::timeout(Duration::from_secs(budget), materialize(&owner, kind, renewal, old.as_ref(), &state_created, &sender)) => match result {
                                Ok(result) => result.map_err(|error| format!("{error:#}")),
                                Err(_) => Err("ACME certificate preparation deadline exceeded".into()),
                            }
                        }
                    };
                    let start_renewal = {
                        let mut slots = owner
                            .slots
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let slot = slots.entry(kind).or_default();
                        slot.pending = None;
                        if let Ok(ready) = &result {
                            slot.ready = Some(ready.clone());
                            slot.failed_until = None;
                            let start = !slot.renewal_started && !*owner.stop.borrow();
                            slot.renewal_started = true;
                            start
                        } else {
                            if slot.ready.is_none() && state_created.load(Ordering::Relaxed) {
                                slot.failed_until =
                                    Some(tokio::time::Instant::now() + Duration::from_secs(60));
                            }
                            false
                        }
                    };
                    sender.send_replace(Progress {
                        result: Some(result),
                        finished: true,
                        state_created: state_created.load(Ordering::Relaxed),
                    });
                    if start_renewal {
                        spawn_renewal(Arc::downgrade(&owner), kind);
                    }
                });
                (receiver, true)
            }
        };
        loop {
            let progress = receiver.borrow().clone();
            if let Some(result) = progress.result {
                if progress.finished {
                    // Only the creating caller receives the authorization
                    // error. Existing state waiters observe tlscert's missing
                    // certificate, just as callers during the retry minute.
                    if !is_owner && progress.state_created && result.is_err() {
                        return Err("acme/autocert: missing certificate".into());
                    }
                    return result;
                }
                if !is_owner && !renewal && result.is_ok() {
                    return result;
                }
            }
            tokio::select! {
                biased;
                _ = stop.changed() => return Err("ACME manager is stopped".into()),
                result = receiver.changed() => if result.is_err() { return Err("ACME certificate owner stopped".into()); }
            }
        }
    })
}

async fn materialize(
    inner: &Arc<Inner>,
    kind: AcmeCertificateKind,
    renewal: bool,
    old: Option<&Ready>,
    state_created: &AtomicBool,
    progress: &watch::Sender<Progress>,
) -> anyhow::Result<Ready> {
    let cached =
        tls::lookup_autocert_certificate(&inner.config.cache_dir, &inner.config.hostname, kind);
    if !renewal && let Err(error) = &cached {
        return Err(anyhow::anyhow!(error.to_string()));
    }
    if let Ok(Some(cached)) = cached {
        let ready = Ready {
            config: Arc::new(tls::build_acme_selected_server_config(
                &cached.cert_pem,
                &cached.key_pem,
            )?),
            key_pem: cached.key_pem,
            not_before: cached.not_before,
            not_after: cached.expires_at,
        };
        if !renewal || renewal_delay(&ready) > Duration::ZERO {
            return Ok(ready);
        }
    }
    let key = certificate_key(kind, old.map(|ready| ready.key_pem.as_str()))?;
    // certState inserts only after successful key generation. Cache I/O and
    // private-key errors above, and key-generation failure, are not retained.
    state_created.store(true, Ordering::Relaxed);
    let request = certificate_request_with_key(&inner.config.hostname, &key)?;
    let account = {
        let mut account = inner.account.lock().await;
        if account.is_none() {
            *account = Some(load_or_create_account(&inner.config).await?);
        }
        account.as_ref().expect("ACME account initialized").clone()
    };
    let (key_pem, cert_pem) = native_order::issue(
        &inner.config,
        account,
        request,
        inner.http01.as_ref(),
        inner
            .initial
            .acme_tls_alpn_resolver
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ACME challenge resolver missing"))?,
    )
    .await?;
    // Validate the issued leaf/key/kind before touching the cache or memory.
    let valid = tls::validate_autocert_certificate(
        &inner.config.cache_dir,
        &inner.config.hostname,
        kind,
        &key_pem,
        &cert_pem,
    )?;
    let config = Arc::new(tls::build_acme_selected_server_config(
        &valid.cert_pem,
        &valid.key_pem,
    )?);
    let canonical = tls::autocert_cache_entry(&valid.key_pem, &valid.cert_pem)?;
    let ready = Ready {
        config,
        key_pem: valid.key_pem,
        not_before: valid.not_before,
        not_after: valid.expires_at,
    };
    if !renewal {
        // createCert unlocks valid state before GetCertificate's best-effort
        // cachePut, so other handshakes can already use the new certificate.
        let start_renewal = {
            let mut slots = inner
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = slots.entry(kind).or_default();
            slot.ready = Some(ready.clone());
            let start = !slot.renewal_started && !*inner.stop.borrow();
            slot.renewal_started = true;
            start
        };
        progress.send_replace(Progress {
            result: Some(Ok(ready.clone())),
            finished: false,
            state_created: true,
        });
        if start_renewal {
            spawn_renewal(Arc::downgrade(inner), kind);
        }
    }
    match write_bytes_atomically(&valid.cache_path, canonical.as_bytes()) {
        Ok(()) => {}
        Err(error) if !renewal => {
            tracing::warn!(%error, "ACME cache write failed; retaining issued certificate in memory");
        }
        Err(error) => return Err(error),
    }
    Ok(ready)
}

fn random_below(upper: u64) -> u64 {
    if upper == 0 {
        return 0;
    }
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = rand_core::OsRng.next_u64();
        if value >= threshold {
            return value % upper;
        }
    }
}

fn renewal_delay(ready: &Ready) -> Duration {
    let lifetime = (ready.not_after - ready.not_before)
        .num_nanoseconds()
        .unwrap_or(i64::MAX)
        .max(0) as u64;
    let threshold = (lifetime / 3).min(30 * 24 * 60 * 60 * 1_000_000_000);
    let jitter = random_below((threshold / 10).min(60 * 60 * 1_000_000_000));
    let at = ready.not_after - chrono::Duration::nanoseconds((threshold - jitter) as i64);
    (at - Utc::now()).to_std().unwrap_or(Duration::ZERO)
}

fn spawn_renewal(weak: Weak<Inner>, kind: AcmeCertificateKind) {
    tokio::spawn(async move {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let mut stop = inner.stop.subscribe();
        let mut delay = {
            let slots = inner
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slots
                .get(&kind)
                .and_then(|slot| slot.ready.as_ref())
                .map_or(Duration::ZERO, renewal_delay)
        };
        drop(inner);
        loop {
            if *stop.borrow() {
                return;
            }
            tokio::select! { biased; _ = stop.changed() => return, () = tokio::time::sleep(delay) => {} }
            let Some(inner) = weak.upgrade() else {
                return;
            };
            match obtain(inner, kind, true).await {
                Ok(ready) => delay = renewal_delay(&ready),
                Err(error) => {
                    tracing::warn!(%error, "ACME renewal failed; keeping existing certificate");
                    delay = Duration::from_nanos(
                        30 * 60 * 1_000_000_000 + random_below(30 * 60 * 1_000_000_000),
                    );
                }
            }
        }
    });
}
