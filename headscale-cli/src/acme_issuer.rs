use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use headscale_api::tailscale_wire::acme::AcmeHttp01ChallengeStore;
use headscale_api::tailscale_wire::tls::{
    self, AcmeTlsAlpnChallengeResolver, ReloadableServerConfig,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const ACCOUNT_CACHE_SUFFIX: &str = "instant-acme-account.json";
const ORDER_POLL_TIMEOUT: Duration = Duration::from_secs(90);
const CERTIFICATE_POLL_TIMEOUT: Duration = Duration::from_secs(90);
const CERTIFICATE_RENEWAL_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
const CERTIFICATE_RENEWAL_CHECK_MIN: Duration = Duration::from_secs(30 * 60);
const CERTIFICATE_RENEWAL_CHECK_MAX: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone)]
pub(crate) struct AcmeHttp01IssuerConfig {
    pub directory_url: String,
    pub email: Option<String>,
    pub hostname: String,
    pub cache_dir: PathBuf,
    pub ca_root_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcmeHttp01CertificateOutcome {
    pub cache_path: PathBuf,
    pub issued: bool,
}

#[derive(Clone)]
pub(crate) struct AcmeTlsReloaders {
    pub public_tls: ReloadableServerConfig,
    pub remote_grpc_tls: Option<ReloadableServerConfig>,
}

pub(crate) async fn ensure_http01_certificate(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    match tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) {
        Ok(material) if !certificate_is_expired(material.expires_at, Utc::now()) => {
            return Ok(AcmeHttp01CertificateOutcome {
                cache_path,
                issued: false,
            });
        }
        Ok(material) => {
            tracing::info!(
                hostname = %config.hostname,
                expires_at = %material.expires_at,
                "ACME HTTP-01 cached certificate is expired; starting online issuance"
            );
        }
        Err(err) => {
            tracing::info!(
                hostname = %config.hostname,
                cache_dir = %config.cache_dir.display(),
                error = %err,
                "ACME HTTP-01 cached certificate missing or invalid; starting online issuance"
            );
        }
    }

    tracing::info!(
        hostname = %config.hostname,
        cache_dir = %config.cache_dir.display(),
        directory_url = %config.directory_url,
        "ACME HTTP-01 online issuance started"
    );
    let (key_pem, certificate_pem) = issue_http01_certificate(config, store).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    tls::load_from_autocert_cache(&config.cache_dir, &config.hostname).with_context(|| {
        format!(
            "validate ACME cache entry {} after online issuance",
            cache_path.display()
        )
    })?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

pub(crate) async fn ensure_tls_alpn_certificate(
    config: &AcmeHttp01IssuerConfig,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    match tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) {
        Ok(material) if !certificate_is_expired(material.expires_at, Utc::now()) => {
            return Ok(AcmeHttp01CertificateOutcome {
                cache_path,
                issued: false,
            });
        }
        Ok(material) => {
            tracing::info!(
                hostname = %config.hostname,
                expires_at = %material.expires_at,
                "ACME TLS-ALPN-01 cached certificate is expired; starting online issuance"
            );
        }
        Err(err) => {
            tracing::info!(
                hostname = %config.hostname,
                cache_dir = %config.cache_dir.display(),
                error = %err,
                "ACME TLS-ALPN-01 cached certificate missing or invalid; starting online issuance"
            );
        }
    }

    tracing::info!(
        hostname = %config.hostname,
        cache_dir = %config.cache_dir.display(),
        directory_url = %config.directory_url,
        "ACME TLS-ALPN-01 online issuance started"
    );
    let (key_pem, certificate_pem) = issue_tls_alpn_certificate(config, resolver).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    tls::load_from_autocert_cache_with_tls_alpn(&config.cache_dir, &config.hostname).with_context(
        || {
            format!(
                "validate ACME TLS-ALPN cache entry {} after online issuance",
                cache_path.display()
            )
        },
    )?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

pub(crate) fn spawn_http01_renewal_task(
    config: AcmeHttp01IssuerConfig,
    store: AcmeHttp01ChallengeStore,
    reloaders: AcmeTlsReloaders,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            hostname = %config.hostname,
            cache_dir = %config.cache_dir.display(),
            "ACME HTTP-01 live renewal and TLS reload task started"
        );
        loop {
            match renew_http01_certificate_once(&config, &store, &reloaders).await {
                Ok(outcome) if outcome.issued => {
                    tracing::info!(
                        path = %outcome.cache_path.display(),
                        hostname = %config.hostname,
                        "ACME HTTP-01 certificate renewed and TLS configs reloaded"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        hostname = %config.hostname,
                        "ACME HTTP-01 renewal failed; keeping existing TLS material"
                    );
                }
            }

            let expires_at = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
                .ok()
                .map(|material| material.expires_at);
            tokio::time::sleep(next_renewal_check_delay(expires_at, Utc::now())).await;
        }
    })
}

pub(crate) fn spawn_tls_alpn_renewal_task(
    config: AcmeHttp01IssuerConfig,
    resolver: Arc<AcmeTlsAlpnChallengeResolver>,
    reloaders: AcmeTlsReloaders,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            hostname = %config.hostname,
            cache_dir = %config.cache_dir.display(),
            "ACME TLS-ALPN-01 live renewal and TLS reload task started"
        );
        loop {
            match renew_tls_alpn_certificate_once(&config, &resolver, &reloaders).await {
                Ok(outcome) if outcome.issued => {
                    tracing::info!(
                        path = %outcome.cache_path.display(),
                        hostname = %config.hostname,
                        "ACME TLS-ALPN-01 certificate renewed and TLS configs reloaded"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        hostname = %config.hostname,
                        "ACME TLS-ALPN-01 renewal failed; keeping existing TLS material"
                    );
                }
            }

            let expires_at = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
                .ok()
                .map(|material| material.expires_at);
            tokio::time::sleep(next_renewal_check_delay(expires_at, Utc::now())).await;
        }
    })
}

pub(crate) async fn renew_http01_certificate_once(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
    reloaders: &AcmeTlsReloaders,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    let Ok(material) = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) else {
        let outcome = ensure_http01_certificate(config, store).await?;
        if outcome.issued {
            reload_acme_tls_material(config, reloaders)?;
        }
        return Ok(outcome);
    };

    if !certificate_renewal_due(material.expires_at, Utc::now()) {
        return Ok(AcmeHttp01CertificateOutcome {
            cache_path,
            issued: false,
        });
    }

    tracing::info!(
        hostname = %config.hostname,
        expires_at = %material.expires_at,
        "ACME HTTP-01 cached certificate reached renewal window; starting online renewal"
    );
    let (key_pem, certificate_pem) = issue_http01_certificate(config, store).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write renewed ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    reload_acme_tls_material(config, reloaders)?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

pub(crate) async fn renew_tls_alpn_certificate_once(
    config: &AcmeHttp01IssuerConfig,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
    reloaders: &AcmeTlsReloaders,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    let Ok(material) = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) else {
        let outcome = ensure_tls_alpn_certificate(config, resolver).await?;
        if outcome.issued {
            reload_acme_tls_alpn_material(config, resolver, reloaders)?;
        }
        return Ok(outcome);
    };

    if !certificate_renewal_due(material.expires_at, Utc::now()) {
        return Ok(AcmeHttp01CertificateOutcome {
            cache_path,
            issued: false,
        });
    }

    tracing::info!(
        hostname = %config.hostname,
        expires_at = %material.expires_at,
        "ACME TLS-ALPN-01 cached certificate reached renewal window; starting online renewal"
    );
    let (key_pem, certificate_pem) = issue_tls_alpn_certificate(config, resolver).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write renewed ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    reload_acme_tls_alpn_material(config, resolver, reloaders)?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

fn reload_acme_tls_material(
    config: &AcmeHttp01IssuerConfig,
    reloaders: &AcmeTlsReloaders,
) -> Result<tls::TlsMaterial> {
    let material = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
        .with_context(|| {
            format!(
                "load renewed ACME cache entry for hostname {} from {}",
                config.hostname,
                config.cache_dir.display()
            )
        })?;
    reloaders
        .public_tls
        .replace(Arc::clone(&material.server_config));
    if let Some(remote_grpc_tls) = &reloaders.remote_grpc_tls {
        let grpc_tls = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
            .context("build renewed remote gRPC TLS config")?;
        remote_grpc_tls.replace(Arc::new(grpc_tls));
    }
    Ok(material)
}

pub(crate) fn reload_acme_tls_alpn_material(
    config: &AcmeHttp01IssuerConfig,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
    reloaders: &AcmeTlsReloaders,
) -> Result<tls::TlsMaterial> {
    let material = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
        .with_context(|| {
            format!(
                "load renewed ACME TLS-ALPN cache entry for hostname {} from {}",
                config.hostname,
                config.cache_dir.display()
            )
        })?;
    let (public_tls, _) = tls::build_server_config_with_existing_acme_tls_alpn_resolver(
        &material.cert_pem,
        &material.key_pem,
        resolver.clone(),
    )
    .context("build renewed public TLS config with ACME TLS-ALPN resolver")?;
    reloaders.public_tls.replace(Arc::new(public_tls));
    if let Some(remote_grpc_tls) = &reloaders.remote_grpc_tls {
        let grpc_tls = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
            .context("build renewed remote gRPC TLS config")?;
        remote_grpc_tls.replace(Arc::new(grpc_tls));
    }
    Ok(material)
}

fn certificate_is_expired(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now
}

fn certificate_renewal_due(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now + chrono::Duration::seconds(CERTIFICATE_RENEWAL_WINDOW_SECS)
}

fn next_renewal_check_delay(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Duration {
    let Some(expires_at) = expires_at else {
        return CERTIFICATE_RENEWAL_CHECK_MIN;
    };
    let renewal_at = expires_at - chrono::Duration::seconds(CERTIFICATE_RENEWAL_WINDOW_SECS);
    let seconds_until_renewal = (renewal_at - now).num_seconds();
    if seconds_until_renewal <= 0 {
        return CERTIFICATE_RENEWAL_CHECK_MIN;
    }

    let candidate = Duration::from_secs(seconds_until_renewal as u64);
    candidate.clamp(CERTIFICATE_RENEWAL_CHECK_MIN, CERTIFICATE_RENEWAL_CHECK_MAX)
}

async fn issue_http01_certificate(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
) -> Result<(String, String)> {
    let account = load_or_create_account(config).await?;
    let identifiers = [Identifier::Dns(config.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .with_context(|| format!("create ACME order for {}", config.hostname))?;
    let mut cleanup = ChallengeCleanup::new(store.clone());

    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .with_context(|| format!("fetch ACME authorization for {}", config.hostname))?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                bail!(
                    "ACME authorization for {} is {:?}, expected pending or valid",
                    config.hostname,
                    authorization.status
                );
            }

            let mut challenge =
                authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| {
                        anyhow::anyhow!("ACME server did not offer HTTP-01 for {}", config.hostname)
                    })?;
            let token = challenge.token.clone();
            if token.is_empty() {
                bail!(
                    "ACME HTTP-01 challenge for {} did not include a token",
                    config.hostname
                );
            }
            let key_authorization = challenge.key_authorization().as_str().to_string();
            store.insert(token.clone(), key_authorization);
            cleanup.track(token);
            challenge.set_ready().await.with_context(|| {
                format!("mark ACME HTTP-01 challenge ready for {}", config.hostname)
            })?;
        }
    }

    match order
        .poll_ready(&RetryPolicy::new().timeout(ORDER_POLL_TIMEOUT))
        .await
        .with_context(|| format!("wait for ACME order readiness for {}", config.hostname))?
    {
        OrderStatus::Ready | OrderStatus::Valid => {}
        status => bail!(
            "ACME order for {} reached {:?}, expected ready",
            config.hostname,
            status
        ),
    }

    let key_pem = order
        .finalize()
        .await
        .with_context(|| format!("finalize ACME order for {}", config.hostname))?;
    let certificate_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(CERTIFICATE_POLL_TIMEOUT))
        .await
        .with_context(|| format!("retrieve ACME certificate for {}", config.hostname))?;
    Ok((key_pem, certificate_pem))
}

async fn issue_tls_alpn_certificate(
    config: &AcmeHttp01IssuerConfig,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
) -> Result<(String, String)> {
    let account = load_or_create_account(config).await?;
    let identifiers = [Identifier::Dns(config.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .with_context(|| format!("create ACME order for {}", config.hostname))?;
    let mut cleanup = TlsAlpnChallengeCleanup::new(resolver.clone());

    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .with_context(|| format!("fetch ACME authorization for {}", config.hostname))?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                bail!(
                    "ACME authorization for {} is {:?}, expected pending or valid",
                    config.hostname,
                    authorization.status
                );
            }

            let mut challenge = authorization
                .challenge(ChallengeType::TlsAlpn01)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "ACME server did not offer TLS-ALPN-01 for {}",
                        config.hostname
                    )
                })?;
            let key_authorization = challenge.key_authorization().as_str().to_string();
            let (challenge_cert_pem, challenge_key_pem) =
                tls::build_acme_tls_alpn_challenge_certificate(
                    &config.hostname,
                    &key_authorization,
                )
                .with_context(|| {
                    format!(
                        "build ACME TLS-ALPN-01 challenge certificate for {}",
                        config.hostname
                    )
                })?;
            resolver
                .set_challenge_certificate(
                    config.hostname.clone(),
                    &challenge_cert_pem,
                    &challenge_key_pem,
                )
                .with_context(|| {
                    format!(
                        "install ACME TLS-ALPN-01 challenge certificate for {}",
                        config.hostname
                    )
                })?;
            cleanup.track(config.hostname.clone());
            challenge.set_ready().await.with_context(|| {
                format!(
                    "mark ACME TLS-ALPN-01 challenge ready for {}",
                    config.hostname
                )
            })?;
        }
    }

    match order
        .poll_ready(&RetryPolicy::new().timeout(ORDER_POLL_TIMEOUT))
        .await
        .with_context(|| format!("wait for ACME order readiness for {}", config.hostname))?
    {
        OrderStatus::Ready | OrderStatus::Valid => {}
        status => bail!(
            "ACME order for {} reached {:?}, expected ready",
            config.hostname,
            status
        ),
    }

    let key_pem = order
        .finalize()
        .await
        .with_context(|| format!("finalize ACME order for {}", config.hostname))?;
    let certificate_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(CERTIFICATE_POLL_TIMEOUT))
        .await
        .with_context(|| format!("retrieve ACME certificate for {}", config.hostname))?;
    Ok((key_pem, certificate_pem))
}

async fn load_or_create_account(config: &AcmeHttp01IssuerConfig) -> Result<Account> {
    let account_path =
        account_cache_path(&config.cache_dir, &config.hostname, &config.directory_url);
    if let Ok(bytes) = fs::read(&account_path) {
        match serde_json::from_slice::<AccountCredentials>(&bytes) {
            Ok(credentials) => match account_builder(config)?.from_credentials(credentials).await {
                Ok(account) => return Ok(account),
                Err(err) => {
                    tracing::warn!(
                        path = %account_path.display(),
                        error = %err,
                        "failed to restore cached ACME account credentials; creating a new account"
                    );
                }
            },
            Err(err) => {
                tracing::warn!(
                    path = %account_path.display(),
                    error = %err,
                    "failed to parse cached ACME account credentials; creating a new account"
                );
            }
        }
    }

    let contact = config.email.as_deref().and_then(acme_contact_uri);
    let contacts = contact.iter().map(String::as_str).collect::<Vec<_>>();
    let new_account = NewAccount {
        contact: &contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = account_builder(config)?
        .create(&new_account, config.directory_url.clone(), None)
        .await
        .with_context(|| format!("create ACME account at {}", config.directory_url))?;
    write_json_atomically(&account_path, &credentials).with_context(|| {
        format!(
            "write ACME account credentials cache {}",
            account_path.display()
        )
    })?;
    Ok(account)
}

fn account_builder(config: &AcmeHttp01IssuerConfig) -> Result<instant_acme::AccountBuilder> {
    match &config.ca_root_path {
        Some(path) => Account::builder_with_root(path)
            .with_context(|| format!("build ACME HTTP client with root {}", path.display())),
        None => Account::builder().context("build ACME HTTP client"),
    }
}

fn acme_contact_uri(email: &str) -> Option<String> {
    let email = email.trim();
    if email.is_empty() {
        None
    } else if email.contains(':') {
        Some(email.to_string())
    } else {
        Some(format!("mailto:{email}"))
    }
}

fn write_autocert_cache_entry(
    cache_dir: &Path,
    hostname: &str,
    key_pem: &str,
    certificate_pem: &str,
) -> Result<()> {
    let cache_path = autocert_cache_path(cache_dir, hostname);
    let mut combined = String::with_capacity(key_pem.len() + certificate_pem.len() + 1);
    combined.push_str(key_pem.trim_end());
    combined.push('\n');
    combined.push_str(certificate_pem.trim_start());
    write_bytes_atomically(&cache_path, combined.as_bytes())
}

fn write_json_atomically<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_atomically(path, &bytes)
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create cache directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{:016x}", OsRng.next_u64()));
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("create temporary cache file {}", tmp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write temporary cache file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync temporary cache file {}", tmp_path.display()))?;
    }
    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod temporary cache file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "rename temporary cache file {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn autocert_cache_path(cache_dir: &Path, hostname: &str) -> PathBuf {
    cache_dir.join(clean_autocert_name(hostname))
}

fn account_cache_path(cache_dir: &Path, hostname: &str, directory_url: &str) -> PathBuf {
    let digest = Sha256::digest(directory_url.as_bytes());
    let directory_hash = hex::encode(&digest[..8]);
    cache_dir.join(format!(
        "{}.{directory_hash}.{ACCOUNT_CACHE_SUFFIX}",
        clean_autocert_name(hostname)
    ))
}

fn clean_autocert_name(name: &str) -> String {
    let clean = name
        .trim()
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    if clean.is_empty() {
        "acme-empty-hostname".to_string()
    } else {
        clean
    }
}

struct ChallengeCleanup {
    store: AcmeHttp01ChallengeStore,
    tokens: Vec<String>,
}

impl ChallengeCleanup {
    fn new(store: AcmeHttp01ChallengeStore) -> Self {
        Self {
            store,
            tokens: Vec::new(),
        }
    }

    fn track(&mut self, token: String) {
        self.tokens.push(token);
    }
}

impl Drop for ChallengeCleanup {
    fn drop(&mut self) {
        for token in &self.tokens {
            self.store.remove(token);
        }
    }
}

struct TlsAlpnChallengeCleanup {
    resolver: Arc<AcmeTlsAlpnChallengeResolver>,
    hostnames: Vec<String>,
}

impl TlsAlpnChallengeCleanup {
    fn new(resolver: Arc<AcmeTlsAlpnChallengeResolver>) -> Self {
        Self {
            resolver,
            hostnames: Vec::new(),
        }
    }

    fn track(&mut self, hostname: String) {
        self.hostnames.push(hostname);
    }
}

impl Drop for TlsAlpnChallengeCleanup {
    fn drop(&mut self) {
        for hostname in &self.hostnames {
            self.resolver.clear_challenge_certificate(hostname);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::extract::State;
    use axum::http::header::{CONTENT_TYPE, LOCATION};
    use axum::http::{HeaderName, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, head, post};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hyper_util::rt::TokioIo;
    use serde_json::{Value, json};
    use tempfile::tempdir;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls;
    use tower::ServiceExt;

    const LOCAL_ACME_HOSTNAME: &str = "headscale.test";
    const LOCAL_ACME_TOKEN: &str = "hsrs-token";
    const REPLAY_NONCE: HeaderName = HeaderName::from_static("replay-nonce");

    #[derive(Clone, Copy)]
    enum LocalAcmeChallenge {
        Http01,
        TlsAlpn01,
    }

    impl LocalAcmeChallenge {
        fn acme_name(self) -> &'static str {
            match self {
                Self::Http01 => "http-01",
                Self::TlsAlpn01 => "tls-alpn-01",
            }
        }
    }

    struct LocalAcmeCa {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
    }

    impl LocalAcmeCa {
        fn new() -> Self {
            install_test_crypto_provider();
            let mut params =
                rcgen::CertificateParams::new(vec!["headscale-rs test ACME CA".into()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "headscale-rs test ACME CA");
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            Self { cert, key }
        }

        fn root_pem(&self) -> String {
            self.cert.pem()
        }

        fn server_config(&self) -> rustls::ServerConfig {
            install_test_crypto_provider();
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "localhost");
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
            let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
            );
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key_der)
                .unwrap()
        }

        fn sign_csr(&self, csr_der: Vec<u8>) -> Result<String> {
            let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(csr_der);
            let csr = rcgen::CertificateSigningRequestParams::from_der(&csr_der)
                .context("parse ACME finalize CSR")?;
            let cert = csr
                .signed_by(&self.cert, &self.key)
                .context("sign ACME finalize CSR")?;
            Ok(cert.pem())
        }
    }

    #[derive(Clone)]
    struct LocalAcmeState {
        base_url: String,
        challenge: LocalAcmeChallenge,
        ca: Arc<LocalAcmeCa>,
        http_store: Option<AcmeHttp01ChallengeStore>,
        tls_resolver: Option<Arc<AcmeTlsAlpnChallengeResolver>>,
        challenge_seen: Arc<AtomicBool>,
        finalized: Arc<AtomicBool>,
        cert_pem: Arc<Mutex<Option<String>>>,
    }

    impl LocalAcmeState {
        fn url(&self, path: &str) -> String {
            format!("{}/{}", self.base_url, path.trim_start_matches('/'))
        }

        fn order_body(&self, status: &str) -> Value {
            json!({
                "status": status,
                "authorizations": [self.url("authz/1")],
                "finalize": self.url("finalize/1"),
                "certificate": if self.finalized.load(Ordering::SeqCst) {
                    Value::String(self.url("cert/1"))
                } else {
                    Value::Null
                }
            })
        }

        fn authorization_body(&self, status: &str) -> Value {
            json!({
                "identifier": {
                    "type": "dns",
                    "value": LOCAL_ACME_HOSTNAME
                },
                "status": status,
                "challenges": [{
                    "type": self.challenge.acme_name(),
                    "url": self.url("challenge/1"),
                    "token": LOCAL_ACME_TOKEN,
                    "status": status
                }]
            })
        }

        fn validate_challenge_material(&self) -> Result<()> {
            match self.challenge {
                LocalAcmeChallenge::Http01 => {
                    let key_authorization = self
                        .http_store
                        .as_ref()
                        .and_then(|store| store.get(LOCAL_ACME_TOKEN))
                        .context("HTTP-01 key authorization was not installed")?;
                    if !key_authorization.starts_with(&format!("{LOCAL_ACME_TOKEN}.")) {
                        bail!(
                            "HTTP-01 key authorization {key_authorization:?} does not match token"
                        );
                    }
                }
                LocalAcmeChallenge::TlsAlpn01 => {
                    let resolver = self
                        .tls_resolver
                        .as_ref()
                        .context("TLS-ALPN resolver was not provided")?;
                    if !resolver.has_challenge_certificate(LOCAL_ACME_HOSTNAME) {
                        bail!("TLS-ALPN challenge certificate was not installed");
                    }
                }
            }
            Ok(())
        }
    }

    struct LocalAcmeServer {
        directory_url: String,
        ca_root_path: PathBuf,
        _ca_dir: tempfile::TempDir,
        challenge_seen: Arc<AtomicBool>,
        finalized: Arc<AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl LocalAcmeServer {
        async fn spawn_http01(store: AcmeHttp01ChallengeStore) -> Self {
            Self::spawn(LocalAcmeChallenge::Http01, Some(store), None).await
        }

        async fn spawn_tls_alpn(resolver: Arc<AcmeTlsAlpnChallengeResolver>) -> Self {
            Self::spawn(LocalAcmeChallenge::TlsAlpn01, None, Some(resolver)).await
        }

        async fn spawn(
            challenge: LocalAcmeChallenge,
            http_store: Option<AcmeHttp01ChallengeStore>,
            tls_resolver: Option<Arc<AcmeTlsAlpnChallengeResolver>>,
        ) -> Self {
            install_test_crypto_provider();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let base_url = format!("https://localhost:{port}");
            let challenge_seen = Arc::new(AtomicBool::new(false));
            let finalized = Arc::new(AtomicBool::new(false));
            let ca = Arc::new(LocalAcmeCa::new());
            let ca_dir = tempdir().unwrap();
            let ca_root_path = ca_dir.path().join("root.pem");
            fs::write(&ca_root_path, ca.root_pem()).unwrap();
            let tls_config = ca.server_config();
            let state = LocalAcmeState {
                base_url: base_url.clone(),
                challenge,
                ca,
                http_store,
                tls_resolver,
                challenge_seen: challenge_seen.clone(),
                finalized: finalized.clone(),
                cert_pem: Arc::new(Mutex::new(None)),
            };
            let app = axum::Router::new()
                .route("/directory", get(local_acme_directory))
                .route("/new-nonce", head(local_acme_nonce))
                .route("/new-account", post(local_acme_new_account))
                .route("/new-order", post(local_acme_new_order))
                .route("/authz/1", post(local_acme_authorization))
                .route("/challenge/1", post(local_acme_challenge_ready))
                .route("/order/1", post(local_acme_order))
                .route("/finalize/1", post(local_acme_finalize))
                .route("/cert/1", post(local_acme_certificate))
                .with_state(state);
            let task = tokio::spawn(async move {
                serve_local_acme_tls(listener, app, tls_config).await;
            });
            Self {
                directory_url: format!("{base_url}/directory"),
                ca_root_path,
                _ca_dir: ca_dir,
                challenge_seen,
                finalized,
                task,
            }
        }

        fn challenge_seen(&self) -> bool {
            self.challenge_seen.load(Ordering::SeqCst)
        }

        fn finalized(&self) -> bool {
            self.finalized.load(Ordering::SeqCst)
        }
    }

    async fn serve_local_acme_tls(
        listener: tokio::net::TcpListener,
        app: axum::Router,
        tls_config: rustls::ServerConfig,
    ) {
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        loop {
            let Ok((tcp, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let req =
                                axum::http::Request::from_parts(parts, axum::body::Body::new(body));
                            app.oneshot(req)
                                .await
                                .map_err(|err| std::io::Error::other(err.to_string()))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    }

    impl Drop for LocalAcmeServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn local_acme_directory(State(state): State<LocalAcmeState>) -> Response {
        json_response(
            StatusCode::OK,
            None,
            json!({
                "newNonce": state.url("new-nonce"),
                "newAccount": state.url("new-account"),
                "newOrder": state.url("new-order"),
                "revokeCert": state.url("revoke-cert"),
                "keyChange": state.url("key-change")
            }),
        )
    }

    async fn local_acme_nonce() -> Response {
        let mut response = StatusCode::OK.into_response();
        add_replay_nonce(response.headers_mut());
        response
    }

    async fn local_acme_new_account(State(state): State<LocalAcmeState>) -> Response {
        json_response(StatusCode::CREATED, Some(state.url("account/1")), json!({}))
    }

    async fn local_acme_new_order(
        State(state): State<LocalAcmeState>,
        Json(body): Json<Value>,
    ) -> Response {
        let payload = match decode_jose_payload(&body) {
            Ok(payload) => payload,
            Err(err) => return problem_response(&format!("{err:#}")),
        };
        let identifier = payload
            .get("identifiers")
            .and_then(Value::as_array)
            .and_then(|identifiers| identifiers.first())
            .cloned()
            .unwrap_or(Value::Null);
        if identifier.get("type").and_then(Value::as_str) != Some("dns")
            || identifier.get("value").and_then(Value::as_str) != Some(LOCAL_ACME_HOSTNAME)
        {
            return problem_response(&format!("unexpected ACME identifier payload: {payload:?}"));
        }

        json_response(
            StatusCode::CREATED,
            Some(state.url("order/1")),
            state.order_body("pending"),
        )
    }

    async fn local_acme_authorization(State(state): State<LocalAcmeState>) -> Response {
        let status = if state.challenge_seen.load(Ordering::SeqCst) {
            "valid"
        } else {
            "pending"
        };
        json_response(StatusCode::OK, None, state.authorization_body(status))
    }

    async fn local_acme_challenge_ready(State(state): State<LocalAcmeState>) -> Response {
        if let Err(err) = state.validate_challenge_material() {
            return problem_response(&format!("{err:#}"));
        }
        state.challenge_seen.store(true, Ordering::SeqCst);
        json_response(StatusCode::OK, None, challenge_body(&state, "valid"))
    }

    async fn local_acme_order(State(state): State<LocalAcmeState>) -> Response {
        let status = if state.finalized.load(Ordering::SeqCst) {
            "valid"
        } else if state.challenge_seen.load(Ordering::SeqCst) {
            "ready"
        } else {
            "pending"
        };
        json_response(StatusCode::OK, None, state.order_body(status))
    }

    async fn local_acme_finalize(
        State(state): State<LocalAcmeState>,
        Json(body): Json<Value>,
    ) -> Response {
        let payload = match decode_jose_payload(&body) {
            Ok(payload) => payload,
            Err(err) => return problem_response(&format!("{err:#}")),
        };
        let Some(csr) = payload.get("csr").and_then(Value::as_str) else {
            return problem_response(&format!("missing finalize CSR in payload: {payload:?}"));
        };
        let csr_der = match URL_SAFE_NO_PAD.decode(csr.as_bytes()) {
            Ok(csr_der) => csr_der,
            Err(err) => return problem_response(&format!("decode finalize CSR: {err}")),
        };
        let cert_pem = match state.ca.sign_csr(csr_der) {
            Ok(cert_pem) => cert_pem,
            Err(err) => return problem_response(&format!("{err:#}")),
        };
        *state.cert_pem.lock().unwrap() = Some(cert_pem);
        state.finalized.store(true, Ordering::SeqCst);
        json_response(StatusCode::OK, None, state.order_body("valid"))
    }

    async fn local_acme_certificate(State(state): State<LocalAcmeState>) -> Response {
        let Some(cert_pem) = state.cert_pem.lock().unwrap().clone() else {
            return problem_response("certificate requested before finalize");
        };
        let mut response = (StatusCode::OK, cert_pem).into_response();
        add_replay_nonce(response.headers_mut());
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/pem-certificate-chain"),
        );
        response
    }

    fn challenge_body(state: &LocalAcmeState, status: &str) -> Value {
        json!({
            "type": state.challenge.acme_name(),
            "url": state.url("challenge/1"),
            "token": LOCAL_ACME_TOKEN,
            "status": status
        })
    }

    fn json_response(status: StatusCode, location: Option<String>, body: Value) -> Response {
        let mut response = (status, Json(body)).into_response();
        add_replay_nonce(response.headers_mut());
        if let Some(location) = location {
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_str(&location).unwrap());
        }
        response
    }

    fn problem_response(detail: &str) -> Response {
        json_response(
            StatusCode::BAD_REQUEST,
            None,
            json!({
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": detail,
                "status": 400
            }),
        )
    }

    fn add_replay_nonce(headers: &mut axum::http::HeaderMap) {
        headers.insert(REPLAY_NONCE, HeaderValue::from_static("hsrs-nonce"));
    }

    fn decode_jose_payload(body: &Value) -> Result<Value> {
        let payload = body
            .get("payload")
            .and_then(Value::as_str)
            .context("missing JWS payload")?;
        if payload.is_empty() {
            return Ok(json!({}));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .context("decode JWS payload")?;
        serde_json::from_slice(&decoded).context("parse JWS payload")
    }

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn acme_contact_uri_wraps_plain_email() {
        assert_eq!(
            acme_contact_uri("ops@example.com").as_deref(),
            Some("mailto:ops@example.com")
        );
        assert_eq!(
            acme_contact_uri("mailto:ops@example.com").as_deref(),
            Some("mailto:ops@example.com")
        );
        assert_eq!(acme_contact_uri("   "), None);
    }

    #[test]
    fn account_cache_path_depends_on_directory_url() {
        let cache_dir = Path::new("/tmp/acme");
        let production = account_cache_path(
            cache_dir,
            "headscale.example",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        let staging = account_cache_path(
            cache_dir,
            "headscale.example",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );

        assert_ne!(production, staging);
        assert!(production.starts_with(cache_dir));
        assert!(
            production
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("headscale.example.")
                    && name.ends_with(ACCOUNT_CACHE_SUFFIX))
        );
    }

    #[test]
    fn write_autocert_cache_entry_matches_go_dircache_layout() {
        let dir = tempdir().unwrap();
        write_autocert_cache_entry(
            dir.path(),
            "headscale.example",
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let path = dir.path().join("headscale.example");
        let bytes = fs::read_to_string(path).unwrap();
        assert_eq!(
            bytes,
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn challenge_cleanup_removes_tracked_tokens() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token", "token.thumbprint");
        {
            let mut cleanup = ChallengeCleanup::new(store.clone());
            cleanup.track("token".to_string());
        }

        assert_eq!(store.get("token"), None);
    }

    #[test]
    fn tls_alpn_challenge_cleanup_removes_tracked_hostnames() {
        let dir = tempdir().unwrap();
        let generated = tls::load_or_generate(
            dir.path().join("generated"),
            &tls::SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        let challenge = tls::load_or_generate(
            dir.path().join("challenge"),
            &tls::SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        let (_server_config, resolver) = tls::build_server_config_with_acme_tls_alpn_resolver(
            &generated.cert_pem,
            &generated.key_pem,
        )
        .unwrap();
        resolver
            .set_challenge_certificate("headscale.example", &challenge.cert_pem, &challenge.key_pem)
            .unwrap();
        {
            let mut cleanup = TlsAlpnChallengeCleanup::new(resolver.clone());
            cleanup.track("headscale.example".to_string());
        }

        assert!(!resolver.has_challenge_certificate("headscale.example"));
    }

    #[test]
    fn certificate_renewal_due_uses_thirty_day_window() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        assert!(certificate_is_expired(now, now));
        assert!(certificate_renewal_due(
            now + chrono::Duration::days(29),
            now
        ));
        assert!(certificate_renewal_due(
            now + chrono::Duration::days(30),
            now
        ));
        assert!(!certificate_renewal_due(
            now + chrono::Duration::days(31),
            now
        ));
    }

    #[test]
    fn next_renewal_check_delay_is_clamped() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        assert_eq!(
            next_renewal_check_delay(None, now),
            CERTIFICATE_RENEWAL_CHECK_MIN
        );
        assert_eq!(
            next_renewal_check_delay(Some(now + chrono::Duration::days(1)), now),
            CERTIFICATE_RENEWAL_CHECK_MIN
        );
        assert_eq!(
            next_renewal_check_delay(
                Some(now + chrono::Duration::days(30) + chrono::Duration::minutes(45)),
                now
            ),
            Duration::from_secs(45 * 60)
        );
        assert_eq!(
            next_renewal_check_delay(Some(now + chrono::Duration::days(90)), now),
            CERTIFICATE_RENEWAL_CHECK_MAX
        );
    }

    #[tokio::test]
    async fn ensure_http01_certificate_reuses_valid_cached_material() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        let generated = tls::load_or_generate(
            &source_dir,
            &tls::SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        write_autocert_cache_entry(
            &cache_dir,
            "headscale.example",
            &generated.key_pem,
            &generated.cert_pem,
        )
        .unwrap();
        let config = AcmeHttp01IssuerConfig {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            email: None,
            hostname: "headscale.example".into(),
            cache_dir: cache_dir.clone(),
            ca_root_path: None,
        };

        let outcome = ensure_http01_certificate(&config, &AcmeHttp01ChallengeStore::new())
            .await
            .unwrap();

        assert_eq!(outcome.cache_path, cache_dir.join("headscale.example"));
        assert!(!outcome.issued);
    }

    #[tokio::test]
    async fn ensure_http01_certificate_issues_against_local_acme_directory() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let store = AcmeHttp01ChallengeStore::new();
        let server = LocalAcmeServer::spawn_http01(store.clone()).await;
        let config = AcmeHttp01IssuerConfig {
            directory_url: server.directory_url.clone(),
            email: Some("ops@example.com".into()),
            hostname: LOCAL_ACME_HOSTNAME.into(),
            cache_dir: cache_dir.clone(),
            ca_root_path: Some(server.ca_root_path.clone()),
        };

        let outcome = ensure_http01_certificate(&config, &store).await.unwrap();

        assert!(outcome.issued);
        assert_eq!(outcome.cache_path, cache_dir.join(LOCAL_ACME_HOSTNAME));
        assert!(server.challenge_seen());
        assert!(server.finalized());
        assert_eq!(store.get(LOCAL_ACME_TOKEN), None);
        let material = tls::load_from_autocert_cache(&cache_dir, LOCAL_ACME_HOSTNAME).unwrap();
        assert!(material.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[tokio::test]
    async fn ensure_tls_alpn_certificate_reuses_valid_cached_material() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        let generated = tls::load_or_generate(
            &source_dir,
            &tls::SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        write_autocert_cache_entry(
            &cache_dir,
            "headscale.example",
            &generated.key_pem,
            &generated.cert_pem,
        )
        .unwrap();
        let (_server_config, resolver) = tls::build_server_config_with_acme_tls_alpn_resolver(
            &generated.cert_pem,
            &generated.key_pem,
        )
        .unwrap();
        let config = AcmeHttp01IssuerConfig {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            email: None,
            hostname: "headscale.example".into(),
            cache_dir: cache_dir.clone(),
            ca_root_path: None,
        };

        let outcome = ensure_tls_alpn_certificate(&config, &resolver)
            .await
            .unwrap();

        assert_eq!(outcome.cache_path, cache_dir.join("headscale.example"));
        assert!(!outcome.issued);
    }

    #[tokio::test]
    async fn ensure_tls_alpn_certificate_issues_against_local_acme_directory() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        let generated = tls::load_or_generate(
            &source_dir,
            &tls::SanConfig::with_hostname(LOCAL_ACME_HOSTNAME),
        )
        .unwrap();
        let (_server_config, resolver) = tls::build_server_config_with_acme_tls_alpn_resolver(
            &generated.cert_pem,
            &generated.key_pem,
        )
        .unwrap();
        let server = LocalAcmeServer::spawn_tls_alpn(resolver.clone()).await;
        let config = AcmeHttp01IssuerConfig {
            directory_url: server.directory_url.clone(),
            email: Some("ops@example.com".into()),
            hostname: LOCAL_ACME_HOSTNAME.into(),
            cache_dir: cache_dir.clone(),
            ca_root_path: Some(server.ca_root_path.clone()),
        };

        let outcome = ensure_tls_alpn_certificate(&config, &resolver)
            .await
            .unwrap();

        assert!(outcome.issued);
        assert_eq!(outcome.cache_path, cache_dir.join(LOCAL_ACME_HOSTNAME));
        assert!(server.challenge_seen());
        assert!(server.finalized());
        assert!(!resolver.has_challenge_certificate(LOCAL_ACME_HOSTNAME));
        let material =
            tls::load_from_autocert_cache_with_tls_alpn(&cache_dir, LOCAL_ACME_HOSTNAME).unwrap();
        assert!(material.acme_tls_alpn_resolver.is_some());
    }
}
