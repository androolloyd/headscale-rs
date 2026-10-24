// Copyright 2016 The Go Authors. All rights reserved.
// Order/challenge sequencing adapts x/crypto/acme/autocert.verifyRFC;
// see LICENSE-GO-STDLIB. HTTP transport/polling uses instant-acme.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use headscale_api::tailscale_wire::{
    acme::AcmeHttp01ChallengeStore,
    tls::{self, AcmeTlsAlpnChallengeResolver},
};
use headscale_api_acl::go_strconv::quote;
use instant_acme::{Account, Identifier, NewOrder, Order, OrderStatus};

use super::{
    AcmeHttp01IssuerConfig, CertificateRequest, ChallengeCleanup, TlsAlpnChallengeCleanup,
};

// The provider owner supplies the enclosing five/ten-minute context. Keep
// local polling within its largest budget without adding an earlier 90s cap.
const POLL_BUDGET: Duration = Duration::from_secs(600);

pub(super) async fn issue(
    config: &AcmeHttp01IssuerConfig,
    account: Account,
    request: CertificateRequest,
    store: Option<&AcmeHttp01ChallengeStore>,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
) -> Result<(String, String)> {
    let hostname = tls::autocert_cache_hostname(&config.hostname)?;
    let mut order = authorize_order(&account, &hostname, store, resolver).await?;
    order
        .go_finalize_csr(&request.csr)
        .await
        .context("finalize ACME certificate request")?;
    // Go's CreateOrderCert: `if o.Status != StatusValid { o, err = WaitOrder }`.
    // A missing order resource cannot be valid, so it also waits.
    if order
        .go_resource()
        .is_none_or(|wire| wire.status != "valid")
    {
        wait_order(&mut order).await?;
    }
    // Go: "The only acceptable status post finalize and WaitOrder is valid",
    // otherwise it returns an OrderError.
    if order
        .go_resource()
        .is_none_or(|wire| wire.status != "valid")
    {
        bail!("ACME finalized order is not valid");
    }
    let certificate_pem = order
        .go_certificate()
        .await
        .context("retrieve ACME certificate")?;
    Ok((request.key_pem, certificate_pem))
}

enum AuthorizationAction {
    Skip,
    Accepted,
    RetryOrder,
}

async fn authorize_order(
    account: &Account,
    hostname: &str,
    store: Option<&AcmeHttp01ChallengeStore>,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
) -> Result<Order> {
    let mut next_type = 0;
    let mut pending_cleanup = PendingAuthorizations::default();
    // Go retains all successful fulfillment cleanups until verifyRFC returns,
    // including those from abandoned orders, then cleans up before finalizing.
    let mut http_cleanup = store.map(|store| ChallengeCleanup::new(store.clone()));
    let mut tls_cleanup = TlsAlpnChallengeCleanup::new(resolver.clone());

    'orders: loop {
        let identifiers = [Identifier::Dns(hostname.to_owned())];
        let resource = account
            .go_new_order_resource(&NewOrder::new(&identifiers))
            .await
            .context("create ACME order")?;
        let urls = resource.authorization_urls.clone();
        pending_cleanup.0.push((account.clone(), urls.clone()));
        match resource.status.as_str() {
            "ready" => return Ok(resource.order?),
            "pending" => {}
            _ => bail!(
                "acme/autocert: invalid new order status {}; order URL: {}",
                quote(&resource.status),
                quote(&resource.location),
            ),
        }
        let mut order = resource.order?;

        for url in urls {
            match fulfill_authorization(
                account,
                &url,
                hostname,
                &mut next_type,
                store,
                resolver,
                &mut http_cleanup,
                &mut tls_cleanup,
            )
            .await?
            {
                AuthorizationAction::Skip => continue,
                AuthorizationAction::RetryOrder => continue 'orders,
                AuthorizationAction::Accepted => {}
            }
            if wait_authorization(account, &url).await.is_err() {
                continue 'orders;
            }
        }
        if wait_order(&mut order).await.is_err() {
            continue;
        }
        return Ok(order);
    }
}

#[allow(clippy::too_many_arguments)]
async fn fulfill_authorization(
    account: &Account,
    url: &str,
    hostname: &str,
    next_type: &mut usize,
    store: Option<&AcmeHttp01ChallengeStore>,
    resolver: &Arc<AcmeTlsAlpnChallengeResolver>,
    http_cleanup: &mut Option<ChallengeCleanup>,
    tls_cleanup: &mut TlsAlpnChallengeCleanup,
) -> Result<AuthorizationAction> {
    // Initial GetAuthorization errors are fatal, unlike polling decode errors.
    let authorization = account
        .go_authorization_resource(url)
        .await
        .context("fetch ACME authorization")?;
    if authorization.status != "pending" {
        return Ok(AuthorizationAction::Skip);
    }

    let mut selected = None;
    let types = if store.is_some() { 2 } else { 1 };
    while selected.is_none() && *next_type < types {
        let candidate = if *next_type == 0 {
            "tls-alpn-01"
        } else {
            "http-01"
        };
        *next_type += 1;
        selected = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == candidate);
    }
    let Some(challenge) = selected else {
        bail!(
            "acme/autocert: unable to satisfy {} for domain {}: no viable challenge type found",
            quote(url),
            quote(hostname)
        );
    };
    let key_authorization = format!("{}.{}", challenge.token, account.key_thumbprint());
    if challenge.kind == "http-01" {
        let token = challenge.token.clone();
        store
            .context("HTTP-01 challenge store missing")?
            .insert(token.clone(), key_authorization);
        http_cleanup
            .as_mut()
            .context("HTTP-01 challenge cleanup missing")?
            .track(token);
    } else {
        let fulfilled = (|| -> Result<()> {
            let (cert_pem, key_pem) =
                tls::build_acme_tls_alpn_challenge_certificate(hostname, &key_authorization)?;
            resolver.set_challenge_certificate(hostname.to_owned(), &cert_pem, &key_pem)?;
            Ok(())
        })();
        if fulfilled.is_err() {
            return Ok(AuthorizationAction::RetryOrder);
        }
        tls_cleanup.track(hostname.to_owned());
    }
    if account.go_accept_challenge(&challenge.url).await.is_err() {
        return Ok(AuthorizationAction::RetryOrder);
    }
    Ok(AuthorizationAction::Accepted)
}

async fn wait_authorization(account: &Account, url: &str) -> Result<()> {
    tokio::time::timeout(POLL_BUDGET, async {
        loop {
            let response = account.go_poll_authorization_resource(url).await?;
            let delay = response.retry_delay();
            match response.decoded {
                Ok(state) if state.status == "valid" => return Ok(()),
                Ok(state) if state.status == "invalid" => {
                    bail!("ACME authorization is invalid")
                }
                // Body/JSON decode failure belongs to this polling phase:
                // retry the same URL, not a new authorization/order.
                Ok(_) | Err(_) => tokio::time::sleep(delay).await,
            }
        }
    })
    .await
    .context("wait for ACME authorization deadline")?
}

async fn wait_order(order: &mut Order) -> Result<()> {
    tokio::time::timeout(POLL_BUDGET, async {
        loop {
            let response = order.go_poll().await?;
            let delay = response.retry_delay();
            match response.decoded {
                Ok(OrderStatus::Ready | OrderStatus::Valid) => return Ok(()),
                Ok(OrderStatus::Invalid) => bail!("ACME order is invalid"),
                Ok(_) | Err(_) => tokio::time::sleep(delay).await,
            }
        }
    })
    .await
    .context("wait for ACME order deadline")?
}

/// Each successful AuthorizeOrder registers cleanup before its status is
/// inspected. Drop also runs when the owning issuance future is cancelled.
#[derive(Default)]
struct PendingAuthorizations(Vec<(Account, Vec<String>)>);

impl Drop for PendingAuthorizations {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // Go's verifyRFC defers launch in reverse order; each order receives a
        // detached five-minute cleanup context, independent of caller shutdown.
        for (account, urls) in std::mem::take(&mut self.0).into_iter().rev() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(300), async {
                    for url in urls {
                        // Direct POST-as-GET, then deactivate ONLY Pending.
                        // Valid/invalid/expired authorizations are untouched.
                        let _ = account.go_deactivate_pending_authorization(&url).await;
                    }
                })
                .await;
            });
        }
    }
}
