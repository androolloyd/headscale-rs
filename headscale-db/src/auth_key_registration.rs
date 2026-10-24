//! Commit auth-key consumption and its node mutation together.
//!
//! Native captured-key entry points follow Go's save-then-claim transaction.
//! Candidate-only callers capture one verified model before the write transaction.
//! Failed writes roll back both the node and the single-use key.

use chrono::Utc;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{DbError, headscale_nodes, preauth_keys};
use headscale_nodes::{CreateParams, HeadscaleNodeRow};
use preauth_keys::{PreauthKeyRow, UseError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Credential(#[from] UseError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("node authorization state changed during registration; retry registration")]
    Conflict,
    #[error("{context}: {source}")]
    Operation {
        context: &'static str,
        #[source]
        source: DbError,
    },
}

/// Key state captured by the authenticated read. No bearer/hash or mutable
/// database credential fields are needed to claim its one-shot use.
#[derive(Clone, Debug)]
pub struct CapturedAuthKey {
    pub id: i64,
    pub reusable: bool,
    pub used: Arc<AtomicBool>,
}

fn saving_node(source: impl Into<DbError>) -> Error {
    Error::Operation {
        context: "saving node",
        source: source.into(),
    }
}

fn updating_used(source: sqlx::Error) -> Error {
    Error::Operation {
        context: "using pre auth key: updating key used status in database",
        source: source.into(),
    }
}

async fn claim_captured_sqlite(
    conn: &mut SqliteConnection,
    key: &CapturedAuthKey,
    fresh: bool,
) -> Result<(), Error> {
    if key.reusable || (!fresh && key.used.load(Ordering::Acquire)) {
        return Ok(());
    }
    let changed = sqlx::query("UPDATE pre_auth_keys SET used = true WHERE id = ? AND used = false")
        .bind(key.id)
        .execute(&mut *conn)
        .await
        .map_err(updating_used)?
        .rows_affected();
    if changed == 0 {
        return Err(UseError::AlreadyUsed.into());
    }
    // Go mutates the captured PreAuthKey pointer after SQL succeeds, before
    // the surrounding commit. A failed commit does not reset that pointer.
    key.used.store(true, Ordering::Release);
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn claim_captured_postgres(
    conn: &mut PgConnection,
    key: &CapturedAuthKey,
    fresh: bool,
) -> Result<(), Error> {
    if key.reusable || (!fresh && key.used.load(Ordering::Acquire)) {
        return Ok(());
    }
    let changed =
        sqlx::query("UPDATE pre_auth_keys SET used = true WHERE id = $1 AND used = false")
            .bind(key.id)
            .execute(&mut *conn)
            .await
            .map_err(updating_used)?
            .rows_affected();
    if changed == 0 {
        return Err(UseError::AlreadyUsed.into());
    }
    // Go mutates the captured PreAuthKey pointer after SQL succeeds, before
    // the surrounding commit. A failed commit does not reset that pointer.
    key.used.store(true, Ordering::Release);
    Ok(())
}

/// Existing cache-selected node: save its selected columns, then claim only
/// an unused one-shot key. A missing SQL node remains a valid no-op save.
pub async fn commit_cached_sqlite_with_key(
    pool: &SqlitePool,
    prior: &HeadscaleNodeRow,
    registration: headscale_nodes::CachedNodeRegistration,
    key: &CapturedAuthKey,
) -> Result<(), Error> {
    if registration.node.id != prior.id
        || !matches!(registration.auth_key, headscale_nodes::RegistrationAuthKey::Set(Some(id)) if id == key.id)
    {
        return Err(Error::Conflict);
    }
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    headscale_nodes::save_cached_registration_on_connection(&mut tx, registration)
        .await
        .map_err(saving_node)?;
    claim_captured_sqlite(&mut tx, key, false).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_new_sqlite_with_key(
    pool: &SqlitePool,
    node: headscale_nodes::NewNodeRegistration,
    key: &CapturedAuthKey,
) -> Result<HeadscaleNodeRow, Error> {
    if node.auth_key_id != Some(key.id) {
        return Err(Error::Conflict);
    }
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    let node = headscale_nodes::create_new_registration_on_connection(&mut tx, node)
        .await
        .map_err(saving_node)?;
    claim_captured_sqlite(&mut tx, key, true).await?;
    tx.commit().await?;
    Ok(node)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_cached_postgres_with_key(
    pool: &PgPool,
    prior: &HeadscaleNodeRow,
    registration: headscale_nodes::CachedNodeRegistration,
    key: &CapturedAuthKey,
) -> Result<(), Error> {
    if registration.node.id != prior.id
        || !matches!(registration.auth_key, headscale_nodes::RegistrationAuthKey::Set(Some(id)) if id == key.id)
    {
        return Err(Error::Conflict);
    }
    let mut tx = pool.begin().await.map_err(saving_node)?;
    headscale_nodes::save_postgres_cached_registration_on_connection(&mut tx, registration)
        .await
        .map_err(saving_node)?;
    claim_captured_postgres(&mut tx, key, false).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_new_postgres_with_key(
    pool: &PgPool,
    node: headscale_nodes::NewNodeRegistration,
    key: &CapturedAuthKey,
) -> Result<HeadscaleNodeRow, Error> {
    if node.auth_key_id != Some(key.id) {
        return Err(Error::Conflict);
    }
    let mut tx = pool.begin().await.map_err(saving_node)?;
    let node = headscale_nodes::create_postgres_new_registration_on_connection(&mut tx, node)
        .await
        .map_err(saving_node)?;
    claim_captured_postgres(&mut tx, key, true).await?;
    tx.commit().await?;
    Ok(node)
}

pub async fn commit_new_sqlite_with_associations(
    pool: &SqlitePool,
    node: headscale_nodes::NewNodeRegistration,
    key: &CapturedAuthKey,
    mut material: preauth_keys::RegistrationKey,
) -> Result<headscale_nodes::NewNodeSave, Error> {
    if node.auth_key_id != Some(key.id) || material.key.id != key.id {
        return Err(Error::Conflict);
    }
    material.key.reusable = key.reusable;
    material.key.used_at = key
        .used
        .load(Ordering::Acquire)
        .then_some(material.key.expiration.unwrap_or(material.key.created_at));
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    let mut saved = headscale_nodes::create_new_registration_with_associations_on_connection(
        &mut transaction,
        node,
        headscale_nodes::NewNodeAssociations::AuthKey(Box::new(material)),
    )
    .await
    .map_err(saving_node)?;
    let effective_key = CapturedAuthKey {
        id: saved.node.auth_key_id.ok_or(Error::Conflict)?,
        reusable: key.reusable,
        used: key.used.clone(),
    };
    claim_captured_sqlite(&mut transaction, &effective_key, true).await?;
    if !key.reusable {
        saved.note_key_used();
    }
    transaction.commit().await?;
    Ok(saved)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_new_postgres_with_associations(
    pool: &PgPool,
    node: headscale_nodes::NewNodeRegistration,
    key: &CapturedAuthKey,
    mut material: preauth_keys::RegistrationKey,
) -> Result<headscale_nodes::NewNodeSave, Error> {
    if node.auth_key_id != Some(key.id) || material.key.id != key.id {
        return Err(Error::Conflict);
    }
    material.key.reusable = key.reusable;
    material.key.used_at = key
        .used
        .load(Ordering::Acquire)
        .then_some(material.key.expiration.unwrap_or(material.key.created_at));
    let mut transaction = pool.begin().await.map_err(saving_node)?;
    let mut saved =
        headscale_nodes::create_postgres_new_registration_with_associations_on_connection(
            &mut transaction,
            node,
            headscale_nodes::NewNodeAssociations::AuthKey(Box::new(material)),
        )
        .await
        .map_err(saving_node)?;
    let effective_key = CapturedAuthKey {
        id: saved.node.auth_key_id.ok_or(Error::Conflict)?,
        reusable: key.reusable,
        used: key.used.clone(),
    };
    claim_captured_postgres(&mut transaction, &effective_key, true).await?;
    if !key.reusable {
        saved.note_key_used();
    }
    transaction.commit().await?;
    Ok(saved)
}

/// Headless adapters retain their SQL-selected node contract while using the
/// original authenticated key model instead of a second credential lookup.
pub async fn commit_sqlite_with_captured_associations(
    pool: &SqlitePool,
    expected: Option<&HeadscaleNodeRow>,
    mut params: CreateParams,
    key: &CapturedAuthKey,
    mut material: preauth_keys::RegistrationKey,
    require_fresh: bool,
) -> Result<headscale_nodes::NewNodeSave, Error> {
    params.canonicalize_keys()?;
    if params.auth_key_id != Some(key.id) || material.key.id != key.id {
        return Err(Error::Conflict);
    }
    material.key.reusable = key.reusable;
    material.key.used_at = key
        .used
        .load(Ordering::Acquire)
        .then_some(material.key.expiration.unwrap_or(material.key.created_at));
    let fresh = needs_fresh_key(expected, &material.key, &params, require_fresh)?;
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    let mut saved = if let Some(expected) = expected {
        let current: HeadscaleNodeRow =
            sqlx::query_as(&headscale_nodes::node_select("WHERE id = ?"))
                .bind(expected.id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(Error::Conflict)?;
        if !unchanged_authorization(expected, &current)? {
            return Err(Error::Conflict);
        }
        let node = headscale_nodes::update_from_auth_path_on_connection(
            &mut transaction,
            current.id,
            params,
        )
        .await
        .map_err(saving_node)?;
        headscale_nodes::NewNodeSave {
            node,
            associations: headscale_nodes::NewNodeAssociations::None,
        }
    } else {
        headscale_nodes::create_with_associations_on_connection(
            &mut transaction,
            params,
            headscale_nodes::NewNodeAssociations::AuthKey(Box::new(material)),
        )
        .await
        .map_err(saving_node)?
    };
    let effective_key = CapturedAuthKey {
        id: saved.node.auth_key_id.ok_or(Error::Conflict)?,
        reusable: key.reusable,
        used: key.used.clone(),
    };
    claim_captured_sqlite(&mut transaction, &effective_key, fresh).await?;
    if fresh && !key.reusable {
        saved.note_key_used();
    }
    transaction.commit().await?;
    Ok(saved)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_postgres_with_captured_associations(
    pool: &PgPool,
    expected: Option<&HeadscaleNodeRow>,
    mut params: CreateParams,
    key: &CapturedAuthKey,
    mut material: preauth_keys::RegistrationKey,
    require_fresh: bool,
) -> Result<headscale_nodes::NewNodeSave, Error> {
    params.canonicalize_keys()?;
    if params.auth_key_id != Some(key.id) || material.key.id != key.id {
        return Err(Error::Conflict);
    }
    material.key.reusable = key.reusable;
    material.key.used_at = key
        .used
        .load(Ordering::Acquire)
        .then_some(material.key.expiration.unwrap_or(material.key.created_at));
    let fresh = needs_fresh_key(expected, &material.key, &params, require_fresh)?;
    let mut transaction = pool.begin().await.map_err(saving_node)?;
    let mut saved = if let Some(expected) = expected {
        let current: HeadscaleNodeRow = sqlx::query_as(&headscale_nodes::postgres_node_select(
            "WHERE id = $1 FOR UPDATE",
        ))
        .bind(expected.id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(Error::Conflict)?;
        if !unchanged_authorization(expected, &current)? {
            return Err(Error::Conflict);
        }
        let node = headscale_nodes::update_postgres_from_auth_path_on_connection(
            &mut transaction,
            current.id,
            params,
        )
        .await
        .map_err(saving_node)?;
        headscale_nodes::NewNodeSave {
            node,
            associations: headscale_nodes::NewNodeAssociations::None,
        }
    } else {
        headscale_nodes::create_postgres_with_associations_on_connection(
            &mut transaction,
            params,
            headscale_nodes::NewNodeAssociations::AuthKey(Box::new(material)),
        )
        .await
        .map_err(saving_node)?
    };
    let effective_key = CapturedAuthKey {
        id: saved.node.auth_key_id.ok_or(Error::Conflict)?,
        reusable: key.reusable,
        used: key.used.clone(),
    };
    claim_captured_postgres(&mut transaction, &effective_key, fresh).await?;
    if fresh && !key.reusable {
        saved.note_key_used();
    }
    transaction.commit().await?;
    Ok(saved)
}

impl Error {
    pub fn headscale_go_message(&self) -> String {
        match self {
            Self::Database(error) => error.headscale_go_message(),
            Self::Operation { context, source } => {
                format!("{context}: {}", source.headscale_go_message())
            }
            error => error.to_string(),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.into())
    }
}

fn unchanged_authorization(
    before: &HeadscaleNodeRow,
    current: &HeadscaleNodeRow,
) -> Result<bool, Error> {
    let before_tags = before.try_tag_list()?;
    let current_tags = current.try_tag_list()?;
    Ok(before.try_machine_key()? == current.try_machine_key()?
        && before.try_node_key()? == current.try_node_key()?
        && before.user_id == current.user_id
        && before_tags == current_tags
        && before.auth_key_id == current.auth_key_id
        && before.expiry_text == current.expiry_text)
}

fn validate_key_binding(key: &PreauthKeyRow, params: &CreateParams) -> Result<(), Error> {
    if params.auth_key_id != Some(key.id) {
        return Err(UseError::NotFound.into());
    }
    if params.tags.is_empty()
        && params.user_id.map(|id| id.to_string()).as_deref() != Some(key.user_id.as_str())
    {
        return Err(UseError::NotFound.into());
    }
    Ok(())
}

fn capture_verified_key(key: &PreauthKeyRow) -> CapturedAuthKey {
    CapturedAuthKey {
        id: key.id,
        reusable: key.reusable,
        used: Arc::new(AtomicBool::new(key.used_at.is_some())),
    }
}

fn needs_fresh_key(
    current: Option<&HeadscaleNodeRow>,
    key: &PreauthKeyRow,
    params: &CreateParams,
    require_fresh: bool,
) -> Result<bool, Error> {
    if require_fresh {
        return Ok(true);
    }
    let Some(node) = current else {
        return Ok(true);
    };
    let tagged = !node.try_tag_list()?.is_empty();
    let expired = preauth_keys::node_timestamp_is_expired(
        node.expiry,
        node.expiry_text.as_deref(),
        Utc::now(),
    );
    Ok(node.try_node_key()? != params.node_key
        || node.try_machine_key()? != params.machine_key
        || (!tagged && expired)
        || (!key.try_tag_list()?.is_empty() && (!tagged || node.auth_key_id != Some(key.id))))
}

fn validate_proposed_tags(
    current: Option<&HeadscaleNodeRow>,
    key: &PreauthKeyRow,
    params: &CreateParams,
) -> Result<(), Error> {
    let key_tags = key.try_tag_list()?;
    let current_tags = current.map(HeadscaleNodeRow::try_tag_list).transpose()?;
    let mut expected_tags = match (current, current_tags) {
        (Some(node), Some(tags))
            if key_tags.is_empty() || (!tags.is_empty() && node.auth_key_id == Some(key.id)) =>
        {
            tags
        }
        _ => key_tags,
    };
    let mut proposed_tags = params.tags.clone();
    expected_tags.sort();
    expected_tags.dedup();
    proposed_tags.sort();
    proposed_tags.dedup();
    if expected_tags != proposed_tags || (!proposed_tags.is_empty() && params.user_id.is_some()) {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_live_key(key: &PreauthKeyRow) -> Result<(), Error> {
    if key.is_expired_at(Utc::now()) {
        return Err(UseError::Expired.into());
    }
    if key.is_used() {
        return Err(UseError::AlreadyUsed.into());
    }
    Ok(())
}

/// Candidate-only adapters validate their one captured read before saving it.
/// Serving callers that already validated an original lookup use the captured
/// commit entry points directly and do not revalidate at write time.
pub fn validate_captured_registration_key(
    prior: Option<&HeadscaleNodeRow>,
    key: &PreauthKeyRow,
    params: &CreateParams,
    require_fresh: bool,
) -> Result<(), Error> {
    validate_key_binding(key, params)?;
    validate_proposed_tags(prior, key, params)?;
    if needs_fresh_key(prior, key, params, require_fresh)? {
        validate_live_key(key)?;
    }
    Ok(())
}

fn cached_key_params(
    registration: &headscale_nodes::CachedNodeRegistration,
) -> Result<CreateParams, Error> {
    let headscale_nodes::RegistrationAuthKey::Set(Some(auth_key_id)) = registration.auth_key else {
        return Err(Error::Conflict);
    };
    let mut params = CreateParams {
        machine_key: registration.node.machine_key.clone(),
        node_key: registration.node.node_key.clone(),
        disco_key: registration.node.disco_key.clone(),
        user_id: registration.node.user_id,
        tags: registration.node.tags.clone().unwrap_or_default(),
        auth_key_id: Some(auth_key_id),
        ..CreateParams::default()
    };
    params.canonicalize_keys()?;
    Ok(params)
}

fn new_key_params(node: &headscale_nodes::NewNodeRegistration) -> Result<CreateParams, Error> {
    let mut params = CreateParams {
        machine_key: node.machine_key.clone(),
        node_key: node.node_key.clone(),
        disco_key: node.disco_key.clone(),
        user_id: node.user_id,
        tags: node.tags.clone().unwrap_or_default(),
        auth_key_id: node.auth_key_id,
        ..CreateParams::default()
    };
    params.canonicalize_keys()?;
    Ok(params)
}

/// Fresh registration inserts its original node fields and consumes the key
/// before commit. The returned projection has its ID but no SQL name lookup
/// or row reread; live PutNode name resolution happens after this returns.
pub async fn commit_new_sqlite(
    pool: &SqlitePool,
    node: headscale_nodes::NewNodeRegistration,
    candidate: &str,
) -> Result<HeadscaleNodeRow, Error> {
    let params = new_key_params(&node)?;
    let material = preauth_keys::get_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(None, &material.key, &params)?;
    validate_live_key(&material.key)?;
    let key = capture_verified_key(&material.key);
    commit_new_sqlite_with_associations(pool, node, &key, material)
        .await
        .map(|saved| saved.node)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_new_postgres(
    pool: &PgPool,
    node: headscale_nodes::NewNodeRegistration,
    candidate: &str,
) -> Result<HeadscaleNodeRow, Error> {
    let params = new_key_params(&node)?;
    let material = preauth_keys::get_postgres_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(None, &material.key, &params)?;
    validate_live_key(&material.key)?;
    let key = capture_verified_key(&material.key);
    commit_new_postgres_with_associations(pool, node, &key, material)
        .await
        .map(|saved| saved.node)
}

/// Existing-node registration from a live NodeStore snapshot. Credential rows
/// are captured once before the transaction. Node identity/tags/expiry come
/// from the cache, and a missing SQL node row is a valid no-op save.
pub async fn commit_cached_sqlite(
    pool: &SqlitePool,
    prior: &HeadscaleNodeRow,
    registration: headscale_nodes::CachedNodeRegistration,
    candidate: &str,
    require_fresh: bool,
) -> Result<(), Error> {
    if registration.node.id != prior.id {
        return Err(Error::Conflict);
    }
    let params = cached_key_params(&registration)?;
    let material = preauth_keys::get_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(Some(prior), &material.key, &params)?;
    let fresh = needs_fresh_key(Some(prior), &material.key, &params, require_fresh)?;
    if fresh {
        validate_live_key(&material.key)?;
    }
    let key = capture_verified_key(&material.key);
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    headscale_nodes::save_cached_registration_on_connection(&mut transaction, registration)
        .await
        .map_err(saving_node)?;
    claim_captured_sqlite(&mut transaction, &key, fresh).await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_cached_postgres(
    pool: &PgPool,
    prior: &HeadscaleNodeRow,
    registration: headscale_nodes::CachedNodeRegistration,
    candidate: &str,
    require_fresh: bool,
) -> Result<(), Error> {
    if registration.node.id != prior.id {
        return Err(Error::Conflict);
    }
    let params = cached_key_params(&registration)?;
    let material = preauth_keys::get_postgres_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(Some(prior), &material.key, &params)?;
    let fresh = needs_fresh_key(Some(prior), &material.key, &params, require_fresh)?;
    if fresh {
        validate_live_key(&material.key)?;
    }
    let key = capture_verified_key(&material.key);
    let mut transaction = pool.begin().await.map_err(saving_node)?;
    headscale_nodes::save_postgres_cached_registration_on_connection(
        &mut transaction,
        registration,
    )
    .await
    .map_err(saving_node)?;
    claim_captured_postgres(&mut transaction, &key, fresh).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn commit_sqlite(
    pool: &SqlitePool,
    expected: Option<&HeadscaleNodeRow>,
    mut params: CreateParams,
    candidate: &str,
    require_fresh: bool,
) -> Result<HeadscaleNodeRow, Error> {
    params.canonicalize_keys()?;
    let material = preauth_keys::get_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(expected, &material.key, &params)?;
    if needs_fresh_key(expected, &material.key, &params, require_fresh)? {
        validate_live_key(&material.key)?;
    }
    let key = capture_verified_key(&material.key);
    commit_sqlite_with_captured_associations(pool, expected, params, &key, material, require_fresh)
        .await
        .map(|saved| saved.node)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn commit_postgres(
    pool: &PgPool,
    expected: Option<&HeadscaleNodeRow>,
    mut params: CreateParams,
    candidate: &str,
    require_fresh: bool,
) -> Result<HeadscaleNodeRow, Error> {
    params.canonicalize_keys()?;
    let material = preauth_keys::get_postgres_by_token_for_registration(pool, candidate)
        .await
        .map_err(|_| Error::Credential(UseError::NotFound))?;
    validate_key_binding(&material.key, &params)?;
    validate_proposed_tags(expected, &material.key, &params)?;
    if needs_fresh_key(expected, &material.key, &params, require_fresh)? {
        validate_live_key(&material.key)?;
    }
    let key = capture_verified_key(&material.key);
    commit_postgres_with_captured_associations(
        pool,
        expected,
        params,
        &key,
        material,
        require_fresh,
    )
    .await
    .map(|saved| saved.node)
}
