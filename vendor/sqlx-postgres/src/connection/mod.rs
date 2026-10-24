use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use crate::HashMap;
use futures_core::future::BoxFuture;
use futures_util::FutureExt;

use crate::common::StatementCache;
use crate::error::Error;
use crate::ext::ustr::UStr;
use crate::io::StatementId;
use crate::message::{
    BackendMessageFormat, Close, Query, ReadyForQuery, ReceivedMessage, Terminate,
    TransactionStatus,
};
use crate::statement::PgStatementMetadata;
use crate::transaction::Transaction;
use crate::types::Oid;
use crate::{PgConnectOptions, PgTypeInfo, Postgres};

pub(crate) use sqlx_core::connection::*;

pub use self::stream::PgStream;

pub(crate) mod describe;
mod establish;
mod executor;
mod go_auth;
mod go_query;
mod sasl;
mod stream;
mod tls;

/// A connection to a PostgreSQL database.
///
/// See [`PgConnectOptions`] for connection URL reference.
pub struct PgConnection {
    pub(crate) inner: Box<PgConnectionInner>,
}

pub struct PgConnectionInner {
    // underlying TCP or UDS stream,
    // wrapped in a potentially TLS stream,
    // wrapped in a buffered stream
    pub(crate) stream: PgStream,

    // process id of this backend
    // used to send cancel requests
    #[allow(dead_code)]
    process_id: u32,

    // secret key of this backend
    // used to send cancel requests
    #[allow(dead_code)]
    secret_key: sqlx_core::bytes::Bytes,

    // sequence of statement IDs for use in preparing statements
    // in PostgreSQL, the statement is prepared to a user-supplied identifier
    next_statement_id: StatementId,

    // cache statement by query string to the id and columns
    cache_statement: StatementCache<(StatementId, Arc<PgStatementMetadata>)>,
    go_query: Option<go_query::GoQueryState>,

    // cache user-defined types by id <-> info
    cache_type_info: HashMap<Oid, PgTypeInfo>,
    cache_type_oid: HashMap<UStr, Oid>,
    cache_elem_type_to_array: HashMap<Oid, Oid>,

    // number of ReadyForQuery messages that we are currently expecting
    pub(crate) pending_ready_for_query_count: usize,

    // current transaction status
    transaction_status: TransactionStatus,
    pub(crate) transaction_depth: usize,

    log_settings: LogSettings,
}

impl PgConnection {
    pub(crate) fn uses_go_query_mode(&self) -> bool {
        self.inner.go_query.is_some()
    }

    /// Whether the latest ReadyForQuery message reports an idle transaction
    /// status, including transactions opened through raw SQL. Drain pending
    /// protocol work with `Connection::flush` before using this snapshot for
    /// pool admission. This method performs no I/O.
    pub fn transaction_status_is_idle(&self) -> bool {
        matches!(&self.inner.transaction_status, TransactionStatus::Idle)
    }

    /// the version number of the server in `libpq` format
    pub fn server_version_num(&self) -> Option<u32> {
        self.inner.stream.server_version_num
    }

    // will return when the connection is ready for another query
    pub(crate) async fn wait_until_ready(&mut self) -> Result<(), Error> {
        self.inner.stream.ensure_usable()?;
        if !self.inner.stream.write_buffer_mut().is_empty() {
            self.inner.stream.flush().await?;
        }

        while self.inner.pending_ready_for_query_count > 0 {
            let message = self.inner.stream.recv().await?;

            if let BackendMessageFormat::ReadyForQuery = message.format {
                self.handle_ready_for_query(message)?;
            } else {
                self.inner.stream.validate_native_drain_message(message)?;
            }
        }

        Ok(())
    }

    async fn recv_ready_for_query(&mut self) -> Result<(), Error> {
        let r: ReadyForQuery = self.inner.stream.recv_expect().await?;
        self.apply_ready_for_query(Ok(r))
    }

    #[inline(always)]
    fn handle_ready_for_query(&mut self, message: ReceivedMessage) -> Result<(), Error> {
        if !self.uses_go_query_mode() {
            // Retain generic SQLx's existing counter/decode ordering.
            self.inner.pending_ready_for_query_count = self
                .inner
                .pending_ready_for_query_count
                .checked_sub(1)
                .ok_or_else(|| {
                    err_protocol!("received more ReadyForQuery messages than expected")
                })?;
            self.inner.transaction_status = message.decode::<ReadyForQuery>()?.transaction_status;
            return Ok(());
        }
        self.apply_ready_for_query(message.decode())
    }

    fn apply_ready_for_query(&mut self, ready: Result<ReadyForQuery, Error>) -> Result<(), Error> {
        let result = ready.and_then(|ready| {
            self.inner
                .pending_ready_for_query_count
                .checked_sub(1)
                .map(|pending| (ready, pending))
                .ok_or_else(|| err_protocol!("received more ReadyForQuery messages than expected"))
        });
        match result {
            Ok((ready, pending)) => {
                self.inner.pending_ready_for_query_count = pending;
                self.inner.transaction_status = ready.transaction_status;
                Ok(())
            }
            Err(error) => {
                self.inner.stream.mark_native_protocol_error(&error);
                Err(error)
            }
        }
    }

    /// Queue a simple query (not prepared) to execute the next time this connection is used.
    ///
    /// Used for rolling back transactions and releasing advisory locks.
    #[inline(always)]
    pub(crate) fn queue_simple_query(&mut self, query: &str) -> Result<(), Error> {
        self.inner.stream.write_msg(Query(query))?;
        self.inner.pending_ready_for_query_count += 1;

        Ok(())
    }

    pub(crate) fn in_transaction(&self) -> bool {
        match self.inner.transaction_status {
            TransactionStatus::Transaction => true,
            TransactionStatus::Error | TransactionStatus::Idle => false,
        }
    }
}

impl Debug for PgConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConnection").finish()
    }
}

impl Connection for PgConnection {
    type Database = Postgres;

    type Options = PgConnectOptions;

    fn close(mut self) -> BoxFuture<'static, Result<(), Error>> {
        // The normal, graceful termination procedure is that the frontend sends a Terminate
        // message and immediately closes the connection.

        // On receipt of this message, the backend closes the
        // connection and terminates.

        Box::pin(async move {
            if self.inner.stream.protocol_failed() {
                // Dropping the owned socket closes it. Do not flush queued
                // statements or Terminate over a malformed native stream.
                return Ok(());
            }
            self.inner.stream.send(Terminate).await?;
            self.inner.stream.shutdown().await?;

            Ok(())
        })
    }

    fn close_hard(mut self) -> BoxFuture<'static, Result<(), Error>> {
        Box::pin(async move {
            if self.inner.stream.protocol_failed() {
                return Ok(());
            }
            self.inner.stream.shutdown().await?;

            Ok(())
        })
    }

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        // Users were complaining about this showing up in query statistics on the server.
        // By sending a comment we avoid an error if the connection was in the middle of a rowset
        // self.execute("/* SQLx ping */").map_ok(|_| ()).boxed()

        Box::pin(async move {
            // The simplest call-and-response that's possible.
            self.inner.stream.ensure_usable()?;
            self.write_sync();
            self.wait_until_ready().await
        })
    }

    fn begin(&mut self) -> BoxFuture<'_, Result<Transaction<'_, Self::Database>, Error>>
    where
        Self: Sized,
    {
        Transaction::begin(self, None)
    }

    fn begin_with(
        &mut self,
        statement: impl Into<Cow<'static, str>>,
    ) -> BoxFuture<'_, Result<Transaction<'_, Self::Database>, Error>>
    where
        Self: Sized,
    {
        Transaction::begin(self, Some(statement.into()))
    }

    fn cached_statements_size(&self) -> usize {
        self.inner.cache_statement.len()
    }

    fn clear_cached_statements(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.inner.cache_type_oid.clear();

            let mut cleared = 0_usize;

            self.wait_until_ready().await?;
            if let Some(go) = &mut self.inner.go_query {
                go.descriptions.clear();
                while let Some((id, _)) = self.inner.cache_statement.remove_lru() {
                    go.invalidated.push(id);
                }
                self.close_go_invalidated().await?;
                return Ok(());
            }

            while let Some((id, _)) = self.inner.cache_statement.remove_lru() {
                self.inner.stream.write_msg(Close::Statement(id))?;
                cleared += 1;
            }

            if cleared > 0 {
                self.write_sync();
                self.inner.stream.flush().await?;

                self.wait_for_close_complete(cleared).await?;
                self.recv_ready_for_query().await?;
            }

            Ok(())
        })
    }

    fn shrink_buffers(&mut self) {
        self.inner.stream.shrink_buffers();
    }

    #[doc(hidden)]
    fn flush(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        self.wait_until_ready().boxed()
    }

    #[doc(hidden)]
    fn should_flush(&self) -> bool {
        self.inner.stream.protocol_failed() || !self.inner.stream.write_buffer().is_empty()
    }
}

// Implement `AsMut<Self>` so that `PgConnection` can be wrapped in
// a `PgAdvisoryLockGuard`.
//
// See: https://github.com/launchbadge/sqlx/issues/2520
impl AsMut<PgConnection> for PgConnection {
    fn as_mut(&mut self) -> &mut PgConnection {
        self
    }
}
