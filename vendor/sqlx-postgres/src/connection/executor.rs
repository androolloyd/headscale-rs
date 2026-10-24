use super::go_query;
use crate::describe::Describe;
use crate::error::Error;
use crate::executor::{Execute, Executor};
use crate::io::{PortalId, StatementId};
use crate::logger::QueryLogger;
use crate::message::{
    self, BackendMessageFormat, Bind, Close, CommandComplete, DataRow, ParameterDescription, Parse,
    ParseComplete, Query, RowDescription, TransactionStatus,
};
use crate::options::GoQueryExecMode;
use crate::statement::PgStatementMetadata;
use crate::{
    statement::PgStatement, PgArguments, PgConnection, PgQueryResult, PgRow, PgTypeInfo,
    PgValueFormat, Postgres,
};
use futures_core::future::BoxFuture;
use futures_core::stream::BoxStream;
use futures_core::Stream;
use futures_util::TryStreamExt;
use sqlx_core::arguments::Arguments;
use sqlx_core::Either;
use std::{borrow::Cow, pin::pin, sync::Arc};

async fn prepare(
    conn: &mut PgConnection,
    sql: &str,
    parameters: &[PgTypeInfo],
    metadata: Option<Arc<PgStatementMetadata>>,
    persistent: bool,
) -> Result<(StatementId, Arc<PgStatementMetadata>), Error> {
    let id =
        if persistent && conn.inner.go_query.is_some() && conn.inner.cache_statement.is_enabled() {
            StatementId::go_cache(sql)
        } else if persistent {
            let id = conn.inner.next_statement_id;
            conn.inner.next_statement_id = id.next();
            id
        } else {
            StatementId::UNNAMED
        };
    let mut preparation = conn
        .inner
        .go_query
        .as_ref()
        .filter(|_| persistent)
        .map(|go| go.invalidated.preparing(id));

    // build a list of type OIDs to send to the database in the PARSE command
    // we have not yet started the query sequence, so we are *safe* to cleanly make
    // additional queries here to get any missing OIDs

    let prepared = async {
        let mut param_types = Vec::with_capacity(parameters.len());

        for ty in parameters {
            param_types.push(conn.resolve_type_id(&ty.0).await?);
        }

        // flush and wait until we are re-ready
        conn.wait_until_ready().await?;

        if conn.inner.go_query.is_some() {
            let frame = go_query::prepare_frame(sql, id, &param_types, metadata.is_none())?;
            conn.inner.stream.write(frame)?;
            conn.inner.pending_ready_for_query_count += 1;
        } else {
            // next we send the PARSE command to the server
            conn.inner.stream.write_msg(Parse {
                param_types: &param_types,
                query: sql,
                statement: id,
            })?;

            if metadata.is_none() {
                // get the statement columns and parameters
                conn.inner
                    .stream
                    .write_msg(message::Describe::Statement(id))?;
            }

            conn.write_sync();
        }

        // we ask for the server to immediately send us the result of the PARSE command
        conn.inner.stream.flush().await?;

        // indicates that the SQL query string is now successfully parsed and has semantic validity
        conn.inner.stream.recv_expect::<ParseComplete>().await?;

        let metadata = if let Some(metadata) = metadata {
            // each SYNC produces one READY FOR QUERY
            conn.recv_ready_for_query().await?;

            // we already have metadata
            metadata
        } else {
            let parameters = recv_desc_params(conn).await?;

            let rows = recv_desc_rows(conn).await?;

            // each SYNC produces one READY FOR QUERY
            conn.recv_ready_for_query().await?;

            let parameters = conn.handle_parameter_description(parameters).await?;

            let (columns, column_names) = conn.handle_row_description(rows, true).await?;

            // ensure that if we did fetch custom data, we wait until we are fully ready before
            // continuing
            conn.wait_until_ready().await?;

            Arc::new(PgStatementMetadata {
                parameters,
                columns,
                column_names: Arc::new(column_names),
            })
        };

        Ok::<_, Error>(metadata)
    }
    .await;
    if prepared.is_ok() {
        if let Some(preparation) = &mut preparation {
            preparation.complete();
        }
    }
    prepared.map(|metadata| (id, metadata))
}

async fn recv_desc_params(conn: &mut PgConnection) -> Result<ParameterDescription, Error> {
    if conn.inner.go_query.is_some() {
        let message = conn.inner.stream.recv().await?;
        if message.format != BackendMessageFormat::ParameterDescription {
            let error = err_protocol!("expected native ParameterDescription");
            conn.inner.stream.mark_native_protocol_error(&error);
            return Err(error);
        }
        let result = ParameterDescription::decode_go_body(message.contents);
        if let Err(error) = &result {
            conn.inner.stream.mark_native_protocol_error(error);
        }
        result
    } else {
        conn.inner.stream.recv_expect().await
    }
}

async fn recv_desc_rows(conn: &mut PgConnection) -> Result<Option<RowDescription>, Error> {
    let rows: Option<RowDescription> = match conn.inner.stream.recv().await? {
        // describes the rows that will be returned when the statement is eventually executed
        message if message.format == BackendMessageFormat::RowDescription => {
            Some(message.decode().map_err(|error| {
                conn.inner.stream.mark_native_protocol_error(&error);
                error
            })?)
        }

        // no data would be returned if this statement was executed
        message if message.format == BackendMessageFormat::NoData => None,

        message => {
            let error = err_protocol!(
                "expecting RowDescription or NoData but received {:?}",
                message.format
            );
            conn.inner.stream.mark_native_protocol_error(&error);
            return Err(error);
        }
    };

    Ok(rows)
}

impl PgConnection {
    pub(super) fn invalidate_go_query(&mut self, sql: &str) {
        if let Some(go) = &mut self.inner.go_query {
            go.descriptions.remove(sql);
            if let Some((id, _)) = self.inner.cache_statement.remove(sql) {
                go.invalidated.push(id);
            }
        }
    }

    pub(super) async fn close_go_invalidated(&mut self) -> Result<(), Error> {
        if self.inner.go_query.is_some()
            && !matches!(
                self.inner.transaction_status,
                TransactionStatus::Idle | TransactionStatus::Transaction
            )
        {
            // pgx defers invalidated statement deallocation while the backend
            // reports a failed transaction. Retain the queue until rollback
            // returns ReadyForQuery with an idle/in-transaction status.
            return Ok(());
        }
        let invalidated = match &self.inner.go_query {
            Some(go) => go.invalidated.snapshot(),
            None => return Ok(()),
        };
        if invalidated.is_empty() {
            return Ok(());
        }
        let count = invalidated.len();
        let frame = go_query::close_frame(&invalidated)?;
        self.inner.stream.write(frame)?;
        self.inner.pending_ready_for_query_count += 1;
        self.inner.stream.flush().await?;
        self.wait_for_close_complete(count).await?;
        self.recv_ready_for_query().await?;
        if let Some(go) = &mut self.inner.go_query {
            // Keep the retired IDs until the complete close cycle succeeds.
            // If this future is cancelled, wait_until_ready drains its reply
            // and a later call can harmlessly close those names again.
            go.invalidated.acknowledge(count);
        }
        Ok(())
    }

    async fn go_statement(
        &mut self,
        sql: &str,
        mode: GoQueryExecMode,
        metadata: Option<Arc<PgStatementMetadata>>,
    ) -> Result<
        (
            StatementId,
            Arc<PgStatementMetadata>,
            Option<Vec<crate::types::Oid>>,
        ),
        Error,
    > {
        match mode {
            GoQueryExecMode::CacheStatement => {
                if !self.inner.cache_statement.is_enabled() && metadata.is_none() {
                    return Err(err_protocol!(
                        "cannot use QueryExecModeCacheStatement with disabled statement cache"
                    ));
                }
                self.get_or_prepare(sql, &[], true, metadata)
                    .await
                    .map(|(id, metadata)| (id, metadata, None))
            }
            GoQueryExecMode::CacheDescribe => {
                let go = self
                    .inner
                    .go_query
                    .as_mut()
                    .ok_or_else(|| err_protocol!("native query state is missing"))?;
                if !go.descriptions.is_enabled() {
                    return Err(err_protocol!(
                        "cannot use QueryExecModeCacheDescribe with disabled description cache"
                    ));
                }
                let cached = go.descriptions.get_mut(sql).cloned();
                let metadata = if let Some(metadata) = cached {
                    metadata
                } else {
                    let (_, metadata) = prepare(self, sql, &[], None, false).await?;
                    if let Some(go) = &mut self.inner.go_query {
                        go.descriptions.insert(sql, Arc::clone(&metadata));
                    }
                    metadata
                };
                let mut types = Vec::with_capacity(metadata.parameters.len());
                for ty in &metadata.parameters {
                    types.push(self.resolve_type_id(&ty.0).await?);
                }
                self.wait_until_ready().await?;
                Ok((StatementId::UNNAMED, metadata, Some(types)))
            }
            GoQueryExecMode::DescribeExec => {
                let (_, metadata) = prepare(self, sql, &[], None, false).await?;
                let mut types = Vec::with_capacity(metadata.parameters.len());
                for ty in &metadata.parameters {
                    types.push(self.resolve_type_id(&ty.0).await?);
                }
                self.wait_until_ready().await?;
                // SQLx may load custom-type metadata with intervening queries.
                // Reparse the original SQL in the execution frame so it cannot
                // bind against an unnamed statement replaced by those queries.
                Ok((StatementId::UNNAMED, metadata, Some(types)))
            }
            GoQueryExecMode::Exec => Ok((
                StatementId::UNNAMED,
                Arc::new(PgStatementMetadata::default()),
                Some(Vec::new()),
            )),
            GoQueryExecMode::SimpleProtocol => {
                Err(err_protocol!("simple protocol does not prepare statements"))
            }
        }
    }

    // wait for CloseComplete to indicate a statement was closed
    pub(super) async fn wait_for_close_complete(&mut self, mut count: usize) -> Result<(), Error> {
        // we need to wait for the [CloseComplete] to be returned from the server
        while count > 0 {
            match self.inner.stream.recv().await? {
                message if message.format == BackendMessageFormat::PortalSuspended => {
                    // there was an open portal
                    // this can happen if the last time a statement was used it was not fully executed
                }

                message if message.format == BackendMessageFormat::CloseComplete => {
                    // successfully closed the statement (and freed up the server resources)
                    count -= 1;
                }

                message => {
                    let error = err_protocol!(
                        "expecting PortalSuspended or CloseComplete but received {:?}",
                        message.format
                    );
                    self.inner.stream.mark_native_protocol_error(&error);
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn write_sync(&mut self) {
        self.inner
            .stream
            .write_msg(message::Sync)
            .expect("BUG: Sync should not be too big for protocol");

        // all SYNC messages will return a ReadyForQuery
        self.inner.pending_ready_for_query_count += 1;
    }

    async fn get_or_prepare<'a>(
        &mut self,
        sql: &str,
        parameters: &[PgTypeInfo],
        persistent: bool,
        // optional metadata that was provided by the user, this means they are reusing
        // a statement object
        metadata: Option<Arc<PgStatementMetadata>>,
    ) -> Result<(StatementId, Arc<PgStatementMetadata>), Error> {
        if let Some(statement) = self.inner.cache_statement.get_mut(sql) {
            return Ok((*statement).clone());
        }

        let statement = prepare(self, sql, parameters, metadata, persistent).await?;

        if persistent && self.inner.cache_statement.is_enabled() {
            if let Some((id, _)) = self.inner.cache_statement.insert(sql, statement.clone()) {
                if let Some(go) = &mut self.inner.go_query {
                    go.invalidated.push(id);
                    return Ok(statement);
                }
                self.inner.stream.write_msg(Close::Statement(id))?;
                self.write_sync();

                self.inner.stream.flush().await?;

                self.wait_for_close_complete(1).await?;
                self.recv_ready_for_query().await?;
            }
        }

        Ok(statement)
    }

    pub(crate) async fn run<'e, 'c: 'e, 'q: 'e>(
        &'c mut self,
        query: &'q str,
        arguments: Option<PgArguments>,
        persistent: bool,
        metadata_opt: Option<Arc<PgStatementMetadata>>,
    ) -> Result<impl Stream<Item = Result<Either<PgQueryResult, PgRow>, Error>> + 'e, Error> {
        self.run_with_intent(query, arguments, persistent, metadata_opt, false)
            .await
    }

    async fn run_with_intent<'e, 'c: 'e, 'q: 'e>(
        &'c mut self,
        query: &'q str,
        arguments: Option<PgArguments>,
        persistent: bool,
        metadata_opt: Option<Arc<PgStatementMetadata>>,
        command: bool,
    ) -> Result<impl Stream<Item = Result<Either<PgQueryResult, PgRow>, Error>> + 'e, Error> {
        let mut logger = QueryLogger::new(query, self.inner.log_settings.clone());

        // before we continue, wait until we are "ready" to accept more queries
        self.wait_until_ready().await?;
        self.close_go_invalidated().await?;

        macro_rules! go_try {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        self.invalidate_go_query(query);
                        return Err(error);
                    }
                }
            };
        }

        let mut metadata: Arc<PgStatementMetadata>;
        let mut row_formats: Option<Arc<[PgValueFormat]>> = None;

        let mode = self.inner.go_query.as_ref().map(|go| go.mode);
        let format = if let Some(mode) = mode {
            if command
                && arguments
                    .as_ref()
                    .is_none_or(|arguments| arguments.types.is_empty())
            {
                // Conn.Exec overrides every configured mode when no arguments
                // remain. Conn.Query instead keeps its configured mode.
                let frame = go_try!(go_query::query_frame(query));
                go_try!(self.inner.stream.write(frame));
                self.inner.pending_ready_for_query_count += 1;
                metadata = Arc::new(PgStatementMetadata::default());
                PgValueFormat::Text
            } else {
                let empty_arguments = PgArguments::default();
                let arguments = arguments.as_ref().unwrap_or(&empty_arguments);
                // Query's separate empty-SQL override still sanitizes through
                // its simple-protocol path, including the session checks.
                if mode == GoQueryExecMode::SimpleProtocol || (!command && query.is_empty()) {
                    if self
                        .inner
                        .stream
                        .parameter_statuses
                        .get("standard_conforming_strings")
                        .map(String::as_str)
                        != Some("on")
                    {
                        go_try!(Err::<(), _>(err_protocol!("simple protocol queries must be run with standard_conforming_strings=on")));
                    }
                    if self
                        .inner
                        .stream
                        .parameter_statuses
                        .get("client_encoding")
                        .map(String::as_str)
                        != Some("UTF8")
                    {
                        go_try!(Err::<(), _>(err_protocol!(
                            "simple protocol queries must be run with client_encoding=UTF8"
                        )));
                    }
                    let arguments = go_try!(go_query::arguments(arguments));
                    let sql = go_try!(go_query::simple(query, &arguments));
                    let frame = go_try!(go_query::query_frame(&sql));
                    go_try!(self.inner.stream.write(frame));
                    self.inner.pending_ready_for_query_count += 1;
                    metadata = Arc::new(PgStatementMetadata::default());
                    PgValueFormat::Text
                } else {
                    let (statement, description, parse_types) =
                        go_try!(self.go_statement(query, mode, metadata_opt).await);
                    if mode != GoQueryExecMode::Exec
                        && description.parameters.len() != arguments.types.len()
                    {
                        let error = if command {
                            err_protocol!("mismatched param and argument count")
                        } else {
                            err_protocol!(
                                "expected {} arguments, got {}",
                                description.parameters.len(),
                                arguments.types.len()
                            )
                        };
                        go_try!(Err::<(), _>(error));
                    }
                    metadata = description;
                    let arguments = go_try!(go_query::arguments(arguments));
                    let format = if mode == GoQueryExecMode::Exec {
                        PgValueFormat::Text
                    } else {
                        PgValueFormat::Binary
                    };
                    let result_formats = if mode == GoQueryExecMode::Exec {
                        None
                    } else {
                        let mut formats = Vec::with_capacity(metadata.columns.len());
                        for column in &metadata.columns {
                            let oid = go_try!(self.resolve_type_id(&column.type_info.0).await);
                            formats.push(if command {
                                go_query::preferred_result_format(oid)
                            } else {
                                go_query::database_sql_result_format(oid)
                            });
                        }
                        // Type resolution can issue catalog queries. Complete
                        // those cycles before writing the actual Bind frame.
                        go_try!(self.wait_until_ready().await);
                        row_formats = Some(Arc::from(formats.clone()));
                        Some(formats)
                    };
                    let frame = go_try!(go_query::extended_frame(
                        query,
                        statement,
                        parse_types.as_deref(),
                        &arguments,
                        result_formats.as_deref()
                    ));
                    go_try!(self.inner.stream.write(frame));
                    self.inner.pending_ready_for_query_count += 1;
                    format
                }
            }
        } else if let Some(mut arguments) = arguments {
            // Check this before we write anything to the stream.
            //
            // Note: Postgres actually interprets this value as unsigned,
            // making the max number of parameters 65535, not 32767
            // https://github.com/launchbadge/sqlx/issues/3464
            // https://www.postgresql.org/docs/current/limits.html
            let num_params = u16::try_from(arguments.len()).map_err(|_| {
                err_protocol!(
                    "PgConnection::run(): too many arguments for query: {}",
                    arguments.len()
                )
            })?;

            // prepare the statement if this our first time executing it
            // always return the statement ID here
            let (statement, metadata_) = self
                .get_or_prepare(query, &arguments.types, persistent, metadata_opt)
                .await?;

            metadata = metadata_;

            // patch holes created during encoding
            arguments.apply_patches(self, &metadata.parameters).await?;

            // consume messages till `ReadyForQuery` before bind and execute
            self.wait_until_ready().await?;

            // bind to attach the arguments to the statement and create a portal
            self.inner.stream.write_msg(Bind {
                portal: PortalId::UNNAMED,
                statement,
                formats: &[PgValueFormat::Binary],
                num_params,
                params: &arguments.buffer,
                result_formats: &[PgValueFormat::Binary],
            })?;

            // executes the portal up to the passed limit
            // the protocol-level limit acts nearly identically to the `LIMIT` in SQL
            self.inner.stream.write_msg(message::Execute {
                portal: PortalId::UNNAMED,
                // Non-zero limits cause query plan pessimization by disabling parallel workers:
                // https://github.com/launchbadge/sqlx/issues/3673
                limit: 0,
            })?;
            // From https://www.postgresql.org/docs/current/protocol-flow.html:
            //
            // "An unnamed portal is destroyed at the end of the transaction, or as
            // soon as the next Bind statement specifying the unnamed portal as
            // destination is issued. (Note that a simple Query message also
            // destroys the unnamed portal."

            // we ask the database server to close the unnamed portal and free the associated resources
            // earlier - after the execution of the current query.
            self.inner
                .stream
                .write_msg(Close::Portal(PortalId::UNNAMED))?;

            // finally, [Sync] asks postgres to process the messages that we sent and respond with
            // a [ReadyForQuery] message when it's completely done. Theoretically, we could send
            // dozens of queries before a [Sync] and postgres can handle that. Execution on the server
            // is still serial but it would reduce round-trips. Some kind of builder pattern that is
            // termed batching might suit this.
            self.write_sync();

            // prepared statements are binary
            PgValueFormat::Binary
        } else {
            // Query will trigger a ReadyForQuery
            self.inner.stream.write_msg(Query(query))?;
            self.inner.pending_ready_for_query_count += 1;

            // metadata starts out as "nothing"
            metadata = Arc::new(PgStatementMetadata::default());

            // and unprepared statements are text
            PgValueFormat::Text
        };

        go_try!(self.inner.stream.flush().await.map_err(Error::from));

        let native_rows = self.inner.go_query.is_some() && !command;
        let mut first_result_done = false;

        // Only backend decoding/invariants poison native connections. Client
        // argument or statement validation above may also use Error::Protocol
        // but leaves a synchronized transport reusable.
        macro_rules! backend_try {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        self.inner.stream.mark_native_protocol_error(&error);
                        self.invalidate_go_query(query);
                        return Err(error);
                    }
                }
            };
        }

        Ok(try_stream! {
            loop {
                let message = go_try!(self.inner.stream.recv().await);

                match message.format {
                    BackendMessageFormat::BindComplete
                    | BackendMessageFormat::ParseComplete
                    | BackendMessageFormat::ParameterDescription
                    | BackendMessageFormat::NoData
                    // unnamed portal has been closed
                    | BackendMessageFormat::CloseComplete
                    => {
                        // harmless messages to ignore
                    }

                    // "Execute phase is always terminated by the appearance of
                    // exactly one of these messages: CommandComplete,
                    // EmptyQueryResponse (if the portal was created from an
                    // empty query string), ErrorResponse, or PortalSuspended"
                    BackendMessageFormat::CommandComplete => {
                        // a SQL command completed normally
                        let cc: CommandComplete = backend_try!(message.decode());

                        let rows_affected = if self.inner.go_query.is_some() {
                            backend_try!(cc.validate_go());
                            cc.go_rows_affected()
                        } else {
                            cc.rows_affected()
                        };
                        if native_rows && first_result_done {
                            continue;
                        }
                        // pgx Query exposes the first ResultReader. Its Close
                        // drains the other results without replacing its tag.
                        first_result_done = true;
                        logger.increase_rows_affected(rows_affected);
                        r#yield!(Either::Left(PgQueryResult {
                            rows_affected,
                        }));
                    }

                    BackendMessageFormat::EmptyQueryResponse => {
                        // empty query string passed to an unprepared execute
                        first_result_done = true;
                    }

                    // Message::ErrorResponse is handled in self.stream.recv()

                    // incomplete query execution has finished
                    BackendMessageFormat::PortalSuspended => {}

                    BackendMessageFormat::RowDescription => {
                        // indicates that a *new* set of rows are about to be returned
                        let rows: RowDescription = backend_try!(message.decode());
                        if self.inner.go_query.is_some() {
                            let formats = backend_try!(rows.fields.iter().map(|field| {
                                match field.format {
                                    0 => Ok(PgValueFormat::Text),
                                    1 => Ok(PgValueFormat::Binary),
                                    format => Err(err_protocol!(
                                        "invalid native PostgreSQL row format code: {format}"
                                    )),
                                }
                            }).collect::<Result<Vec<_>, Error>>());
                            if native_rows && first_result_done {
                                continue;
                            }
                            row_formats = Some(Arc::from(formats));
                        }
                        let (columns, column_names) = go_try!(self
                            .handle_row_description(Some(rows), false)
                            .await);

                        metadata = Arc::new(PgStatementMetadata {
                            column_names: Arc::new(column_names),
                            columns,
                            parameters: Vec::default(),
                        });
                    }

                    BackendMessageFormat::DataRow => {
                        // one of the set of rows returned by a SELECT, FETCH, etc query
                        let data: DataRow = backend_try!(message.decode());
                        if native_rows && first_result_done {
                            continue;
                        }
                        logger.increment_rows_returned();
                        if self.inner.go_query.is_some() && data.values.len() != metadata.columns.len() {
                            backend_try!(Err::<(), _>(err_protocol!("row value count does not match native statement metadata")));
                        }
                        let row = PgRow {
                            data,
                            format,
                            formats: row_formats.clone(),
                            metadata: Arc::clone(&metadata),
                        };

                        r#yield!(Either::Right(row));
                    }

                    BackendMessageFormat::ReadyForQuery => {
                        // processing of the query string is complete
                        backend_try!(self.handle_ready_for_query(message));
                        break;
                    }

                    _ => {
                        backend_try!(Err::<(), _>(err_protocol!(
                            "execute: unexpected message: {:?}",
                            message.format
                        )));
                    }
                }
            }

            Ok(())
        })
    }
}

impl<'c> Executor<'c> for &'c mut PgConnection {
    type Database = Postgres;

    fn execute<'e, 'q: 'e, E>(self, mut query: E) -> BoxFuture<'e, Result<PgQueryResult, Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Self::Database>,
    {
        if self.inner.go_query.is_none() {
            // Keep SQLx's aggregate result contract outside native mode.
            return Box::pin(self.execute_many(query).try_collect());
        }

        let sql = query.sql();
        let metadata = query
            .statement()
            .map(|statement| Arc::clone(&statement.metadata));
        let arguments = query.take_arguments().map_err(Error::Encode);
        let persistent = query.persistent();

        Box::pin(async move {
            let arguments = match arguments {
                Ok(arguments) => arguments,
                Err(error) => {
                    self.invalidate_go_query(sql);
                    return Err(error);
                }
            };
            let mut stream = pin!(
                self.run_with_intent(sql, arguments, persistent, metadata, true)
                    .await?
            );
            let mut last = PgQueryResult::default();
            // Conn.Exec returns the final simple-protocol CommandTag, and
            // still drains every result through ReadyForQuery so a later
            // command/deferred-constraint failure cannot appear successful.
            while let Some(result) = stream.try_next().await? {
                if let Either::Left(result) = result {
                    last = result;
                }
            }
            Ok(last)
        })
    }

    fn fetch_many<'e, 'q, E>(
        self,
        mut query: E,
    ) -> BoxStream<'e, Result<Either<PgQueryResult, PgRow>, Error>>
    where
        'c: 'e,
        E: Execute<'q, Self::Database>,
        'q: 'e,
        E: 'q,
    {
        let sql = query.sql();
        // False positive: https://github.com/rust-lang/rust-clippy/issues/12560
        #[allow(clippy::map_clone)]
        let metadata = query.statement().map(|s| Arc::clone(&s.metadata));
        let arguments = query.take_arguments().map_err(Error::Encode);
        let persistent = query.persistent();

        Box::pin(try_stream! {
            let arguments = match arguments {
                Ok(arguments) => arguments,
                Err(error) => {
                    self.invalidate_go_query(sql);
                    return Err(error);
                }
            };
            let mut s = pin!(self.run(sql, arguments, persistent, metadata).await?);

            while let Some(v) = s.try_next().await? {
                r#yield!(v);
            }

            Ok(())
        })
    }

    fn fetch_optional<'e, 'q, E>(self, mut query: E) -> BoxFuture<'e, Result<Option<PgRow>, Error>>
    where
        'c: 'e,
        E: Execute<'q, Self::Database>,
        'q: 'e,
        E: 'q,
    {
        let sql = query.sql();
        // False positive: https://github.com/rust-lang/rust-clippy/issues/12560
        #[allow(clippy::map_clone)]
        let metadata = query.statement().map(|s| Arc::clone(&s.metadata));
        let arguments = query.take_arguments().map_err(Error::Encode);
        let persistent = query.persistent();

        Box::pin(async move {
            let arguments = match arguments {
                Ok(arguments) => arguments,
                Err(error) => {
                    self.invalidate_go_query(sql);
                    return Err(error);
                }
            };
            let mut s = pin!(self.run(sql, arguments, persistent, metadata).await?);

            // With deferred constraints we need to check all responses as we
            // could get a OK response (with uncommitted data), only to get an
            // error response after (when the deferred constraint is actually
            // checked).
            let mut ret = None;
            while let Some(result) = s.try_next().await? {
                match result {
                    Either::Right(r) if ret.is_none() => ret = Some(r),
                    _ => {}
                }
            }
            Ok(ret)
        })
    }

    fn prepare_with<'e, 'q: 'e>(
        self,
        sql: &'q str,
        parameters: &'e [PgTypeInfo],
    ) -> BoxFuture<'e, Result<PgStatement<'q>, Error>>
    where
        'c: 'e,
    {
        Box::pin(async move {
            self.wait_until_ready().await?;
            self.close_go_invalidated().await?;

            let (_, metadata) = self.get_or_prepare(sql, parameters, true, None).await?;

            Ok(PgStatement {
                sql: Cow::Borrowed(sql),
                metadata,
            })
        })
    }

    fn describe<'e, 'q: 'e>(
        self,
        sql: &'q str,
    ) -> BoxFuture<'e, Result<Describe<Self::Database>, Error>>
    where
        'c: 'e,
    {
        Box::pin(async move {
            self.wait_until_ready().await?;
            self.close_go_invalidated().await?;

            let (stmt_id, metadata) = self.get_or_prepare(sql, &[], true, None).await?;

            let nullable = self.get_nullable_for_columns(stmt_id, &metadata).await?;

            Ok(Describe {
                columns: metadata.columns.clone(),
                nullable,
                parameters: Some(Either::Left(metadata.parameters.clone())),
            })
        })
    }
}
