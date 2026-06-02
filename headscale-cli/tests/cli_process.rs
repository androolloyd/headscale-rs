#![allow(unknown_lints, clippy::duration_suboptimal_units)]

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
#[cfg(feature = "postgres-sqlx")]
use std::time::{SystemTime, UNIX_EPOCH};

use headscale_api::admin::{
    PersistentApiKeyAdmin, PersistentMachineAdmin, PersistentPreauthAdmin, PersistentUserAdmin,
    WireMachineAdmin,
};
use headscale_api::grpc::upstream::{DatabaseHealthCheck, HeadscaleAdminService};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::tls::{self, SanConfig};
use headscale_api::tailscale_wire::{AllocError, IpAllocator, MachineRegistry};
use httpmock::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::transport::server::Connected;

const CLEAN_ENV: &[&str] = &[
    "HEADSCALE_CONFIG",
    "HEADSCALE_LOG",
    "HEADSCALE_URL",
    "HEADSCALE_ADMIN_TOKEN",
    "HEADSCALE_CLI_ADDRESS",
    "HEADSCALE_CLI_API_KEY",
    "HEADSCALE_CLI_INSECURE",
    "HEADSCALE_CLI_TIMEOUT",
    "HEADSCALE_DNS_MAGIC_DNS",
    "HEADSCALE_DNS_BASE_DOMAIN",
    "HEADSCALE_DNS_OVERRIDE_LOCAL_DNS",
    "HEADSCALE_DNS_NAMESERVERS_GLOBAL",
    "HEADSCALE_DNS_NAMESERVERS_SPLIT",
    "HEADSCALE_DNS_SEARCH_DOMAINS",
    "HEADSCALE_DNS_EXTRA_RECORDS",
    "HEADSCALE_DNS_EXTRA_RECORDS_PATH",
    "HEADSCALE_DERP_SERVER_ENABLED",
    "HEADSCALE_DERP_SERVER_REGION_ID",
    "HEADSCALE_DERP_SERVER_REGION_CODE",
    "HEADSCALE_DERP_SERVER_REGION_NAME",
    "HEADSCALE_DERP_SERVER_VERIFY_CLIENTS",
    "HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR",
    "HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH",
    "HEADSCALE_DERP_SERVER_IPV4",
    "HEADSCALE_DERP_SERVER_IPV6",
    "HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION",
    "HEADSCALE_DERP_URLS",
    "HEADSCALE_DERP_PATHS",
    "HEADSCALE_DERP_AUTO_UPDATE_ENABLED",
    "HEADSCALE_DERP_UPDATE_FREQUENCY",
    "HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT",
    "HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT",
    "HEADSCALE_DISABLE_CHECK_UPDATES",
    "HEADSCALE_LOGTAIL_ENABLED",
    "HEADSCALE_AUTO_UPDATE_ENABLED",
    "HEADSCALE_DATABASE_TYPE",
    "HEADSCALE_DATABASE_DEBUG",
    "HEADSCALE_DATABASE_GORM_DEBUG",
    "HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD",
    "HEADSCALE_DATABASE_GORM_SKIP_ERR_RECORD_NOT_FOUND",
    "HEADSCALE_DATABASE_GORM_PARAMETERIZED_QUERIES",
    "HEADSCALE_DATABASE_GORM_PREPARE_STMT",
    "HEADSCALE_DATABASE_SQLITE_PATH",
    "HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG",
    "HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT",
    "HEADSCALE_DATABASE_POSTGRES_HOST",
    "HEADSCALE_DATABASE_POSTGRES_PORT",
    "HEADSCALE_DATABASE_POSTGRES_NAME",
    "HEADSCALE_DATABASE_POSTGRES_USER",
    "HEADSCALE_DATABASE_POSTGRES_PASS",
    "HEADSCALE_DATABASE_POSTGRES_SSL",
    "HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS",
    "HEADSCALE_DATABASE_POSTGRES_MAX_IDLE_CONNS",
    "HEADSCALE_DATABASE_POSTGRES_CONN_MAX_IDLE_TIME_SECS",
    "HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE",
    "HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT",
    "HEADSCALE_ACME_URL",
    "HEADSCALE_ACME_EMAIL",
    "HEADSCALE_TLS_LETSENCRYPT_HOSTNAME",
    "HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR",
    "HEADSCALE_TLS_LETSENCRYPT_LISTEN",
    "HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE",
    "HEADSCALE_TLS_CERT_PATH",
    "HEADSCALE_TLS_KEY_PATH",
    "HEADSCALE_POLICY_MODE",
    "HEADSCALE_POLICY_PATH",
    "HEADSCALE_SERVER_URL",
    "HEADSCALE_LISTEN_ADDR",
    "HEADSCALE_METRICS_LISTEN_ADDR",
    "HEADSCALE_GRPC_LISTEN_ADDR",
    "HEADSCALE_GRPC_ALLOW_INSECURE",
    "HEADSCALE_UNIX_SOCKET",
    "HEADSCALE_UNIX_SOCKET_PERMISSION",
];

const MOCKOIDC_ENV: &[&str] = &[
    "MOCKOIDC_CLIENT_ID",
    "MOCKOIDC_CLIENT_SECRET",
    "MOCKOIDC_ADDR",
    "MOCKOIDC_PORT",
    "MOCKOIDC_USERS",
    "MOCKOIDC_ACCESS_TTL",
];

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

type BoxTestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn headscale_clean_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_headscale"));
    for key in CLEAN_ENV {
        command.env_remove(key);
    }
    command
}

fn headscale(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_headscale"))
        .args(args)
        .output()
        .expect("run headscale binary")
}

fn headscale_clean(args: &[&str]) -> Output {
    let mut command = headscale_clean_command();
    command.args(args);
    command.output().expect("run headscale binary")
}

fn headscale_with_config(config: &Path, args: &[&str]) -> Output {
    let mut command = headscale_clean_command();
    command.arg("--config").arg(config).args(args);
    command.output().expect("run headscale binary")
}

fn headscale_in(args: &[&str], cwd: &Path, home: &Path) -> Output {
    headscale_in_with_env(args, cwd, home, &[])
}

fn headscale_in_with_env(args: &[&str], cwd: &Path, home: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = headscale_clean_command();
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .envs(envs.iter().copied());
    command.output().expect("run headscale binary")
}

fn headscale_clean_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = headscale_clean_command();
    command.args(args).envs(envs.iter().copied());
    command.output().expect("run headscale binary")
}

fn headscale_in_with_mockoidc_env(
    args: &[&str],
    cwd: &Path,
    home: &Path,
    mockoidc_env: &[(&str, &str)],
) -> Output {
    let mut command = headscale_clean_command();
    command.args(args).current_dir(cwd).env("HOME", home);
    for key in MOCKOIDC_ENV {
        command.env_remove(key);
    }
    command.envs(mockoidc_env.iter().copied());
    command.output().expect("run headscale binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout utf8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf8")
}

fn trim_line_end_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for segment in text.split_inclusive('\n') {
        if let Some(line) = segment.strip_suffix('\n') {
            out.push_str(line.trim_end_matches([' ', '\t']));
            out.push('\n');
        } else {
            out.push_str(segment.trim_end_matches([' ', '\t']));
        }
    }
    out
}

fn normalize_localhost_port(text: &str) -> String {
    let mut normalized = text.to_string();
    let mut start = 0;
    const PREFIX: &str = "http://127.0.0.1:";
    while let Some(relative) = normalized[start..].find(PREFIX) {
        let port_start = start + relative + PREFIX.len();
        let port_end = normalized[port_start..]
            .find(|c: char| !c.is_ascii_digit())
            .map_or(normalized.len(), |offset| port_start + offset);
        if port_start == port_end {
            start = port_end;
            continue;
        }
        normalized.replace_range(port_start..port_end, "<port>");
        start = port_start + "<port>".len();
    }
    normalized
}

fn normalize_os_error_number(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut rest = text;
    const PREFIX: &str = "(os error ";

    while let Some(offset) = rest.find(PREFIX) {
        let (before, after_prefix) = rest.split_at(offset);
        normalized.push_str(before);
        let after_prefix = &after_prefix[PREFIX.len()..];
        let digits_len = after_prefix.bytes().take_while(u8::is_ascii_digit).count();

        if digits_len > 0 && after_prefix[digits_len..].starts_with(')') {
            normalized.push_str("(os error <errno>)");
            rest = &after_prefix[digits_len + 1..];
        } else {
            normalized.push_str(PREFIX);
            rest = after_prefix;
        }
    }

    normalized.push_str(rest);
    normalized
}

fn normalize_acme_http01_bind_failure_stderr(text: &str, addr: SocketAddr) -> String {
    normalize_os_error_number(&text.replace(&addr.to_string(), "<addr>"))
}

fn normalize_no_config_warning_timestamp(text: &str) -> String {
    const WARNING_SUFFIX: &str = " WRN no config file found, using defaults";
    let mut normalized = String::with_capacity(text.len());
    for segment in text.split_inclusive('\n') {
        let (line, line_ending) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        if line.ends_with(WARNING_SUFFIX) {
            normalized.push_str("<timestamp>");
            normalized.push_str(WARNING_SUFFIX);
        } else {
            normalized.push_str(line);
        }
        normalized.push_str(line_ending);
    }
    normalized
}

fn assert_stdout_snapshot(args: &[&str], expected: &str) {
    let output = headscale_clean(args);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        trim_line_end_spaces(&stdout(&output)),
        trim_line_end_spaces(expected),
        "stdout snapshot for {args:?}"
    );
    assert_eq!(stderr(&output), "", "stderr snapshot for {args:?}");
}

fn assert_stdout_stderr_snapshot(args: &[&str], expected_stdout: &str, expected_stderr: &str) {
    let output = headscale_clean(args);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        trim_line_end_spaces(&stdout(&output)),
        trim_line_end_spaces(expected_stdout),
        "stdout snapshot for {args:?}"
    );
    assert_eq!(
        trim_line_end_spaces(&stderr(&output)),
        trim_line_end_spaces(expected_stderr),
        "stderr snapshot for {args:?}"
    );
}

fn assert_stdout_no_config_warning_snapshot(args: &[&str], expected: &str) {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = headscale_in(args, cwd.path(), home.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        trim_line_end_spaces(&stdout(&output)),
        trim_line_end_spaces(expected),
        "stdout snapshot for {args:?}"
    );
    assert_eq!(
        trim_line_end_spaces(&normalize_no_config_warning_timestamp(&stderr(&output))),
        trim_line_end_spaces(include_str!("snapshots/no_config_default_warning.stderr")),
        "stderr snapshot for {args:?}"
    );
}

fn assert_normalized_node_stdout_snapshot(output: &Output, expected: &str, label: &str) {
    assert!(output.status.success(), "stderr: {}", stderr(output));
    assert_eq!(
        trim_line_end_spaces(&normalize_generated_node_stdout(&stdout(output))),
        trim_line_end_spaces(expected),
        "stdout snapshot for {label}"
    );
    assert_eq!(stderr(output), "", "stderr snapshot for {label}");
}

fn assert_normalized_secret_stdout_snapshot(output: &Output, expected: &str, label: &str) {
    assert!(output.status.success(), "stderr: {}", stderr(output));
    assert_eq!(
        trim_line_end_spaces(&normalize_generated_secret_stdout(&stdout(output))),
        trim_line_end_spaces(expected),
        "stdout snapshot for {label}"
    );
    assert_eq!(stderr(output), "", "stderr snapshot for {label}");
}

fn assert_stderr_snapshot(args: &[&str], expected_status: i32, expected: &str) {
    let output = headscale_clean(args);
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "unexpected status for {args:?}; stdout: {}; stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stdout(&output), "", "stdout snapshot for {args:?}");
    assert_eq!(
        trim_line_end_spaces(&stderr(&output)),
        trim_line_end_spaces(expected),
        "stderr snapshot for {args:?}"
    );
}

fn assert_stderr_no_config_warning_snapshot(args: &[&str], expected_status: i32, expected: &str) {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = headscale_in(args, cwd.path(), home.path());
    let expected = format!(
        "{}{}",
        include_str!("snapshots/no_config_default_warning.stderr"),
        expected
    );
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "unexpected status for {args:?}; stdout: {}; stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stdout(&output), "", "stdout snapshot for {args:?}");
    assert_eq!(
        trim_line_end_spaces(&normalize_no_config_warning_timestamp(&stderr(&output))),
        trim_line_end_spaces(&expected),
        "stderr snapshot for {args:?}"
    );
}

fn assert_process_stderr_snapshot(
    output: &Output,
    expected_status: i32,
    expected: &str,
    label: &str,
) {
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "unexpected status for {label}; stdout: {}; stderr: {}",
        stdout(output),
        stderr(output)
    );
    assert_eq!(stdout(output), "", "stdout snapshot for {label}");
    assert_eq!(
        trim_line_end_spaces(&stderr(output)),
        trim_line_end_spaces(expected),
        "stderr snapshot for {label}"
    );
}

fn assert_process_no_config_warning_stderr_snapshot(
    output: &Output,
    expected_status: i32,
    expected: &str,
    label: &str,
) {
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "unexpected status for {label}; stdout: {}; stderr: {}",
        stdout(output),
        stderr(output)
    );
    assert_eq!(stdout(output), "", "stdout snapshot for {label}");
    assert_eq!(
        trim_line_end_spaces(&normalize_no_config_warning_timestamp(&stderr(output))),
        trim_line_end_spaces(expected),
        "stderr snapshot for {label}"
    );
}

fn configtest_expected_stderr(validation_expected: &str) -> String {
    let Some(rest) = validation_expected.strip_prefix("Error: ") else {
        return validation_expected.to_string();
    };
    if rest.starts_with("Failed to load config:") {
        return validation_expected.to_string();
    }
    format!("Error: configuration error: loading configuration: {rest}")
}

fn assert_configtest_stderr_snapshot(
    output: &Output,
    expected_status: i32,
    validation_expected: &str,
    label: &str,
) {
    let expected = configtest_expected_stderr(validation_expected);
    assert_process_stderr_snapshot(output, expected_status, &expected, label);
}

fn assert_config_stderr_snapshot(
    config: &Path,
    args: &[&str],
    expected_status: i32,
    expected: &str,
) {
    let output = headscale_with_config(config, args);
    assert_process_stderr_snapshot(&output, expected_status, expected, &format!("{args:?}"));
}

async fn wait_for_headscale_status(config: &Path, args: &[&str], expected_status: i32) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = headscale_with_config(config, args);
        if output.status.code() == Some(expected_status) {
            return output;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {args:?} to exit {expected_status}; last status {:?}; stdout: {}; stderr: {}",
            output.status.code(),
            stdout(&output),
            stderr(&output)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn spawn_process_grpc_service(
    database_health_fails: bool,
) -> (
    tempfile::TempDir,
    headscale_db::Database,
    std::path::PathBuf,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("headscale.sock");
    let db = headscale_db::Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    let machines = Arc::new(MachineRegistry::new());
    let service = HeadscaleAdminService::with_user_admin(
        users.clone(),
        Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
        Arc::new(PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users)),
        PolicyStore::new(),
        Arc::new(WireMachineAdmin::new(machines)),
    );
    let service = if database_health_fails {
        service.with_database_health(Arc::new(FailingDatabaseHealth))
    } else {
        service.with_database_pool(db.pool().clone())
    };
    let listener = UnixListener::bind(&socket).unwrap();
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(service.into_service_server())
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    });

    (dir, db, socket, handle)
}

async fn spawn_process_grpc_service_with_persistent_machines() -> (
    tempfile::TempDir,
    headscale_db::Database,
    std::path::PathBuf,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("headscale.sock");
    let db = headscale_db::Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    let machines =
        Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone()));
    let service = HeadscaleAdminService::with_user_admin(
        users.clone(),
        Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
        Arc::new(PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users)),
        PolicyStore::new(),
        machines,
    )
    .with_database_pool(db.pool().clone())
    .with_ip_allocator(Arc::new(FixedProcessIpAllocator));
    let listener = UnixListener::bind(&socket).unwrap();
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(service.into_service_server())
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    });

    (dir, db, socket, handle)
}

async fn spawn_process_remote_grpc_service(
    database_health_fails: bool,
) -> (
    tempfile::TempDir,
    headscale_db::Database,
    String,
    String,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = headscale_db::Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let api_keys = Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone()));
    let token = headscale_db::api_keys::create_for_test(
        db.pool(),
        headscale_db::api_keys::CreateParams { expiration: None },
    )
    .await
    .unwrap()
    .plaintext;
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    let machines = Arc::new(MachineRegistry::new());
    let service = HeadscaleAdminService::with_user_admin(
        users.clone(),
        api_keys,
        Arc::new(PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users)),
        PolicyStore::new(),
        Arc::new(WireMachineAdmin::new(machines)),
    );
    let service = if database_health_fails {
        service.with_database_health(Arc::new(FailingDatabaseHealth))
    } else {
        service.with_database_pool(db.pool().clone())
    }
    .require_api_key_auth();

    let material = tls::load_or_generate(
        dir.path().join("remote-grpc-tls"),
        &SanConfig::with_hostname("localhost"),
    )
    .unwrap();
    let server_config = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
        .expect("test grpc TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("localhost:{}", listener.local_addr().unwrap().port());
    let incoming = TcpListenerStream::new(listener).then({
        let acceptor = acceptor.clone();
        move |accepted| {
            let acceptor = acceptor.clone();
            async move {
                let stream = accepted?;
                acceptor
                    .accept(stream)
                    .await
                    .map(ConnectedTlsStream)
                    .map_err(io::Error::other)
            }
        }
    });
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(service.into_service_server())
            .serve_with_incoming(incoming)
            .await
    });

    (dir, db, address, token, handle)
}

struct ConnectedTlsStream(TlsStream<TcpStream>);

impl Connected for ConnectedTlsStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for ConnectedTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnectedTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

struct FailingDatabaseHealth;

#[async_trait::async_trait]
impl DatabaseHealthCheck for FailingDatabaseHealth {
    async fn ping(&self) -> Result<(), String> {
        Err("forced offline".to_string())
    }
}

struct FixedProcessIpAllocator;

impl IpAllocator for FixedProcessIpAllocator {
    fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 42))
    }
}

fn write_unix_socket_config(dir: &Path, socket: &Path) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    let socket = socket
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(&config, format!("unix_socket: \"{socket}\"\n")).unwrap();
    config
}

fn write_remote_grpc_config(dir: &Path, address: &str, api_key: &str) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    fs::write(
        &config,
        format!("cli:\n  address: \"{address}\"\n  api_key: \"{api_key}\"\n  insecure: true\n"),
    )
    .unwrap();
    config
}

fn write_remote_grpc_config_without_api_key(dir: &Path, address: &str) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    fs::write(
        &config,
        format!("cli:\n  address: \"{address}\"\n  insecure: true\n"),
    )
    .unwrap();
    config
}

fn write_sqlite_serve_config(
    dir: &Path,
    listen: std::net::SocketAddr,
    metrics: std::net::SocketAddr,
    grpc: std::net::SocketAddr,
) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    let socket = dir.join("headscale.sock");
    let noise = dir.join("state").join("noise_private.key");
    let db = dir.join("db.sqlite");
    fs::write(
        &config,
        format!(
            r#"
server_url: "http://{listen}"
listen_addr: "{listen}"
metrics_listen_addr: "{metrics}"
grpc_listen_addr: "{grpc}"
grpc_allow_insecure: true
unix_socket: {}
noise:
  private_key_path: {}
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: {}
policy:
  mode: database
"#,
            yaml_double_quoted(&socket.to_string_lossy()),
            yaml_double_quoted(&noise.to_string_lossy()),
            yaml_double_quoted(&db.to_string_lossy()),
        ),
    )
    .unwrap();
    config
}

#[cfg(feature = "postgres-sqlx")]
struct TempPostgresServeDatabase {
    admin_pool: sqlx::PgPool,
    fields: PostgresServeConfigFields,
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Clone, Debug)]
struct PostgresServeConfigFields {
    host: String,
    port: u16,
    name: String,
    user: String,
    pass: String,
    ssl: String,
}

#[cfg(feature = "postgres-sqlx")]
impl TempPostgresServeDatabase {
    async fn open(test_name: &str) -> BoxTestResult<Option<Self>> {
        let Ok(url) = std::env::var(POSTGRES_TEST_URL_ENV) else {
            eprintln!(
                "skipping Postgres runtime smoke {test_name}: {POSTGRES_TEST_URL_ENV} is not set"
            );
            return Ok(None);
        };

        let parsed = url::Url::parse(&url)?;
        let Some(host) = parsed.host_str() else {
            eprintln!("skipping Postgres runtime smoke {test_name}: URL must include a TCP host");
            return Ok(None);
        };
        let port = parsed.port().unwrap_or(5432);
        let user = parsed.username().to_string();
        let pass = parsed.password().unwrap_or_default().to_string();
        let ssl = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "sslmode").then(|| value.into_owned()))
            .unwrap_or_else(|| "false".to_string());

        let admin_pool = headscale_db::open_postgres_pool(&url).await?;
        let name = temporary_postgres_database_name(test_name);
        if let Err(err) = sqlx::query(&format!("CREATE DATABASE {}", quote_pg_identifier(&name)))
            .execute(&admin_pool)
            .await
        {
            eprintln!(
                "skipping Postgres runtime smoke {test_name}: cannot create temporary database: {err}"
            );
            admin_pool.close().await;
            return Ok(None);
        }

        Ok(Some(Self {
            admin_pool,
            fields: PostgresServeConfigFields {
                host: host.to_string(),
                port,
                name,
                user,
                pass,
                ssl,
            },
        }))
    }

    fn fields(&self) -> &PostgresServeConfigFields {
        &self.fields
    }

    async fn cleanup(self) -> BoxTestResult {
        let database = quote_pg_identifier(&self.fields.name);
        let _ = sqlx::query(
            "
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = $1
              AND pid <> pg_backend_pid()
            ",
        )
        .bind(&self.fields.name)
        .execute(&self.admin_pool)
        .await;
        if let Err(err) = sqlx::query(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
            .execute(&self.admin_pool)
            .await
        {
            eprintln!(
                "failed to drop temporary Postgres database {} with FORCE: {err}",
                self.fields.name
            );
            sqlx::query(&format!("DROP DATABASE IF EXISTS {database}"))
                .execute(&self.admin_pool)
                .await?;
        }
        self.admin_pool.close().await;
        Ok(())
    }
}

#[cfg(feature = "postgres-sqlx")]
fn temporary_postgres_database_name(test_name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after UNIX epoch")
        .as_nanos();
    format!(
        "headscale_rs_pg_serve_{}_{}_{}",
        std::process::id(),
        test_name,
        nanos
    )
}

#[cfg(feature = "postgres-sqlx")]
fn quote_pg_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}

fn yaml_double_quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn unused_loopback_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

#[cfg(feature = "postgres-sqlx")]
fn write_postgres_serve_config(
    dir: &Path,
    postgres: &PostgresServeConfigFields,
    listen: std::net::SocketAddr,
    metrics: std::net::SocketAddr,
    grpc: std::net::SocketAddr,
) -> std::path::PathBuf {
    write_postgres_serve_config_with_policy_block(
        dir,
        postgres,
        listen,
        metrics,
        grpc,
        "  mode: database\n",
    )
}

#[cfg(feature = "postgres-sqlx")]
fn write_postgres_serve_config_with_policy_file(
    dir: &Path,
    postgres: &PostgresServeConfigFields,
    listen: std::net::SocketAddr,
    metrics: std::net::SocketAddr,
    grpc: std::net::SocketAddr,
    policy_path: &Path,
) -> std::path::PathBuf {
    let policy = format!(
        "  mode: file\n  path: {}\n",
        yaml_double_quoted(&policy_path.to_string_lossy())
    );
    write_postgres_serve_config_with_policy_block(dir, postgres, listen, metrics, grpc, &policy)
}

#[cfg(feature = "postgres-sqlx")]
fn write_postgres_serve_config_with_policy_block(
    dir: &Path,
    postgres: &PostgresServeConfigFields,
    listen: std::net::SocketAddr,
    metrics: std::net::SocketAddr,
    grpc: std::net::SocketAddr,
    policy_block: &str,
) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    let socket = dir.join("headscale.sock");
    let noise = dir.join("state").join("noise_private.key");
    fs::write(
        &config,
        format!(
            r#"
server_url: "http://{listen}"
listen_addr: "{listen}"
metrics_listen_addr: "{metrics}"
grpc_listen_addr: "{grpc}"
grpc_allow_insecure: true
unix_socket: {}
noise:
  private_key_path: {}
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
  postgres:
    host: {}
    port: {}
    name: {}
    user: {}
    pass: {}
    ssl: {}
policy:
{policy_block}
"#,
            yaml_double_quoted(&socket.to_string_lossy()),
            yaml_double_quoted(&noise.to_string_lossy()),
            yaml_double_quoted(&postgres.host),
            postgres.port,
            yaml_double_quoted(&postgres.name),
            yaml_double_quoted(&postgres.user),
            yaml_double_quoted(&postgres.pass),
            yaml_double_quoted(&postgres.ssl),
        ),
    )
    .unwrap();
    config
}

fn spawn_headscale_serve(config: &Path, cwd: &Path) -> BoxTestResult<Child> {
    let mut command = headscale_clean_command();
    command
        .arg("--config")
        .arg(config)
        .arg("serve")
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command.spawn()?)
}

fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(all(feature = "postgres-sqlx", unix))]
fn send_sighup(child: &Child) -> BoxTestResult {
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(child.id().to_string())
        .status()?;
    assert!(status.success(), "kill -HUP exited {status:?}");
    Ok(())
}

fn normalize_users_list_stdout(text: &str) -> String {
    let mut normalized = String::new();
    for line in text.lines() {
        let mut line = line.to_string();
        if line.starts_with("1   ") && line.len() >= 19 {
            let timestamp_start = line.len() - 19;
            line.replace_range(timestamp_start.., "0000-00-00 00:00:00");
        }
        normalized.push_str(&line);
        normalized.push('\n');
    }
    normalized
}

fn normalize_generated_node_stdout(text: &str) -> String {
    let text = replace_short_key_bodies(text, "mkey:");
    let text = replace_short_key_bodies(&text, "nodekey:");
    replace_rfc3339_second_timestamps(&text)
}

fn normalize_generated_secret_stdout(text: &str) -> String {
    let text = replace_full_preauth_key_bodies(text);
    let text = replace_display_token_bodies(&text, "hskey-auth-");
    let text = replace_display_token_bodies(&text, "hskey-api-");
    replace_human_second_timestamps(&text)
}

fn normalize_generated_private_key_stdout(text: &str) -> String {
    replace_full_hex_key_bodies(text, "privkey:", 64)
}

fn normalize_version_stdout(text: &str) -> String {
    let mut normalized = text.to_string();
    let version = env!("CARGO_PKG_VERSION");
    let dirty = option_env!("HEADSCALE_RS_DIRTY").is_some_and(|value| value == "true");
    let human_version = if dirty {
        format!("{version}-dirty")
    } else {
        version.to_string()
    };
    let commit = option_env!("HEADSCALE_RS_COMMIT").unwrap_or("unknown");
    let build_time = option_env!("HEADSCALE_RS_BUILD_TIME").unwrap_or("unknown");
    let runtime_version = option_env!("RUSTC_VERSION").unwrap_or("unknown");
    let os = test_go_os_label(std::env::consts::OS);
    let arch = test_go_arch_label(std::env::consts::ARCH);

    for (from, to) in [
        (
            format!("headscale version {human_version}"),
            "headscale version <version>".to_string(),
        ),
        (
            format!("\"version\": \"{version}\""),
            "\"version\": \"<version>\"".to_string(),
        ),
        (
            format!("\"version\":\"{version}\""),
            "\"version\":\"<version>\"".to_string(),
        ),
        (
            format!("version: {version}"),
            "version: <version>".to_string(),
        ),
        (format!("commit: {commit}"), "commit: <commit>".to_string()),
        (
            format!("\"commit\": \"{commit}\""),
            "\"commit\": \"<commit>\"".to_string(),
        ),
        (
            format!("\"commit\":\"{commit}\""),
            "\"commit\":\"<commit>\"".to_string(),
        ),
        (
            format!("build time: {build_time}"),
            "build time: <build-time>".to_string(),
        ),
        (
            format!("buildtime: {build_time}"),
            "buildtime: <build-time>".to_string(),
        ),
        (
            format!("\"buildTime\": \"{build_time}\""),
            "\"buildTime\": \"<build-time>\"".to_string(),
        ),
        (
            format!("\"buildTime\":\"{build_time}\""),
            "\"buildTime\":\"<build-time>\"".to_string(),
        ),
        (
            format!("built with: {runtime_version} {os}/{arch}"),
            "built with: <runtime-version> <go-os>/<go-arch>".to_string(),
        ),
        (
            format!("    version: {runtime_version}"),
            "    version: <runtime-version>".to_string(),
        ),
        (
            format!("  version: {runtime_version}"),
            "  version: <runtime-version>".to_string(),
        ),
        (
            format!("\"version\": \"{runtime_version}\""),
            "\"version\": \"<runtime-version>\"".to_string(),
        ),
        (
            format!("\"version\":\"{runtime_version}\""),
            "\"version\":\"<runtime-version>\"".to_string(),
        ),
        (format!("    os: {os}"), "    os: <go-os>".to_string()),
        (format!("  os: {os}"), "  os: <go-os>".to_string()),
        (
            format!("\"os\": \"{os}\""),
            "\"os\": \"<go-os>\"".to_string(),
        ),
        (format!("\"os\":\"{os}\""), "\"os\":\"<go-os>\"".to_string()),
        (
            format!("    arch: {arch}"),
            "    arch: <go-arch>".to_string(),
        ),
        (format!("  arch: {arch}"), "  arch: <go-arch>".to_string()),
        (
            format!("\"arch\": \"{arch}\""),
            "\"arch\": \"<go-arch>\"".to_string(),
        ),
        (
            format!("\"arch\":\"{arch}\""),
            "\"arch\":\"<go-arch>\"".to_string(),
        ),
        (
            "\"dirty\": true".to_string(),
            "\"dirty\": false".to_string(),
        ),
        ("\"dirty\":true".to_string(), "\"dirty\":false".to_string()),
        ("dirty: true".to_string(), "dirty: false".to_string()),
    ] {
        normalized = normalized.replace(&from, &to);
    }

    normalized
}

fn test_go_os_label(os: &str) -> &'static str {
    match os {
        "macos" => "darwin",
        "windows" => "windows",
        "linux" => "linux",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        _ => "unknown",
    }
}

fn test_go_arch_label(arch: &str) -> &'static str {
    match arch {
        "x86" => "386",
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        _ => "unknown",
    }
}

fn replace_full_hex_key_bodies(text: &str, prefix: &str, body_len: usize) -> String {
    let placeholder = "0".repeat(body_len);
    let mut normalized = text.to_string();
    let mut start = 0;
    while let Some(relative) = normalized[start..].find(prefix) {
        let body_start = start + relative + prefix.len();
        let body_end = body_start + body_len;
        if body_end <= normalized.len()
            && normalized[body_start..body_end]
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        {
            normalized.replace_range(body_start..body_end, &placeholder);
            start = body_end;
        } else {
            start = body_start;
        }
    }
    normalized
}

fn replace_short_key_bodies(text: &str, prefix: &str) -> String {
    let mut normalized = text.to_string();
    let mut start = 0;
    while let Some(relative) = normalized[start..].find(prefix) {
        let body_start = start + relative + prefix.len();
        if body_start + 12 > normalized.len() {
            break;
        }
        let body_end = body_start + 12;
        let has_hex_body = normalized[body_start..body_end]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit());
        let has_ellipsis = normalized[body_end..].starts_with("…");
        if has_hex_body && has_ellipsis {
            normalized.replace_range(body_start..body_end, "000000000000");
            start = body_end + "…".len();
        } else {
            start = body_start;
        }
    }
    normalized
}

fn replace_full_preauth_key_bodies(text: &str) -> String {
    const PREFIX: &str = "hskey-auth-";
    const PREFIX_PLACEHOLDER: &str = "aaaaaaaaaaaa";
    const SECRET_PLACEHOLDER: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let mut normalized = text.to_string();
    let mut start = 0;
    while let Some(relative) = normalized[start..].find(PREFIX) {
        let body_start = start + relative + PREFIX.len();
        let dash = body_start + PREFIX_PLACEHOLDER.len();
        let secret_start = dash + 1;
        let secret_end = secret_start + SECRET_PLACEHOLDER.len();
        if secret_end <= normalized.len()
            && normalized.as_bytes().get(dash) == Some(&b'-')
            && is_urlsafe_token_body(&normalized[body_start..dash])
            && is_urlsafe_token_body(&normalized[secret_start..secret_end])
        {
            normalized.replace_range(secret_start..secret_end, SECRET_PLACEHOLDER);
            normalized.replace_range(body_start..dash, PREFIX_PLACEHOLDER);
            start = secret_end;
        } else {
            start = body_start;
        }
    }
    normalized
}

fn replace_display_token_bodies(text: &str, prefix: &str) -> String {
    const PREFIX_PLACEHOLDER: &str = "aaaaaaaaaaaa";
    const DISPLAY_SUFFIX: &str = "-***";

    let mut normalized = text.to_string();
    let mut start = 0;
    while let Some(relative) = normalized[start..].find(prefix) {
        let body_start = start + relative + prefix.len();
        let body_end = body_start + PREFIX_PLACEHOLDER.len();
        if body_end <= normalized.len()
            && normalized[body_end..].starts_with(DISPLAY_SUFFIX)
            && is_urlsafe_token_body(&normalized[body_start..body_end])
        {
            normalized.replace_range(body_start..body_end, PREFIX_PLACEHOLDER);
            start = body_end + DISPLAY_SUFFIX.len();
        } else {
            start = body_start;
        }
    }
    normalized
}

fn is_urlsafe_token_body(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn replace_rfc3339_second_timestamps(text: &str) -> String {
    const PLACEHOLDER: &str = "0000-00-00T00:00:00Z";
    let mut normalized = String::with_capacity(text.len());
    let mut last = 0;
    let mut i = 0;
    let bytes = text.as_bytes();
    while i + PLACEHOLDER.len() <= text.len() {
        if is_rfc3339_second_timestamp_at(bytes, i) {
            normalized.push_str(&text[last..i]);
            normalized.push_str(PLACEHOLDER);
            i += PLACEHOLDER.len();
            last = i;
        } else {
            i += 1;
        }
    }
    normalized.push_str(&text[last..]);
    normalized
}

fn is_rfc3339_second_timestamp_at(bytes: &[u8], i: usize) -> bool {
    fn digit(bytes: &[u8], idx: usize) -> bool {
        bytes.get(idx).is_some_and(u8::is_ascii_digit)
    }

    (0..4).all(|offset| digit(bytes, i + offset))
        && bytes.get(i + 4) == Some(&b'-')
        && digit(bytes, i + 5)
        && digit(bytes, i + 6)
        && bytes.get(i + 7) == Some(&b'-')
        && digit(bytes, i + 8)
        && digit(bytes, i + 9)
        && bytes.get(i + 10) == Some(&b'T')
        && digit(bytes, i + 11)
        && digit(bytes, i + 12)
        && bytes.get(i + 13) == Some(&b':')
        && digit(bytes, i + 14)
        && digit(bytes, i + 15)
        && bytes.get(i + 16) == Some(&b':')
        && digit(bytes, i + 17)
        && digit(bytes, i + 18)
        && bytes.get(i + 19) == Some(&b'Z')
}

fn replace_human_second_timestamps(text: &str) -> String {
    const PLACEHOLDER: &str = "0000-00-00 00:00:00";
    let mut normalized = String::with_capacity(text.len());
    let mut last = 0;
    let mut i = 0;
    let bytes = text.as_bytes();
    while i + PLACEHOLDER.len() <= text.len() {
        if is_human_second_timestamp_at(bytes, i) {
            normalized.push_str(&text[last..i]);
            normalized.push_str(PLACEHOLDER);
            i += PLACEHOLDER.len();
            last = i;
        } else {
            i += 1;
        }
    }
    normalized.push_str(&text[last..]);
    normalized
}

fn is_human_second_timestamp_at(bytes: &[u8], i: usize) -> bool {
    fn digit(bytes: &[u8], idx: usize) -> bool {
        bytes.get(idx).is_some_and(u8::is_ascii_digit)
    }

    (0..4).all(|offset| digit(bytes, i + offset))
        && bytes.get(i + 4) == Some(&b'-')
        && digit(bytes, i + 5)
        && digit(bytes, i + 6)
        && bytes.get(i + 7) == Some(&b'-')
        && digit(bytes, i + 8)
        && digit(bytes, i + 9)
        && bytes.get(i + 10) == Some(&b' ')
        && digit(bytes, i + 11)
        && digit(bytes, i + 12)
        && bytes.get(i + 13) == Some(&b':')
        && digit(bytes, i + 14)
        && digit(bytes, i + 15)
        && bytes.get(i + 16) == Some(&b':')
        && digit(bytes, i + 17)
        && digit(bytes, i + 18)
}

fn display_prefix(secret: &str, token_prefix: &str) -> String {
    let rest = secret
        .strip_prefix(token_prefix)
        .unwrap_or_else(|| panic!("{secret:?} missing {token_prefix} prefix"));
    assert!(
        rest.len() >= 12,
        "{secret:?} shorter than expected display prefix"
    );
    format!("{token_prefix}{}-***", &rest[..12])
}

fn json_output(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "stderr: {}", stderr(output));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn yaml_output(output: &Output) -> serde_yaml::Value {
    assert!(output.status.success(), "stderr: {}", stderr(output));
    serde_yaml::from_slice(&output.stdout).unwrap()
}

fn assert_status_command_failed(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}; stderr: {}",
        stdout(output),
        stderr(output)
    );
    assert_eq!(stdout(output), "");
}

#[test]
fn top_level_help_exposes_upstream_operator_commands() {
    let output = headscale(&["--help"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    for command in [
        "serve",
        "users",
        "nodes",
        "preauthkeys",
        "auth",
        "apikeys",
        "policy",
        "debug",
        "generate",
        "mockoidc",
        "health",
        "version",
        "completion",
        "configtest",
    ] {
        assert!(out.contains(command), "missing {command} in help:\n{out}");
    }
    for hidden in ["  server", "  tailnet", "  status", "  init-config"] {
        assert!(!out.contains(hidden), "unexpected {hidden} in help:\n{out}");
    }
}

#[test]
fn top_level_help_matches_current_upstream_snapshot() {
    assert_stdout_snapshot(&["--help"], include_str!("snapshots/top_level_help.stdout"));
    assert_stdout_snapshot(&["-h"], include_str!("snapshots/top_level_help.stdout"));
    assert_stdout_no_config_warning_snapshot(
        &["help"],
        include_str!("snapshots/top_level_help.stdout"),
    );
}

#[test]
fn exact_help_aliases_match_current_upstream_snapshots() {
    assert_stdout_snapshot(
        &["version", "-h"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "version"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "mockoidc"],
        include_str!("snapshots/mockoidc_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "dumpConfig"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "completion", "bash"],
        include_str!("snapshots/completion_bash_help.stdout"),
    );
    assert_stdout_snapshot(&["auth", "-h"], include_str!("snapshots/auth_help.stdout"));
    assert_stdout_no_config_warning_snapshot(
        &["help", "auth", "register"],
        include_str!("snapshots/auth_register_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "-h"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "user"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "users", "create"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["user", "new", "--help"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "users", "c"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "ls", "-h"],
        include_str!("snapshots/users_list_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "user", "show"],
        include_str!("snapshots/users_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["user", "mv", "--help"],
        include_str!("snapshots/users_rename_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "delete", "--help"],
        include_str!("snapshots/users_destroy_help.stdout"),
    );
    assert_stdout_snapshot(&["node", "-h"], include_str!("snapshots/nodes_help.stdout"));
    assert_stdout_stderr_snapshot(
        &["nodes", "register", "--help"],
        include_str!("snapshots/nodes_register_help.stdout"),
        include_str!("snapshots/nodes_register_help.stderr"),
    );
    assert_stdout_stderr_snapshot(
        &["node", "register", "--help"],
        include_str!("snapshots/nodes_register_help.stdout"),
        include_str!("snapshots/nodes_register_help.stderr"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "nodes", "register"],
        include_str!("snapshots/nodes_register_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "nodes", "routes"],
        include_str!("snapshots/nodes_list_routes_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "logout", "-h"],
        include_str!("snapshots/nodes_expire_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "node", "t"],
        include_str!("snapshots/nodes_tag_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "del", "--help"],
        include_str!("snapshots/nodes_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["authkey", "new", "--help"],
        include_str!("snapshots/preauthkeys_create_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "pre", "rm"],
        include_str!("snapshots/preauthkeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["api", "revoke", "-h"],
        include_str!("snapshots/apikeys_expire_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "apikey", "remove"],
        include_str!("snapshots/apikeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "--help"],
        include_str!("snapshots/policy_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "policy", "fetch"],
        include_str!("snapshots/policy_get_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "update", "-h"],
        include_str!("snapshots/policy_set_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "policy", "check"],
        include_str!("snapshots/policy_check_help.stdout"),
    );
}

#[test]
fn auth_and_preauth_delete_help_are_accepted() {
    let auth = headscale(&["auth", "--help"]);
    assert!(auth.status.success(), "stderr: {}", stderr(&auth));
    let out = stdout(&auth);
    assert!(out.contains("register"));
    assert!(out.contains("approve"));
    assert!(out.contains("reject"));

    let register = headscale(&["auth", "register", "--help"]);
    assert!(register.status.success(), "stderr: {}", stderr(&register));
    let out = stdout(&register);
    assert!(out.contains("--user"));
    assert!(out.contains("--auth-id"));

    let delete = headscale(&["preauthkeys", "delete", "--help"]);
    assert!(delete.status.success(), "stderr: {}", stderr(&delete));
    assert!(stdout(&delete).contains("--id"));
}

#[test]
fn serve_and_debug_create_node_help_are_accepted() {
    let serve = headscale(&["serve", "--help"]);
    assert!(serve.status.success(), "stderr: {}", stderr(&serve));
    assert!(stdout(&serve).contains("Launches the headscale server"));

    let debug = headscale(&["debug", "create-node", "--help"]);
    assert!(debug.status.success(), "stderr: {}", stderr(&debug));
    let out = stdout(&debug);
    assert!(out.contains("--user"));
    assert!(out.contains("--key"));
    assert!(out.contains("--name"));
    assert!(out.contains("--route"));
}

#[test]
fn mockoidc_help_and_missing_env_do_not_load_config() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();

    let help = headscale_in(&["mockoidc", "--help"], cwd.path(), home.path());
    assert!(help.status.success(), "stderr: {}", stderr(&help));
    assert!(stdout(&help).contains("OpenID Connect for testing purposes"));

    let missing_client_id =
        headscale_in_with_mockoidc_env(&["mockoidc"], cwd.path(), home.path(), &[]);
    assert_process_stderr_snapshot(
        &missing_client_id,
        1,
        include_str!("snapshots/mockoidc_missing_client_id.stderr"),
        "mockoidc missing client id",
    );
    assert!(
        !stderr(&missing_client_id).contains("Failed to load config"),
        "stderr: {}",
        stderr(&missing_client_id)
    );

    let missing_addr = headscale_in_with_mockoidc_env(
        &["mockoidc"],
        cwd.path(),
        home.path(),
        &[
            ("MOCKOIDC_CLIENT_ID", "client"),
            ("MOCKOIDC_CLIENT_SECRET", "secret"),
        ],
    );
    assert_process_stderr_snapshot(
        &missing_addr,
        1,
        include_str!("snapshots/mockoidc_missing_addr.stderr"),
        "mockoidc missing addr",
    );

    let missing_port = headscale_in_with_mockoidc_env(
        &["mockoidc"],
        cwd.path(),
        home.path(),
        &[
            ("MOCKOIDC_CLIENT_ID", "client"),
            ("MOCKOIDC_CLIENT_SECRET", "secret"),
            ("MOCKOIDC_ADDR", "127.0.0.1"),
        ],
    );
    assert_process_stderr_snapshot(
        &missing_port,
        1,
        include_str!("snapshots/mockoidc_missing_port.stderr"),
        "mockoidc missing port",
    );

    let missing_users = headscale_in_with_mockoidc_env(
        &["mockoidc"],
        cwd.path(),
        home.path(),
        &[
            ("MOCKOIDC_CLIENT_ID", "client"),
            ("MOCKOIDC_CLIENT_SECRET", "secret"),
            ("MOCKOIDC_ADDR", "127.0.0.1"),
            ("MOCKOIDC_PORT", "0"),
        ],
    );
    assert_process_stderr_snapshot(
        &missing_users,
        1,
        include_str!("snapshots/mockoidc_missing_users.stderr"),
        "mockoidc missing users",
    );

    let missing_users_before_invalid_port = headscale_in_with_mockoidc_env(
        &["mockoidc"],
        cwd.path(),
        home.path(),
        &[
            ("MOCKOIDC_CLIENT_ID", "client"),
            ("MOCKOIDC_CLIENT_SECRET", "secret"),
            ("MOCKOIDC_ADDR", "127.0.0.1"),
            ("MOCKOIDC_PORT", "bad"),
        ],
    );
    assert_process_stderr_snapshot(
        &missing_users_before_invalid_port,
        1,
        include_str!("snapshots/mockoidc_missing_users.stderr"),
        "mockoidc missing users before invalid port",
    );

    let invalid_port = headscale_in_with_mockoidc_env(
        &["mockoidc"],
        cwd.path(),
        home.path(),
        &[
            ("MOCKOIDC_CLIENT_ID", "client"),
            ("MOCKOIDC_CLIENT_SECRET", "secret"),
            ("MOCKOIDC_ADDR", "127.0.0.1"),
            ("MOCKOIDC_PORT", "bad"),
            ("MOCKOIDC_USERS", "[]"),
        ],
    );
    assert_process_stderr_snapshot(
        &invalid_port,
        1,
        include_str!("snapshots/mockoidc_invalid_port.stderr"),
        "mockoidc invalid port",
    );
}

#[test]
fn generate_private_key_outputs_tailscale_machine_private_key() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = headscale_in(&["generate", "private-key"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    let key = out.trim();
    assert!(key.starts_with("privkey:"), "stdout: {out}");
    assert_eq!(key.len(), "privkey:".len() + 64);
}

#[test]
fn generate_private_key_ignores_extra_positionals_like_upstream_cobra() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    for args in [
        &["generate", "private-key", "extra"][..],
        &["generate", "private-key", "--", "--bad"][..],
        &["generate", "private-key", "--", "--help"][..],
        &["generate", "private-key", "--output", "--help"][..],
        &["gen", "private-key", "extra", "--force"][..],
        &["gen", "private-key", "-o", "--help"][..],
        &["gen", "private-key", "--", "--bad"][..],
    ] {
        let output = headscale_in(args, cwd.path(), home.path());

        assert!(
            output.status.success(),
            "args: {args:?}; stderr: {}",
            stderr(&output)
        );
        let out = stdout(&output);
        let key = out.trim();
        assert!(key.starts_with("privkey:"), "args: {args:?}; stdout: {out}");
        assert_eq!(key.len(), "privkey:".len() + 64);
    }
}

#[test]
fn generate_private_key_structured_outputs_match_current_upstream_snapshots() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    for (args, expected) in [
        (
            &["-o", "json", "generate", "private-key"][..],
            include_str!("snapshots/generate_private_key_json.stdout"),
        ),
        (
            &["-ojson-line", "generate", "private-key"][..],
            include_str!("snapshots/generate_private_key_json_line.stdout"),
        ),
        (
            &["-oyaml", "generate", "private-key"][..],
            include_str!("snapshots/generate_private_key_yaml.stdout"),
        ),
    ] {
        let output = headscale_in(args, cwd.path(), home.path());
        assert!(
            output.status.success(),
            "args: {args:?}; stderr: {}",
            stderr(&output)
        );
        let normalized =
            trim_line_end_spaces(&normalize_generated_private_key_stdout(&stdout(&output)));
        let expected = trim_line_end_spaces(expected);
        assert_eq!(
            normalized.trim_end_matches('\n'),
            expected.trim_end_matches('\n'),
            "stdout snapshot for {args:?}"
        );
        if args.contains(&"-oyaml") {
            assert!(
                stdout(&output).ends_with("\n\n"),
                "yaml stdout should keep upstream trailing blank line for {args:?}: {}",
                stdout(&output)
            );
        }
        assert_eq!(stderr(&output), "", "stderr snapshot for {args:?}");
    }
}

#[test]
fn version_human_uses_upstream_headscale_label() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["version"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.starts_with("headscale version "), "stdout: {out}");
    assert!(out.contains("\ncommit: "), "stdout: {out}");
    assert!(out.contains("\nbuild time: "), "stdout: {out}");
    assert!(out.contains("\nbuilt with: "), "stdout: {out}");
    assert!(!out.contains("headscale-rs version"), "stdout: {out}");
}

#[test]
fn version_ignores_extra_positionals_like_upstream_cobra() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();

    let output = headscale_in(&["version", "extra"], cwd.path(), home.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with("headscale version "));
    assert_eq!(stderr(&output), "");

    let output = headscale_in(
        &["version", "extra", "-o", "json-line"],
        cwd.path(),
        home.path(),
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with(r#"{"version":"#));
    assert_eq!(stderr(&output), "");

    let output = headscale_in(&["version", "--", "-o", "json"], cwd.path(), home.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with("headscale version "));
    assert_eq!(stderr(&output), "");

    let output = headscale_in(&["version", "extra", "--help"], cwd.path(), home.path());
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        include_str!("snapshots/version_help.stdout")
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn version_json_line_is_machine_readable() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["version", "-o", "json-line"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("version json-line");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["go"]["os"].is_string());
    assert!(value["go"]["arch"].is_string());
    assert!(value.get("rust").is_none());
}

#[test]
fn version_outputs_match_current_upstream_snapshots() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();

    for (args, expected) in [
        (&["version"][..], include_str!("snapshots/version.stdout")),
        (
            &["version", "-o", "json"][..],
            include_str!("snapshots/version_json.stdout"),
        ),
        (
            &["version", "-ojson-line"][..],
            include_str!("snapshots/version_json_line.stdout"),
        ),
        (
            &["version", "-oyaml"][..],
            include_str!("snapshots/version_yaml.stdout"),
        ),
    ] {
        let output = headscale_in(args, cwd.path(), home.path());
        assert!(
            output.status.success(),
            "args: {args:?}; stderr: {}",
            stderr(&output)
        );
        let normalized = trim_line_end_spaces(&normalize_version_stdout(&stdout(&output)));
        let expected = trim_line_end_spaces(expected);
        assert_eq!(
            normalized.trim_end_matches('\n'),
            expected.trim_end_matches('\n'),
            "stdout snapshot for {args:?}"
        );
        if args.contains(&"-oyaml") {
            assert!(
                stdout(&output).ends_with("\n\n"),
                "yaml stdout should keep upstream trailing blank line for {args:?}: {}",
                stdout(&output)
            );
        }
        assert_eq!(stderr(&output), "", "stderr snapshot for {args:?}");
    }
}

#[test]
fn version_yaml_uses_upstream_go_yaml_shape() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["version", "-o", "yaml"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    let expected_os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let expected_arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86" => "386",
        "x86_64" => "amd64",
        other => other,
    };
    assert!(out.contains("\nbuildtime: "), "stdout: {out}");
    assert!(!out.contains("buildTime:"), "stdout: {out}");
    assert!(
        out.contains(&format!("\n    os: {expected_os}\n")),
        "stdout: {out}"
    );
    assert!(
        out.contains(&format!("\n    arch: {expected_arch}\n")),
        "stdout: {out}"
    );
}

#[test]
fn completion_bash_does_not_load_config() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["completion", "bash"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("_headscale"), "stdout: {out}");
    assert!(out.contains("complete"), "stdout: {out}");
}

#[test]
fn completion_missing_or_unknown_shell_matches_upstream_help() {
    for args in [&["completion"][..], &["completion", "bad"][..]] {
        let output = headscale_clean(args);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert_eq!(
            trim_line_end_spaces(&stdout(&output)),
            trim_line_end_spaces(include_str!("snapshots/completion_help.stdout")),
            "stdout snapshot for {args:?}"
        );
        assert_eq!(stderr(&output), "", "stderr snapshot for {args:?}");
    }
}

#[test]
fn generate_missing_or_unknown_subcommand_matches_upstream_help() {
    for args in [
        &["generate"][..],
        &["gen"][..],
        &["generate", "bad"][..],
        &["gen", "bad"][..],
    ] {
        let output = headscale_clean(args);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert_eq!(
            trim_line_end_spaces(&stdout(&output)),
            trim_line_end_spaces(include_str!("snapshots/generate_help.stdout")),
            "stdout snapshot for {args:?}"
        );
        assert_eq!(stderr(&output), "", "stderr snapshot for {args:?}");
    }
}

#[test]
fn utility_unknown_subcommands_with_help_flags_match_upstream_help_snapshots() {
    for args in [
        &["completion", "bad", "--help"][..],
        &["completion", "bad", "extra", "--help"][..],
    ] {
        assert_stdout_snapshot(args, include_str!("snapshots/completion_help.stdout"));
    }
    assert_stdout_snapshot(
        &["completion", "bash", "extra", "--help"],
        include_str!("snapshots/completion_bash_help.stdout"),
    );

    for args in [
        &["generate", "bad", "--help"][..],
        &["gen", "bad", "--help"][..],
        &["generate", "bad", "extra", "--help"][..],
        &["gen", "bad", "extra", "--help"][..],
    ] {
        assert_stdout_snapshot(args, include_str!("snapshots/generate_help.stdout"));
    }
}

#[test]
fn utility_unknown_flags_match_upstream_stderr_snapshots() {
    assert_stderr_snapshot(
        &["serve", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["serve", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["version", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["version", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["health", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["health", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["configtest", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["configtest", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["dumpConfig", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["dumpConfig", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["mockoidc", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["mockoidc", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["mockoidc", "--config", "missing.yaml", "--help"],
        1,
        include_str!("snapshots/utility_mockoidc_late_config_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bad", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bad", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bash", "--bad"],
        1,
        include_str!("snapshots/utility_completion_bash_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bash", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["gen", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "bad", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["gen", "bad", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "bad", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["gen", "bad", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "private-key", "--bad"],
        1,
        include_str!("snapshots/utility_generate_private_key_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["gen", "private-key", "--bad"],
        1,
        include_str!("snapshots/utility_generate_private_key_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "private-key", "-x"],
        1,
        include_str!("snapshots/utility_unknown_shorthand_flag.stderr"),
    );
}

#[test]
fn serve_unknown_flags_honor_output_format_like_current_upstream() {
    assert_stderr_snapshot(
        &["serve", "-o", "json", "--bad"],
        1,
        include_str!("snapshots/serve_unknown_flag_json.stderr"),
    );
    assert_stderr_snapshot(
        &["serve", "--output", "json-line", "--bad"],
        1,
        include_str!("snapshots/serve_unknown_flag_json_line.stderr"),
    );
    assert_stderr_snapshot(
        &["serve", "-oyaml", "--bad"],
        1,
        &format!(
            "{}\n",
            include_str!("snapshots/serve_unknown_flag_yaml.stderr")
        ),
    );
    assert_stderr_snapshot(
        &["serve", "--output", "weird", "--bad"],
        1,
        include_str!("snapshots/serve_unknown_flag_unknown_output.stderr"),
    );
}

#[test]
fn utility_missing_global_flag_values_match_current_upstream_cobra() {
    assert_stderr_snapshot(
        &["version", "--output"],
        1,
        include_str!("snapshots/utility_missing_output_value.stderr"),
    );
    assert_stderr_snapshot(
        &["version", "-o"],
        1,
        include_str!("snapshots/utility_missing_output_shorthand_value.stderr"),
    );
    assert_stderr_snapshot(
        &["health", "--config"],
        1,
        include_str!("snapshots/utility_missing_config_value.stderr"),
    );
    assert_stderr_snapshot(
        &["serve", "-c"],
        1,
        include_str!("snapshots/utility_missing_config_shorthand_value.stderr"),
    );
    assert_stderr_snapshot(
        &["configtest", "--output"],
        1,
        include_str!("snapshots/utility_missing_output_value.stderr"),
    );

    let top_level_missing_output = include_str!("snapshots/utility_top_level_json_flag.stderr")
        .replace("unknown flag: --json", "flag needs an argument: --output");
    assert_stderr_snapshot(&["--output"], 1, &top_level_missing_output);
}

#[test]
fn utility_global_flags_consume_help_as_values_like_current_upstream_cobra() {
    assert_stderr_snapshot(
        &["configtest", "--output", "--help"],
        1,
        include_str!("snapshots/configtest_output_consumed_help.stderr"),
    );

    for args in [
        &["health", "--config", "--help"][..],
        &["dumpConfig", "--config", "--help"][..],
        &["serve", "--config", "--help"][..],
    ] {
        assert_stderr_snapshot(
            args,
            1,
            include_str!("snapshots/utility_config_consumed_help.stderr"),
        );
    }

    let version = headscale_clean(&["version", "--output", "--help"]);
    assert!(version.status.success(), "stderr: {}", stderr(&version));
    assert!(stdout(&version).starts_with("headscale version "));
    assert_eq!(stderr(&version), "");
}

#[test]
fn utility_skip_config_commands_reject_late_global_flags_like_current_upstream_cobra() {
    assert_stderr_snapshot(
        &["version", "--config", "missing.yaml"],
        1,
        include_str!("snapshots/utility_version_config_flag_after_command.stderr"),
    );
    assert_stderr_snapshot(
        &["mockoidc", "--output", "json"],
        1,
        include_str!("snapshots/utility_mockoidc_output_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "zsh", "--config", "missing.yaml"],
        1,
        include_str!("snapshots/utility_completion_zsh_config_flag.stderr"),
    );
}

#[test]
fn server_alias_matches_current_upstream_unknown_command() {
    for args in [
        &["server"][..],
        &["server", "--help"][..],
        &["server", "--bad"][..],
        &["server", "-x"][..],
        &["server", "ignored"][..],
    ] {
        assert_stderr_snapshot(
            args,
            1,
            include_str!("snapshots/utility_server_unknown_command.stderr"),
        );
    }
}

#[test]
fn removed_hidden_compatibility_aliases_match_current_upstream_unknown_commands() {
    for (args, expected) in [
        (
            &["namespace"][..],
            include_str!("snapshots/utility_namespace_unknown_command.stderr"),
        ),
        (
            &["namespace", "--help"][..],
            include_str!("snapshots/utility_namespace_unknown_command.stderr"),
        ),
        (
            &["namespaces", "--help"][..],
            include_str!("snapshots/utility_namespaces_unknown_command.stderr"),
        ),
        (
            &["ns", "users"][..],
            include_str!("snapshots/utility_ns_unknown_command.stderr"),
        ),
        (
            &["machine", "--help"][..],
            include_str!("snapshots/utility_machine_unknown_command.stderr"),
        ),
        (
            &["machines", "--help"][..],
            include_str!("snapshots/utility_machines_unknown_command.stderr"),
        ),
        (
            &["tailnet"][..],
            include_str!("snapshots/utility_tailnet_unknown_command.stderr"),
        ),
        (
            &["tailnet", "--help"][..],
            include_str!("snapshots/utility_tailnet_unknown_command.stderr"),
        ),
        (
            &["tailnet", "status", "--help"][..],
            include_str!("snapshots/utility_tailnet_unknown_command.stderr"),
        ),
        (
            &["init-config"][..],
            include_str!("snapshots/utility_init_config_unknown_command.stderr"),
        ),
        (
            &["init-config", "--help"][..],
            include_str!("snapshots/utility_init_config_unknown_command.stderr"),
        ),
        (
            &["init-config", "--output", "headscale.toml"][..],
            include_str!("snapshots/utility_init_config_unknown_command.stderr"),
        ),
    ] {
        assert_stderr_snapshot(args, 1, expected);
    }
}

#[test]
fn debug_create_node_namespace_alias_matches_current_upstream_unknown_flag() {
    assert_stderr_snapshot(
        &[
            "debug",
            "create-node",
            "--namespace",
            "alice",
            "--key",
            "k",
            "--name",
            "node-one",
        ],
        1,
        "Error: unknown flag: --namespace\n",
    );
    assert_stderr_snapshot(
        &[
            "debug",
            "create-node",
            "-n",
            "alice",
            "--key",
            "k",
            "--name",
            "node-one",
        ],
        1,
        "Error: unknown shorthand flag: 'n' in -n\n",
    );
}

#[test]
fn debug_create_node_required_flag_errors_match_current_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing.sock");
    let config = write_unix_socket_config(dir.path(), &socket);

    assert_config_stderr_snapshot(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--name",
            "node-one",
        ],
        1,
        "Error: required flag(s) \"key\" not set\n",
    );
}

#[test]
fn nodes_register_required_flag_errors_match_current_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing.sock");
    let config = write_unix_socket_config(dir.path(), &socket);

    assert_config_stderr_snapshot(
        &config,
        &["nodes", "register", "--user", "alice"],
        1,
        "Command \"register\" is deprecated, use 'headscale auth register --auth-id <id> --user <user>' instead\nError: required flag(s) \"key\" not set\n",
    );
}

#[test]
fn serve_help_with_extra_args_matches_current_upstream_snapshot() {
    assert_stdout_snapshot(
        &["serve", "ignored", "--help"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stdout_snapshot(
        &["serve", "--config", "missing.yaml", "--help"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stderr_snapshot(
        &["serve", "--listen", "127.0.0.1:0", "--help"],
        1,
        "Error: unknown flag: --listen\n",
    );
}

#[test]
fn help_unknown_topics_match_current_upstream_snapshots() {
    assert_stderr_no_config_warning_snapshot(
        &["help", "server"],
        0,
        include_str!("snapshots/help_server_unknown_topic.stderr"),
    );
    assert_stderr_no_config_warning_snapshot(
        &["help", "status"],
        0,
        include_str!("snapshots/help_status_unknown_topic.stderr"),
    );
}

#[test]
fn utility_json_flag_matches_upstream_stderr_snapshots() {
    assert_stderr_snapshot(
        &["version", "--json"],
        1,
        include_str!("snapshots/utility_json_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["users", "list", "--json"],
        1,
        include_str!("snapshots/utility_json_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["--json", "version"],
        1,
        include_str!("snapshots/utility_top_level_json_flag.stderr"),
    );
}

#[test]
fn utility_top_level_unknown_flags_match_upstream_stderr_snapshots() {
    let unknown_flag =
        include_str!("snapshots/utility_top_level_json_flag.stderr").replace("--json", "--bad");
    assert_stderr_snapshot(&["--bad"], 1, &unknown_flag);

    let unknown_shorthand = include_str!("snapshots/utility_top_level_json_flag.stderr")
        .replace("unknown flag: --json", "unknown shorthand flag: 'x' in -x");
    assert_stderr_snapshot(&["-x"], 1, &unknown_shorthand);
}

#[test]
fn utility_extra_args_match_upstream_unknown_command_errors() {
    for args in [
        &["health", "bad"][..],
        &["configtest", "bad"][..],
        &["dumpConfig", "bad"][..],
        &["mockoidc", "bad"][..],
    ] {
        let output = headscale_clean(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "unexpected status for {args:?}; stdout: {}; stderr: {}",
            stdout(&output),
            stderr(&output)
        );
        assert_eq!(stdout(&output), "", "stdout snapshot for {args:?}");
        assert_eq!(
            stderr(&output),
            format!(
                "Error: unknown command \"{}\" for \"headscale\"\n",
                args.join(" ")
            ),
            "stderr snapshot for {args:?}"
        );
    }

    for (args, expected) in [
        (
            &["completion", "bash", "bad"][..],
            "Error: unknown command \"bad\" for \"headscale completion bash\"\n",
        ),
        (
            &["completion", "bash", "--no-descriptions", "bad"][..],
            "Error: unknown command \"bad\" for \"headscale completion bash\"\n",
        ),
        (
            &["completion", "zsh", "bad"][..],
            include_str!("snapshots/utility_completion_zsh_unknown_command.stderr"),
        ),
        (
            &["completion", "zsh", "--no-descriptions", "bad"][..],
            include_str!("snapshots/utility_completion_zsh_unknown_command.stderr"),
        ),
        (
            &["completion", "fish", "bad"][..],
            include_str!("snapshots/utility_completion_fish_unknown_command.stderr"),
        ),
        (
            &["completion", "fish", "--no-descriptions", "bad"][..],
            include_str!("snapshots/utility_completion_fish_unknown_command.stderr"),
        ),
        (
            &["completion", "powershell", "bad"][..],
            include_str!("snapshots/utility_completion_powershell_unknown_command.stderr"),
        ),
        (
            &["completion", "powershell", "--no-descriptions", "bad"][..],
            include_str!("snapshots/utility_completion_powershell_unknown_command.stderr"),
        ),
    ] {
        let output = headscale_clean(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "unexpected status for {args:?}; stdout: {}; stderr: {}",
            stdout(&output),
            stderr(&output)
        );
        assert_eq!(stdout(&output), "", "stdout snapshot for {args:?}");
        assert_eq!(stderr(&output), expected, "stderr snapshot for {args:?}");
    }
}

#[test]
fn help_topics_with_extra_arg_match_upstream_snapshots() {
    assert_stdout_no_config_warning_snapshot(
        &["help", "version", "bad"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "auth", "bad"],
        include_str!("snapshots/auth_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "auth", "register", "bad"],
        include_str!("snapshots/auth_register_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "users", "bad"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "users", "create", "bad"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "nodes", "bad"],
        include_str!("snapshots/nodes_help.stdout"),
    );
}

#[test]
fn residual_current_upstream_parser_edges_match_stderr_snapshots() {
    assert_stderr_snapshot(
        &["completion", "bash", "--", "bad"],
        1,
        include_str!("snapshots/utility_completion_bash_dashdash_unknown_command.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bash", "--no-descriptions", "--", "bad"],
        1,
        include_str!(
            "snapshots/utility_completion_bash_no_descriptions_dashdash_unknown_command.stderr"
        ),
    );
    assert_stderr_snapshot(
        &["completion", "--no-descriptions"],
        1,
        include_str!("snapshots/utility_completion_missing_shell_no_descriptions.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bad", "--no-descriptions"],
        1,
        include_str!("snapshots/utility_completion_unknown_shell_no_descriptions.stderr"),
    );
    assert_stderr_snapshot(
        &["completion", "bash", "--no-descriptions", "--bad"],
        1,
        include_str!("snapshots/utility_version_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "private-key", "--force", "--bad"],
        1,
        include_str!("snapshots/utility_generate_private_key_unknown_flag.stderr"),
    );
    assert_stderr_snapshot(
        &["generate", "private-key", "--force", "-x"],
        1,
        include_str!("snapshots/utility_generate_private_key_force_unknown_shorthand.stderr"),
    );
}

#[test]
fn completion_fish_no_descriptions_dashdash_unknown_command_matches_current_upstream() {
    assert_stderr_snapshot(
        &["completion", "fish", "--no-descriptions", "--", "bad"],
        1,
        include_str!(
            "snapshots/utility_completion_fish_no_descriptions_dashdash_unknown_command.stderr"
        ),
    );
}

#[test]
fn completion_no_descriptions_strips_zsh_help_text() {
    let output = headscale_clean(&["completion", "zsh"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let with_descriptions = stdout(&output);
    assert!(with_descriptions.contains("--config=[config file"));

    let output = headscale_clean(&["completion", "zsh", "--no-descriptions"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let without_descriptions = stdout(&output);
    assert!(without_descriptions.contains("#compdef headscale"));
    assert!(without_descriptions.contains("--config=[]:CONFIG:_files"));
    assert!(!without_descriptions.contains("--config=[config file"));
}

#[test]
fn leading_config_flag_on_version_loads_config_like_upstream_cobra() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let missing = cwd.path().join("missing.yaml");
    let output = headscale_in(
        &["--config", missing.to_str().unwrap(), "version"],
        cwd.path(),
        home.path(),
    );

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Failed to load config file"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn configtest_loads_default_config_from_current_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "http://127.0.0.1:8080"
listen_addr: "127.0.0.1:8080"
database:
  type: sqlite
  sqlite:
    path: "/tmp/headscale-rs-test.sqlite"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
"#,
    )
    .unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_accepts_current_upstream_https_and_derp_fixture() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/headscale-go-v0.28-config-example.yaml");

    let output = headscale_with_config(&config, &["configtest"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn dump_config_missing_target_matches_current_upstream_snapshots() {
    if Path::new("/etc/headscale").exists() {
        eprintln!("skipping dumpConfig missing-target snapshot: /etc/headscale exists");
        return;
    }

    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    for (args, expected, label) in [
        (
            &["dumpConfig"][..],
            include_str!("snapshots/dump_config_missing_target.stderr"),
            "dumpConfig missing target",
        ),
        (
            &["-o", "json", "dumpConfig"][..],
            include_str!("snapshots/dump_config_missing_target_json.stderr"),
            "dumpConfig missing target json",
        ),
        (
            &["-ojson-line", "dumpConfig"][..],
            include_str!("snapshots/dump_config_missing_target_json_line.stderr"),
            "dumpConfig missing target json-line",
        ),
        (
            &["-oyaml", "dumpConfig"][..],
            include_str!("snapshots/dump_config_missing_target_yaml.stderr"),
            "dumpConfig missing target yaml",
        ),
    ] {
        let output = headscale_in(args, cwd.path(), home.path());
        let expected = if label.ends_with("yaml") {
            format!("{expected}\n")
        } else {
            expected.to_string()
        };
        assert_eq!(
            output.status.code(),
            Some(1),
            "unexpected status for {label}; stdout: {}; stderr: {}",
            stdout(&output),
            stderr(&output)
        );
        assert_eq!(stdout(&output), "", "stdout snapshot for {label}");
        assert_eq!(
            trim_line_end_spaces(&normalize_no_config_warning_timestamp(&stderr(&output))),
            trim_line_end_spaces(&expected),
            "stderr snapshot for {label}"
        );
    }
}

#[test]
fn configtest_rejects_env_invalid_grpc_listen_addr() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_GRPC_LISTEN_ADDR", "not-a-socket")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_invalid_grpc_listen.stderr"),
        "configtest invalid gRPC listener from env",
    );
}

#[test]
fn configtest_accepts_tls_alpn_acme_runtime() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#,
    )
    .unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/configtest_tls_alpn_acme_port_warning.stderr")
    );
}

#[test]
fn configtest_accepts_postgres_config() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
"#,
    )
    .unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_applies_database_env_overrides() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_DATABASE_TYPE", "postgres"),
            ("HEADSCALE_DATABASE_POSTGRES_HOST", "127.0.0.1"),
            ("HEADSCALE_DATABASE_POSTGRES_PORT", "5432"),
            ("HEADSCALE_DATABASE_POSTGRES_NAME", "headscale"),
            ("HEADSCALE_DATABASE_POSTGRES_USER", "headscale"),
            ("HEADSCALE_DATABASE_POSTGRES_SSL", "false"),
        ],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_DATABASE_TYPE", "postgres"),
            ("HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS", "-1"),
        ],
    );
    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_invalid_postgres_pool.stderr"),
        "configtest invalid postgres pool from env",
    );
}

#[test]
fn configtest_rejects_invalid_postgres_pool_config() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
  postgres:
    max_open_conns: -1
"#,
    )
    .unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_invalid_postgres_pool.stderr"),
        "configtest invalid postgres pool",
    );
}

fn assert_configtest_default_config_snapshot(config: &str, expected: &str, label: &str) {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), config).unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert_configtest_stderr_snapshot(&output, 1, expected, label);
}

fn assert_serve_default_config_snapshot(config: &str, expected: &str, label: &str) {
    assert_serve_default_config_args_snapshot(config, &["serve"], expected, label);
}

fn assert_serve_default_config_args_snapshot(
    config: &str,
    args: &[&str],
    expected: &str,
    label: &str,
) {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let db_path = cwd.path().join("should-not-exist.sqlite");
    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"{config}
database:
  type: sqlite
  sqlite:
    path: "{}"
"#,
            db_path.display()
        ),
    )
    .unwrap();

    let output = headscale_in(args, cwd.path(), home.path());

    assert_process_stderr_snapshot(&output, 1, expected, label);
    assert!(
        !db_path.exists(),
        "invalid serve config should fail before opening SQLite at {}",
        db_path.display()
    );
}

#[test]
fn configtest_rejects_supported_server_init_validation_errors() {
    assert_configtest_default_config_snapshot(
        r"
randomize_client_port: true
",
        include_str!("snapshots/configtest_removed_randomize_client_port.stderr"),
        "configtest removed randomize_client_port",
    );

    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), "").unwrap();
    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_RANDOMIZE_CLIENT_PORT", "true")],
    );
    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_removed_randomize_client_port.stderr"),
        "configtest removed randomize_client_port env override",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#,
        include_str!("snapshots/configtest_missing_noise_private_key.stderr"),
        "configtest missing noise private key",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "headscale.example"
"#,
        include_str!("snapshots/configtest_bad_server_url_scheme.stderr"),
        "configtest bad server_url scheme",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
prefixes:
  v4: "not-a-cidr"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
"#,
        include_str!("snapshots/configtest_invalid_prefix_v4.stderr"),
        "configtest invalid prefixes.v4",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
prefixes:
  v6: "not-a-cidr"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
"#,
        include_str!("snapshots/configtest_invalid_prefix_v6.stderr"),
        "configtest invalid prefixes.v6",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://login.tail.example.org"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: true
  override_local_dns: false
  base_domain: "tail.example.org"
"#,
        include_str!("snapshots/configtest_server_url_under_base_domain.stderr"),
        "configtest server_url under DNS base_domain",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_cert_path: "/etc/headscale/cert.pem"
"#,
        include_str!("snapshots/configtest_manual_tls_incomplete.stderr"),
        "configtest incomplete manual TLS",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
tls_letsencrypt_hostname: "headscale.example"
tls_cert_path: "/etc/headscale/cert.pem"
"#,
        include_str!("snapshots/configtest_tls_conflict.stderr"),
        "configtest TLS conflict",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_listen: "not-a-socket"
tls_letsencrypt_challenge_type: "HTTP-01"
"#,
        include_str!("snapshots/configtest_invalid_acme_http01_listen.stderr"),
        "configtest invalid ACME HTTP-01 listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: ""
"#,
        include_str!("snapshots/configtest_empty_acme_challenge_type.stderr"),
        "configtest empty ACME challenge type",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
metrics_listen_addr: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_metrics_listen.stderr"),
        "configtest invalid metrics listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
grpc_listen_addr: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_grpc_listen.stderr"),
        "configtest invalid gRPC listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
server:
  https_listen: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_https_listen.stderr"),
        "configtest invalid HTTPS listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
derp:
  server:
    enabled: true
    automatically_add_embedded_derp_region: false
"#,
        include_str!("snapshots/configtest_invalid_derp.stderr"),
        "configtest invalid DERP",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
derp:
  server:
    enabled: true
    stun_listen_addr: null
"#,
        include_str!("snapshots/configtest_derp_missing_stun_listen.stderr"),
        "configtest DERP missing STUN listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
policy:
  mode: consul
"#,
        include_str!("snapshots/configtest_invalid_policy_mode.stderr"),
        "configtest invalid policy mode",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
node:
  routes:
    ha:
      probe_interval: 5
      probe_timeout: 5
"#,
        include_str!("snapshots/configtest_invalid_node_route_ha.stderr"),
        "configtest invalid node route HA timing",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
node:
  routes:
    ha:
      probe_timeout: 10s
"#,
        include_str!("snapshots/configtest_invalid_node_route_ha_default_interval.stderr"),
        "configtest invalid node route HA timing against default interval",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
trusted_proxies:
  - "0.0.0.0/0"
"#,
        include_str!("snapshots/configtest_unsafe_trusted_proxy.stderr"),
        "configtest unsafe trusted proxy",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "headscale.example"
tls_letsencrypt_challenge_type: "DNS-01"
dns:
  magic_dns: false
  override_local_dns: true
node:
  routes:
    ha:
      probe_interval: 1s
      probe_timeout: 0s
tuning:
  node_store_batch_size: 0
  node_store_batch_timeout: 0s
"#,
        include_str!("snapshots/configtest_accumulates_upstream_fatal_errors.stderr"),
        "configtest accumulates upstream fatal errors",
    );
}

#[test]
fn configtest_applies_policy_env_overrides() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let good_policy = cwd.path().join("policy.hujson");
    fs::write(
        &good_policy,
        r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
    )
    .unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: file
  path: missing-policy.hujson
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_POLICY_MODE", "database")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_POLICY_PATH", good_policy.to_str().unwrap())],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_dns_env_override_requires_global_nameservers() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_DNS_OVERRIDE_LOCAL_DNS", "true")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        "Error: Fatal config error: dns.nameservers.global must be set when dns.override_local_dns is true\n",
        "configtest dns env override requires global nameservers",
    );
}

#[test]
fn configtest_dns_env_nameservers_global_satisfies_override() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_DNS_OVERRIDE_LOCAL_DNS", "true"),
            ("HEADSCALE_DNS_NAMESERVERS_GLOBAL", "1.1.1.1"),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_rejects_env_derp_disabled_embedded_region_without_paths() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_DERP_SERVER_ENABLED", "true"),
            (
                "HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION",
                "false",
            ),
        ],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_invalid_derp.stderr"),
        "configtest invalid DERP from env",
    );
}

#[test]
fn configtest_rejects_env_ephemeral_node_inactivity_timeout() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT", "65s")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        "Error: Fatal config error: node.ephemeral.inactivity_timeout (65s) is set too low, must be more than 65s\n",
        "configtest invalid deprecated ephemeral timeout from env",
    );

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT", "66s")],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_rejects_env_invalid_tuning_node_store_values() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE", "0")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        "Error: Fatal config error: tuning.node_store_batch_size must be positive, got 0\n",
        "configtest invalid tuning node store batch size from env",
    );

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT", "0s")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        "Error: Fatal config error: tuning.node_store_batch_timeout must be positive, got 0s\n",
        "configtest invalid tuning node store batch timeout from env",
    );

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE", "25"),
            ("HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT", "50ms"),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), "");
}

#[test]
fn configtest_rejects_env_invalid_tls_letsencrypt_challenge_type() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        cwd.path().join("config.yaml"),
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
policy:
  mode: database
"#,
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["configtest"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE", "DNS-01")],
    );

    assert_configtest_stderr_snapshot(
        &output,
        1,
        "Error: Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n",
        "configtest invalid TLS ACME challenge type from env",
    );
}

#[test]
fn serve_rejects_supported_server_init_validation_before_state_startup() {
    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#,
        include_str!("snapshots/configtest_missing_noise_private_key.stderr"),
        "serve missing noise private key",
    );

    assert_serve_default_config_args_snapshot(
        r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#,
        &["-o", "json", "serve"],
        include_str!("snapshots/serve_missing_noise_private_key_json.stderr"),
        "serve missing noise private key json",
    );

    assert_serve_default_config_args_snapshot(
        r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#,
        &["-ojson-line", "serve"],
        include_str!("snapshots/serve_missing_noise_private_key_json_line.stderr"),
        "serve missing noise private key json-line",
    );

    assert_serve_default_config_args_snapshot(
        r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#,
        &["-oyaml", "serve"],
        include_str!("snapshots/serve_missing_noise_private_key_yaml.stderr"),
        "serve missing noise private key yaml",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "headscale.example"
"#,
        include_str!("snapshots/configtest_bad_server_url_scheme.stderr"),
        "serve bad server_url scheme",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://login.tail.example.org"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: true
  override_local_dns: false
  base_domain: "tail.example.org"
"#,
        include_str!("snapshots/configtest_server_url_under_base_domain.stderr"),
        "serve server_url under DNS base_domain",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_cert_path: "/etc/headscale/cert.pem"
"#,
        include_str!("snapshots/configtest_manual_tls_incomplete.stderr"),
        "serve incomplete manual TLS",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
tls_letsencrypt_hostname: "headscale.example"
tls_cert_path: "/etc/headscale/cert.pem"
"#,
        include_str!("snapshots/configtest_tls_conflict.stderr"),
        "serve TLS conflict",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_listen: "not-a-socket"
tls_letsencrypt_challenge_type: "HTTP-01"
"#,
        include_str!("snapshots/serve_invalid_acme_http01_listen.stderr"),
        "serve invalid ACME HTTP-01 listener",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
metrics_listen_addr: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_metrics_listen.stderr"),
        "serve invalid metrics listener",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
grpc_listen_addr: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_grpc_listen.stderr"),
        "serve invalid gRPC listener",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
policy:
  mode: consul
"#,
        include_str!("snapshots/serve_invalid_policy_mode.stderr"),
        "serve invalid policy mode",
    );

    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
trusted_proxies:
  - "0.0.0.0/0"
"#,
        include_str!("snapshots/serve_unsafe_trusted_proxy.stderr"),
        "serve unsafe trusted proxy",
    );
}

#[test]
fn serve_rejects_invalid_https_listen_before_state_startup() {
    assert_serve_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
server:
  https_listen: "not-a-socket"
"#,
        include_str!("snapshots/serve_invalid_https_listen.stderr"),
        "serve invalid HTTPS listener",
    );
}

#[test]
fn serve_rejects_http01_acme_challenge_listener_collision_before_public_ca_network() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let challenge_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let challenge_addr = challenge_listener.local_addr().unwrap();
    let db_path = cwd.path().join("db.sqlite");
    let cache_dir = cwd.path().join("acme-cache");
    let noise_path = cwd.path().join("noise_private.key");
    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:0"
noise:
  private_key_path: {}
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: {}
policy:
  mode: database
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: {}
tls_letsencrypt_listen: "{challenge_addr}"
tls_letsencrypt_challenge_type: "HTTP-01"
"#,
            yaml_double_quoted(&noise_path.to_string_lossy()),
            yaml_double_quoted(&db_path.to_string_lossy()),
            yaml_double_quoted(&cache_dir.to_string_lossy()),
        ),
    )
    .unwrap();

    let output = headscale_in_with_env(
        &["serve"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_LOG", "error")],
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected status for serve HTTP-01 ACME listener collision; stdout: {}; stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
    assert_eq!(
        trim_line_end_spaces(&normalize_acme_http01_bind_failure_stderr(
            &stderr(&output),
            challenge_addr,
        )),
        trim_line_end_spaces(include_str!(
            "snapshots/serve_acme_http01_challenge_listener_collision.stderr"
        )),
        "stderr snapshot for serve HTTP-01 ACME listener collision"
    );
    assert!(
        !cache_dir.join("headscale.example").exists(),
        "ACME certificate cache should not be written after listener bind failure"
    );
}

#[test]
fn serve_ignores_extra_positional_args_like_upstream_before_validation() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let db_path = cwd.path().join("should-not-exist.sqlite");
    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: "{}"
"#,
            db_path.display()
        ),
    )
    .unwrap();

    let output = headscale_in(&["serve", "ignored"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_missing_noise_private_key.stderr"),
        "serve ignores extra positional args",
    );
    assert!(
        !db_path.exists(),
        "invalid serve config should fail before opening SQLite at {}",
        db_path.display()
    );
}

#[cfg(not(feature = "postgres-sqlx"))]
#[test]
fn serve_rejects_unsupported_postgres_before_sqlite_startup() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let db_path = cwd.path().join("should-not-exist.sqlite");
    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"
server_url: "http://127.0.0.1:8080"
listen_addr: "127.0.0.1:0"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
  sqlite:
    path: "{}"
"#,
            db_path.display()
        ),
    )
    .unwrap();

    let output = headscale_in(&["serve"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/serve_unsupported_postgres.stderr"),
        "serve unsupported postgres",
    );

    let output = headscale_in(&["-o", "json", "serve"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/serve_unsupported_postgres_json.stderr"),
        "serve unsupported postgres json",
    );

    let output = headscale_in(&["-ojson-line", "serve"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/serve_unsupported_postgres_json_line.stderr"),
        "serve unsupported postgres json-line",
    );

    let output = headscale_in(&["-oyaml", "serve"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/serve_unsupported_postgres_yaml.stderr"),
        "serve unsupported postgres yaml",
    );
    assert!(
        !db_path.exists(),
        "unsupported postgres serve path should fail before opening SQLite at {}",
        db_path.display()
    );
}

#[test]
fn implemented_admin_command_help_matches_snapshots() {
    assert_stdout_snapshot(
        &["users", "--help"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "create", "--help"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "list", "--help"],
        include_str!("snapshots/users_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "rename", "--help"],
        include_str!("snapshots/users_rename_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "destroy", "--help"],
        include_str!("snapshots/users_destroy_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "--help"],
        include_str!("snapshots/nodes_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "list", "--help"],
        include_str!("snapshots/nodes_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "list-routes", "--help"],
        include_str!("snapshots/nodes_list_routes_help.stdout"),
    );
    assert_stdout_stderr_snapshot(
        &["nodes", "register", "--help"],
        include_str!("snapshots/nodes_register_help.stdout"),
        include_str!("snapshots/nodes_register_help.stderr"),
    );
    assert_stdout_snapshot(
        &["nodes", "expire", "--help"],
        include_str!("snapshots/nodes_expire_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "rename", "--help"],
        include_str!("snapshots/nodes_rename_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "tag", "--help"],
        include_str!("snapshots/nodes_tag_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "create", "--help"],
        include_str!("snapshots/preauthkeys_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "approve-routes", "--help"],
        include_str!("snapshots/nodes_approve_routes_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "delete", "--help"],
        include_str!("snapshots/nodes_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "backfillips", "--help"],
        include_str!("snapshots/nodes_backfillips_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "list", "--help"],
        include_str!("snapshots/preauthkeys_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "--help"],
        include_str!("snapshots/preauthkeys_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "expire", "--help"],
        include_str!("snapshots/preauthkeys_expire_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "delete", "--help"],
        include_str!("snapshots/preauthkeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "create", "--help"],
        include_str!("snapshots/apikeys_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "--help"],
        include_str!("snapshots/apikeys_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "list", "--help"],
        include_str!("snapshots/apikeys_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "expire", "--help"],
        include_str!("snapshots/apikeys_expire_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "delete", "--help"],
        include_str!("snapshots/apikeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "--help"],
        include_str!("snapshots/policy_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "get", "--help"],
        include_str!("snapshots/policy_get_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "set", "--help"],
        include_str!("snapshots/policy_set_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "check", "--help"],
        include_str!("snapshots/policy_check_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "--help"],
        include_str!("snapshots/auth_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "register", "--help"],
        include_str!("snapshots/auth_register_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "approve", "--help"],
        include_str!("snapshots/auth_approve_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "reject", "--help"],
        include_str!("snapshots/auth_reject_help.stdout"),
    );
    assert_stdout_snapshot(
        &["debug", "create-node", "--help"],
        include_str!("snapshots/debug_create_node_help.stdout"),
    );
}

#[test]
fn unknown_admin_group_children_match_upstream_parent_help() {
    assert_stdout_snapshot(
        &["users", "bogus"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "bogus"],
        include_str!("snapshots/auth_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "bogus"],
        include_str!("snapshots/policy_help.stdout"),
    );
}

#[test]
fn operator_top_level_command_help_matches_snapshots() {
    assert_stdout_snapshot(
        &["serve", "--help"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stdout_snapshot(
        &["serve", "-h"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "serve"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stdout_snapshot(
        &["health", "--help"],
        include_str!("snapshots/health_help.stdout"),
    );
    assert_stdout_snapshot(
        &["--force=false", "health", "--help"],
        include_str!("snapshots/health_help.stdout"),
    );
    assert_stdout_snapshot(
        &["health", "--force=false", "--help"],
        include_str!("snapshots/health_help.stdout"),
    );
    assert_stdout_snapshot(
        &["health", "--config", "missing.yaml", "--help"],
        include_str!("snapshots/health_help.stdout"),
    );
    assert_stdout_snapshot(
        &["health", "-o", "json", "--help"],
        include_str!("snapshots/health_help.stdout"),
    );
    assert_stdout_snapshot(
        &["version", "--help"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_snapshot(
        &["configtest", "--help"],
        include_str!("snapshots/configtest_help.stdout"),
    );
    assert_stdout_snapshot(
        &["configtest", "-c", "missing.yaml", "--help"],
        include_str!("snapshots/configtest_help.stdout"),
    );
    assert_stdout_snapshot(
        &["configtest", "--output=json", "--help"],
        include_str!("snapshots/configtest_help.stdout"),
    );
    assert_stdout_snapshot(
        &["dumpConfig", "--help"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_snapshot(
        &["dumpConfig", "--config=missing.yaml", "--help"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_snapshot(
        &["dumpConfig", "--force", "--help"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "dumpConfig"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_snapshot(
        &["generate", "--help"],
        include_str!("snapshots/generate_help.stdout"),
    );
    assert_stdout_snapshot(
        &["gen", "--help"],
        include_str!("snapshots/generate_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "gen"],
        include_str!("snapshots/generate_help.stdout"),
    );
    assert_stdout_snapshot(
        &["generate", "private-key", "--help"],
        include_str!("snapshots/generate_private_key_help.stdout"),
    );
    assert_stdout_snapshot(
        &["gen", "private-key", "--help"],
        include_str!("snapshots/generate_private_key_help.stdout"),
    );
    assert_stdout_snapshot(
        &["mockoidc", "--help"],
        include_str!("snapshots/mockoidc_help.stdout"),
    );
    assert_stdout_snapshot(
        &["mockoidc", "ignored", "--help"],
        include_str!("snapshots/mockoidc_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "mockoidc"],
        include_str!("snapshots/mockoidc_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "--help"],
        include_str!("snapshots/completion_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "bash", "--help"],
        include_str!("snapshots/completion_bash_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "bash", "--no-descriptions", "--help"],
        include_str!("snapshots/completion_bash_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "completion", "bash"],
        include_str!("snapshots/completion_bash_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "fish", "--help"],
        include_str!("snapshots/completion_fish_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "completion", "fish"],
        include_str!("snapshots/completion_fish_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "powershell", "--help"],
        include_str!("snapshots/completion_powershell_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "completion", "powershell"],
        include_str!("snapshots/completion_powershell_help.stdout"),
    );
    assert_stdout_snapshot(
        &["debug", "--help"],
        include_str!("snapshots/debug_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "zsh", "--help"],
        include_str!("snapshots/completion_zsh_help.stdout"),
    );
    assert_stdout_no_config_warning_snapshot(
        &["help", "completion", "zsh"],
        include_str!("snapshots/completion_zsh_help.stdout"),
    );
}

#[test]
fn policy_file_flag_and_direct_database_bypass_match_upstream_shape() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let db_path = dir.path().join("db.sqlite");
    let policy_path = dir.path().join("policy.hujson");
    fs::write(
        &config_path,
        format!(
            "server:\n  db_path: {}\npolicy:\n  mode: database\n",
            db_path.display()
        ),
    )
    .unwrap();
    fs::write(&policy_path, "{\n  // preserved\n  \"acls\": []\n}\n").unwrap();

    let positional = headscale_clean(&["policy", "set", "policy.hujson"]);
    assert!(!positional.status.success());
    assert_eq!(positional.status.code(), Some(2));
    assert!(
        stderr(&positional).contains("unexpected argument 'policy.hujson'"),
        "stderr: {}",
        stderr(&positional)
    );

    let config = config_path.to_str().unwrap();
    let policy = policy_path.to_str().unwrap();
    let bypass = "--bypass-grpc-and-access-database-directly";

    let empty_get = headscale_clean(&["--config", config, "--force", "policy", "get", bypass]);
    assert_eq!(empty_get.status.code(), Some(6));
    assert_eq!(stdout(&empty_get), "");
    assert_eq!(
        stderr(&empty_get),
        include_str!("snapshots/policy_direct_db_missing.stderr")
    );

    let set = headscale_clean(&[
        "--config", config, "--force", "-o", "json", "policy", "set", "--file", policy, bypass,
    ]);
    assert!(set.status.success(), "stderr: {}", stderr(&set));
    assert_eq!(stdout(&set), "Policy updated.\n");
    assert_eq!(stderr(&set), "");

    let set_text = headscale_clean(&[
        "--config", config, "--force", "policy", "set", "--file", policy, bypass,
    ]);
    assert!(set_text.status.success(), "stderr: {}", stderr(&set_text));
    assert_eq!(stdout(&set_text), "Policy updated.\n");
    assert_eq!(stderr(&set_text), "");

    let get = headscale_clean(&[
        "--config", config, "--force", "-o", "json", "policy", "get", bypass,
    ]);
    assert!(get.status.success(), "stderr: {}", stderr(&get));
    assert_eq!(stdout(&get), "{\n  // preserved\n  \"acls\": []\n}\n");
    assert_eq!(stderr(&get), "");

    let get_text = headscale_clean(&["--config", config, "--force", "policy", "get", bypass]);
    assert!(get_text.status.success(), "stderr: {}", stderr(&get_text));
    assert_eq!(stdout(&get_text), "{\n  // preserved\n  \"acls\": []\n}\n");
    assert_eq!(stderr(&get_text), "");

    let check = headscale_clean(&[
        "--config", config, "--force", "policy", "check", "--file", policy, bypass,
    ]);
    assert!(check.status.success(), "stderr: {}", stderr(&check));
    assert_eq!(stdout(&check), "Policy is valid\n");
    assert_eq!(stderr(&check), "");
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_direct_db_bypass_supports_postgres_without_server() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("direct_policy").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let config = write_postgres_serve_config(
        dir.path(),
        database.fields(),
        unused_loopback_addr(),
        unused_loopback_addr(),
        unused_loopback_addr(),
    );
    let policy_path = dir.path().join("pg-direct-policy.hujson");
    fs::write(&policy_path, "{\n  // preserved pg\n  \"acls\": []\n}\n")?;
    let policy = policy_path.to_string_lossy().to_string();
    let bypass = "--bypass-grpc-and-access-database-directly";

    let result = async {
        let empty_get = headscale_with_config(&config, &["--force", "policy", "get", bypass]);
        assert_eq!(empty_get.status.code(), Some(6));
        assert_eq!(stdout(&empty_get), "");
        assert!(
            stderr(&empty_get).contains("loading ACL from Postgres database: acl policy not found"),
            "stderr: {}",
            stderr(&empty_get)
        );

        let set_json = headscale_with_config(
            &config,
            &[
                "--force", "-o", "json", "policy", "set", "--file", &policy, bypass,
            ],
        );
        assert!(set_json.status.success(), "stderr: {}", stderr(&set_json));
        assert_eq!(stdout(&set_json), "Policy updated.\n");
        assert_eq!(stderr(&set_json), "");

        let set_text = headscale_with_config(
            &config,
            &["--force", "policy", "set", "--file", &policy, bypass],
        );
        assert!(set_text.status.success(), "stderr: {}", stderr(&set_text));
        assert_eq!(stdout(&set_text), "Policy updated.\n");
        assert_eq!(stderr(&set_text), "");

        let get =
            headscale_with_config(&config, &["--force", "-o", "json", "policy", "get", bypass]);
        assert!(get.status.success(), "stderr: {}", stderr(&get));
        assert_eq!(stdout(&get), "{\n  // preserved pg\n  \"acls\": []\n}\n");
        assert_eq!(stderr(&get), "");

        let check = headscale_with_config(
            &config,
            &["--force", "policy", "check", "--file", &policy, bypass],
        );
        assert!(check.status.success(), "stderr: {}", stderr(&check));
        assert_eq!(stdout(&check), "Policy is valid\n");
        assert_eq!(stderr(&check), "");

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    database.cleanup().await?;
    result
}

#[test]
fn implemented_admin_local_errors_match_snapshots() {
    assert_stderr_snapshot(
        &["auth", "register"],
        1,
        include_str!("snapshots/auth_register_missing_flags.stderr"),
    );
    assert_stderr_snapshot(
        &["auth", "register", "--user", "alice"],
        1,
        include_str!("snapshots/auth_missing_auth_id.stderr"),
    );
    assert_stderr_snapshot(
        &["auth", "approve"],
        1,
        include_str!("snapshots/auth_missing_auth_id.stderr"),
    );
    assert_stderr_snapshot(
        &["users", "create"],
        1,
        include_str!("snapshots/users_create_missing_name.stderr"),
    );
    assert_stderr_snapshot(
        &["users", "create", "--display-name", "Alice"],
        1,
        include_str!("snapshots/users_create_missing_name.stderr"),
    );
    assert_stderr_snapshot(
        &["users", "rename", "--name", "alice"],
        1,
        include_str!("snapshots/users_rename_missing_new_name.stderr"),
    );
    assert_stderr_snapshot(
        &["preauthkeys", "expire"],
        1,
        include_str!("snapshots/preauthkeys_missing_id.stderr"),
    );
    assert_stderr_snapshot(
        &["preauthkeys", "delete"],
        1,
        include_str!("snapshots/preauthkeys_missing_id.stderr"),
    );
    assert_stderr_snapshot(
        &["apikeys", "expire"],
        1,
        include_str!("snapshots/apikeys_missing_selector.stderr"),
    );
    assert_stderr_snapshot(
        &["--server", "http://127.0.0.1:9", "apikeys", "expire"],
        1,
        include_str!("snapshots/apikeys_missing_selector.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "apikeys",
            "delete",
            "--id",
            "7",
            "--prefix",
            "hskey-api-abcdefghijkl-***",
        ],
        1,
        include_str!("snapshots/apikeys_conflicting_selector.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "apikeys",
            "delete",
            "--id",
            "7",
            "--prefix",
            "hskey-api-abcdefghijkl-***",
        ],
        1,
        include_str!("snapshots/apikeys_conflicting_selector.stderr"),
    );
    assert_stderr_snapshot(
        &["--server", "http://127.0.0.1:9", "nodes", "expire"],
        6,
        include_str!("snapshots/nodes_missing_identifier.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "nodes",
            "expire",
            "1",
            "--identifier",
            "2",
        ],
        6,
        include_str!("snapshots/nodes_conflicting_identifier.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "nodes",
            "delete",
            "1",
            "--identifier",
            "2",
        ],
        6,
        include_str!("snapshots/nodes_conflicting_identifier.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "nodes",
            "rename",
            "new-name",
        ],
        6,
        include_str!("snapshots/nodes_rename_missing_identifier.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "auth",
            "approve",
            "--auth-id",
            "abc",
        ],
        6,
        include_str!("snapshots/auth_legacy_http_error.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "users",
            "rename",
            "--name",
            "alice",
            "--new-name",
            "bob",
        ],
        6,
        include_str!("snapshots/users_rename_legacy_http_error.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--server",
            "http://127.0.0.1:9",
            "nodes",
            "register",
            "-u",
            "alice",
            "-k",
            "nodekey:abc",
        ],
        6,
        include_str!("snapshots/nodes_register_legacy_http_error.stderr"),
    );
    assert_stderr_snapshot(
        &["--address", "http://127.0.0.1:9", "users", "list"],
        6,
        include_str!("snapshots/grpc_remote_missing_api_key.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=json",
            "--address",
            "http://127.0.0.1:9",
            "users",
            "list",
        ],
        6,
        include_str!("snapshots/grpc_remote_missing_api_key_json.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=json-line",
            "--address",
            "http://127.0.0.1:9",
            "users",
            "list",
        ],
        6,
        include_str!("snapshots/grpc_remote_missing_api_key_json_line.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=yaml",
            "--address",
            "http://127.0.0.1:9",
            "users",
            "list",
        ],
        6,
        include_str!("snapshots/grpc_remote_missing_api_key_yaml.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--address",
            "http://127.0.0.1:9",
            "--api-key",
            "test",
            "users",
            "list",
        ],
        3,
        include_str!("snapshots/grpc_remote_connection_failure.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=json",
            "--address",
            "http://127.0.0.1:9",
            "--api-key",
            "test",
            "users",
            "list",
        ],
        3,
        include_str!("snapshots/grpc_remote_connection_failure_json.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=json-line",
            "--address",
            "http://127.0.0.1:9",
            "--api-key",
            "test",
            "users",
            "list",
        ],
        3,
        include_str!("snapshots/grpc_remote_connection_failure_json_line.stderr"),
    );
    assert_stderr_snapshot(
        &[
            "--output=yaml",
            "--address",
            "http://127.0.0.1:9",
            "--api-key",
            "test",
            "users",
            "list",
        ],
        3,
        include_str!("snapshots/grpc_remote_connection_failure_yaml.stderr"),
    );
}

#[test]
fn local_unix_socket_connection_warnings_match_current_upstream_snapshots() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let default = headscale_in_with_env(
        &["users", "list"],
        cwd.path(),
        home.path(),
        &[("HEADSCALE_CLI_TIMEOUT", "1s")],
    );
    assert_process_no_config_warning_stderr_snapshot(
        &default,
        1,
        include_str!("snapshots/grpc_default_unix_socket_connection_failure.stderr"),
        "default Unix socket connection failure",
    );

    let socket = "/tmp/headscale-missing-parity-env.sock";
    let _ = fs::remove_file(socket);
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let env_socket = headscale_in_with_env(
        &["users", "list"],
        cwd.path(),
        home.path(),
        &[
            ("HEADSCALE_UNIX_SOCKET", socket),
            ("HEADSCALE_CLI_TIMEOUT", "1s"),
        ],
    );
    assert_process_no_config_warning_stderr_snapshot(
        &env_socket,
        1,
        include_str!("snapshots/grpc_env_unix_socket_connection_failure.stderr"),
        "env Unix socket connection failure",
    );

    let socket = "/tmp/headscale-missing-parity-config.sock";
    let _ = fs::remove_file(socket);
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    fs::write(
        &config,
        format!("unix_socket: \"{socket}\"\ncli:\n  timeout: \"1s\"\n"),
    )
    .unwrap();
    let config_socket = headscale_with_config(&config, &["users", "list"]);
    assert_process_stderr_snapshot(
        &config_socket,
        1,
        include_str!("snapshots/grpc_config_unix_socket_connection_failure.stderr"),
        "config Unix socket connection failure",
    );
}

#[test]
fn grpc_identifier_usage_errors_happen_before_connection() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing.sock");
    let config = write_unix_socket_config(dir.path(), &socket);
    let expected = "Error: required flag(s) \"identifier\" not set\n";

    for args in [
        &["nodes", "expire"][..],
        &["nodes", "expire", "1"][..],
        &["nodes", "rename", "node-new"][..],
        &["nodes", "tag", "--tags", "tag:prod"][..],
        &["nodes", "tag", "1", "--tags", "tag:prod"][..],
        &["nodes", "delete"][..],
        &["nodes", "delete", "1"][..],
        &["nodes", "approve-routes", "--routes", "10.0.0.0/24"][..],
    ] {
        assert_config_stderr_snapshot(&config, args, 1, expected);
    }

    assert_config_stderr_snapshot(
        &config,
        &["nodes", "list-routes", "--identifier", "abc"],
        1,
        "Error: invalid argument \"abc\" for \"-i, --identifier\" flag: strconv.ParseUint: parsing \"abc\": invalid syntax\n",
    );
    assert_config_stderr_snapshot(
        &config,
        &["nodes", "list-routes", "--identifier", "-1"],
        1,
        "Error: invalid argument \"-1\" for \"-i, --identifier\" flag: strconv.ParseUint: parsing \"-1\": invalid syntax\n",
    );
    assert_config_stderr_snapshot(
        &config,
        &["users", "list", "--identifier", "abc"],
        1,
        "Error: invalid argument \"abc\" for \"-i, --identifier\" flag: strconv.ParseInt: parsing \"abc\": invalid syntax\n",
    );
}

#[test]
fn upstream_cli_parse_errors_match_cobra_for_admin_edges() {
    assert_stderr_snapshot(
        &["userz"],
        1,
        "Error: unknown command \"userz\" for \"headscale\"\n\nDid you mean this?\n\tusers\n\n",
    );
    assert_stderr_snapshot(
        &["nodes", "list", "--user"],
        1,
        "Error: flag needs an argument: --user\n",
    );
    assert_stderr_snapshot(
        &["-o", "json", "nodes", "list", "--user"],
        1,
        include_str!("snapshots/nodes_list_missing_user_json.stderr"),
    );
    assert_stderr_snapshot(
        &["-ojson-line", "nodes", "list", "--user"],
        1,
        include_str!("snapshots/nodes_list_missing_user_json_line.stderr"),
    );
    assert_stderr_snapshot(
        &["--output=yaml", "nodes", "list", "--user"],
        1,
        &format!(
            "{}\n",
            include_str!("snapshots/nodes_list_missing_user_yaml.stderr")
        ),
    );
    assert_stderr_snapshot(
        &["preauthkeys", "create", "--user"],
        1,
        "Error: flag needs an argument: --user\n",
    );
    assert_stderr_snapshot(
        &["preauthkeys", "create", "--user", "abc"],
        1,
        "Error: invalid argument \"abc\" for \"-u, --user\" flag: strconv.ParseUint: parsing \"abc\": invalid syntax\n",
    );
    assert_stderr_snapshot(
        &["preauthkeys", "create", "--user", "-1"],
        1,
        "Error: invalid argument \"-1\" for \"-u, --user\" flag: strconv.ParseUint: parsing \"-1\": invalid syntax\n",
    );
    assert_stderr_snapshot(
        &["preauthkeys", "create", "-u", "-o", "json"],
        1,
        "Error: invalid argument \"-o\" for \"-u, --user\" flag: strconv.ParseUint: parsing \"-o\": invalid syntax\n",
    );
    assert_stderr_snapshot(
        &["preauthkeys", "--user", "abc", "create"],
        1,
        "Error: invalid argument \"abc\" for \"-u, --user\" flag: strconv.ParseUint: parsing \"abc\": invalid syntax\n",
    );
}

#[test]
fn unknown_output_selector_falls_back_to_human_version_output() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["version", "--output", "xml"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with("headscale version "));
    assert_eq!(stderr(&output), "");
}

#[test]
fn unknown_output_selector_falls_back_to_human_error_output() {
    let output = headscale_clean(&["-o", "xml", "preauthkeys", "expire"]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/preauthkeys_missing_id.stderr")
    );
}

#[test]
fn implemented_admin_errors_follow_output_format() {
    let auth_register = headscale_clean(&["-o", "json", "auth", "register"]);
    assert_eq!(auth_register.status.code(), Some(1));
    assert_eq!(stdout(&auth_register), "");
    assert_eq!(
        stderr(&auth_register),
        "{\n\t\"error\": \"required flag(s) \\\"auth-id\\\", \\\"user\\\" not set\"\n}\n"
    );

    let auth_approve = headscale_clean(&["auth", "approve", "-ojson-line"]);
    assert_eq!(auth_approve.status.code(), Some(1));
    assert_eq!(stdout(&auth_approve), "");
    assert_eq!(
        stderr(&auth_approve),
        "{\"error\":\"required flag(s) \\\"auth-id\\\" not set\"}\n"
    );

    let preauth_missing_user = headscale_clean(&["-o", "json", "preauthkeys", "create", "--user"]);
    assert_eq!(preauth_missing_user.status.code(), Some(1));
    assert_eq!(stdout(&preauth_missing_user), "");
    assert_eq!(
        stderr(&preauth_missing_user),
        "{\n\t\"error\": \"flag needs an argument: --user\"\n}\n"
    );

    let preauth_invalid_user =
        headscale_clean(&["preauthkeys", "create", "-o", "json", "--user", "abc"]);
    assert_eq!(preauth_invalid_user.status.code(), Some(1));
    assert_eq!(stdout(&preauth_invalid_user), "");
    assert_eq!(
        stderr(&preauth_invalid_user),
        "{\n\t\"error\": \"invalid argument \\\"abc\\\" for \\\"-u, --user\\\" flag: strconv.ParseUint: parsing \\\"abc\\\": invalid syntax\"\n}\n"
    );

    let users_create = headscale_clean(&["--output", "yaml", "users", "create"]);
    assert_eq!(users_create.status.code(), Some(1));
    assert_eq!(stdout(&users_create), "");
    assert_eq!(stderr(&users_create), "error: missing parameters\n\n");

    let json = headscale_clean(&["-o", "json", "preauthkeys", "expire"]);
    assert_eq!(json.status.code(), Some(1));
    assert_eq!(stdout(&json), "");
    assert_eq!(
        stderr(&json),
        "{\n\t\"error\": \"missing --id parameter: missing parameters\"\n}\n"
    );

    let json_line = headscale_clean(&["-ojson-line", "preauthkeys", "delete"]);
    assert_eq!(json_line.status.code(), Some(1));
    assert_eq!(stdout(&json_line), "");
    assert_eq!(
        stderr(&json_line),
        "{\"error\":\"missing --id parameter: missing parameters\"}\n"
    );

    let yaml = headscale_clean(&["--output", "yaml", "apikeys", "expire"]);
    assert_eq!(yaml.status.code(), Some(1));
    assert_eq!(stdout(&yaml), "");
    assert_eq!(
        stderr(&yaml),
        "error: 'either --id or --prefix must be provided: missing parameters'\n\n"
    );

    assert_stderr_snapshot(
        &["-o", "json", "apikeys", "delete"],
        1,
        include_str!("snapshots/apikeys_delete_missing_selector_json.stderr"),
    );
    assert_stderr_snapshot(
        &["-ojson-line", "apikeys", "delete"],
        1,
        include_str!("snapshots/apikeys_delete_missing_selector_json_line.stderr"),
    );
    assert_stderr_snapshot(
        &["--output", "yaml", "apikeys", "delete"],
        1,
        "error: 'either --id or --prefix must be provided: missing parameters'\n\n",
    );

    let remote = headscale_clean(&[
        "--output=json",
        "--address",
        "http://127.0.0.1:9",
        "users",
        "list",
    ]);
    assert_eq!(remote.status.code(), Some(6));
    assert_eq!(stdout(&remote), "");
    assert_eq!(
        stderr(&remote),
        "{\n\t\"error\": \"HEADSCALE_CLI_API_KEY environment variable needs to be set\"\n}\n"
    );
}

#[test]
fn auth_reject_yaml_missing_auth_id_matches_current_upstream_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing.sock");
    let config = write_unix_socket_config(dir.path(), &socket);

    assert_config_stderr_snapshot(
        &config,
        &["--output=yaml", "auth", "reject"],
        1,
        concat!(
            include_str!("snapshots/auth_reject_missing_auth_id_yaml.stderr"),
            "\n"
        ),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_sqlite_runtime_separates_public_metrics_and_remote_grpc_smoke() -> BoxTestResult {
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let metrics_url = format!("http://{metrics}");
    let remote_grpc_address = format!("http://{grpc}");
    let config = write_sqlite_serve_config(dir.path(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let public_health = headscale_clean(&["status", "--server", &server_url]);
        assert!(
            public_health.status.success(),
            "stderr: {}",
            stderr(&public_health)
        );
        assert_eq!(
            stdout(&public_health),
            format!("Control plane at {server_url} is healthy\n")
        );
        assert_eq!(stderr(&public_health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "separated"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key_secret = json_output(&api_key)
            .as_str()
            .expect("api key secret")
            .to_string();
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let remote_grpc_dir = tempfile::tempdir()?;
        let remote_grpc_config = write_remote_grpc_config(
            remote_grpc_dir.path(),
            &remote_grpc_address,
            &api_key_secret,
        );
        let remote_health = wait_for_headscale_status(&remote_grpc_config, &["health"], 0).await;
        assert_eq!(stdout(&remote_health), "\n");
        assert_eq!(stderr(&remote_health), "");

        let remote_users =
            headscale_with_config(&remote_grpc_config, &["-o", "json", "users", "list"]);
        assert!(
            remote_users.status.success(),
            "stderr: {}",
            stderr(&remote_users)
        );
        let remote_users = json_output(&remote_users);
        assert_eq!(remote_users[0]["name"].as_str(), Some("separated"));

        let http = reqwest::Client::new();
        let metrics_response = http.get(format!("{metrics_url}/metrics")).send().await?;
        assert_eq!(metrics_response.status(), reqwest::StatusCode::OK);
        let metrics_body = metrics_response.text().await?;
        assert!(
            metrics_body.contains("headscale_nodes_registered"),
            "metrics body: {metrics_body}"
        );

        let debug_config = http
            .get(format!("{metrics_url}/debug/config"))
            .send()
            .await?;
        assert_eq!(debug_config.status(), reqwest::StatusCode::OK);
        let debug_config = debug_config.json::<serde_json::Value>().await?;
        assert_eq!(
            debug_config["GRPCAddr"].as_str(),
            Some(&remote_grpc_address[7..])
        );
        let metrics_addr = metrics.to_string();
        assert_eq!(
            debug_config["MetricsAddr"].as_str(),
            Some(metrics_addr.as_str())
        );

        let public_metrics = http.get(format!("{server_url}/metrics")).send().await?;
        assert_eq!(public_metrics.status(), reqwest::StatusCode::OK);
        let public_metrics_body = public_metrics.text().await?;
        assert!(
            !public_metrics_body.contains("headscale_nodes_registered"),
            "public metrics body: {public_metrics_body}"
        );

        let public_debug_config = http
            .get(format!("{server_url}/debug/config"))
            .send()
            .await?;
        assert_eq!(public_debug_config.status(), reqwest::StatusCode::OK);
        let public_debug_config_body = public_debug_config.text().await?;
        assert!(
            !public_debug_config_body.contains("\"GRPCAddr\""),
            "public debug config body: {public_debug_config_body}"
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_runtime_projects_upstream_derp_and_explicit_https_without_acme() -> BoxTestResult {
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let https = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let https_url = format!("https://{https}");

    let config = dir.path().join("config.yaml");
    let socket = dir.path().join("headscale.sock");
    let noise = dir.path().join("state").join("noise_private.key");
    let db = dir.path().join("db.sqlite");
    let derp_key = dir.path().join("derp_server_private.key");
    fs::write(
        &config,
        format!(
            r#"
server_url: "https://headscale.example:8443"
listen_addr: "{listen}"
metrics_listen_addr: "{metrics}"
grpc_listen_addr: "{grpc}"
grpc_allow_insecure: true
noise:
  private_key_path: {}
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: {}
policy:
  mode: database
server:
  https_listen: "{https}"
  unix_socket: {}
derp:
  server:
    enabled: true
    region_id: 901
    region_code: "hs"
    region_name: "Headscale Runtime DERP"
    verify_clients: true
    stun_listen_addr: "127.0.0.1:0"
    private_key_path: {}
    automatically_add_embedded_derp_region: true
    ipv4: "198.51.100.44"
    ipv6: "2001:db8::44"
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 3h
"#,
            yaml_double_quoted(&noise.to_string_lossy()),
            yaml_double_quoted(&db.to_string_lossy()),
            yaml_double_quoted(&socket.to_string_lossy()),
            yaml_double_quoted(&derp_key.to_string_lossy()),
        ),
    )?;

    let mut child = spawn_headscale_serve(&config, dir.path())?;
    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let https_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let https_health = https_client
            .get(format!("{https_url}/health"))
            .send()
            .await?;
        assert_eq!(https_health.status(), reqwest::StatusCode::OK);
        assert_eq!(
            https_health.json::<serde_json::Value>().await?,
            serde_json::json!({ "status": "pass" })
        );

        let http = reqwest::Client::new();
        let debug_config = http
            .get(format!("{metrics_url}/debug/config"))
            .send()
            .await?;
        assert_eq!(debug_config.status(), reqwest::StatusCode::OK);
        let debug_config = debug_config.json::<serde_json::Value>().await?;

        assert_eq!(debug_config["ServerURL"], "https://headscale.example:8443");
        assert_eq!(debug_config["Addr"], listen.to_string());
        assert_eq!(debug_config["MetricsAddr"], metrics.to_string());
        assert_eq!(debug_config["GRPCAddr"], grpc.to_string());
        assert_eq!(debug_config["DERP"]["ServerEnabled"], true);
        assert_eq!(
            debug_config["DERP"]["AutomaticallyAddEmbeddedDerpRegion"],
            true
        );
        assert_eq!(debug_config["DERP"]["ServerRegionID"], 901);
        assert_eq!(debug_config["DERP"]["ServerRegionCode"], "hs");
        assert_eq!(
            debug_config["DERP"]["ServerRegionName"],
            "Headscale Runtime DERP"
        );
        assert_eq!(debug_config["DERP"]["ServerVerifyClients"], true);
        assert_eq!(debug_config["DERP"]["STUNAddr"], "127.0.0.1:0");
        assert_eq!(debug_config["DERP"]["AutoUpdate"], false);
        assert_eq!(
            debug_config["DERP"]["UpdateFrequency"],
            10_800_000_000_000i64
        );
        assert_eq!(debug_config["DERP"]["IPv4"], "198.51.100.44");
        assert_eq!(debug_config["DERP"]["IPv6"], "2001:db8::44");

        let projected_region = &debug_config["DERP"]["DERPMap"]["Regions"]["901"];
        assert_eq!(projected_region["RegionID"], 901);
        assert_eq!(projected_region["RegionCode"], "hs");
        assert_eq!(projected_region["RegionName"], "Headscale Runtime DERP");
        assert_eq!(projected_region["Nodes"][0]["Name"], "901");
        assert_eq!(
            projected_region["Nodes"][0]["HostName"],
            "headscale.example"
        );
        assert_eq!(projected_region["Nodes"][0]["DERPPort"], 8443);
        assert_eq!(projected_region["Nodes"][0]["IPv4"], "198.51.100.44");
        assert_eq!(projected_region["Nodes"][0]["IPv6"], "2001:db8::44");
        assert_eq!(debug_config["TLS"]["LetsEncrypt"]["Hostname"], "");
        assert_eq!(
            debug_config["TLS"]["LetsEncrypt"]["ChallengeType"],
            "HTTP-01"
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_local_grpc_admin_surface_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("admin_surface").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let public_health = headscale_clean(&["status", "--server", &server_url]);
        assert!(
            public_health.status.success(),
            "stderr: {}",
            stderr(&public_health)
        );
        assert_eq!(
            stdout(&public_health),
            format!("Control plane at {server_url} is healthy\n")
        );
        assert_eq!(stderr(&public_health), "");

        let health_json = headscale_with_config(&config, &["-o", "json", "health"]);
        assert!(
            health_json.status.success(),
            "stderr: {}",
            stderr(&health_json)
        );
        assert_eq!(
            json_output(&health_json)["database_connectivity"].as_bool(),
            Some(true)
        );

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let list_users = headscale_with_config(&config, &["users", "list"]);
        assert!(
            list_users.status.success(),
            "stderr: {}",
            stderr(&list_users)
        );
        assert!(
            stdout(&list_users).contains("alice"),
            "stdout: {}",
            stdout(&list_users)
        );
        assert_eq!(stderr(&list_users), "");

        let list_users_json =
            headscale_with_config(&config, &["-o", "json", "users", "list", "--name", "alice"]);
        assert!(
            list_users_json.status.success(),
            "stderr: {}",
            stderr(&list_users_json)
        );
        let list_users_json = json_output(&list_users_json);
        assert_eq!(list_users_json.as_array().expect("users").len(), 1);
        let user_id = list_users_json[0]["id"]
            .as_u64()
            .expect("user id")
            .to_string();

        let preauth = headscale_with_config(
            &config,
            &[
                "preauthkeys",
                "create",
                "--user",
                &user_id,
                "--reusable",
                "--expiration",
                "1h",
            ],
        );
        assert!(preauth.status.success(), "stderr: {}", stderr(&preauth));
        assert!(
            stdout(&preauth).contains("hskey-auth-"),
            "stdout: {}",
            stdout(&preauth)
        );
        assert_eq!(stderr(&preauth), "");

        let preauth_json = headscale_with_config(&config, &["-o", "json", "preauthkeys", "list"]);
        let preauth_json = json_output(&preauth_json);
        assert_eq!(preauth_json[0]["user"]["name"].as_str(), Some("alice"));
        let preauth_id = preauth_json[0]["id"]
            .as_u64()
            .expect("preauth key id")
            .to_string();
        assert!(preauth_json[0]["key"].as_str().is_some_and(|key| {
            key.starts_with("hskey-auth-") || key.starts_with("preauthkey:hskey-auth-")
        }));

        let expire_preauth =
            headscale_with_config(&config, &["preauthkeys", "expire", "--id", &preauth_id]);
        assert!(
            expire_preauth.status.success(),
            "stderr: {}",
            stderr(&expire_preauth)
        );
        assert_eq!(stdout(&expire_preauth), "Key expired\n");
        assert_eq!(stderr(&expire_preauth), "");

        let delete_preauth =
            headscale_with_config(&config, &["preauthkeys", "delete", "--id", &preauth_id]);
        assert!(
            delete_preauth.status.success(),
            "stderr: {}",
            stderr(&delete_preauth)
        );
        assert_eq!(stdout(&delete_preauth), "Key deleted\n");
        assert_eq!(stderr(&delete_preauth), "");

        let empty_preauth_json =
            headscale_with_config(&config, &["-o", "json", "preauthkeys", "list"]);
        assert!(
            empty_preauth_json.status.success(),
            "stderr: {}",
            stderr(&empty_preauth_json)
        );
        assert_eq!(
            json_output(&empty_preauth_json)
                .as_array()
                .expect("preauth keys")
                .len(),
            0
        );
        assert_eq!(stderr(&empty_preauth_json), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret").to_string();
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let api_keys = headscale_with_config(&config, &["-o", "json", "apikeys", "list"]);
        let api_keys = json_output(&api_keys);
        let api_id = api_keys[0]["id"].as_u64().expect("api key id").to_string();
        assert!(
            api_keys[0]["prefix"]
                .as_str()
                .is_some_and(|prefix| !prefix.is_empty())
        );

        let http = reqwest::Client::new();
        let gateway_health = http
            .get(format!("{server_url}/api/v1/health"))
            .send()
            .await?;
        assert_eq!(gateway_health.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(gateway_health.text().await?, "Unauthorized");

        let gateway_health = http
            .get(format!("{server_url}/api/v1/health"))
            .bearer_auth(&api_key_secret)
            .send()
            .await?;
        assert_eq!(gateway_health.status(), reqwest::StatusCode::OK);
        let gateway_health = gateway_health.json::<serde_json::Value>().await?;
        assert_eq!(gateway_health["databaseConnectivity"].as_bool(), Some(true));

        let gateway_users = http
            .get(format!("{server_url}/api/v1/user?name=alice"))
            .bearer_auth(&api_key_secret)
            .send()
            .await?;
        assert_eq!(gateway_users.status(), reqwest::StatusCode::OK);
        let gateway_users = gateway_users.json::<serde_json::Value>().await?;
        assert_eq!(gateway_users["users"][0]["name"].as_str(), Some("alice"));

        let remote_grpc_dir = tempfile::tempdir()?;
        let remote_grpc_address = format!("http://{grpc}");
        let remote_grpc_config = write_remote_grpc_config(
            remote_grpc_dir.path(),
            &remote_grpc_address,
            &api_key_secret,
        );
        let remote_health = wait_for_headscale_status(&remote_grpc_config, &["health"], 0).await;
        assert_eq!(stdout(&remote_health), "\n");
        assert_eq!(stderr(&remote_health), "");

        let remote_users =
            headscale_with_config(&remote_grpc_config, &["-o", "json", "users", "list"]);
        assert!(
            remote_users.status.success(),
            "stderr: {}",
            stderr(&remote_users)
        );
        let remote_users = json_output(&remote_users);
        assert_eq!(remote_users[0]["name"].as_str(), Some("alice"));

        let bad_remote_grpc_dir = tempfile::tempdir()?;
        let bad_remote_grpc_config = write_remote_grpc_config(
            bad_remote_grpc_dir.path(),
            &remote_grpc_address,
            "bad-token",
        );
        let bad_remote_auth =
            wait_for_headscale_status(&bad_remote_grpc_config, &["health"], 4).await;
        assert_eq!(stdout(&bad_remote_auth), "");
        assert_eq!(
            stderr(&bad_remote_auth),
            include_str!("snapshots/grpc_remote_auth_failure.stderr")
        );

        let policy_path = dir.path().join("pg-policy.hujson");
        fs::write(&policy_path, r#"{"tagOwners":{"tag:server":["alice@"]}}"#).unwrap();
        let policy_path = policy_path.to_string_lossy().to_string();
        let set_policy = headscale_with_config(
            &config,
            &["-o", "json", "policy", "set", "--file", &policy_path],
        );
        assert!(
            set_policy.status.success(),
            "stderr: {}",
            stderr(&set_policy)
        );
        assert_eq!(stdout(&set_policy), "Policy updated.\n");
        assert_eq!(stderr(&set_policy), "");

        let get_policy = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
        assert!(
            get_policy.status.success(),
            "stderr: {}",
            stderr(&get_policy)
        );
        assert_eq!(
            stdout(&get_policy),
            "{\"tagOwners\":{\"tag:server\":[\"alice@\"]}}\n"
        );
        assert_eq!(stderr(&get_policy), "");

        let auth_register_id = "abababababababababababab";
        let auth_id = format!("hskey-authreq-{auth_register_id}");
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                &auth_id,
                "--name",
                "pg-admin-node",
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", &auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(stdout(&auth_register), "Node pg-admin-node registered\n");
        assert_eq!(stderr(&auth_register), "");

        let nodes_json = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        let nodes_json = json_output(&nodes_json);
        let node_id = nodes_json[0]["id"].as_u64().expect("node id").to_string();
        assert_eq!(nodes_json[0]["user"]["name"].as_str(), Some("alice"));
        assert_eq!(nodes_json[0]["given_name"].as_str(), Some("pg-admin-node"));
        assert!(nodes_json[0]["ip_addresses"].as_array().is_some_and(|ips| {
            ips.iter()
                .any(|ip| ip.as_str().is_some_and(|ip| ip.starts_with("100.")))
        }));

        let rename_node = headscale_with_config(
            &config,
            &[
                "nodes",
                "rename",
                "pg-renamed-node",
                "--identifier",
                &node_id,
            ],
        );
        assert!(
            rename_node.status.success(),
            "stderr: {}",
            stderr(&rename_node)
        );
        assert_eq!(stdout(&rename_node), "Node renamed\n");
        assert_eq!(stderr(&rename_node), "");

        let tag_node = headscale_with_config(
            &config,
            &[
                "nodes",
                "tag",
                "--identifier",
                &node_id,
                "--tags",
                "tag:server",
            ],
        );
        assert!(tag_node.status.success(), "stderr: {}", stderr(&tag_node));
        assert_eq!(stdout(&tag_node), "Node updated\n");
        assert_eq!(stderr(&tag_node), "");

        let expire_node =
            headscale_with_config(&config, &["nodes", "expire", "--identifier", &node_id]);
        assert!(
            expire_node.status.success(),
            "stderr: {}",
            stderr(&expire_node)
        );
        assert_eq!(stdout(&expire_node), "Node expired\n");
        assert_eq!(stderr(&expire_node), "");

        let backfill_ips = headscale_with_config(&config, &["--force", "nodes", "backfillips"]);
        assert!(
            backfill_ips.status.success(),
            "stderr: {}",
            stderr(&backfill_ips)
        );
        assert_eq!(stdout(&backfill_ips), "Node IPs backfilled successfully\n");
        assert_eq!(stderr(&backfill_ips), "");

        let delete_node = headscale_with_config(
            &config,
            &["--force", "nodes", "delete", "--identifier", &node_id],
        );
        assert!(
            delete_node.status.success(),
            "stderr: {}",
            stderr(&delete_node)
        );
        assert_eq!(stdout(&delete_node), "Node deleted\n");
        assert_eq!(stderr(&delete_node), "");

        let expire_api_key =
            headscale_with_config(&config, &["apikeys", "expire", "--id", &api_id]);
        assert!(
            expire_api_key.status.success(),
            "stderr: {}",
            stderr(&expire_api_key)
        );
        assert_eq!(stdout(&expire_api_key), "Key expired\n");
        assert_eq!(stderr(&expire_api_key), "");

        let delete_api_key =
            headscale_with_config(&config, &["apikeys", "delete", "--id", &api_id]);
        assert!(
            delete_api_key.status.success(),
            "stderr: {}",
            stderr(&delete_api_key)
        );
        assert_eq!(stdout(&delete_api_key), "Key deleted\n");
        assert_eq!(stderr(&delete_api_key), "");

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_local_grpc_mutations_survive_restart_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("local_grpc_restart").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let policy_path = dir.path().join("restart-policy.hujson");
        fs::write(
            &policy_path,
            r#"{"tagOwners":{"tag:router":["alice@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
        )?;
        let policy_path = policy_path.to_string_lossy().to_string();
        let set_policy = headscale_with_config(
            &config,
            &["-o", "json", "policy", "set", "--file", &policy_path],
        );
        assert!(
            set_policy.status.success(),
            "stderr: {}",
            stderr(&set_policy)
        );
        assert_eq!(stdout(&set_policy), "Policy updated.\n");
        assert_eq!(stderr(&set_policy), "");

        let auth_id = "hskey-authreq-bcbcbcbcbcbcbcbcbcbcbcbc";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-restart-node",
                "--route",
                "10.40.0.0/24",
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(stdout(&auth_register), "Node pg-restart-node registered\n");
        assert_eq!(stderr(&auth_register), "");

        let nodes_json = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        let nodes_json = json_output(&nodes_json);
        let node_id_number = nodes_json[0]["id"].as_u64().expect("node id");
        let node_id = node_id_number.to_string();
        assert_eq!(nodes_json[0]["user"]["name"].as_str(), Some("alice"));

        let approve_routes = headscale_with_config(
            &config,
            &[
                "nodes",
                "approve-routes",
                "--identifier",
                &node_id,
                "--routes",
                "10.40.0.0/24",
            ],
        );
        assert!(
            approve_routes.status.success(),
            "stderr: {}",
            stderr(&approve_routes)
        );
        assert_eq!(stdout(&approve_routes), "Node updated\n");
        assert_eq!(stderr(&approve_routes), "");

        let tag_node = headscale_with_config(
            &config,
            &[
                "nodes",
                "tag",
                "--identifier",
                &node_id,
                "--tags",
                "tag:router",
            ],
        );
        assert!(tag_node.status.success(), "stderr: {}", stderr(&tag_node));
        assert_eq!(stdout(&tag_node), "Node updated\n");
        assert_eq!(stderr(&tag_node), "");

        stop_child(&mut child);
        child = spawn_headscale_serve(&config, dir.path())?;

        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let users = headscale_with_config(&config, &["-o", "json", "users", "list"]);
        let users = json_output(&users);
        assert_eq!(users.as_array().expect("users").len(), 1);
        assert_eq!(users[0]["name"].as_str(), Some("alice"));

        let policy = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
        assert!(policy.status.success(), "stderr: {}", stderr(&policy));
        assert_eq!(
            stdout(&policy),
            "{\"tagOwners\":{\"tag:router\":[\"alice@\"]},\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}\n"
        );
        assert_eq!(stderr(&policy), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        let nodes = json_output(&nodes);
        assert_eq!(nodes.as_array().expect("nodes").len(), 1);
        assert_eq!(nodes[0]["id"].as_u64().unwrap().to_string(), node_id);
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-restart-node"));
        assert_eq!(nodes[0]["given_name"].as_str(), Some("pg-restart-node"));
        assert_eq!(nodes[0]["user"]["name"].as_str(), Some("alice"));
        assert_eq!(nodes[0]["tags"], serde_json::json!(["tag:router"]));
        assert_eq!(
            nodes[0]["available_routes"],
            serde_json::json!(["10.40.0.0/24"])
        );
        assert_eq!(
            nodes[0]["approved_routes"],
            serde_json::json!(["10.40.0.0/24"])
        );

        let routes = headscale_with_config(&config, &["nodes", "list-routes"]);
        assert!(routes.status.success(), "stderr: {}", stderr(&routes));
        let routes_stdout = stdout(&routes);
        assert!(
            routes_stdout.contains("10.40.0.0/24"),
            "routes stdout: {routes_stdout}"
        );
        assert_eq!(stderr(&routes), "");

        let http = reqwest::Client::new();
        let nodestore = http
            .get(format!("{metrics_url}/debug/nodestore"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
        let nodestore = nodestore.json::<serde_json::Value>().await?;
        let live_node = nodestore
            .get(&node_id)
            .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
        assert_eq!(live_node["hostname"].as_str(), Some("pg-restart-node"));
        assert_eq!(live_node["user"].as_str(), Some("alice"));
        assert_eq!(live_node["forced_tags"], serde_json::json!(["tag:router"]));
        assert_eq!(
            live_node["available_routes"],
            serde_json::json!(["10.40.0.0/24"])
        );
        assert_eq!(
            live_node["approved_routes"],
            serde_json::json!(["10.40.0.0/24"])
        );

        let debug_routes = http
            .get(format!("{metrics_url}/debug/routes"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(debug_routes.status(), reqwest::StatusCode::OK);
        let debug_routes = debug_routes.json::<serde_json::Value>().await?;
        assert_eq!(
            debug_routes["available_routes"][&node_id],
            serde_json::json!(["10.40.0.0/24"])
        );
        assert_eq!(
            debug_routes["primary_routes"]["10.40.0.0/24"],
            serde_json::json!(node_id_number)
        );

        let policy_manager = http
            .get(format!("{metrics_url}/debug/policy-manager"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(policy_manager.status(), reqwest::StatusCode::OK);
        let policy_manager = policy_manager.json::<serde_json::Value>().await?;
        let policy_manager = policy_manager["content"]
            .as_str()
            .expect("policy manager content");
        assert!(
            policy_manager.contains("TagOwner (1):")
                && policy_manager.contains("tag:router")
                && policy_manager.contains("Compiled filter:"),
            "policy manager content: {policy_manager}"
        );

        let filter = http.get(format!("{metrics_url}/debug/filter")).send().await?;
        assert_eq!(filter.status(), reqwest::StatusCode::OK);
        let filter = filter.json::<serde_json::Value>().await?;
        assert!(
            filter.as_array().is_some_and(|rules| !rules.is_empty()),
            "debug filter: {filter}"
        );

        let rename_after_restart = headscale_with_config(
            &config,
            &[
                "nodes",
                "rename",
                "pg-restart-renamed",
                "--identifier",
                &node_id,
            ],
        );
        assert!(
            rename_after_restart.status.success(),
            "stderr: {}",
            stderr(&rename_after_restart)
        );
        assert_eq!(stdout(&rename_after_restart), "Node renamed\n");
        assert_eq!(stderr(&rename_after_restart), "");

        let renamed = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        let renamed = json_output(&renamed);
        assert_eq!(renamed[0]["name"].as_str(), Some("pg-restart-renamed"));

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_live_admin_rename_updates_nodestore_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("live_admin_rename").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let auth_id = "hskey-authreq-cdcdcdcdcdcdcdcdcdcdcdcd";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-live-node",
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(stdout(&auth_register), "Node pg-live-node registered\n");
        assert_eq!(stderr(&auth_register), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        let node_id = nodes[0]["id"].as_u64().expect("node id").to_string();
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-live-node"));
        assert_eq!(nodes[0]["user"]["name"].as_str(), Some("alice"));

        let http = reqwest::Client::new();
        let nodestore = http
            .get(format!("{metrics_url}/debug/nodestore"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
        let nodestore = nodestore.json::<serde_json::Value>().await?;
        let live_node = nodestore
            .get(&node_id)
            .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
        assert_eq!(live_node["hostname"].as_str(), Some("pg-live-node"));
        assert_eq!(live_node["user"].as_str(), Some("alice"));

        let rename = headscale_with_config(
            &config,
            &[
                "nodes",
                "rename",
                "pg-live-renamed",
                "--identifier",
                &node_id,
            ],
        );
        assert!(rename.status.success(), "stderr: {}", stderr(&rename));
        assert_eq!(stdout(&rename), "Node renamed\n");
        assert_eq!(stderr(&rename), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        assert_eq!(nodes[0]["id"].as_u64().unwrap().to_string(), node_id);
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-live-renamed"));
        assert_eq!(nodes[0]["given_name"].as_str(), Some("pg-live-renamed"));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let nodestore = http
                .get(format!("{metrics_url}/debug/nodestore"))
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await?;
            assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
            let nodestore = nodestore.json::<serde_json::Value>().await?;
            let live_node = nodestore
                .get(&node_id)
                .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
            if live_node["hostname"].as_str() == Some("pg-live-renamed") {
                assert_eq!(live_node["user"].as_str(), Some("alice"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for live registry rename; nodestore: {nodestore}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_live_cli_policy_tag_updates_nodestore_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("live_cli_policy_tag").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let auth_id = "hskey-authreq-acacacacacacacacacacacac";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-live-tag-node",
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(stdout(&auth_register), "Node pg-live-tag-node registered\n");
        assert_eq!(stderr(&auth_register), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        let node_id = nodes[0]["id"].as_u64().expect("node id").to_string();
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-live-tag-node"));
        assert_eq!(nodes[0]["user"]["name"].as_str(), Some("alice"));
        assert_eq!(nodes[0]["tags"], serde_json::json!([]));

        let http = reqwest::Client::new();
        let nodestore = http
            .get(format!("{metrics_url}/debug/nodestore"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
        let nodestore = nodestore.json::<serde_json::Value>().await?;
        let live_node = nodestore
            .get(&node_id)
            .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
        assert_eq!(live_node["hostname"].as_str(), Some("pg-live-tag-node"));
        assert_eq!(live_node["user"].as_str(), Some("alice"));
        assert_eq!(live_node["forced_tags"], serde_json::json!([]));

        let policy_path = dir.path().join("live-tag-policy.hujson");
        fs::write(&policy_path, r#"{"tagOwners":{"tag:server":["alice@"]}}"#)?;
        let policy_path = policy_path.to_string_lossy().to_string();
        let set_policy = headscale_with_config(
            &config,
            &["-o", "json", "policy", "set", "--file", &policy_path],
        );
        assert!(
            set_policy.status.success(),
            "stderr: {}",
            stderr(&set_policy)
        );
        assert_eq!(stdout(&set_policy), "Policy updated.\n");
        assert_eq!(stderr(&set_policy), "");

        let tag_node = headscale_with_config(
            &config,
            &[
                "nodes",
                "tag",
                "--identifier",
                &node_id,
                "--tags",
                "tag:server",
            ],
        );
        assert!(tag_node.status.success(), "stderr: {}", stderr(&tag_node));
        assert_eq!(stdout(&tag_node), "Node updated\n");
        assert_eq!(stderr(&tag_node), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        assert_eq!(nodes[0]["id"].as_u64().unwrap().to_string(), node_id);
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-live-tag-node"));
        assert_eq!(nodes[0]["tags"], serde_json::json!(["tag:server"]));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let nodestore = http
                .get(format!("{metrics_url}/debug/nodestore"))
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await?;
            assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
            let nodestore = nodestore.json::<serde_json::Value>().await?;
            let live_node = nodestore
                .get(&node_id)
                .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
            if live_node["forced_tags"] == serde_json::json!(["tag:server"]) {
                assert_eq!(live_node["hostname"].as_str(), Some("pg-live-tag-node"));
                assert_eq!(live_node["user"].as_str(), Some("alice"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for live registry tag update; nodestore: {nodestore}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_db_policy_live_route_auto_approval_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("db_policy_live").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let auth_id = "hskey-authreq-dadadadadadadadadadadada";
        let advertised_route = "10.89.1.0/24";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-db-policy-router",
                "--route",
                advertised_route,
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(
            stdout(&auth_register),
            "Node pg-db-policy-router registered\n"
        );
        assert_eq!(stderr(&auth_register), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        let node = &nodes[0];
        let node_id_number = node["id"].as_u64().expect("node id");
        let node_id = node_id_number.to_string();
        assert_eq!(node["user"]["name"].as_str(), Some("alice"));
        assert_eq!(
            node["available_routes"],
            serde_json::json!([advertised_route])
        );
        assert_eq!(node["approved_routes"], serde_json::json!([]));

        let policy_path = dir.path().join("db-policy-live.hujson");
        let policy = r#"{
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]}
  ],
  "autoApprovers": {
    "routes": {"10.89.0.0/16": ["alice@"]}
  }
}"#;
        fs::write(&policy_path, policy)?;
        let policy_path = policy_path.to_string_lossy().to_string();
        let set_policy = headscale_with_config(&config, &["policy", "set", "--file", &policy_path]);
        assert!(
            set_policy.status.success(),
            "stderr: {}",
            stderr(&set_policy)
        );
        assert_eq!(stdout(&set_policy), "Policy updated.\n");
        assert_eq!(stderr(&set_policy), "");

        let deadline = Instant::now() + Duration::from_secs(5);
        let approved_nodes = loop {
            let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
            assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
            let nodes = json_output(&nodes);
            if nodes[0]["approved_routes"] == serde_json::json!([advertised_route]) {
                break nodes;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for database policy set to auto-approve route; nodes: {nodes}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(
            approved_nodes[0]["id"].as_u64().unwrap().to_string(),
            node_id
        );
        assert_eq!(
            approved_nodes[0]["available_routes"],
            serde_json::json!([advertised_route])
        );

        let get_policy = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
        assert!(
            get_policy.status.success(),
            "stderr: {}",
            stderr(&get_policy)
        );
        assert_eq!(stdout(&get_policy), format!("{policy}\n"));
        assert_eq!(stderr(&get_policy), "");

        let http = reqwest::Client::new();
        let nodestore = http
            .get(format!("{metrics_url}/debug/nodestore"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
        let nodestore = nodestore.json::<serde_json::Value>().await?;
        let live_node = nodestore
            .get(&node_id)
            .unwrap_or_else(|| panic!("missing live registry node {node_id}: {nodestore}"));
        assert_eq!(live_node["hostname"].as_str(), Some("pg-db-policy-router"));
        assert_eq!(live_node["user"].as_str(), Some("alice"));
        assert_eq!(
            live_node["available_routes"],
            serde_json::json!([advertised_route])
        );
        assert_eq!(
            live_node["approved_routes"],
            serde_json::json!([advertised_route])
        );

        let debug_routes = http
            .get(format!("{metrics_url}/debug/routes"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(debug_routes.status(), reqwest::StatusCode::OK);
        let debug_routes = debug_routes.json::<serde_json::Value>().await?;
        assert_eq!(
            debug_routes["available_routes"][&node_id],
            serde_json::json!([advertised_route])
        );
        assert_eq!(
            debug_routes["primary_routes"][advertised_route],
            serde_json::json!(node_id_number)
        );

        let policy_manager = http
            .get(format!("{metrics_url}/debug/policy-manager"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(policy_manager.status(), reqwest::StatusCode::OK);
        let policy_manager = policy_manager.json::<serde_json::Value>().await?;
        let policy_manager = policy_manager["content"]
            .as_str()
            .expect("policy manager content");
        assert!(
            policy_manager.contains("AutoApprover (1):")
                && policy_manager.contains("10.89.0.0/16")
                && policy_manager.contains("alice@")
                && policy_manager.contains("Compiled filter:"),
            "policy manager content: {policy_manager}"
        );

        let filter = http
            .get(format!("{metrics_url}/debug/filter"))
            .send()
            .await?;
        assert_eq!(filter.status(), reqwest::StatusCode::OK);
        let filter = filter.json::<serde_json::Value>().await?;
        assert!(
            filter.as_array().is_some_and(|rules| !rules.is_empty()),
            "debug filter: {filter}"
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(all(feature = "postgres-sqlx", unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_policy_file_reload_auto_approves_route_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("policy_file_reload").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let policy_path = dir.path().join("acl.hujson");
    fs::write(&policy_path, r#"{"acls":[]}"#)?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config_with_policy_file(
        dir.path(),
        database.fields(),
        listen,
        metrics,
        grpc,
        &policy_path,
    );
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let auth_id = "hskey-authreq-fefefefefefefefefefefefe";
        let advertised_route = "10.88.1.0/24";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-policy-reload-router",
                "--route",
                advertised_route,
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let auth_register = headscale_with_config(
            &config,
            &["auth", "register", "--user", "alice", "--auth-id", auth_id],
        );
        assert!(
            auth_register.status.success(),
            "stderr: {}",
            stderr(&auth_register)
        );
        assert_eq!(
            stdout(&auth_register),
            "Node pg-policy-reload-router registered\n"
        );
        assert_eq!(stderr(&auth_register), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        let node = &nodes[0];
        let node_id_number = node["id"].as_u64().expect("node id");
        let node_id = node_id_number.to_string();
        assert_eq!(node["user"]["name"].as_str(), Some("alice"));
        assert_eq!(
            node["available_routes"],
            serde_json::json!([advertised_route])
        );
        assert_eq!(node["approved_routes"], serde_json::json!([]));

        let reloaded_policy = r#"{
  "autoApprovers": {
    "routes": {"10.88.0.0/16": ["alice@"]}
  }
}"#;
        fs::write(&policy_path, reloaded_policy)?;
        send_sighup(&child)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let approved_nodes = loop {
            let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
            assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
            let nodes = json_output(&nodes);
            if nodes[0]["approved_routes"] == serde_json::json!([advertised_route]) {
                break nodes;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for SIGHUP policy reload to approve route; nodes: {nodes}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(
            approved_nodes[0]["available_routes"],
            serde_json::json!([advertised_route])
        );
        assert_eq!(
            approved_nodes[0]["id"].as_u64().unwrap().to_string(),
            node_id
        );

        let policy = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
        assert!(policy.status.success(), "stderr: {}", stderr(&policy));
        assert_eq!(stdout(&policy), format!("{reloaded_policy}\n"));
        assert_eq!(stderr(&policy), "");

        let http = reqwest::Client::new();
        let debug_routes = http
            .get(format!("{metrics_url}/debug/routes"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(debug_routes.status(), reqwest::StatusCode::OK);
        let debug_routes = debug_routes.json::<serde_json::Value>().await?;
        assert_eq!(
            debug_routes["available_routes"][&node_id],
            serde_json::json!([advertised_route])
        );
        assert_eq!(
            debug_routes["primary_routes"][advertised_route],
            serde_json::json!(node_id_number)
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_gateway_auth_register_survives_restart_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_auth_register").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let metrics_url = format!("http://{metrics}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
        assert!(
            create_user.status.success(),
            "stderr: {}",
            stderr(&create_user)
        );
        assert_eq!(stdout(&create_user), "User created\n");
        assert_eq!(stderr(&create_user), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret");
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let auth_id = "hskey-authreq-eeeeeeeeeeeeeeeeeeeeeeee";
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--user",
                "alice",
                "--key",
                auth_id,
                "--name",
                "pg-web-register-node",
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stdout(&debug_create), "Node created\n");
        assert_eq!(stderr(&debug_create), "");

        let http = reqwest::Client::new();
        let web_register = http
            .get(format!("{server_url}/register/{auth_id}"))
            .send()
            .await?;
        assert_eq!(web_register.status(), reqwest::StatusCode::OK);
        let web_register = web_register.text().await?;
        assert!(
            web_register
                .contains("headscale auth register --auth-id hskey-authreq-eeeeeeeeeeeeeeeeeeeeeeee --user USERNAME"),
            "web register page: {web_register}"
        );

        let gateway_register = http
            .post(format!("{server_url}/api/v1/auth/register"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({
                "user": "alice",
                "authId": auth_id
            }))
            .send()
            .await?;
        assert_eq!(gateway_register.status(), reqwest::StatusCode::OK);
        let gateway_register = gateway_register.json::<serde_json::Value>().await?;
        let node_id = gateway_register["node"]["id"]
            .as_str()
            .expect("registered node id")
            .to_string();
        assert!(!node_id.is_empty());
        assert_eq!(
            gateway_register["node"]["name"].as_str(),
            Some("pg-web-register-node")
        );
        assert_eq!(
            gateway_register["node"]["registerMethod"].as_str(),
            Some("REGISTER_METHOD_CLI")
        );
        assert!(
            gateway_register["node"]["ipAddresses"]
                .as_array()
                .is_some_and(|ips| {
                    ips.iter()
                        .any(|ip| ip.as_str().is_some_and(|ip| ip.starts_with("100.")))
                }),
            "gateway registered node: {gateway_register}"
        );

        stop_child(&mut child);
        child = spawn_headscale_serve(&config, dir.path())?;

        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let nodes = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
        assert!(nodes.status.success(), "stderr: {}", stderr(&nodes));
        let nodes = json_output(&nodes);
        assert_eq!(nodes.as_array().expect("nodes").len(), 1);
        assert_eq!(nodes[0]["id"].as_u64().unwrap().to_string(), node_id);
        assert_eq!(nodes[0]["user"]["name"].as_str(), Some("alice"));
        assert_eq!(nodes[0]["name"].as_str(), Some("pg-web-register-node"));
        assert_eq!(
            nodes[0]["given_name"].as_str(),
            Some("pg-web-register-node")
        );
        assert_eq!(nodes[0]["register_method"].as_i64(), Some(2));

        let nodestore = http
            .get(format!("{metrics_url}/debug/nodestore"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        assert_eq!(nodestore.status(), reqwest::StatusCode::OK);
        let nodestore = nodestore.json::<serde_json::Value>().await?;
        let live_node = nodestore
            .as_object()
            .and_then(|nodes| {
                nodes.values().find(|node| {
                    node["user"].as_str() == Some("alice")
                        && node["hostname"].as_str() == Some("pg-web-register-node")
                })
            })
            .unwrap_or_else(|| panic!("missing hydrated node {node_id}: {nodestore}"));
        assert_eq!(live_node["user"].as_str(), Some("alice"));
        assert_eq!(
            live_node["hostname"].as_str(),
            Some("pg-web-register-node")
        );
        assert!(
            live_node["ipv4"]
                .as_str()
                .is_some_and(|ip| ip.starts_with("100.")),
            "hydrated node: {live_node}"
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_grpc_gateway_user_crud_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_user_crud").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret");
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let http = reqwest::Client::new();
        let created = http
            .post(format!("{server_url}/api/v1/user"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({
                "name": "alice",
                "displayName": "Alice Smith",
                "email": "alice@example.com",
                "pictureUrl": "https://example.com/alice.png"
            }))
            .send()
            .await?;
        assert_eq!(created.status(), reqwest::StatusCode::OK);
        let created = created.json::<serde_json::Value>().await?;
        let user_id = created["user"]["id"].as_str().expect("created user id");
        assert_eq!(user_id, "1");
        assert_eq!(created["user"]["name"].as_str(), Some("alice"));
        assert_eq!(created["user"]["displayName"].as_str(), Some("Alice Smith"));
        assert_eq!(
            created["user"]["profilePicUrl"].as_str(),
            Some("https://example.com/alice.png")
        );
        assert!(
            created["user"]["createdAt"]
                .as_str()
                .is_some_and(|created_at| created_at.ends_with('Z')),
            "created user: {created}"
        );

        let listed = http
            .get(format!("{server_url}/api/v1/user?name=alice"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        assert_eq!(listed["users"].as_array().expect("users").len(), 1);
        assert_eq!(listed["users"][0]["id"].as_str(), Some(user_id));

        let renamed = http
            .post(format!("{server_url}/api/v1/user/{user_id}/rename/bob"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(renamed.status(), reqwest::StatusCode::OK);
        let renamed = renamed.json::<serde_json::Value>().await?;
        assert_eq!(renamed["user"]["id"].as_str(), Some(user_id));
        assert_eq!(renamed["user"]["name"].as_str(), Some("bob"));

        let deleted = http
            .delete(format!("{server_url}/api/v1/user/{user_id}"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(deleted.status(), reqwest::StatusCode::OK);
        assert_eq!(
            deleted.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let listed = http
            .get(format!("{server_url}/api/v1/user"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        assert_eq!(listed["users"], serde_json::json!([]));

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_grpc_gateway_api_key_lifecycle_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_api_key").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let bootstrap = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(bootstrap.status.success(), "stderr: {}", stderr(&bootstrap));
        let bootstrap = json_output(&bootstrap);
        let bootstrap_secret = bootstrap.as_str().expect("bootstrap api key secret");
        assert!(
            bootstrap_secret.starts_with("hskey-api-"),
            "api key: {bootstrap_secret}"
        );

        let http = reqwest::Client::new();
        let created = http
            .post(format!("{server_url}/api/v1/apikey"))
            .bearer_auth(bootstrap_secret)
            .json(&serde_json::json!({ "expiration": "2030-01-02T03:04:05Z" }))
            .send()
            .await?;
        assert_eq!(created.status(), reqwest::StatusCode::OK);
        let created = created.json::<serde_json::Value>().await?;
        let created_secret = created["apiKey"].as_str().expect("created api key secret");
        assert!(
            created_secret.starts_with("hskey-api-"),
            "created api key: {created}"
        );

        let listed = http
            .get(format!("{server_url}/api/v1/apikey"))
            .bearer_auth(bootstrap_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        let api_keys = listed["apiKeys"].as_array().expect("apiKeys");
        assert_eq!(api_keys.len(), 2, "listed api keys: {listed}");
        let created_row = api_keys
            .iter()
            .find(|key| key["id"] == "2")
            .expect("created api key row");
        let created_prefix = created_row["prefix"]
            .as_str()
            .expect("created api key prefix")
            .to_string();
        assert!(
            created_prefix.starts_with("hskey-api-") && created_prefix.ends_with("-***"),
            "created api key row: {created_row}"
        );
        assert_eq!(created_row["expiration"], "2030-01-02T03:04:05Z");
        assert!(
            created_row["createdAt"]
                .as_str()
                .is_some_and(|created_at| created_at.ends_with('Z')),
            "created api key row: {created_row}"
        );
        assert!(created_row.get("lastSeen").is_none());

        let expired = http
            .post(format!("{server_url}/api/v1/apikey/expire"))
            .bearer_auth(bootstrap_secret)
            .json(&serde_json::json!({ "id": "2" }))
            .send()
            .await?;
        assert_eq!(expired.status(), reqwest::StatusCode::OK);
        assert_eq!(
            expired.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let deleted = http
            .delete(format!("{server_url}/api/v1/apikey/{created_prefix}"))
            .bearer_auth(bootstrap_secret)
            .send()
            .await?;
        assert_eq!(deleted.status(), reqwest::StatusCode::OK);
        assert_eq!(
            deleted.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let listed = http
            .get(format!("{server_url}/api/v1/apikey"))
            .bearer_auth(bootstrap_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        let api_keys = listed["apiKeys"].as_array().expect("apiKeys");
        assert_eq!(api_keys.len(), 1, "listed api keys after delete: {listed}");
        assert_eq!(api_keys[0]["id"], "1");

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_grpc_gateway_node_lifecycle_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_node_lifecycle").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret");
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let http = reqwest::Client::new();
        let created_user = http
            .post(format!("{server_url}/api/v1/user"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "name": "alice" }))
            .send()
            .await?;
        assert_eq!(created_user.status(), reqwest::StatusCode::OK);
        let created_user = created_user.json::<serde_json::Value>().await?;
        assert_eq!(created_user["user"]["name"].as_str(), Some("alice"));

        let registration_key = "dddddddddddddddddddddddd";
        let auth_id = format!("hskey-authreq-{registration_key}");
        let debug_created = http
            .post(format!("{server_url}/api/v1/debug/node"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({
                "user": "alice",
                "key": auth_id,
                "name": "pg-gateway-node",
                "routes": ["10.30.0.0/24"]
            }))
            .send()
            .await?;
        assert_eq!(debug_created.status(), reqwest::StatusCode::OK);
        let debug_created = debug_created.json::<serde_json::Value>().await?;
        let node_id = debug_created["node"]["id"]
            .as_str()
            .expect("debug node id")
            .to_string();
        assert!(!node_id.is_empty());
        assert_eq!(
            debug_created["node"]["name"].as_str(),
            Some("pg-gateway-node")
        );
        assert_eq!(
            debug_created["node"]["givenName"].as_str(),
            Some("pg-gateway-node")
        );
        assert_eq!(
            debug_created["node"]["user"]["name"].as_str(),
            Some("alice")
        );
        assert!(
            debug_created["node"]["machineKey"]
                .as_str()
                .is_some_and(|key| key.starts_with("mkey:")),
            "debug node: {debug_created}"
        );
        assert!(
            debug_created["node"]["nodeKey"]
                .as_str()
                .is_some_and(|key| key.starts_with("nodekey:")),
            "debug node: {debug_created}"
        );
        assert_eq!(
            debug_created["node"]["availableRoutes"],
            serde_json::json!(["10.30.0.0/24"])
        );

        let registered = http
            .post(format!(
                "{server_url}/api/v1/node/register?user=alice&key={auth_id}"
            ))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(registered.status(), reqwest::StatusCode::OK);
        let registered = registered.json::<serde_json::Value>().await?;
        assert_eq!(registered["node"]["id"].as_str(), Some(node_id.as_str()));
        assert_eq!(
            registered["node"]["registerMethod"].as_str(),
            Some("REGISTER_METHOD_CLI")
        );
        assert!(
            registered["node"]["ipAddresses"]
                .as_array()
                .is_some_and(|ips| {
                    ips.iter()
                        .any(|ip| ip.as_str().is_some_and(|ip| ip.starts_with("100.")))
                }),
            "registered node: {registered}"
        );

        let listed = http
            .get(format!("{server_url}/api/v1/node?user=alice"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        let nodes = listed["nodes"].as_array().expect("nodes");
        assert_eq!(nodes.len(), 1, "listed nodes: {listed}");
        assert_eq!(nodes[0]["id"].as_str(), Some(node_id.as_str()));

        let fetched = http
            .get(format!("{server_url}/api/v1/node/{node_id}"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(fetched.status(), reqwest::StatusCode::OK);
        let fetched = fetched.json::<serde_json::Value>().await?;
        assert_eq!(fetched["node"]["id"].as_str(), Some(node_id.as_str()));

        let policy = r#"{"tagOwners":{"tag:router":["alice@"]}}"#;
        let updated_policy = http
            .put(format!("{server_url}/api/v1/policy"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "policy": policy }))
            .send()
            .await?;
        assert_eq!(updated_policy.status(), reqwest::StatusCode::OK);

        let tagged = http
            .post(format!("{server_url}/api/v1/node/{node_id}/tags"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "tags": ["tag:router"] }))
            .send()
            .await?;
        assert_eq!(tagged.status(), reqwest::StatusCode::OK);
        let tagged = tagged.json::<serde_json::Value>().await?;
        assert_eq!(tagged["node"]["tags"], serde_json::json!(["tag:router"]));

        let approved_routes = http
            .post(format!("{server_url}/api/v1/node/{node_id}/approve_routes"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "routes": ["10.30.0.0/24"] }))
            .send()
            .await?;
        assert_eq!(approved_routes.status(), reqwest::StatusCode::OK);
        let approved_routes = approved_routes.json::<serde_json::Value>().await?;
        assert_eq!(
            approved_routes["node"]["approvedRoutes"],
            serde_json::json!(["10.30.0.0/24"])
        );
        assert_eq!(
            approved_routes["node"]["subnetRoutes"],
            serde_json::json!(["10.30.0.0/24"])
        );

        let renamed = http
            .post(format!(
                "{server_url}/api/v1/node/{node_id}/rename/pg-gateway-renamed"
            ))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(renamed.status(), reqwest::StatusCode::OK);
        let renamed = renamed.json::<serde_json::Value>().await?;
        assert_eq!(renamed["node"]["name"].as_str(), Some("pg-gateway-renamed"));
        assert_eq!(
            renamed["node"]["givenName"].as_str(),
            Some("pg-gateway-renamed")
        );

        let expired = http
            .post(format!("{server_url}/api/v1/node/{node_id}/expire"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(expired.status(), reqwest::StatusCode::OK);
        let expired = expired.json::<serde_json::Value>().await?;
        assert!(
            expired["node"]["expiry"]
                .as_str()
                .is_some_and(|expiry| expiry.ends_with('Z')),
            "expired node: {expired}"
        );

        let backfilled = http
            .post(format!(
                "{server_url}/api/v1/node/backfillips?confirmed=true"
            ))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(backfilled.status(), reqwest::StatusCode::OK);
        assert!(
            backfilled.json::<serde_json::Value>().await?["changes"]
                .as_array()
                .is_some()
        );

        let deleted = http
            .delete(format!("{server_url}/api/v1/node/{node_id}"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(deleted.status(), reqwest::StatusCode::OK);
        assert_eq!(
            deleted.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let listed = http
            .get(format!("{server_url}/api/v1/node"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        assert_eq!(listed["nodes"], serde_json::json!([]));

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_grpc_gateway_preauth_key_lifecycle_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_preauth").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret");
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let http = reqwest::Client::new();
        let created_user = http
            .post(format!("{server_url}/api/v1/user"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "name": "preauth-user" }))
            .send()
            .await?;
        assert_eq!(created_user.status(), reqwest::StatusCode::OK);
        let created_user = created_user.json::<serde_json::Value>().await?;
        let user_id = created_user["user"]["id"]
            .as_str()
            .expect("created user id");
        assert_eq!(user_id, "1");

        let created = http
            .post(format!("{server_url}/api/v1/preauthkey"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({
                "user": user_id,
                "reusable": true,
                "ephemeral": true,
                "aclTags": ["tag:test"]
            }))
            .send()
            .await?;
        assert_eq!(created.status(), reqwest::StatusCode::OK);
        let created = created.json::<serde_json::Value>().await?;
        let preauth = &created["preAuthKey"];
        assert_eq!(preauth["id"].as_str(), Some("1"));
        assert_eq!(preauth["user"]["id"].as_str(), Some(user_id));
        assert_eq!(preauth["user"]["name"].as_str(), Some("preauth-user"));
        assert!(
            preauth["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("hskey-auth-")),
            "created preauth key: {created}"
        );
        assert_eq!(preauth["reusable"].as_bool(), Some(true));
        assert_eq!(preauth["ephemeral"].as_bool(), Some(true));
        assert_eq!(preauth["used"].as_bool(), Some(false));
        assert_eq!(preauth["aclTags"], serde_json::json!(["tag:test"]));
        assert!(
            preauth["createdAt"]
                .as_str()
                .is_some_and(|created_at| created_at.ends_with('Z')),
            "created preauth key: {created}"
        );

        let listed = http
            .get(format!("{server_url}/api/v1/preauthkey"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        let preauth_keys = listed["preAuthKeys"].as_array().expect("preAuthKeys");
        assert_eq!(preauth_keys.len(), 1, "listed preauth keys: {listed}");
        assert_eq!(preauth_keys[0]["id"].as_str(), Some("1"));
        assert_eq!(preauth_keys[0]["aclTags"], serde_json::json!(["tag:test"]));

        let expired = http
            .post(format!("{server_url}/api/v1/preauthkey/expire"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "id": "1" }))
            .send()
            .await?;
        assert_eq!(expired.status(), reqwest::StatusCode::OK);
        assert_eq!(
            expired.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let deleted = http
            .delete(format!("{server_url}/api/v1/preauthkey?id=1"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(deleted.status(), reqwest::StatusCode::OK);
        assert_eq!(
            deleted.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        let listed = http
            .get(format!("{server_url}/api/v1/preauthkey"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        let listed = listed.json::<serde_json::Value>().await?;
        assert_eq!(listed["preAuthKeys"], serde_json::json!([]));

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[cfg(feature = "postgres-sqlx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_postgres_runtime_grpc_gateway_policy_write_smoke() -> BoxTestResult {
    let Some(database) = TempPostgresServeDatabase::open("gateway_policy").await? else {
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let listen = unused_loopback_addr();
    let metrics = unused_loopback_addr();
    let grpc = unused_loopback_addr();
    let server_url = format!("http://{listen}");
    let config = write_postgres_serve_config(dir.path(), database.fields(), listen, metrics, grpc);
    let mut child = spawn_headscale_serve(&config, dir.path())?;

    let result = async {
        let health = wait_for_headscale_status(&config, &["health"], 0).await;
        assert_eq!(stdout(&health), "\n");
        assert_eq!(stderr(&health), "");

        let api_key = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(api_key.status.success(), "stderr: {}", stderr(&api_key));
        let api_key = json_output(&api_key);
        let api_key_secret = api_key.as_str().expect("api key secret");
        assert!(
            api_key_secret.starts_with("hskey-api-"),
            "api key: {api_key_secret}"
        );

        let http = reqwest::Client::new();
        let policy = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:443"]}]}"#;
        let updated = http
            .put(format!("{server_url}/api/v1/policy"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "policy": policy }))
            .send()
            .await?;
        assert_eq!(updated.status(), reqwest::StatusCode::OK);
        let updated = updated.json::<serde_json::Value>().await?;
        assert_eq!(updated["policy"].as_str(), Some(policy));
        assert!(
            updated["updatedAt"]
                .as_str()
                .is_some_and(|updated_at| updated_at.ends_with('Z')),
            "updated policy: {updated}"
        );

        let fetched = http
            .get(format!("{server_url}/api/v1/policy"))
            .bearer_auth(api_key_secret)
            .send()
            .await?;
        assert_eq!(fetched.status(), reqwest::StatusCode::OK);
        let fetched = fetched.json::<serde_json::Value>().await?;
        assert_eq!(fetched["policy"].as_str(), Some(policy));
        assert!(
            fetched["updatedAt"]
                .as_str()
                .is_some_and(|updated_at| updated_at.ends_with('Z')),
            "fetched policy: {fetched}"
        );

        let checked = http
            .post(format!("{server_url}/api/v1/policy/check"))
            .bearer_auth(api_key_secret)
            .json(&serde_json::json!({ "policy": r#"{"acls":[]}"# }))
            .send()
            .await?;
        assert_eq!(checked.status(), reqwest::StatusCode::OK);
        assert_eq!(
            checked.json::<serde_json::Value>().await?,
            serde_json::json!({})
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    stop_child(&mut child);
    database.cleanup().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usercommand_preauthkeycommand_preauthkeycommandwithoutexpiry_preauthkeycommandreusableephemeral_preauthkeycorrectuserloggedincommand_apikeycommand()
 {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    for user in ["user1", "user2"] {
        let create = headscale_with_config(&config, &["users", "create", user]);
        assert!(create.status.success(), "stderr: {}", stderr(&create));
        assert_eq!(
            stdout(&create),
            include_str!("snapshots/usercommand_create.stdout")
        );
        assert_eq!(stderr(&create), "");
    }

    let list = headscale_with_config(&config, &["-o", "json", "users", "list"]);
    let list = json_output(&list);
    assert_eq!(list.as_array().expect("users").len(), 2);
    assert_eq!(list[0]["name"].as_str(), Some("user1"));
    assert_eq!(list[1]["name"].as_str(), Some("user2"));

    let rename = headscale_with_config(
        &config,
        &[
            "users",
            "rename",
            "--identifier",
            "2",
            "--new-name",
            "newname",
        ],
    );
    assert!(rename.status.success(), "stderr: {}", stderr(&rename));
    assert_eq!(
        stdout(&rename),
        include_str!("snapshots/usercommand_rename.stdout")
    );
    assert_eq!(stderr(&rename), "");

    let renamed = headscale_with_config(
        &config,
        &["-o", "json", "users", "list", "--name", "newname"],
    );
    let renamed = json_output(&renamed);
    assert_eq!(renamed.as_array().expect("renamed user").len(), 1);
    assert_eq!(renamed[0]["id"].as_u64(), Some(2));
    assert_eq!(renamed[0]["name"].as_str(), Some("newname"));

    let destroy = headscale_with_config(
        &config,
        &["--force", "users", "destroy", "--identifier", "1"],
    );
    assert!(destroy.status.success(), "stderr: {}", stderr(&destroy));
    assert_eq!(
        stdout(&destroy),
        include_str!("snapshots/usercommand_destroy.stdout")
    );
    assert_eq!(stderr(&destroy), "");

    let after_destroy = headscale_with_config(&config, &["-o", "json", "users", "list"]);
    let after_destroy = json_output(&after_destroy);
    assert_eq!(after_destroy.as_array().expect("remaining users").len(), 1);
    assert_eq!(after_destroy[0]["name"].as_str(), Some("newname"));

    let mut preauth_ids = Vec::new();
    for _ in 0..3 {
        let create = headscale_with_config(
            &config,
            &[
                "-o",
                "json",
                "preauthkeys",
                "--user",
                "2",
                "create",
                "--reusable",
                "--expiration",
                "1h",
                "--tags",
                "tag:test1,tag:test2",
            ],
        );
        assert!(create.status.success(), "stderr: {}", stderr(&create));
        assert_eq!(stderr(&create), "");
        let key = json_output(&create);
        assert!(key["key"].as_str().unwrap().starts_with("hskey-auth-"));
        assert_eq!(key["user"]["name"].as_str(), Some("newname"));
        assert_eq!(key["reusable"].as_bool(), Some(true));
        assert_eq!(
            key["acl_tags"],
            serde_json::json!(["tag:test1", "tag:test2"])
        );
        preauth_ids.push(key["id"].as_u64().unwrap().to_string());
    }

    let listed_preauth = headscale_with_config(&config, &["-o", "json", "preauthkeys", "list"]);
    let listed_preauth = json_output(&listed_preauth);
    assert_eq!(listed_preauth.as_array().expect("preauth keys").len(), 3);
    for key in listed_preauth.as_array().unwrap() {
        assert_eq!(key["user"]["name"].as_str(), Some("newname"));
        assert_eq!(key["reusable"].as_bool(), Some(true));
        assert_eq!(
            key["acl_tags"],
            serde_json::json!(["tag:test1", "tag:test2"])
        );
        assert!(key["expiration"]["seconds"].as_i64().is_some());
    }

    let expire_preauth =
        headscale_with_config(&config, &["preauthkeys", "expire", "--id", &preauth_ids[0]]);
    assert!(
        expire_preauth.status.success(),
        "stderr: {}",
        stderr(&expire_preauth)
    );
    assert_eq!(
        stdout(&expire_preauth),
        include_str!("snapshots/preauthkeycommand_expire.stdout")
    );
    assert_eq!(stderr(&expire_preauth), "");

    let no_expiry = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "--user",
            "2",
            "create",
            "--reusable",
        ],
    );
    assert!(no_expiry.status.success(), "stderr: {}", stderr(&no_expiry));
    let no_expiry = json_output(&no_expiry);
    assert_eq!(no_expiry["user"]["name"].as_str(), Some("newname"));
    assert_eq!(no_expiry["reusable"].as_bool(), Some(true));
    assert!(no_expiry["expiration"]["seconds"].as_i64().is_some());

    let ephemeral = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "--user",
            "2",
            "create",
            "--ephemeral",
        ],
    );
    assert!(ephemeral.status.success(), "stderr: {}", stderr(&ephemeral));
    let ephemeral = json_output(&ephemeral);
    assert_eq!(ephemeral["user"]["name"].as_str(), Some("newname"));
    assert_eq!(ephemeral["ephemeral"].as_bool(), Some(true));
    assert_ne!(ephemeral["reusable"].as_bool(), Some(true));

    let tagged = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "--user",
            "2",
            "create",
            "--reusable",
            "--expiration",
            "1h",
            "--tags",
            "tag:test1,tag:test2",
        ],
    );
    assert!(tagged.status.success(), "stderr: {}", stderr(&tagged));
    let tagged = json_output(&tagged);
    assert_eq!(tagged["user"]["name"].as_str(), Some("newname"));
    assert_eq!(
        tagged["acl_tags"],
        serde_json::json!(["tag:test1", "tag:test2"])
    );

    let mut api_prefixes = Vec::new();
    for _ in 0..5 {
        let create = headscale_with_config(
            &config,
            &["-o", "json", "apikeys", "create", "--expiration", "1h"],
        );
        assert!(create.status.success(), "stderr: {}", stderr(&create));
        let secret = json_output(&create)
            .as_str()
            .expect("api key secret")
            .to_string();
        assert!(secret.starts_with("hskey-api-"));
        api_prefixes.push(display_prefix(&secret, "hskey-api-"));
    }

    let listed_api_keys = headscale_with_config(&config, &["-o", "json", "apikeys", "list"]);
    let listed_api_keys = json_output(&listed_api_keys);
    assert_eq!(listed_api_keys.as_array().expect("api keys").len(), 5);
    for (index, key) in listed_api_keys.as_array().unwrap().iter().enumerate() {
        assert_eq!(key["id"].as_u64(), Some(index as u64 + 1));
        assert_eq!(key["prefix"].as_str(), Some(api_prefixes[index].as_str()));
        assert!(key["expiration"]["seconds"].as_i64().is_some());
    }

    let expire_api_key = headscale_with_config(
        &config,
        &["apikeys", "expire", "--prefix", &api_prefixes[0]],
    );
    assert!(
        expire_api_key.status.success(),
        "stderr: {}",
        stderr(&expire_api_key)
    );
    assert_eq!(
        stdout(&expire_api_key),
        include_str!("snapshots/apikeycommand_expire.stdout")
    );
    assert_eq!(stderr(&expire_api_key), "");

    let delete_api_key = headscale_with_config(&config, &["apikeys", "delete", "--id", "2"]);
    assert!(
        delete_api_key.status.success(),
        "stderr: {}",
        stderr(&delete_api_key)
    );
    assert_eq!(
        stdout(&delete_api_key),
        include_str!("snapshots/apikeycommand_delete.stdout")
    );
    assert_eq!(stderr(&delete_api_key), "");

    let after_api_delete = headscale_with_config(&config, &["-o", "json", "apikeys", "list"]);
    let after_api_delete = json_output(&after_api_delete);
    assert_eq!(after_api_delete.as_array().expect("api keys").len(), 4);
    assert!(
        after_api_delete
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key["id"].as_u64() != Some(2))
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nodecommand_nodeexpirecommand_noderenamecommand_taggednodesclioutput() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let create_user = headscale_with_config(&config, &["users", "create", "node-user"]);
    assert!(
        create_user.status.success(),
        "stderr: {}",
        stderr(&create_user)
    );
    assert_eq!(stderr(&create_user), "");

    for (name, registration_id) in [
        ("node-1", "aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("node-2", "bbbbbbbbbbbbbbbbbbbbbbbb"),
        ("node-3", "cccccccccccccccccccccccc"),
    ] {
        let auth_id = format!("hskey-authreq-{registration_id}");
        let debug_create = headscale_with_config(
            &config,
            &[
                "debug",
                "create-node",
                "--name",
                name,
                "--user",
                "node-user",
                "--key",
                &auth_id,
            ],
        );
        assert!(
            debug_create.status.success(),
            "stderr: {}",
            stderr(&debug_create)
        );
        assert_eq!(stderr(&debug_create), "");

        let register = headscale_with_config(
            &config,
            &[
                "auth",
                "register",
                "--user",
                "node-user",
                "--auth-id",
                &auth_id,
            ],
        );
        assert!(register.status.success(), "stderr: {}", stderr(&register));
        assert!(
            stdout(&register).contains(name),
            "stdout: {}",
            stdout(&register)
        );
        assert_eq!(stderr(&register), "");
    }

    let listed = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
    let listed = json_output(&listed);
    let listed = listed.as_array().expect("nodes");
    assert_eq!(listed.len(), 3);
    let node_id = |name: &str| {
        listed
            .iter()
            .find(|node| node["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing node {name}: {listed:?}"))["id"]
            .as_u64()
            .unwrap()
    };
    let node_1_id = node_id("node-1");
    let node_2_id = node_id("node-2");
    let node_3_id = node_id("node-3");
    let node_1_id_arg = node_1_id.to_string();
    let node_2_id_arg = node_2_id.to_string();
    let node_3_id_arg = node_3_id.to_string();

    let expire = headscale_with_config(
        &config,
        &["nodes", "expire", "--identifier", &node_1_id_arg],
    );
    assert!(expire.status.success(), "stderr: {}", stderr(&expire));
    assert_eq!(
        stdout(&expire),
        include_str!("snapshots/nodeexpirecommand_expire.stdout")
    );
    assert_eq!(stderr(&expire), "");

    let rename = headscale_with_config(
        &config,
        &[
            "nodes",
            "rename",
            "--identifier",
            &node_2_id_arg,
            "newnode-2",
        ],
    );
    assert!(rename.status.success(), "stderr: {}", stderr(&rename));
    assert_eq!(
        stdout(&rename),
        include_str!("snapshots/noderenamecommand_rename.stdout")
    );
    assert_eq!(stderr(&rename), "");

    let policy_path = config_dir.path().join("tag-policy.hujson");
    fs::write(
        &policy_path,
        r#"{"tagOwners":{"tag:test1":["node-user@"]}}"#,
    )
    .unwrap();
    let policy_path = policy_path.to_string_lossy().to_string();
    let set_policy = headscale_with_config(&config, &["policy", "set", "--file", &policy_path]);
    assert!(
        set_policy.status.success(),
        "stderr: {}",
        stderr(&set_policy)
    );
    assert_eq!(stderr(&set_policy), "");

    let tag = headscale_with_config(
        &config,
        &[
            "nodes",
            "tag",
            "--identifier",
            &node_3_id_arg,
            "--tags",
            "tag:test1",
        ],
    );
    assert!(tag.status.success(), "stderr: {}", stderr(&tag));
    assert_eq!(
        stdout(&tag),
        include_str!("snapshots/taggednodesclioutput_tag.stdout")
    );
    assert_eq!(stderr(&tag), "");

    let after_mutation = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
    let after_mutation = json_output(&after_mutation);
    let after_mutation = after_mutation.as_array().expect("nodes");
    assert_eq!(after_mutation.len(), 3);
    let renamed = after_mutation
        .iter()
        .find(|node| node["id"].as_u64() == Some(node_2_id))
        .expect("renamed node");
    assert_eq!(renamed["given_name"].as_str(), Some("newnode-2"));
    let expired = after_mutation
        .iter()
        .find(|node| node["id"].as_u64() == Some(node_1_id))
        .expect("expired node");
    assert!(expired["expiry"]["seconds"].as_i64().is_some());

    let delete = headscale_with_config(
        &config,
        &["--force", "nodes", "delete", "--identifier", &node_1_id_arg],
    );
    assert!(delete.status.success(), "stderr: {}", stderr(&delete));
    assert_eq!(
        stdout(&delete),
        include_str!("snapshots/nodecommand_delete.stdout")
    );
    assert_eq!(stderr(&delete), "");

    let after_delete = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
    let after_delete = json_output(&after_delete);
    assert_eq!(after_delete.as_array().expect("nodes").len(), 2);

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policycommand_policybrokenconfigcommand() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let policy_path = config_dir.path().join("policy.hujson");
    fs::write(
        &policy_path,
        r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
    )
    .unwrap();
    let policy_path = policy_path.to_string_lossy().to_string();
    let set_policy = headscale_with_config(&config, &["policy", "set", "--file", &policy_path]);
    assert!(
        set_policy.status.success(),
        "stderr: {}",
        stderr(&set_policy)
    );
    assert_eq!(
        stdout(&set_policy),
        include_str!("snapshots/policycommand_set.stdout")
    );
    assert_eq!(stderr(&set_policy), "");

    let get_policy = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
    assert!(
        get_policy.status.success(),
        "stderr: {}",
        stderr(&get_policy)
    );
    assert_eq!(
        stdout(&get_policy),
        include_str!("snapshots/policycommand_get.stdout")
    );
    assert_eq!(stderr(&get_policy), "");

    let bad_policy_path = config_dir.path().join("bad-policy.hujson");
    fs::write(&bad_policy_path, r#"{"unknown":true}"#).unwrap();
    let bad_policy_path = bad_policy_path.to_string_lossy().to_string();
    let bad_policy = headscale_with_config(
        &config,
        &["-o", "json", "policy", "set", "--file", &bad_policy_path],
    );
    assert_process_stderr_snapshot(
        &bad_policy,
        6,
        include_str!("snapshots/policybrokenconfigcommand_set_json.stderr"),
        "policy broken config",
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpcauthenticationbypass_cliwithconfigauthenticationbypass() {
    let (_dir, _db, address, api_key, handle) = spawn_process_remote_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_remote_grpc_config(config_dir.path(), &address, &api_key);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    for user in ["grpcuser1", "grpcuser2"] {
        let create = headscale_with_config(&config, &["users", "create", user]);
        assert!(create.status.success(), "stderr: {}", stderr(&create));
        assert_eq!(stderr(&create), "");
    }

    let address_env = [
        ("HEADSCALE_CLI_ADDRESS", address.as_str()),
        ("HEADSCALE_CLI_INSECURE", "true"),
    ];
    let no_key = headscale_clean_with_env(&["users", "list", "--output", "json"], &address_env);
    assert_process_stderr_snapshot(
        &no_key,
        6,
        include_str!("snapshots/grpcauthenticationbypass_missing_api_key.stderr"),
        "gRPC missing API key",
    );
    assert!(!stderr(&no_key).contains("grpcuser1"));
    assert!(!stderr(&no_key).contains("grpcuser2"));

    let invalid_env = [
        ("HEADSCALE_CLI_ADDRESS", address.as_str()),
        ("HEADSCALE_CLI_API_KEY", "invalid-key-12345"),
        ("HEADSCALE_CLI_INSECURE", "true"),
    ];
    let invalid = headscale_clean_with_env(&["users", "list", "--output", "json"], &invalid_env);
    assert_process_stderr_snapshot(
        &invalid,
        4,
        include_str!("snapshots/grpcauthenticationbypass_invalid_api_key.stderr"),
        "gRPC invalid API key",
    );
    assert!(!stderr(&invalid).contains("grpcuser1"));
    assert!(!stderr(&invalid).contains("grpcuser2"));

    let valid_env = [
        ("HEADSCALE_CLI_ADDRESS", address.as_str()),
        ("HEADSCALE_CLI_API_KEY", api_key.as_str()),
        ("HEADSCALE_CLI_INSECURE", "true"),
    ];
    let valid = headscale_clean_with_env(&["users", "list", "--output", "json"], &valid_env);
    assert!(valid.status.success(), "stderr: {}", stderr(&valid));
    assert_eq!(stderr(&valid), "");
    let valid = json_output(&valid);
    assert_eq!(valid.as_array().expect("users").len(), 2);
    assert_eq!(valid[0]["name"].as_str(), Some("grpcuser1"));
    assert_eq!(valid[1]["name"].as_str(), Some("grpcuser2"));

    let no_key_config_dir = tempfile::tempdir().unwrap();
    let no_key_config =
        write_remote_grpc_config_without_api_key(no_key_config_dir.path(), &address);
    let no_key_config_output =
        headscale_with_config(&no_key_config, &["users", "list", "--output", "json"]);
    assert_process_stderr_snapshot(
        &no_key_config_output,
        1,
        include_str!("snapshots/cliwithconfigauthenticationbypass_missing_api_key.stderr"),
        "CLI config missing API key JSON",
    );
    assert!(!stderr(&no_key_config_output).contains("grpcuser1"));
    assert!(!stderr(&no_key_config_output).contains("grpcuser2"));

    let no_key_config_json_line =
        headscale_with_config(&no_key_config, &["users", "list", "--output", "json-line"]);
    assert_process_stderr_snapshot(
        &no_key_config_json_line,
        1,
        include_str!(
            "snapshots/cliwithconfigauthenticationbypass_missing_api_key_json_line.stderr"
        ),
        "CLI config missing API key JSON-line",
    );
    assert!(!stderr(&no_key_config_json_line).contains("grpcuser1"));
    assert!(!stderr(&no_key_config_json_line).contains("grpcuser2"));

    let no_key_config_yaml =
        headscale_with_config(&no_key_config, &["users", "list", "--output", "yaml"]);
    assert_process_stderr_snapshot(
        &no_key_config_yaml,
        1,
        include_str!("snapshots/cliwithconfigauthenticationbypass_missing_api_key_yaml.stderr"),
        "CLI config missing API key YAML",
    );
    assert!(!stderr(&no_key_config_yaml).contains("grpcuser1"));
    assert!(!stderr(&no_key_config_yaml).contains("grpcuser2"));

    let invalid_config_dir = tempfile::tempdir().unwrap();
    let invalid_config =
        write_remote_grpc_config(invalid_config_dir.path(), &address, "invalid-key-12345");
    let invalid_config_output =
        headscale_with_config(&invalid_config, &["users", "list", "--output", "json"]);
    assert_process_stderr_snapshot(
        &invalid_config_output,
        4,
        include_str!("snapshots/cliwithconfigauthenticationbypass_invalid_api_key.stderr"),
        "CLI config invalid API key",
    );
    assert!(!stderr(&invalid_config_output).contains("grpcuser1"));
    assert!(!stderr(&invalid_config_output).contains("grpcuser2"));

    let valid_config_output =
        headscale_with_config(&config, &["users", "list", "--output", "json"]);
    assert!(
        valid_config_output.status.success(),
        "stderr: {}",
        stderr(&valid_config_output)
    );
    assert_eq!(stderr(&valid_config_output), "");
    let valid_config_output = json_output(&valid_config_output);
    assert_eq!(valid_config_output.as_array().expect("users").len(), 2);
    assert_eq!(valid_config_output[0]["name"].as_str(), Some("grpcuser1"));
    assert_eq!(valid_config_output[1]["name"].as_str(), Some("grpcuser2"));

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_local_grpc_cli_success_outputs_match_snapshots() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let health_json = headscale_with_config(&config, &["-o", "json", "health"]);
    let health_json = json_output(&health_json);
    assert_eq!(health_json["database_connectivity"].as_bool(), Some(true));

    let create_user = headscale_with_config(
        &config,
        &[
            "users",
            "create",
            "alice",
            "--display-name",
            "Alice Example",
            "--email",
            "alice@example.com",
        ],
    );
    assert!(
        create_user.status.success(),
        "stderr: {}",
        stderr(&create_user)
    );
    assert_eq!(stdout(&create_user), "User created\n");
    assert_eq!(stderr(&create_user), "");

    let list_users = headscale_with_config(&config, &["users", "list"]);
    assert!(
        list_users.status.success(),
        "stderr: {}",
        stderr(&list_users)
    );
    assert_eq!(
        trim_line_end_spaces(&normalize_users_list_stdout(&stdout(&list_users))),
        concat!(
            "ID  Name           Username  Email              Created\n",
            "-------------------------------------------------------------------\n",
            "1   Alice Example  alice     alice@example.com  0000-00-00 00:00:00\n",
        )
    );
    assert_eq!(stderr(&list_users), "");

    let create_user_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "users",
            "create",
            "bob",
            "--display-name",
            "Bob Example",
            "--email",
            "bob@example.com",
            "--picture-url",
            "https://example.com/bob.png",
        ],
    );
    let bob_json = json_output(&create_user_json);
    assert_eq!(bob_json["name"].as_str(), Some("bob"));
    assert_eq!(bob_json["display_name"].as_str(), Some("Bob Example"));
    assert_eq!(bob_json["email"].as_str(), Some("bob@example.com"));
    assert_eq!(
        bob_json["profile_pic_url"].as_str(),
        Some("https://example.com/bob.png")
    );
    assert!(bob_json["created_at"]["seconds"].as_i64().is_some());
    assert!(bob_json.get("createdAt").is_none());
    assert!(bob_json.get("displayName").is_none());
    assert!(bob_json.get("profilePicUrl").is_none());
    assert_eq!(stderr(&create_user_json), "");
    let bob_id = bob_json["id"].as_u64().unwrap().to_string();

    let list_user_json =
        headscale_with_config(&config, &["-o", "json", "users", "list", "--name", "bob"]);
    let listed_bob_json = json_output(&list_user_json);
    assert_eq!(listed_bob_json.as_array().unwrap().len(), 1);
    let listed_bob_json = &listed_bob_json[0];
    assert_eq!(listed_bob_json["id"].as_u64().unwrap().to_string(), bob_id);
    assert_eq!(listed_bob_json["name"].as_str(), Some("bob"));
    assert_eq!(
        listed_bob_json["display_name"].as_str(),
        Some("Bob Example")
    );
    assert!(listed_bob_json["created_at"]["seconds"].as_i64().is_some());
    assert!(listed_bob_json.get("createdAt").is_none());
    assert!(listed_bob_json.get("displayName").is_none());
    assert_eq!(stderr(&list_user_json), "");

    let rename_user_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "users",
            "rename",
            "--identifier",
            &bob_id,
            "--new-name",
            "bob-renamed",
        ],
    );
    let renamed_bob_json = json_output(&rename_user_json);
    assert_eq!(renamed_bob_json["name"].as_str(), Some("bob-renamed"));
    assert_eq!(renamed_bob_json["id"].as_u64().unwrap().to_string(), bob_id);
    assert!(renamed_bob_json["created_at"]["seconds"].as_i64().is_some());
    assert!(renamed_bob_json.get("createdAt").is_none());
    assert_eq!(stderr(&rename_user_json), "");

    let destroy_user_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "--force",
            "users",
            "destroy",
            "--identifier",
            &bob_id,
        ],
    );
    assert_eq!(
        json_output(&destroy_user_json).as_object().unwrap().len(),
        0
    );
    assert_eq!(stderr(&destroy_user_json), "");

    let create_user_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "users",
            "create",
            "carol",
            "--display-name",
            "Carol Example",
            "--email",
            "carol@example.com",
        ],
    );
    let carol_json_line: serde_json::Value =
        serde_json::from_slice(&create_user_json_line.stdout).unwrap();
    assert_eq!(carol_json_line["name"].as_str(), Some("carol"));
    assert_eq!(
        carol_json_line["display_name"].as_str(),
        Some("Carol Example")
    );
    assert!(carol_json_line["created_at"]["seconds"].as_i64().is_some());
    assert!(carol_json_line.get("createdAt").is_none());
    assert!(carol_json_line.get("displayName").is_none());
    assert!(!stdout(&create_user_json_line).contains('\t'));
    assert_eq!(stderr(&create_user_json_line), "");
    let carol_id = carol_json_line["id"].as_u64().unwrap().to_string();

    let list_user_json_line = headscale_with_config(
        &config,
        &["-ojson-line", "users", "list", "--identifier", &carol_id],
    );
    let listed_carol_json_line: serde_json::Value =
        serde_json::from_slice(&list_user_json_line.stdout).unwrap();
    let listed_carol_json_line = &listed_carol_json_line[0];
    assert_eq!(listed_carol_json_line["name"].as_str(), Some("carol"));
    assert!(
        listed_carol_json_line["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_carol_json_line.get("createdAt").is_none());
    assert_eq!(stderr(&list_user_json_line), "");

    let rename_user_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "users",
            "rename",
            "--identifier",
            &carol_id,
            "--new-name",
            "carol-renamed",
        ],
    );
    let renamed_carol_json_line: serde_json::Value =
        serde_json::from_slice(&rename_user_json_line.stdout).unwrap();
    assert_eq!(
        renamed_carol_json_line["name"].as_str(),
        Some("carol-renamed")
    );
    assert!(
        renamed_carol_json_line["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(renamed_carol_json_line.get("createdAt").is_none());
    assert_eq!(stderr(&rename_user_json_line), "");

    let destroy_user_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "--force",
            "users",
            "destroy",
            "--identifier",
            &carol_id,
        ],
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&destroy_user_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&destroy_user_json_line), "");

    let create_user_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "users",
            "create",
            "dana",
            "--display-name",
            "Dana Example",
            "--email",
            "dana@example.com",
        ],
    );
    let dana_yaml = yaml_output(&create_user_yaml);
    assert_eq!(dana_yaml["name"].as_str(), Some("dana"));
    assert_eq!(dana_yaml["display_name"].as_str(), Some("Dana Example"));
    assert!(dana_yaml["created_at"]["seconds"].as_i64().is_some());
    assert!(dana_yaml.get("createdAt").is_none());
    assert!(dana_yaml.get("displayName").is_none());
    assert_eq!(stderr(&create_user_yaml), "");
    let dana_id = dana_yaml["id"].as_u64().unwrap().to_string();

    let list_user_yaml =
        headscale_with_config(&config, &["-o", "yaml", "users", "list", "--name", "dana"]);
    let listed_dana_yaml = yaml_output(&list_user_yaml);
    let listed_dana_yaml = &listed_dana_yaml[0];
    assert_eq!(listed_dana_yaml["name"].as_str(), Some("dana"));
    assert!(listed_dana_yaml["created_at"]["seconds"].as_i64().is_some());
    assert!(listed_dana_yaml.get("createdAt").is_none());
    assert_eq!(stderr(&list_user_yaml), "");

    let rename_user_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "users",
            "rename",
            "--identifier",
            &dana_id,
            "--new-name",
            "dana-renamed",
        ],
    );
    let renamed_dana_yaml = yaml_output(&rename_user_yaml);
    assert_eq!(renamed_dana_yaml["name"].as_str(), Some("dana-renamed"));
    assert!(
        renamed_dana_yaml["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(renamed_dana_yaml.get("createdAt").is_none());
    assert_eq!(stderr(&rename_user_yaml), "");

    let destroy_user_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "--force",
            "users",
            "destroy",
            "--identifier",
            &dana_id,
        ],
    );
    assert_eq!(
        yaml_output(&destroy_user_yaml).as_mapping().unwrap().len(),
        0
    );
    assert_eq!(stderr(&destroy_user_yaml), "");

    let create_preauth = headscale_with_config(
        &config,
        &[
            "preauthkeys",
            "--user",
            "1",
            "create",
            "--reusable",
            "--ephemeral",
            "--expiration",
            "1h",
        ],
    );
    assert!(
        create_preauth.status.success(),
        "stderr: {}",
        stderr(&create_preauth)
    );
    let preauth_key = stdout(&create_preauth).trim().to_string();
    assert!(preauth_key.starts_with("hskey-auth-"));
    assert_eq!(stderr(&create_preauth), "");

    let list_preauth = headscale_with_config(&config, &["preauthkeys", "list"]);
    assert!(
        list_preauth.status.success(),
        "stderr: {}",
        stderr(&list_preauth)
    );
    assert_normalized_secret_stdout_snapshot(
        &list_preauth,
        include_str!("snapshots/preauthkeys_list_success.stdout"),
        "preauthkeys list populated",
    );

    let preauth_json = headscale_with_config(&config, &["-o", "json", "preauthkeys", "list"]);
    let preauth_json = json_output(&preauth_json);
    let listed_preauth = &preauth_json[0];
    let expected_listed_preauth_key = display_prefix(&preauth_key, "hskey-auth-");
    assert_eq!(
        listed_preauth["key"].as_str(),
        Some(expected_listed_preauth_key.as_str())
    );
    assert_eq!(listed_preauth["user"]["name"].as_str(), Some("alice"));
    assert_eq!(listed_preauth["reusable"].as_bool(), Some(true));
    assert_eq!(listed_preauth["ephemeral"].as_bool(), Some(true));
    assert!(listed_preauth.get("used").is_none());
    assert!(listed_preauth.get("acl_tags").is_none());
    assert!(listed_preauth["expiration"]["seconds"].as_i64().is_some());
    assert!(listed_preauth["created_at"]["seconds"].as_i64().is_some());
    assert!(listed_preauth.get("createdAt").is_none());
    assert!(listed_preauth.get("aclTags").is_none());
    let preauth_id = listed_preauth["id"].as_u64().unwrap();
    let preauth_id = preauth_id.to_string();
    let expire_preauth =
        headscale_with_config(&config, &["preauthkeys", "expire", "--id", &preauth_id]);
    assert!(
        expire_preauth.status.success(),
        "stderr: {}",
        stderr(&expire_preauth)
    );
    assert_eq!(stdout(&expire_preauth), "Key expired\n");
    assert_eq!(stderr(&expire_preauth), "");
    let delete_preauth =
        headscale_with_config(&config, &["preauthkeys", "delete", "--id", &preauth_id]);
    assert!(
        delete_preauth.status.success(),
        "stderr: {}",
        stderr(&delete_preauth)
    );
    assert_eq!(stdout(&delete_preauth), "Key deleted\n");
    assert_eq!(stderr(&delete_preauth), "");
    let empty_preauth = headscale_with_config(&config, &["preauthkeys", "list"]);
    assert!(
        empty_preauth.status.success(),
        "stderr: {}",
        stderr(&empty_preauth)
    );
    assert_normalized_secret_stdout_snapshot(
        &empty_preauth,
        include_str!("snapshots/preauthkeys_list_empty.stdout"),
        "preauthkeys list empty",
    );

    let create_preauth_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--reusable",
            "--expiration",
            "1h",
            "--tags",
            "tag:test1,tag:test2",
        ],
    );
    let created_preauth_json = json_output(&create_preauth_json);
    assert_eq!(created_preauth_json["user"]["name"].as_str(), Some("alice"));
    assert!(
        created_preauth_json["key"]
            .as_str()
            .unwrap()
            .starts_with("hskey-auth-")
    );
    assert_eq!(created_preauth_json["reusable"].as_bool(), Some(true));
    assert!(created_preauth_json.get("ephemeral").is_none());
    assert_eq!(
        created_preauth_json["acl_tags"],
        serde_json::json!(["tag:test1", "tag:test2"])
    );
    assert!(created_preauth_json.get("aclTags").is_none());
    assert!(
        created_preauth_json["expiration"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(
        created_preauth_json["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(created_preauth_json.get("createdAt").is_none());
    assert_eq!(stderr(&create_preauth_json), "");
    let created_preauth_id = created_preauth_json["id"].as_u64().unwrap().to_string();
    let delete_preauth_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "delete",
            "--id",
            &created_preauth_id,
        ],
    );
    assert_eq!(
        json_output(&delete_preauth_json).as_object().unwrap().len(),
        0
    );
    assert_eq!(stderr(&delete_preauth_json), "");

    let create_preauth_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--reusable",
            "--expiration",
            "1h",
            "--tags",
            "tag:test1,tag:test2",
        ],
    );
    let created_preauth_json_line: serde_json::Value =
        serde_json::from_slice(&create_preauth_json_line.stdout).unwrap();
    assert_eq!(
        created_preauth_json_line["user"]["name"].as_str(),
        Some("alice")
    );
    assert!(
        created_preauth_json_line["key"]
            .as_str()
            .unwrap()
            .starts_with("hskey-auth-")
    );
    assert_eq!(created_preauth_json_line["reusable"].as_bool(), Some(true));
    assert!(created_preauth_json_line.get("ephemeral").is_none());
    assert_eq!(
        created_preauth_json_line["acl_tags"],
        serde_json::json!(["tag:test1", "tag:test2"])
    );
    assert!(created_preauth_json_line.get("aclTags").is_none());
    assert!(
        created_preauth_json_line["expiration"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(
        created_preauth_json_line["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(created_preauth_json_line.get("createdAt").is_none());
    assert!(!stdout(&create_preauth_json_line).contains('\t'));
    assert_eq!(stderr(&create_preauth_json_line), "");

    let list_preauth_json_line =
        headscale_with_config(&config, &["-ojson-line", "preauthkeys", "list"]);
    let listed_preauth_json_line: serde_json::Value =
        serde_json::from_slice(&list_preauth_json_line.stdout).unwrap();
    let listed_preauth_json_line = &listed_preauth_json_line[0];
    let created_preauth_json_line_key = created_preauth_json_line["key"].as_str().unwrap();
    let expected_listed_preauth_json_line_key =
        display_prefix(created_preauth_json_line_key, "hskey-auth-");
    assert_eq!(
        listed_preauth_json_line["key"].as_str(),
        Some(expected_listed_preauth_json_line_key.as_str())
    );
    assert_eq!(
        listed_preauth_json_line["user"]["name"].as_str(),
        Some("alice")
    );
    assert_eq!(listed_preauth_json_line["reusable"].as_bool(), Some(true));
    assert_eq!(
        listed_preauth_json_line["acl_tags"],
        serde_json::json!(["tag:test1", "tag:test2"])
    );
    assert!(
        listed_preauth_json_line["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_preauth_json_line.get("createdAt").is_none());
    assert!(listed_preauth_json_line.get("aclTags").is_none());
    assert_eq!(stderr(&list_preauth_json_line), "");

    let preauth_json_line_id = listed_preauth_json_line["id"].as_u64().unwrap().to_string();
    let expire_preauth_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "preauthkeys",
            "expire",
            "--id",
            &preauth_json_line_id,
        ],
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&expire_preauth_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&expire_preauth_json_line), "");

    let delete_preauth_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "preauthkeys",
            "delete",
            "--id",
            &preauth_json_line_id,
        ],
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&delete_preauth_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&delete_preauth_json_line), "");

    let create_preauth_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--reusable",
            "--expiration",
            "1h",
            "--tags",
            "tag:test1,tag:test2",
        ],
    );
    let created_preauth_yaml = yaml_output(&create_preauth_yaml);
    assert_eq!(created_preauth_yaml["user"]["name"].as_str(), Some("alice"));
    assert!(
        created_preauth_yaml["key"]
            .as_str()
            .unwrap()
            .starts_with("hskey-auth-")
    );
    assert_eq!(created_preauth_yaml["reusable"].as_bool(), Some(true));
    assert!(created_preauth_yaml.get("ephemeral").is_none());
    assert_eq!(
        created_preauth_yaml["acl_tags"],
        serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String("tag:test1".into()),
            serde_yaml::Value::String("tag:test2".into()),
        ])
    );
    assert!(created_preauth_yaml.get("aclTags").is_none());
    assert!(
        created_preauth_yaml["expiration"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(
        created_preauth_yaml["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(created_preauth_yaml.get("createdAt").is_none());
    assert_eq!(stderr(&create_preauth_yaml), "");

    let list_preauth_yaml = headscale_with_config(&config, &["-o", "yaml", "preauthkeys", "list"]);
    let listed_preauth_yaml = yaml_output(&list_preauth_yaml);
    let listed_preauth_yaml = &listed_preauth_yaml[0];
    let created_preauth_yaml_key = created_preauth_yaml["key"].as_str().unwrap();
    let expected_listed_preauth_yaml_key = display_prefix(created_preauth_yaml_key, "hskey-auth-");
    assert_eq!(
        listed_preauth_yaml["key"].as_str(),
        Some(expected_listed_preauth_yaml_key.as_str())
    );
    assert_eq!(listed_preauth_yaml["user"]["name"].as_str(), Some("alice"));
    assert_eq!(listed_preauth_yaml["reusable"].as_bool(), Some(true));
    assert_eq!(
        listed_preauth_yaml["acl_tags"],
        serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String("tag:test1".into()),
            serde_yaml::Value::String("tag:test2".into()),
        ])
    );
    assert!(
        listed_preauth_yaml["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_preauth_yaml.get("createdAt").is_none());
    assert!(listed_preauth_yaml.get("aclTags").is_none());
    assert_eq!(stderr(&list_preauth_yaml), "");

    let preauth_yaml_id = listed_preauth_yaml["id"].as_u64().unwrap().to_string();
    let expire_preauth_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "preauthkeys",
            "expire",
            "--id",
            &preauth_yaml_id,
        ],
    );
    assert_eq!(
        yaml_output(&expire_preauth_yaml)
            .as_mapping()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&expire_preauth_yaml), "");

    let delete_preauth_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "preauthkeys",
            "delete",
            "--id",
            &preauth_yaml_id,
        ],
    );
    assert_eq!(
        yaml_output(&delete_preauth_yaml)
            .as_mapping()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&delete_preauth_yaml), "");

    let create_api_key =
        headscale_with_config(&config, &["apikeys", "create", "--expiration", "1h"]);
    assert!(
        create_api_key.status.success(),
        "stderr: {}",
        stderr(&create_api_key)
    );
    let api_key = stdout(&create_api_key).trim().to_string();
    assert!(api_key.starts_with("hskey-api-"));
    let api_prefix = display_prefix(&api_key, "hskey-api-");
    assert_eq!(stderr(&create_api_key), "");

    let list_api_keys = headscale_with_config(&config, &["apikeys", "list"]);
    assert!(
        list_api_keys.status.success(),
        "stderr: {}",
        stderr(&list_api_keys)
    );
    assert!(stdout(&list_api_keys).contains(&api_prefix));
    assert_normalized_secret_stdout_snapshot(
        &list_api_keys,
        include_str!("snapshots/apikeys_list_success.stdout"),
        "apikeys list populated",
    );

    let api_json = headscale_with_config(&config, &["-o", "json", "apikeys", "list"]);
    let api_id = json_output(&api_json)[0]["id"]
        .as_u64()
        .unwrap()
        .to_string();
    let expire_api_key = headscale_with_config(&config, &["apikeys", "expire", "--id", &api_id]);
    assert!(
        expire_api_key.status.success(),
        "stderr: {}",
        stderr(&expire_api_key)
    );
    assert_eq!(stdout(&expire_api_key), "Key expired\n");
    assert_eq!(stderr(&expire_api_key), "");
    let delete_api_key = headscale_with_config(&config, &["apikeys", "delete", "--id", &api_id]);
    assert!(
        delete_api_key.status.success(),
        "stderr: {}",
        stderr(&delete_api_key)
    );
    assert_eq!(stdout(&delete_api_key), "Key deleted\n");
    assert_eq!(stderr(&delete_api_key), "");
    let empty_api_keys = headscale_with_config(&config, &["apikeys", "list"]);
    assert!(
        empty_api_keys.status.success(),
        "stderr: {}",
        stderr(&empty_api_keys)
    );
    assert_normalized_secret_stdout_snapshot(
        &empty_api_keys,
        include_str!("snapshots/apikeys_list_empty.stdout"),
        "apikeys list empty",
    );

    let create_api_key_json = headscale_with_config(
        &config,
        &["-o", "json", "apikeys", "create", "--expiration", "1h"],
    );
    let api_key_json = json_output(&create_api_key_json)
        .as_str()
        .expect("API-key create JSON is the secret string")
        .to_string();
    assert!(api_key_json.starts_with("hskey-api-"));
    let api_json_prefix = display_prefix(&api_key_json, "hskey-api-");
    assert_eq!(stderr(&create_api_key_json), "");

    let list_api_keys_json = headscale_with_config(&config, &["-o", "json", "apikeys", "list"]);
    let listed_api_keys = json_output(&list_api_keys_json);
    assert_eq!(listed_api_keys.as_array().unwrap().len(), 1);
    let listed_api_key = &listed_api_keys[0];
    assert_eq!(
        listed_api_key["prefix"].as_str(),
        Some(api_json_prefix.as_str())
    );
    assert!(listed_api_key["expiration"]["seconds"].as_i64().is_some());
    assert!(listed_api_key["created_at"]["seconds"].as_i64().is_some());
    assert!(listed_api_key.get("createdAt").is_none());
    assert!(listed_api_key.get("lastSeen").is_none());
    assert!(listed_api_key.get("last_seen").is_none());
    let api_json_id = listed_api_key["id"].as_u64().unwrap().to_string();

    let expire_api_key_json = headscale_with_config(
        &config,
        &["-o", "json", "apikeys", "expire", "--id", &api_json_id],
    );
    assert_eq!(
        json_output(&expire_api_key_json).as_object().unwrap().len(),
        0
    );
    assert_eq!(stderr(&expire_api_key_json), "");

    let delete_api_key_json = headscale_with_config(
        &config,
        &["-o", "json", "apikeys", "delete", "--id", &api_json_id],
    );
    assert_eq!(
        json_output(&delete_api_key_json).as_object().unwrap().len(),
        0
    );
    assert_eq!(stderr(&delete_api_key_json), "");

    let create_api_key_json_line = headscale_with_config(
        &config,
        &["-ojson-line", "apikeys", "create", "--expiration", "1h"],
    );
    let api_key_json_line: String =
        serde_json::from_slice(&create_api_key_json_line.stdout).unwrap();
    assert!(api_key_json_line.starts_with("hskey-api-"));
    assert!(!stdout(&create_api_key_json_line).contains('\t'));
    assert_eq!(stderr(&create_api_key_json_line), "");
    let api_json_line_prefix = display_prefix(&api_key_json_line, "hskey-api-");

    let list_api_keys_json_line =
        headscale_with_config(&config, &["-ojson-line", "apikeys", "list"]);
    let listed_api_keys_json_line: serde_json::Value =
        serde_json::from_slice(&list_api_keys_json_line.stdout).unwrap();
    let listed_api_key_json_line = &listed_api_keys_json_line[0];
    assert_eq!(
        listed_api_key_json_line["prefix"].as_str(),
        Some(api_json_line_prefix.as_str())
    );
    assert!(
        listed_api_key_json_line["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_api_key_json_line.get("createdAt").is_none());
    assert_eq!(stderr(&list_api_keys_json_line), "");

    let expire_api_key_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "apikeys",
            "expire",
            "--prefix",
            &api_json_line_prefix,
        ],
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&expire_api_key_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&expire_api_key_json_line), "");

    let delete_api_key_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "apikeys",
            "delete",
            "--prefix",
            &api_json_line_prefix,
        ],
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&delete_api_key_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&delete_api_key_json_line), "");

    let create_api_key_yaml = headscale_with_config(
        &config,
        &["-o", "yaml", "apikeys", "create", "--expiration", "1h"],
    );
    let api_key_yaml = yaml_output(&create_api_key_yaml)
        .as_str()
        .expect("API-key create YAML is the secret string")
        .to_string();
    assert!(api_key_yaml.starts_with("hskey-api-"));
    assert_eq!(stderr(&create_api_key_yaml), "");
    let api_yaml_prefix = display_prefix(&api_key_yaml, "hskey-api-");

    let list_api_keys_yaml = headscale_with_config(&config, &["-o", "yaml", "apikeys", "list"]);
    let listed_api_keys_yaml = yaml_output(&list_api_keys_yaml);
    let listed_api_key_yaml = &listed_api_keys_yaml[0];
    assert_eq!(
        listed_api_key_yaml["prefix"].as_str(),
        Some(api_yaml_prefix.as_str())
    );
    assert!(
        listed_api_key_yaml["created_at"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_api_key_yaml.get("createdAt").is_none());
    assert_eq!(stderr(&list_api_keys_yaml), "");

    let expire_api_key_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "apikeys",
            "expire",
            "--prefix",
            &api_yaml_prefix,
        ],
    );
    assert_eq!(
        yaml_output(&expire_api_key_yaml)
            .as_mapping()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&expire_api_key_yaml), "");

    let delete_api_key_yaml = headscale_with_config(
        &config,
        &[
            "-o",
            "yaml",
            "apikeys",
            "delete",
            "--prefix",
            &api_yaml_prefix,
        ],
    );
    assert_eq!(
        yaml_output(&delete_api_key_yaml)
            .as_mapping()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&delete_api_key_yaml), "");

    let auth_register_id = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let auth_id = format!("hskey-authreq-{auth_register_id}");
    let debug_create = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &auth_id,
            "--name",
            "auth-node",
        ],
    );
    assert!(
        debug_create.status.success(),
        "stderr: {}",
        stderr(&debug_create)
    );
    assert_eq!(stdout(&debug_create), "Node created\n");
    assert_eq!(stderr(&debug_create), "");
    let auth_register = headscale_with_config(
        &config,
        &["auth", "register", "--user", "alice", "--auth-id", &auth_id],
    );
    assert!(
        auth_register.status.success(),
        "stderr: {}",
        stderr(&auth_register)
    );
    assert_eq!(stdout(&auth_register), "Node auth-node registered\n");
    assert_eq!(stderr(&auth_register), "");

    let nodes_json = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
    let nodes_json_value = json_output(&nodes_json);
    let listed_node = &nodes_json_value[0];
    let node_id = listed_node["id"].as_u64().unwrap().to_string();
    assert_eq!(listed_node["user"]["name"].as_str(), Some("alice"));
    assert!(listed_node["created_at"]["seconds"].as_i64().is_some());
    assert!(listed_node["last_seen"]["seconds"].as_i64().is_some());
    assert!(listed_node.get("createdAt").is_none());
    assert!(listed_node.get("lastSeen").is_none());
    assert!(listed_node.get("machineKey").is_none());
    assert!(listed_node.get("preAuthKey").is_none());
    assert!(listed_node.get("ephemeral").is_none());
    assert!(listed_node.get("expired").is_none());

    let rename_node = headscale_with_config(
        &config,
        &["nodes", "rename", "renamed-node", "--identifier", &node_id],
    );
    assert!(
        rename_node.status.success(),
        "stderr: {}",
        stderr(&rename_node)
    );
    assert_eq!(
        stdout(&rename_node),
        include_str!("snapshots/nodes_rename_success.stdout")
    );
    assert_eq!(stderr(&rename_node), "");

    let policy_path = config_dir.path().join("tag-policy.hujson");
    fs::write(&policy_path, r#"{"tagOwners":{"tag:server":["alice@"]}}"#).unwrap();
    let policy_path_string = policy_path.to_string_lossy().to_string();
    let set_policy = headscale_with_config(
        &config,
        &["-o", "json", "policy", "set", "--file", &policy_path_string],
    );
    assert!(
        set_policy.status.success(),
        "stderr: {}",
        stderr(&set_policy)
    );
    assert_eq!(stdout(&set_policy), "Policy updated.\n");
    assert_eq!(stderr(&set_policy), "");

    let get_policy_json = headscale_with_config(&config, &["-o", "json", "policy", "get"]);
    assert!(
        get_policy_json.status.success(),
        "stderr: {}",
        stderr(&get_policy_json)
    );
    assert_eq!(
        stdout(&get_policy_json),
        "{\"tagOwners\":{\"tag:server\":[\"alice@\"]}}\n"
    );
    assert_eq!(stderr(&get_policy_json), "");

    let tag_node = headscale_with_config(
        &config,
        &[
            "nodes",
            "tag",
            "--identifier",
            &node_id,
            "--tags",
            "tag:server",
        ],
    );
    assert!(tag_node.status.success(), "stderr: {}", stderr(&tag_node));
    assert_eq!(
        stdout(&tag_node),
        include_str!("snapshots/nodes_tag_success.stdout")
    );
    assert_eq!(stderr(&tag_node), "");

    let schedule_expiry = headscale_with_config(
        &config,
        &[
            "nodes",
            "expire",
            "--identifier",
            &node_id,
            "--expiry",
            "2030-01-01T00:00:00Z",
        ],
    );
    assert!(
        schedule_expiry.status.success(),
        "stderr: {}",
        stderr(&schedule_expiry)
    );
    assert_eq!(
        stdout(&schedule_expiry),
        include_str!("snapshots/nodes_expire_scheduled_success.stdout")
    );
    assert_eq!(stderr(&schedule_expiry), "");

    let expire_node =
        headscale_with_config(&config, &["nodes", "expire", "--identifier", &node_id]);
    assert!(
        expire_node.status.success(),
        "stderr: {}",
        stderr(&expire_node)
    );
    assert_eq!(
        stdout(&expire_node),
        include_str!("snapshots/nodes_expire_success.stdout")
    );
    assert_eq!(stderr(&expire_node), "");

    let backfill_ips = headscale_with_config(&config, &["--force", "nodes", "backfillips"]);
    assert!(
        backfill_ips.status.success(),
        "stderr: {}",
        stderr(&backfill_ips)
    );
    assert_eq!(
        stdout(&backfill_ips),
        include_str!("snapshots/nodes_backfillips_success.stdout")
    );
    assert_eq!(stderr(&backfill_ips), "");

    let delete_node = headscale_with_config(
        &config,
        &["--force", "nodes", "delete", "--identifier", &node_id],
    );
    assert!(
        delete_node.status.success(),
        "stderr: {}",
        stderr(&delete_node)
    );
    assert_eq!(stdout(&delete_node), "Node deleted\n");
    assert_eq!(stderr(&delete_node), "");
    let empty_nodes = headscale_with_config(&config, &["nodes", "list"]);
    assert!(
        empty_nodes.status.success(),
        "stderr: {}",
        stderr(&empty_nodes)
    );
    assert_eq!(stdout(&empty_nodes), "No nodes registered.\n");
    assert_eq!(stderr(&empty_nodes), "");

    let nodes_register_id = "cccccccccccccccccccccccc";
    let nodes_register_auth_id = format!("hskey-authreq-{nodes_register_id}");
    let nodes_register_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &nodes_register_auth_id,
            "--name",
            "nodes-register-node",
        ],
    );
    assert!(
        nodes_register_pending.status.success(),
        "stderr: {}",
        stderr(&nodes_register_pending)
    );
    assert_eq!(stdout(&nodes_register_pending), "Node created\n");
    assert_eq!(stderr(&nodes_register_pending), "");

    let nodes_register = headscale_with_config(
        &config,
        &[
            "nodes",
            "register",
            "--user",
            "alice",
            "--key",
            &nodes_register_auth_id,
        ],
    );
    assert!(
        nodes_register.status.success(),
        "stderr: {}",
        stderr(&nodes_register)
    );
    assert_eq!(
        stdout(&nodes_register),
        "Node nodes-register-node registered\n"
    );
    assert_eq!(
        stderr(&nodes_register),
        "use 'headscale auth register --auth-id <id> --user <user>' instead\n"
    );

    let approve_id = "bbbbbbbbbbbbbbbbbbbbbbbb";
    let approve_auth_id = format!("hskey-authreq-{approve_id}");
    let approve_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &approve_auth_id,
            "--name",
            "approve-node",
        ],
    );
    assert!(
        approve_pending.status.success(),
        "stderr: {}",
        stderr(&approve_pending)
    );
    let approve =
        headscale_with_config(&config, &["auth", "approve", "--auth-id", &approve_auth_id]);
    assert!(approve.status.success(), "stderr: {}", stderr(&approve));
    assert_eq!(stdout(&approve), "Auth request approved\n");
    assert_eq!(stderr(&approve), "");

    let approve_json_id = "eeeeeeeeeeeeeeeeeeeeeeee";
    let approve_json_auth_id = format!("hskey-authreq-{approve_json_id}");
    let approve_json_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &approve_json_auth_id,
            "--name",
            "approve-json-node",
        ],
    );
    assert!(
        approve_json_pending.status.success(),
        "stderr: {}",
        stderr(&approve_json_pending)
    );
    let approve_json = headscale_with_config(
        &config,
        &[
            "-o",
            "json",
            "auth",
            "approve",
            "--auth-id",
            &approve_json_auth_id,
        ],
    );
    assert!(
        approve_json.status.success(),
        "stderr: {}",
        stderr(&approve_json)
    );
    assert_eq!(json_output(&approve_json).as_object().unwrap().len(), 0);
    assert_eq!(stderr(&approve_json), "");

    let reject_id = "cccccccccccccccccccccccc";
    let reject_auth_id = format!("hskey-authreq-{reject_id}");
    let reject_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &reject_auth_id,
            "--name",
            "reject-node",
        ],
    );
    assert!(
        reject_pending.status.success(),
        "stderr: {}",
        stderr(&reject_pending)
    );
    let reject = headscale_with_config(&config, &["auth", "reject", "--auth-id", &reject_auth_id]);
    assert!(reject.status.success(), "stderr: {}", stderr(&reject));
    assert_eq!(stdout(&reject), "Auth request rejected\n");
    assert_eq!(stderr(&reject), "");

    let reject_json_line_id = "ffffffffffffffffffffffff";
    let reject_json_line_auth_id = format!("hskey-authreq-{reject_json_line_id}");
    let reject_json_line_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &reject_json_line_auth_id,
            "--name",
            "reject-json-line-node",
        ],
    );
    assert!(
        reject_json_line_pending.status.success(),
        "stderr: {}",
        stderr(&reject_json_line_pending)
    );
    let reject_json_line = headscale_with_config(
        &config,
        &[
            "-ojson-line",
            "auth",
            "reject",
            "--auth-id",
            &reject_json_line_auth_id,
        ],
    );
    assert!(
        reject_json_line.status.success(),
        "stderr: {}",
        stderr(&reject_json_line)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&reject_json_line.stdout)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(stderr(&reject_json_line), "");

    let rename_user = headscale_with_config(
        &config,
        &[
            "users",
            "rename",
            "--identifier",
            "1",
            "--new-name",
            "alice-renamed",
        ],
    );
    assert!(
        rename_user.status.success(),
        "stderr: {}",
        stderr(&rename_user)
    );
    assert_eq!(stdout(&rename_user), "User renamed\n");
    assert_eq!(stderr(&rename_user), "");
    let destroy_user = headscale_with_config(
        &config,
        &["--force", "users", "destroy", "--identifier", "1"],
    );
    assert!(
        destroy_user.status.success(),
        "stderr: {}",
        stderr(&destroy_user)
    );
    assert_eq!(stdout(&destroy_user), "User destroyed\n");
    assert_eq!(stderr(&destroy_user), "");

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_local_grpc_node_list_and_route_outputs_match_snapshots() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service_with_persistent_machines().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
    assert!(
        create_user.status.success(),
        "stderr: {}",
        stderr(&create_user)
    );
    assert_eq!(stdout(&create_user), "User created\n");
    assert_eq!(stderr(&create_user), "");

    let registration_id = "dddddddddddddddddddddddd";
    let auth_id = format!("hskey-authreq-{registration_id}");
    let debug_create = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            &auth_id,
            "--name",
            "route-node",
            "--route",
            "10.10.0.0/24",
        ],
    );
    assert!(
        debug_create.status.success(),
        "stderr: {}",
        stderr(&debug_create)
    );
    assert_eq!(stdout(&debug_create), "Node created\n");
    assert_eq!(stderr(&debug_create), "");

    let auth_register = headscale_with_config(
        &config,
        &["auth", "register", "--user", "alice", "--auth-id", &auth_id],
    );
    assert!(
        auth_register.status.success(),
        "stderr: {}",
        stderr(&auth_register)
    );
    assert_eq!(stdout(&auth_register), "Node route-node registered\n");
    assert_eq!(stderr(&auth_register), "");

    let nodes_json = headscale_with_config(&config, &["-o", "json", "nodes", "list"]);
    let node_id = json_output(&nodes_json)[0]["id"].as_u64().unwrap();
    assert_eq!(node_id, 1);
    let node_id = node_id.to_string();

    let nodes_list = headscale_with_config(&config, &["nodes", "list"]);
    assert_normalized_node_stdout_snapshot(
        &nodes_list,
        include_str!("snapshots/nodes_list_success.stdout"),
        "nodes list",
    );

    let routes_available = headscale_with_config(&config, &["nodes", "list-routes"]);
    assert_normalized_node_stdout_snapshot(
        &routes_available,
        include_str!("snapshots/nodes_list_routes_available.stdout"),
        "nodes list-routes with advertised route",
    );

    let approve_routes = headscale_with_config(
        &config,
        &[
            "nodes",
            "approve-routes",
            "--identifier",
            &node_id,
            "--routes",
            "10.10.0.0/24",
        ],
    );
    assert_normalized_node_stdout_snapshot(
        &approve_routes,
        include_str!("snapshots/nodes_approve_routes_success.stdout"),
        "nodes approve-routes",
    );

    let routes_approved = headscale_with_config(&config, &["nodes", "list-routes"]);
    assert_normalized_node_stdout_snapshot(
        &routes_approved,
        include_str!("snapshots/nodes_list_routes_success.stdout"),
        "nodes list-routes with approved route",
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_local_grpc_cli_domain_errors_match_snapshots() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let create_user = headscale_with_config(&config, &["users", "create", "alice"]);
    assert!(
        create_user.status.success(),
        "stderr: {}",
        stderr(&create_user)
    );
    assert_eq!(stdout(&create_user), "User created\n");
    assert_eq!(stderr(&create_user), "");

    assert_config_stderr_snapshot(
        &config,
        &["users", "create", "alice"],
        6,
        include_str!("snapshots/grpc_live_duplicate_user.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["users", "destroy"],
        6,
        include_str!("snapshots/grpc_live_user_selector_required.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "json", "users", "rename", "--new-name", "bob"],
        6,
        include_str!("snapshots/grpc_live_user_selector_required_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "users",
            "rename",
            "--name",
            "alice",
            "--new-name",
            "alice-renamed-by-name",
        ],
        6,
        include_str!("snapshots/grpc_live_user_rename_name_server_error.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "users",
            "create",
            "badpic",
            "--picture-url",
            "https://example.com/%zz",
        ],
        6,
        include_str!("snapshots/grpc_live_user_bad_picture_url.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-ojson-line",
            "preauthkeys",
            "create",
            "--user",
            "404",
            "--expiration",
            "1h",
        ],
        6,
        include_str!("snapshots/grpc_live_preauth_missing_user_json_line.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-o",
            "yaml",
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--tags",
            "tag:Bad",
            "--expiration",
            "1h",
        ],
        6,
        include_str!("snapshots/grpc_live_bad_tag_yaml.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["apikeys", "create", "--expiration", "nope"],
        6,
        include_str!("snapshots/grpc_live_invalid_duration.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-o",
            "json",
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--expiration",
            "nope",
        ],
        6,
        include_str!("snapshots/grpc_live_invalid_duration_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "json", "apikeys", "expire", "--id", "999"],
        6,
        include_str!("snapshots/grpc_live_apikey_not_found_json.stderr"),
    );
    let missing_auth_id = "hskey-authreq-dddddddddddddddddddddddd";
    for (args, expected) in [
        (
            vec!["auth", "approve", "--auth-id", missing_auth_id],
            include_str!("snapshots/grpc_live_auth_missing.stderr"),
        ),
        (
            vec![
                "-o",
                "json",
                "auth",
                "approve",
                "--auth-id",
                missing_auth_id,
            ],
            include_str!("snapshots/grpc_live_auth_missing_json.stderr"),
        ),
        (
            vec![
                "-ojson-line",
                "auth",
                "approve",
                "--auth-id",
                missing_auth_id,
            ],
            include_str!("snapshots/grpc_live_auth_missing_json_line.stderr"),
        ),
    ] {
        assert_config_stderr_snapshot(&config, &args, 5, expected);
    }
    assert_config_stderr_snapshot(
        &config,
        &[
            "-o",
            "yaml",
            "auth",
            "approve",
            "--auth-id",
            missing_auth_id,
        ],
        5,
        &format!(
            "{}\n",
            include_str!("snapshots/grpc_live_auth_missing_yaml.stderr")
        ),
    );
    for (args, expected) in [
        (
            vec!["auth", "reject", "--auth-id", missing_auth_id],
            include_str!("snapshots/grpc_live_auth_reject_missing.stderr"),
        ),
        (
            vec!["-o", "json", "auth", "reject", "--auth-id", missing_auth_id],
            include_str!("snapshots/grpc_live_auth_reject_missing_json.stderr"),
        ),
        (
            vec![
                "-ojson-line",
                "auth",
                "reject",
                "--auth-id",
                missing_auth_id,
            ],
            include_str!("snapshots/grpc_live_auth_reject_missing_json_line.stderr"),
        ),
    ] {
        assert_config_stderr_snapshot(&config, &args, 5, expected);
    }
    assert_config_stderr_snapshot(
        &config,
        &["-o", "yaml", "auth", "reject", "--auth-id", missing_auth_id],
        5,
        &format!(
            "{}\n",
            include_str!("snapshots/grpc_live_auth_reject_missing_yaml.stderr")
        ),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-ojson-line", "nodes", "expire", "--identifier", "404"],
        5,
        include_str!("snapshots/grpc_live_node_not_found_json_line.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-o",
            "yaml",
            "nodes",
            "tag",
            "--identifier",
            "404",
            "--tags",
            "tag:Bad",
        ],
        6,
        include_str!("snapshots/grpc_live_bad_tag_yaml.stderr"),
    );

    let bad_policy_path = config_dir.path().join("bad-policy.hujson");
    fs::write(&bad_policy_path, r#"{"unknown":true}"#).unwrap();
    let bad_policy_path = bad_policy_path.to_string_lossy().to_string();
    assert_config_stderr_snapshot(
        &config,
        &["-o", "json", "policy", "set", "--file", &bad_policy_path],
        6,
        include_str!("snapshots/grpc_live_policy_set_invalid_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-ojson-line", "policy", "check", "--file", &bad_policy_path],
        6,
        include_str!("snapshots/grpc_live_policy_check_invalid_json_line.stderr"),
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_remote_grpc_config_success_server_and_auth_errors_match_process_output() {
    let (_dir, _db, address, api_key, handle) = spawn_process_remote_grpc_service(false).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_remote_grpc_config(config_dir.path(), &address, &api_key);

    let health = wait_for_headscale_status(&config, &["health"], 0).await;
    assert_eq!(stdout(&health), "\n");
    assert_eq!(stderr(&health), "");

    let create_user = headscale_with_config(&config, &["users", "create", "remote"]);
    assert!(
        create_user.status.success(),
        "stderr: {}",
        stderr(&create_user)
    );
    assert_eq!(stdout(&create_user), "User created\n");
    assert_eq!(stderr(&create_user), "");

    let list_users = headscale_with_config(&config, &["users", "list"]);
    assert!(
        list_users.status.success(),
        "stderr: {}",
        stderr(&list_users)
    );
    assert!(
        stdout(&list_users).contains("remote"),
        "stdout: {}",
        stdout(&list_users)
    );
    assert_eq!(stderr(&list_users), "");

    assert_config_stderr_snapshot(
        &config,
        &["users", "create", "remote"],
        6,
        include_str!("snapshots/grpc_remote_duplicate_user.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "json", "users", "create", "remote"],
        6,
        include_str!("snapshots/grpc_remote_duplicate_user_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-ojson-line", "users", "create", "remote"],
        6,
        include_str!("snapshots/grpc_remote_duplicate_user_json_line.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "yaml", "users", "create", "remote"],
        6,
        include_str!("snapshots/grpc_remote_duplicate_user_yaml.stderr"),
    );

    let missing_auth_id = "hskey-authreq-eeeeeeeeeeeeeeeeeeeeeeee";
    assert_config_stderr_snapshot(
        &config,
        &["auth", "approve", "--auth-id", missing_auth_id],
        5,
        include_str!("snapshots/grpc_remote_auth_missing.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-ojson-line",
            "auth",
            "approve",
            "--auth-id",
            missing_auth_id,
        ],
        5,
        include_str!("snapshots/grpc_remote_auth_missing_json_line.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["auth", "reject", "--auth-id", missing_auth_id],
        5,
        include_str!("snapshots/grpc_remote_auth_reject_missing.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "json", "auth", "reject", "--auth-id", missing_auth_id],
        5,
        include_str!("snapshots/grpc_remote_auth_reject_missing_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &[
            "-ojson-line",
            "auth",
            "reject",
            "--auth-id",
            missing_auth_id,
        ],
        5,
        include_str!("snapshots/grpc_remote_auth_reject_missing_json_line.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["-o", "yaml", "auth", "reject", "--auth-id", missing_auth_id],
        5,
        &format!(
            "{}\n",
            include_str!("snapshots/grpc_remote_auth_reject_missing_yaml.stderr")
        ),
    );

    let bad_config_dir = tempfile::tempdir().unwrap();
    let bad_config = write_remote_grpc_config(bad_config_dir.path(), &address, "bad-token");
    let bad_auth = wait_for_headscale_status(&bad_config, &["health"], 4).await;
    assert_eq!(stdout(&bad_auth), "");
    assert_eq!(
        stderr(&bad_auth),
        include_str!("snapshots/grpc_remote_auth_failure.stderr")
    );

    let bad_auth_json_line =
        wait_for_headscale_status(&bad_config, &["-ojson-line", "health"], 4).await;
    assert_eq!(stdout(&bad_auth_json_line), "");
    assert_eq!(
        stderr(&bad_auth_json_line),
        include_str!("snapshots/grpc_remote_auth_failure_json_line.stderr")
    );

    let bad_auth_json = wait_for_headscale_status(&bad_config, &["-o", "json", "health"], 4).await;
    assert_eq!(stdout(&bad_auth_json), "");
    assert_eq!(
        stderr(&bad_auth_json),
        include_str!("snapshots/grpc_remote_auth_failure_json.stderr")
    );

    let bad_auth_yaml = wait_for_headscale_status(&bad_config, &["-o", "yaml", "health"], 4).await;
    assert_eq!(stdout(&bad_auth_yaml), "");
    assert_eq!(
        stderr(&bad_auth_yaml),
        include_str!("snapshots/grpc_remote_auth_failure_yaml.stderr")
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_remote_grpc_health_failure_matches_process_stderr() {
    let (_dir, _db, address, api_key, handle) = spawn_process_remote_grpc_service(true).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_remote_grpc_config(config_dir.path(), &address, &api_key);

    let output = wait_for_headscale_status(&config, &["health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_remote_health_failure.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-o", "json", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_remote_health_failure_json.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-ojson-line", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_remote_health_failure_json_line.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-o", "yaml", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_live_health_failure_yaml.stderr")
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_local_grpc_health_failure_matches_process_stderr() {
    let (_dir, _db, socket, handle) = spawn_process_grpc_service(true).await;
    let config_dir = tempfile::tempdir().unwrap();
    let config = write_unix_socket_config(config_dir.path(), &socket);

    let output = wait_for_headscale_status(&config, &["health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_live_health_failure.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-o", "json", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_live_health_failure_json.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-ojson-line", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_live_health_failure_json_line.stderr")
    );

    let output = wait_for_headscale_status(&config, &["-o", "yaml", "health"], 6).await;
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/grpc_live_health_failure_yaml.stderr")
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn hidden_status_probe_uses_failure_exit_codes() {
    let healthy = MockServer::start_async().await;
    healthy
        .mock_async(|when, then| {
            when.method(GET).path("/health");
            then.status(200).body("ok");
        })
        .await;
    let output = headscale_clean(&["status", "--server", &healthy.base_url()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("Control plane at {} is healthy\n", healthy.base_url())
    );
    assert_eq!(stderr(&output), "");

    let unhealthy = MockServer::start_async().await;
    unhealthy
        .mock_async(|when, then| {
            when.method(GET).path("/health");
            then.status(500).body("offline");
        })
        .await;
    let output = headscale_clean(&["status", "--server", &unhealthy.base_url()]);
    assert_status_command_failed(&output);
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/status_http_failure.stderr")
    );

    let output = headscale_clean(&["status"]);
    assert_status_command_failed(&output);
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/status_missing_server.stderr")
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let refused_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let output = headscale_clean(&["status", "--server", &refused_url]);
    assert_status_command_failed(&output);
    assert_eq!(stdout(&output), "");
    assert_eq!(
        normalize_localhost_port(&stderr(&output)),
        include_str!("snapshots/status_connection_refused.stderr")
    );
}

#[test]
fn configtest_without_config_fails_server_validation() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert_configtest_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_missing_server_url.stderr"),
        "configtest missing server_url",
    );
}

#[test]
fn explicit_missing_config_still_fails_as_file_load_error() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let missing = cwd.path().join("missing.yaml");
    let output = headscale_in(
        &["--config", missing.to_str().unwrap(), "configtest"],
        cwd.path(),
        home.path(),
    );

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/explicit_missing_config.stderr"),
        "explicit missing config",
    );
}
