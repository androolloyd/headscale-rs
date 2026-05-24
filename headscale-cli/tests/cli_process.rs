use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Output};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

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
    "HEADSCALE_UNIX_SOCKET",
    "HEADSCALE_CLI_INSECURE",
];

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
    Command::new(env!("CARGO_BIN_EXE_headscale"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("HEADSCALE_CONFIG")
        .output()
        .expect("run headscale binary")
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

fn assert_normalized_node_stdout_snapshot(output: &Output, expected: &str, label: &str) {
    assert!(output.status.success(), "stderr: {}", stderr(output));
    assert_eq!(
        trim_line_end_spaces(&normalize_generated_node_stdout(&stdout(output))),
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

async fn spawn_process_remote_grpc_service() -> (
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
    )
    .with_database_pool(db.pool().clone())
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
    assert_stdout_snapshot(&["help"], include_str!("snapshots/top_level_help.stdout"));
}

#[test]
fn exact_help_aliases_match_current_upstream_snapshots() {
    assert_stdout_snapshot(
        &["version", "-h"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_snapshot(
        &["help", "version"],
        include_str!("snapshots/version_help.stdout"),
    );
    assert_stdout_snapshot(&["auth", "-h"], include_str!("snapshots/auth_help.stdout"));
    assert_stdout_snapshot(
        &["help", "auth", "register"],
        include_str!("snapshots/auth_register_help.stdout"),
    );
    assert_stdout_snapshot(
        &["users", "-h"],
        include_str!("snapshots/users_help.stdout"),
    );
    assert_stdout_snapshot(
        &["help", "users", "create"],
        include_str!("snapshots/users_create_help.stdout"),
    );
    assert_stdout_snapshot(&["node", "-h"], include_str!("snapshots/nodes_help.stdout"));
    assert_stdout_snapshot(
        &["help", "nodes", "routes"],
        include_str!("snapshots/nodes_list_routes_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "logout", "-h"],
        include_str!("snapshots/nodes_expire_help.stdout"),
    );
    assert_stdout_snapshot(
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
    assert_stdout_snapshot(
        &["help", "pre", "rm"],
        include_str!("snapshots/preauthkeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["api", "revoke", "-h"],
        include_str!("snapshots/apikeys_expire_help.stdout"),
    );
    assert_stdout_snapshot(
        &["help", "apikey", "remove"],
        include_str!("snapshots/apikeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "--help"],
        include_str!("snapshots/policy_help.stdout"),
    );
    assert_stdout_snapshot(
        &["help", "policy", "fetch"],
        include_str!("snapshots/policy_get_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "update", "-h"],
        include_str!("snapshots/policy_set_help.stdout"),
    );
    assert_stdout_snapshot(
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
fn serve_alias_and_debug_create_node_help_are_accepted() {
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
    assert!(stdout(&help).contains("mock OIDC server"));

    let missing_env = headscale_in(&["mockoidc"], cwd.path(), home.path());
    assert!(!missing_env.status.success());
    let err = stderr(&missing_env);
    assert!(
        err.contains("MOCKOIDC_CLIENT_ID not defined"),
        "stderr: {err}"
    );
    assert!(!err.contains("Failed to load config"), "stderr: {err}");
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
fn version_json_line_is_machine_readable() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), ":\n:not-yaml\n").unwrap();
    let output = headscale_in(&["version", "-o", "json-line"], cwd.path(), home.path());

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("version json-line");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["rust"]["os"].is_string());
    assert!(value["rust"]["arch"].is_string());
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
}

#[test]
fn configtest_rejects_unsupported_acme_runtime() {
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
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#,
    )
    .unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_unsupported_acme.stderr"),
        "configtest unsupported ACME",
    );
}

#[test]
fn configtest_rejects_unsupported_postgres_runtime() {
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

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/configtest_unsupported_postgres.stderr"),
        "configtest unsupported postgres",
    );
}

fn assert_configtest_default_config_snapshot(config: &str, expected: &str, label: &str) {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(cwd.path().join("config.yaml"), config).unwrap();

    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert_process_stderr_snapshot(&output, 1, expected, label);
}

#[test]
fn configtest_rejects_supported_server_init_validation_errors() {
    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
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
metrics_listen_addr: "not-a-socket"
"#,
        include_str!("snapshots/configtest_invalid_metrics_listen.stderr"),
        "configtest invalid metrics listener",
    );

    assert_configtest_default_config_snapshot(
        r#"
server_url: "https://headscale.example"
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
policy:
  mode: consul
"#,
        include_str!("snapshots/configtest_invalid_policy_mode.stderr"),
        "configtest invalid policy mode",
    );
}

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
    assert!(
        !db_path.exists(),
        "unsupported postgres serve path should fail before opening SQLite at {}",
        db_path.display()
    );
}

#[test]
fn serve_rejects_unsupported_acme_before_state_startup() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let db_path = cwd.path().join("should-not-exist.sqlite");
    let cache_dir = "/var/lib/headscale/acme-cache";
    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:0"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: "{}"
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: "{}"
tls_letsencrypt_listen: ":http"
tls_letsencrypt_challenge_type: "HTTP-01"
"#,
            db_path.display(),
            cache_dir
        ),
    )
    .unwrap();

    let output = headscale_in(&["serve"], cwd.path(), home.path());

    assert_process_stderr_snapshot(
        &output,
        1,
        include_str!("snapshots/serve_unsupported_acme.stderr"),
        "serve unsupported ACME",
    );
    assert!(
        !db_path.exists(),
        "unsupported ACME serve path should fail before opening SQLite at {}",
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
    assert_stdout_snapshot(
        &["nodes", "register", "--help"],
        include_str!("snapshots/nodes_register_help.stdout"),
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
        &["tailnet", "status", "--help"],
        include_str!("snapshots/tailnet_status_help.stdout"),
    );
    assert_stdout_snapshot(
        &["debug", "create-node", "--help"],
        include_str!("snapshots/debug_create_node_help.stdout"),
    );
}

#[test]
fn operator_top_level_command_help_matches_snapshots() {
    assert_stdout_snapshot(
        &["serve", "--help"],
        include_str!("snapshots/serve_help.stdout"),
    );
    assert_stdout_snapshot(
        &["health", "--help"],
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
        &["dumpConfig", "--help"],
        include_str!("snapshots/dump_config_help.stdout"),
    );
    assert_stdout_snapshot(
        &["generate", "--help"],
        include_str!("snapshots/generate_help.stdout"),
    );
    assert_stdout_snapshot(
        &["generate", "private-key", "--help"],
        include_str!("snapshots/generate_private_key_help.stdout"),
    );
    assert_stdout_snapshot(
        &["mockoidc", "--help"],
        include_str!("snapshots/mockoidc_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "--help"],
        include_str!("snapshots/completion_help.stdout"),
    );
    assert_stdout_snapshot(
        &["debug", "--help"],
        include_str!("snapshots/debug_help.stdout"),
    );
    assert_stdout_snapshot(
        &["completion", "zsh", "--help"],
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
    let set_json: serde_json::Value = serde_json::from_slice(&set.stdout).unwrap();
    assert_eq!(set_json["applied"], true);
    assert_eq!(set_json["policy"], "{\n  // preserved\n  \"acls\": []\n}\n");

    let set_text = headscale_clean(&[
        "--config", config, "--force", "policy", "set", "--file", policy, bypass,
    ]);
    assert!(set_text.status.success(), "stderr: {}", stderr(&set_text));
    assert_eq!(stdout(&set_text), "Policy applied: true\n");
    assert_eq!(stderr(&set_text), "");

    let get = headscale_clean(&[
        "--config", config, "--force", "-o", "json", "policy", "get", bypass,
    ]);
    assert!(get.status.success(), "stderr: {}", stderr(&get));
    let get_json: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(get_json["policy"], "{\n  // preserved\n  \"acls\": []\n}\n");

    let get_text = headscale_clean(&["--config", config, "--force", "policy", "get", bypass]);
    assert!(get_text.status.success(), "stderr: {}", stderr(&get_text));
    assert_eq!(stdout(&get_text), "{\n  // preserved\n  \"acls\": []\n}\n");
    assert_eq!(stderr(&get_text), "");

    let check = headscale_clean(&[
        "--config", config, "--force", "policy", "check", "--file", policy, bypass,
    ]);
    assert!(check.status.success(), "stderr: {}", stderr(&check));
    assert_eq!(
        stdout(&check),
        format!("Policy at {} validates OK.\n", policy_path.display())
    );
    assert_eq!(stderr(&check), "");
}

#[test]
fn implemented_admin_clap_error_matches_snapshot() {
    let output = headscale_clean(&["users", "list", "--output", "xml"]);

    assert_eq!(output.status.code(), Some(6));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/invalid_output_format.stderr")
    );
}

#[test]
fn implemented_admin_local_errors_match_snapshots() {
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
}

#[test]
fn implemented_admin_errors_follow_output_format() {
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
        "{\n\t\"error\": \"--api-key is required for remote gRPC\"\n}\n"
    );
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
            "create",
            "--user",
            "1",
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
    let list_preauth_stdout = stdout(&list_preauth);
    assert!(list_preauth_stdout.contains("ID  Key/Prefix"));
    assert!(list_preauth_stdout.contains("Reusable"));
    assert!(list_preauth_stdout.contains("Ephemeral"));
    assert!(list_preauth_stdout.contains("Used"));
    assert!(list_preauth_stdout.contains("Expiration"));
    assert!(list_preauth_stdout.contains("Created"));
    assert!(list_preauth_stdout.contains("Owner"));
    assert!(list_preauth_stdout.contains(&preauth_key));
    assert!(list_preauth_stdout.contains("alice"));
    assert!(list_preauth_stdout.contains("true"));
    assert_eq!(stderr(&list_preauth), "");

    let preauth_json = headscale_with_config(&config, &["-o", "json", "preauthkeys", "list"]);
    let preauth_json = json_output(&preauth_json);
    let listed_preauth = &preauth_json[0];
    assert_eq!(listed_preauth["key"].as_str(), Some(preauth_key.as_str()));
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
    assert!(stdout(&empty_preauth).starts_with("ID  Key/Prefix"));
    assert!(!stdout(&empty_preauth).contains("No preauth keys."));
    assert_eq!(stderr(&empty_preauth), "");

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
    assert_eq!(
        listed_preauth_json_line["key"].as_str(),
        created_preauth_json_line["key"].as_str()
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
    assert_eq!(
        listed_preauth_yaml["key"].as_str(),
        created_preauth_yaml["key"].as_str()
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
    let list_api_stdout = stdout(&list_api_keys);
    assert!(list_api_stdout.contains("ID  Prefix"));
    assert!(list_api_stdout.contains("Expiration"));
    assert!(list_api_stdout.contains("Created"));
    assert!(!list_api_stdout.contains("LAST_SEEN"));
    assert!(list_api_stdout.contains(&api_prefix));
    assert_eq!(stderr(&list_api_keys), "");

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
    assert!(stdout(&empty_api_keys).starts_with("ID  Prefix"));
    assert!(!stdout(&empty_api_keys).contains("No API keys."));
    assert_eq!(stderr(&empty_api_keys), "");

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
    assert!(listed_api_key["createdAt"]["seconds"].as_i64().is_some());
    assert!(listed_api_key.get("created_at").is_none());
    assert!(listed_api_key.get("last_seen").is_none());
    assert!(listed_api_key.get("lastSeen").is_none());
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
        listed_api_key_json_line["createdAt"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_api_key_json_line.get("created_at").is_none());
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
        listed_api_key_yaml["createdAt"]["seconds"]
            .as_i64()
            .is_some()
    );
    assert!(listed_api_key_yaml.get("created_at").is_none());
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
    let debug_create = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            auth_register_id,
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
    let auth_id = format!("hskey-authreq-{auth_register_id}");
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
    let node_id = json_output(&nodes_json)[0]["id"]
        .as_u64()
        .unwrap()
        .to_string();

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
    let set_policy =
        headscale_with_config(&config, &["policy", "set", "--file", &policy_path_string]);
    assert!(
        set_policy.status.success(),
        "stderr: {}",
        stderr(&set_policy)
    );
    assert_eq!(stdout(&set_policy), "Policy applied: true\n");
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

    let approve_id = "bbbbbbbbbbbbbbbbbbbbbbbb";
    let approve_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            approve_id,
            "--name",
            "approve-node",
        ],
    );
    assert!(
        approve_pending.status.success(),
        "stderr: {}",
        stderr(&approve_pending)
    );
    let approve = headscale_with_config(&config, &["auth", "approve", "--auth-id", approve_id]);
    assert!(approve.status.success(), "stderr: {}", stderr(&approve));
    assert_eq!(stdout(&approve), "Auth request approved\n");
    assert_eq!(stderr(&approve), "");

    let reject_id = "cccccccccccccccccccccccc";
    let reject_pending = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            reject_id,
            "--name",
            "reject-node",
        ],
    );
    assert!(
        reject_pending.status.success(),
        "stderr: {}",
        stderr(&reject_pending)
    );
    let reject_auth_id = format!("hskey-authreq-{reject_id}");
    let reject = headscale_with_config(&config, &["auth", "reject", "--auth-id", &reject_auth_id]);
    assert!(reject.status.success(), "stderr: {}", stderr(&reject));
    assert_eq!(stdout(&reject), "Auth request rejected\n");
    assert_eq!(stderr(&reject), "");

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
    let debug_create = headscale_with_config(
        &config,
        &[
            "debug",
            "create-node",
            "--user",
            "alice",
            "--key",
            registration_id,
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

    let auth_id = format!("hskey-authreq-{registration_id}");
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
        &[
            "-ojson-line",
            "preauthkeys",
            "create",
            "--user",
            "404",
            "--expiration",
            "1h",
        ],
        5,
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
        &["-o", "json", "apikeys", "expire", "--id", "999"],
        5,
        include_str!("snapshots/grpc_live_apikey_not_found_json.stderr"),
    );
    assert_config_stderr_snapshot(
        &config,
        &["auth", "approve", "--auth-id", "dddddddddddddddddddddddd"],
        5,
        include_str!("snapshots/grpc_live_auth_missing.stderr"),
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
async fn live_remote_grpc_config_success_and_auth_errors_match_process_output() {
    let (_dir, _db, address, api_key, handle) = spawn_process_remote_grpc_service().await;
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
    let err = stderr(&output);
    assert!(
        err.contains("Error: failed to connect to control plane"),
        "stderr: {err}"
    );
    assert!(
        err.contains(&format!("{refused_url}/health")),
        "stderr: {err}"
    );
}

#[test]
fn configtest_without_config_fails_server_validation() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = headscale_in(&["configtest"], cwd.path(), home.path());

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("server.server_url is required"),
        "stderr: {}",
        stderr(&output)
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

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Failed to load config file"),
        "stderr: {}",
        stderr(&output)
    );
}
