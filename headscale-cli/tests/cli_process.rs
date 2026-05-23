use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn headscale(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_headscale"))
        .args(args)
        .output()
        .expect("run headscale binary")
}

fn headscale_clean(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_headscale"));
    command.args(args);
    for key in [
        "HEADSCALE_CONFIG",
        "HEADSCALE_LOG",
        "HEADSCALE_URL",
        "HEADSCALE_ADMIN_TOKEN",
        "HEADSCALE_CLI_ADDRESS",
        "HEADSCALE_CLI_API_KEY",
        "HEADSCALE_UNIX_SOCKET",
        "HEADSCALE_CLI_INSECURE",
    ] {
        command.env_remove(key);
    }
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

#[test]
fn top_level_help_exposes_upstream_operator_commands() {
    let output = headscale(&["--help"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    for command in [
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
    assert!(stdout(&serve).contains("Run the control plane server"));

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
fn implemented_admin_command_help_matches_snapshots() {
    assert_stdout_snapshot(
        &["users", "list", "--help"],
        include_str!("snapshots/users_list_help.stdout"),
    );
    assert_stdout_snapshot(
        &["nodes", "approve-routes", "--help"],
        include_str!("snapshots/nodes_approve_routes_help.stdout"),
    );
    assert_stdout_snapshot(
        &["preauthkeys", "create", "--help"],
        include_str!("snapshots/preauthkeys_create_help.stdout"),
    );
    assert_stdout_snapshot(
        &["apikeys", "delete", "--help"],
        include_str!("snapshots/apikeys_delete_help.stdout"),
    );
    assert_stdout_snapshot(
        &["policy", "check", "--help"],
        include_str!("snapshots/policy_check_help.stdout"),
    );
    assert_stdout_snapshot(
        &["auth", "approve", "--help"],
        include_str!("snapshots/auth_approve_help.stdout"),
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
fn implemented_admin_clap_error_matches_snapshot() {
    let output = headscale_clean(&["users", "list", "--output", "xml"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        include_str!("snapshots/invalid_output_format.stderr")
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
