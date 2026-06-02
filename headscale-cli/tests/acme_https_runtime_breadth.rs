use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

const CLEAN_ENV: &[&str] = &[
    "HEADSCALE_CONFIG",
    "HEADSCALE_LOG",
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
    "HEADSCALE_ACME_URL",
    "HEADSCALE_ACME_EMAIL",
    "HEADSCALE_TLS_LETSENCRYPT_HOSTNAME",
    "HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR",
    "HEADSCALE_TLS_LETSENCRYPT_LISTEN",
    "HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE",
    "HEADSCALE_TLS_CERT_PATH",
    "HEADSCALE_TLS_KEY_PATH",
    "HEADSCALE_SERVER_URL",
    "HEADSCALE_LISTEN_ADDR",
    "HEADSCALE_METRICS_LISTEN_ADDR",
    "HEADSCALE_GRPC_LISTEN_ADDR",
    "HEADSCALE_GRPC_ALLOW_INSECURE",
    "HEADSCALE_UNIX_SOCKET",
    "HEADSCALE_UNIX_SOCKET_PERMISSION",
    "HEADSCALE_DATABASE_TYPE",
    "HEADSCALE_DATABASE_SQLITE_PATH",
    "HEADSCALE_POLICY_MODE",
    "HEADSCALE_POLICY_PATH",
];

fn headscale_clean_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_headscale"));
    for key in CLEAN_ENV {
        command.env_remove(key);
    }
    command
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

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout utf8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf8")
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

fn yaml_double_quoted(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[test]
fn serve_tls_alpn_public_acme_derp_runtime_stops_before_public_ca_on_metrics_bind_collision() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let metrics_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let metrics_addr = metrics_listener.local_addr().unwrap();

    let db_path = cwd.path().join("db.sqlite");
    let noise_path = cwd.path().join("noise_private.key");
    let state_dir = cwd.path().join("state");
    let unix_socket = cwd.path().join("headscale.sock");
    let cache_dir = cwd.path().join("acme-cache");
    let derp_key_path = cwd.path().join("derp_server_private.key");
    let derp_map_path = cwd.path().join("derp.yaml");

    fs::write(
        &derp_map_path,
        r#"
regions:
  901:
    regionid: 901
    regioncode: public-test
    regionname: Public Test DERP
    nodes:
      - name: 901a
        regionid: 901
        hostname: derp901.example.com
        derpport: 443
        stunport: 3478
        ipv4: "198.51.100.2"
        ipv6: "2001:db8::2"
"#,
    )
    .unwrap();

    fs::write(
        cwd.path().join("config.yaml"),
        format!(
            r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:443"
metrics_listen_addr: "{metrics_addr}"
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
  state_dir: {}
  unix_socket: {}
  grpc_listen_addr: "127.0.0.1:0"
derp:
  server:
    enabled: false
    region_id: 901
    region_code: "headscale-test"
    region_name: "Headscale Test DERP"
    verify_clients: true
    stun_listen_addr: "127.0.0.1:0"
    private_key_path: {}
    automatically_add_embedded_derp_region: false
    ipv4: "198.51.100.1"
    ipv6: "2001:db8::1"
  urls: []
  paths:
    - {}
  auto_update_enabled: true
  update_frequency: 3600
acme_url: "https://acme-v02.api.letsencrypt.org/directory"
acme_email: "ops@example.com"
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: {}
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#,
            yaml_double_quoted(&noise_path.to_string_lossy()),
            yaml_double_quoted(&db_path.to_string_lossy()),
            yaml_double_quoted(&state_dir.to_string_lossy()),
            yaml_double_quoted(&unix_socket.to_string_lossy()),
            yaml_double_quoted(&derp_key_path.to_string_lossy()),
            yaml_double_quoted(&derp_map_path.to_string_lossy()),
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
        "unexpected status for serve TLS-ALPN ACME runtime collision; stdout: {}; stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");

    let normalized_stderr = normalize_os_error_number(&stderr(&output));
    assert!(
        normalized_stderr.contains(&format!(
            "Error: start Tailscale wire listeners: internal: bind {metrics_addr}: Address already in use (os error <errno>)"
        )),
        "stderr: {normalized_stderr}"
    );
    assert!(
        !cache_dir.join("headscale.example").exists(),
        "ACME certificate cache should not be written before metrics bind failure"
    );
}
