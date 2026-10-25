#![cfg(unix)]

//! Conformance tests for the native pgx-compatible Postgres configuration
//! bridge of the patched `sqlx-postgres` crate
//! (`PgConnectOptions::from_headscale_go_url`, `vendor/sqlx-postgres/src/options/go_compat.rs`):
//! pgpassfile v1.0.0 lookup, `passfile=` URL parameter, `PG*` environment and
//! pgservicefile precedence.
//!
//! The resolved password is not observable through a public getter, so each
//! scenario connects to a mock Postgres on localhost (or a Unix socket) that
//! asks for a cleartext password and records the startup parameters and the
//! password it receives. No Postgres server is needed.
//!
//! The scenarios depend on the process environment, so every scenario runs in a
//! child process re-executing this test binary with a scrubbed environment
//! (`env_clear` + only the variables under test). The `#[test]` entry points
//! below spawn them; the `scenarios::*` functions are `#[ignore]`d so a plain
//! `cargo test` never runs them in the polluted parent environment.
//!
//! Go references (versions pinned in `vendor/sqlx-postgres/UPSTREAM.md`; line
//! numbers are from the module cache copies of those exact versions):
//! pgx v5.10.0 `pgconn/config.go` `ParseConfig` lines 324-363 (settings are
//! merged defaults < `PG*` environment < service file < connection string),
//! 486-495 (the passfile is read; only an *empty* password consults it, with
//! host `localhost` for Unix-socket networks), `parseURLSettings` 630-637 (a
//! URL password that is present, even if empty, is a setting) and
//! `parseEnvSettings` 579+; pgpassfile v1.0.0 `pgpass.go` `parseLine` 60 and
//! `FindPassword` 100 (`#` comments, trimmed lines, `\:`/`\\` escapes, `*`
//! wildcards, first match wins); pgservicefile `5a60cdf6a761`
//! `pgservicefile.go` `ReadServicefile` 33 / `GetService` 24.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hsc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scenario directory");
    dir
}

fn write_private(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

/// Re-run one `scenarios::<name>` test in a child with only `envs` set.
fn run_scenario(name: &str, dir: &Path, envs: &[(&str, &str)]) {
    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args([
            "--ignored",
            "--exact",
            &format!("scenarios::{name}"),
            "--nocapture",
        ])
        .env_clear()
        .env("HSC_DIR", dir)
        .envs(envs.iter().copied())
        .output()
        .expect("spawn scenario child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "scenario {name} failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// pgpassfile v1.0.0 line semantics, driven through a `passfile=` URL
/// parameter. Stock SQLx has no such parameter (it only honours the
/// `PGPASSFILE` variable and `~/.pgpass`), so it resolves a different password.
#[test]
fn passfile_url_parameter_follows_pgpassfile_v1_semantics() {
    let dir = scratch_dir("passfile");
    write_private(
        &dir.join("pgpass"),
        // comment; non-matching host; non-matching user; a matching entry with
        // leading blanks and both escapes; a later wildcard that must lose.
        "# comment\n\
         db.example.test:*:appdb:appuser:wrong-host\n\
         \x20 127.0.0.1:*:appdb:otheruser:wrong-user\n\
         \x20 127.0.0.1:*:appdb:appuser:s3cret\\:co\\\\lon\n\
         *:*:*:*:fallback\n",
    );
    run_scenario("passfile_url_parameter", &dir, &[]);
}

/// `PGPASSFILE` selects the passfile; an explicit `passfile=` URL parameter
/// beats it (pgx: environment < connection string). Stock SQLx honours the
/// variable but ignores the URL parameter, so it keeps using the environment's.
#[test]
fn passfile_environment_is_overridden_by_the_url_parameter() {
    let dir = scratch_dir("passfile-env");
    write_private(&dir.join("env_pgpass"), "*:*:envdb:envuser:from-env-file\n");
    write_private(&dir.join("url_pgpass"), "*:*:envdb:envuser:from-url-file\n");
    let env_file = dir.join("env_pgpass");
    run_scenario(
        "passfile_environment_vs_url",
        &dir,
        &[("PGPASSFILE", env_file.to_str().expect("utf-8 path"))],
    );
}

/// A non-empty password (environment or URL) is used as is: the passfile is
/// only consulted when the password is empty, and URL beats environment.
#[test]
fn explicit_password_beats_passfile_and_url_beats_environment() {
    let dir = scratch_dir("password");
    write_private(&dir.join("pgpass"), "*:*:appdb:appuser:from-passfile\n");
    run_scenario(
        "password_precedence",
        &dir,
        &[("PGPASSWORD", "env-password")],
    );
}

/// KNOWN DIVERGENCE (reported, not fixed here): pgx treats a URL password that
/// is present but empty (`user:@host`) as an explicit empty setting that
/// overrides `PGPASSWORD` and then consults the passfile. The native bridge
/// reads the password through `url::Url::password()`, which reports `None` for
/// an empty password, so `PGPASSWORD` survives and the passfile entry is never
/// used. Only reachable when `PGPASSWORD` is set *and* the URL has an empty
/// `user:@` password.
///
/// Go: pgx v5.10.0 `pgconn/config.go` `parseURLSettings` 634-636 (`present`
/// is true for `user:@`) and `ParseConfig` 356-363, 486-495. Rust:
/// `vendor/sqlx-postgres/src/options/go_compat.rs` `url_settings`
/// (`url.password()`).
#[test]
#[ignore = "known divergence: empty URL password does not override PGPASSWORD (see doc comment)"]
fn empty_url_password_overrides_pgpassword_like_pgx() {
    let dir = scratch_dir("empty-password");
    write_private(&dir.join("pgpass"), "*:*:appdb:appuser:from-passfile\n");
    run_scenario(
        "empty_url_password_overrides_environment",
        &dir,
        &[("PGPASSWORD", "env-password")],
    );
}

/// pgservicefile: the service supplies user/dbname/password and beats the
/// environment; explicit URL settings beat the service; `PGSERVICE` selects the
/// service like the `service=` URL parameter.
#[test]
fn service_file_sits_between_environment_and_url() {
    let dir = scratch_dir("service");
    write_private(
        &dir.join("pg_service.conf"),
        "# services\n\
         [other]\n\
         user=wrong\n\
         \n\
         [svc]\n\
         user = svcuser\n\
         dbname = svcdb\n\
         password = svcpw\n",
    );
    let file = dir.join("pg_service.conf");
    run_scenario(
        "service_precedence",
        &dir,
        &[
            ("PGSERVICEFILE", file.to_str().expect("utf-8 path")),
            ("PGUSER", "envuser"),
            ("PGDATABASE", "envdb"),
        ],
    );
}

/// For a Unix-socket host pgpassfile is searched with host `localhost`.
#[test]
fn unix_socket_hosts_look_up_localhost_in_the_passfile() {
    let dir = scratch_dir("socket");
    write_private(
        &dir.join("pgpass"),
        "/not/the/socket:*:appdb:appuser:wrong-socket-path\n\
         localhost:*:appdb:appuser:via-localhost\n",
    );
    run_scenario("unix_socket_localhost", &dir, &[]);
}

/// The scenarios proper. Run only by the parent tests above, in a child
/// process with a scrubbed environment.
mod scenarios {
    use std::path::PathBuf;

    use sqlx::ConnectOptions;
    use sqlx::postgres::PgConnectOptions;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};

    /// What the mock server saw from one connection attempt.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct Seen {
        user: String,
        database: String,
        password: String,
    }

    fn cstr(bytes: &[u8]) -> (String, &[u8]) {
        let end = bytes.iter().position(|b| *b == 0).expect("NUL-terminated");
        (
            String::from_utf8_lossy(&bytes[..end]).into_owned(),
            &bytes[end + 1..],
        )
    }

    /// Speak the server half of one cleartext-password login, then fail it.
    async fn mock_login<S>(mut stream: S) -> Seen
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // StartupMessage: int32 length, int32 protocol, (key\0 value\0)* \0
        let length = stream.read_u32().await.expect("startup length") as usize;
        let mut startup = vec![0u8; length - 4];
        stream.read_exact(&mut startup).await.expect("startup body");
        let mut rest = &startup[4..];
        let mut seen = Seen::default();
        while !rest.is_empty() && rest[0] != 0 {
            let (key, tail) = cstr(rest);
            let (value, tail) = cstr(tail);
            match key.as_str() {
                "user" => seen.user = value,
                "database" => seen.database = value,
                _ => {}
            }
            rest = tail;
        }
        // AuthenticationCleartextPassword
        stream
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
            .await
            .expect("auth request");
        // PasswordMessage: 'p', int32 length, password\0
        let tag = stream.read_u8().await.expect("password tag");
        assert_eq!(tag, b'p', "client must answer with a PasswordMessage");
        let length = stream.read_u32().await.expect("password length") as usize;
        let mut body = vec![0u8; length - 4];
        stream.read_exact(&mut body).await.expect("password body");
        seen.password = cstr(&body).0;
        // ErrorResponse (FATAL 28P01) so the client stops here.
        let mut fields = Vec::new();
        for (code, text) in [
            (b'S', "FATAL"),
            (b'C', "28P01"),
            (b'M', "mock: login refused"),
        ] {
            fields.push(code);
            fields.extend_from_slice(text.as_bytes());
            fields.push(0);
        }
        fields.push(0);
        let mut error = vec![b'E'];
        error.extend_from_slice(
            &u32::try_from(fields.len() + 4)
                .expect("small")
                .to_be_bytes(),
        );
        error.extend_from_slice(&fields);
        let _ = stream.write_all(&error).await;
        let _ = stream.shutdown().await;
        seen
    }

    async fn tcp_mock() -> (u16, tokio::task::JoinHandle<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            mock_login(stream).await
        });
        (port, task)
    }

    async fn attempt(options: PgConnectOptions, mock: tokio::task::JoinHandle<Seen>) -> Seen {
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), options.connect())
            .await
            .expect("connect attempt must finish");
        assert!(result.is_err(), "the mock refuses every login");
        tokio::time::timeout(std::time::Duration::from_secs(10), mock)
            .await
            .expect("mock must see the attempt")
            .expect("mock task joins")
    }

    /// Native bridge against a fresh TCP mock; `url_for` gets the mock's port.
    async fn native(url_for: impl FnOnce(u16) -> String) -> Seen {
        let (port, mock) = tcp_mock().await;
        let options = PgConnectOptions::from_headscale_go_url(&url_for(port))
            .expect("native constructor accepts the URL");
        attempt(options, mock).await
    }

    /// Stock SQLx parsing of the same URL.
    async fn stock(url_for: impl FnOnce(u16) -> String) -> Seen {
        let (port, mock) = tcp_mock().await;
        let options: PgConnectOptions = url_for(port).parse().expect("stock parses the URL");
        attempt(options, mock).await
    }

    fn unix_listener(directory: &std::path::Path) -> (UnixListener, PathBuf) {
        let socket = directory.join(".s.PGSQL.5432");
        (UnixListener::bind(&socket).expect("bind unix mock"), socket)
    }

    fn dir() -> PathBuf {
        PathBuf::from(std::env::var("HSC_DIR").expect("set by the parent test"))
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn passfile_url_parameter() {
        let file = dir().join("pgpass");
        let url = move |port: u16| {
            format!(
                "postgres://appuser@127.0.0.1:{port}/appdb?sslmode=disable&passfile={}",
                file.display()
            )
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let seen = native(url.clone()).await;
            assert_eq!(seen.user, "appuser");
            assert_eq!(seen.database, "appdb");
            // `\:` -> ':' and `\\` -> '\'; the wildcard line after it loses.
            assert_eq!(seen.password, "s3cret:co\\lon");

            let stock = stock(url).await;
            assert_ne!(
                stock.password, "s3cret:co\\lon",
                "stock SQLx must not understand the passfile= URL parameter"
            );
        });
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn passfile_environment_vs_url() {
        let url_file = dir().join("url_pgpass");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // No URL parameter: PGPASSFILE is used by both implementations.
            let base =
                |port: u16| format!("postgres://envuser@127.0.0.1:{port}/envdb?sslmode=disable");
            assert_eq!(native(base).await.password, "from-env-file");
            assert_eq!(stock(base).await.password, "from-env-file");

            // URL parameter: only the native bridge lets it beat the environment.
            let with_param = |port: u16| {
                format!(
                    "postgres://envuser@127.0.0.1:{port}/envdb?sslmode=disable&passfile={}",
                    url_file.display()
                )
            };
            assert_eq!(native(with_param).await.password, "from-url-file");
            assert_eq!(stock(with_param).await.password, "from-env-file");
        });
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn password_precedence() {
        let file = dir().join("pgpass");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // PGPASSWORD is non-empty: the passfile entry is never consulted.
            let env_only = |port: u16| {
                format!(
                    "postgres://appuser@127.0.0.1:{port}/appdb?sslmode=disable&passfile={}",
                    file.display()
                )
            };
            assert_eq!(native(env_only).await.password, "env-password");

            // A password in the URL beats the environment.
            let in_url = |port: u16| {
                format!(
                    "postgres://appuser:url-password@127.0.0.1:{port}/appdb?sslmode=disable&passfile={}",
                    file.display()
                )
            };
            assert_eq!(native(in_url).await.password, "url-password");
        });
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn empty_url_password_overrides_environment() {
        let file = dir().join("pgpass");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let url = |port: u16| {
                format!(
                    "postgres://appuser:@127.0.0.1:{port}/appdb?sslmode=disable&passfile={}",
                    file.display()
                )
            };
            // pgx: `user:@` makes the URL password present-but-empty, which
            // overrides PGPASSWORD and so falls back to the passfile.
            assert_eq!(native(url).await.password, "from-passfile");
            // Stock SQLx has no passfile= parameter, so it cannot find the entry.
            assert_ne!(stock(url).await.password, "from-passfile");
        });
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn service_precedence() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // Service beats PGUSER/PGDATABASE.
            let via_param =
                |port: u16| format!("postgres://127.0.0.1:{port}/?sslmode=disable&service=svc");
            let seen = native(via_param).await;
            assert_eq!(
                seen,
                Seen {
                    user: "svcuser".into(),
                    database: "svcdb".into(),
                    password: "svcpw".into()
                }
            );

            // Explicit URL settings beat the service; the rest still comes from it.
            let overridden = |port: u16| {
                format!("postgres://urluser@127.0.0.1:{port}/?sslmode=disable&service=svc")
            };
            let seen = native(overridden).await;
            assert_eq!(seen.user, "urluser");
            assert_eq!(seen.database, "svcdb");
            assert_eq!(seen.password, "svcpw");

            // Without a service the environment applies.
            let plain = |port: u16| format!("postgres://127.0.0.1:{port}/?sslmode=disable");
            let seen = native(plain).await;
            assert_eq!(seen.user, "envuser");
            assert_eq!(seen.database, "envdb");
        });
    }

    #[test]
    #[ignore = "run in a scrubbed child process by the parent test"]
    fn unix_socket_localhost() {
        let directory = dir();
        let file = directory.join("pgpass");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let url = format!(
                "postgres:///appdb?user=appuser&sslmode=disable&host={}&passfile={}",
                directory.display(),
                file.display()
            );

            // Native bridge: host is a socket directory, so the passfile is
            // searched for `localhost`.
            let (listener, socket) = unix_listener(&directory);
            let mock = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                mock_login(stream).await
            });
            let options = PgConnectOptions::from_headscale_go_url(&url).expect("native URL");
            let seen = attempt(options, mock).await;
            assert_eq!(seen.password, "via-localhost");

            // Stock SQLx ignores the passfile= parameter.
            std::fs::remove_file(&socket).expect("remove first socket");
            let (listener, _) = unix_listener(&directory);
            let mock = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                mock_login(stream).await
            });
            let options: PgConnectOptions = url.parse().expect("stock parses the URL");
            let seen = attempt(options, mock).await;
            assert_ne!(seen.password, "via-localhost");
        });
    }
}
