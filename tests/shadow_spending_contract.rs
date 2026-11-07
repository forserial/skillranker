//! A shadow hook whose evaluation cannot be recorded sends no provider
//! requests (sr-winpar.8). Shadow mode publishes nothing, so a run with no
//! recordable ledger would only spend requests. The provider is a real
//! loopback TLS stub that counts what it serves; data is synthetic.
//!
//! Runs on every platform. On Windows no ledger can be opened, so every shadow
//! turn skips; on Linux and macOS a missing or disabled ledger skips and an
//! initialized one records. Advisory mode always ranks.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CANARY: &str = "synthetic-shadow-spending-canary-key";
const SESSION: &str = "shadow-spending-session";
const PROMPT: &str = "Our rust test suite started failing; find out why.";

struct Home {
    root: PathBuf,
}

impl Home {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sr-shadow-spending-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for dir in ["home", "config/sr", "cache", "data", "state", "workspace"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        // Trusted configuration and the ledger need owner-only directories.
        #[cfg(unix)]
        for dir in ["", "home", "config", "config/sr", "cache", "data", "state"] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.join(dir), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let skill = root.join("workspace/.claude/skills/rust-repair");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: rust-repair\ndescription: Runs and repairs failing rust tests.\n---\nBody.\n",
        )
        .unwrap();
        std::fs::write(
            root.join("fixture-ca.pem"),
            include_bytes!("fixtures/jev-tls/ca.pem"),
        )
        .unwrap();
        Self { root }
    }

    fn config(&self, toml: &str) {
        std::fs::write(self.root.join("config/sr/config.toml"), toml).unwrap();
    }

    fn command(&self, port: u16, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sr"));
        command
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("TYPESAFE_API_KEY", CANARY)
            .env("TYPESAFE_ENDPOINT", format!("https://localhost:{port}"))
            .env("SSL_CERT_FILE", self.root.join("fixture-ca.pem"))
            .current_dir(self.root.join("workspace"))
            .args(args);
        system_environment(&mut command);
        command
    }

    /// One user turn delivered to `sr hook claude` as Claude Code would.
    fn hook_turn(&self, port: u16, extra: &[&str]) -> Output {
        self.hook_turn_with(port, extra, PROMPT)
    }

    fn hook_turn_with(&self, port: u16, extra: &[&str], prompt: &str) -> Output {
        let transcript = self.root.join("workspace/transcript.jsonl");
        let record = json!({"type": "user", "uuid": "u0", "parentUuid": Value::Null,
                            "sessionId": SESSION,
                            "message": {"role": "user", "content": prompt}});
        std::fs::write(&transcript, format!("{record}\n")).unwrap();
        let payload = json!({
            "hook_event_name": "UserPromptSubmit", "prompt": prompt,
            "session_id": SESSION, "transcript_path": transcript,
            "cwd": self.root.join("workspace"),
            "prompt_id": format!("shadow-turn-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        });
        let mut args = vec!["hook", "claude"];
        args.extend_from_slice(extra);
        let mut child = self
            .command(port, &args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[cfg(unix)]
    fn ranking_events(&self) -> usize {
        let db = rusqlite::Connection::open(self.root.join("data/sr/ledger.sqlite3")).unwrap();
        db.query_row("SELECT COUNT(*) FROM ranking_events", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|count| usize::try_from(count).unwrap())
        .unwrap()
    }
}

/// Windows children need `SystemRoot` to initialize Winsock.
fn system_environment(command: &mut Command) {
    #[cfg(windows)]
    for name in ["SystemRoot", "SYSTEMROOT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(not(windows))]
    let _ = command;
}

fn python() -> PathBuf {
    // `python` on PATH may be an install-manager alias that needs the user's
    // environment; ask it once for the real interpreter, which then runs with
    // an explicit environment like every other child here.
    #[cfg(windows)]
    {
        let out = Command::new("python")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .expect("the provider stub needs `python` on PATH");
        assert!(out.status.success(), "{}", describe(&out));
        PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
    }
    #[cfg(not(windows))]
    PathBuf::from("/usr/bin/python3")
}

fn describe(out: &Output) -> String {
    format!(
        "exit {:?}\n{}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Exit zero, nothing injected, the key never printed.
fn assert_quiet(out: &Output) {
    assert_eq!(out.status.code(), Some(0), "{}", describe(out));
    assert!(out.stdout.is_empty(), "shadow injected: {}", describe(out));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(CANARY));
}

/// A skipped shadow turn: quiet, with one diagnostic naming the reason.
fn assert_skipped(out: &Output, reason: &str) {
    assert_quiet(out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("shadow hook skipped ranking").count(),
        1,
        "{}",
        describe(out)
    );
    assert!(stderr.contains(reason), "{}", describe(out));
}

struct Provider {
    child: Child,
    lines: BufReader<ChildStdout>,
    port: u16,
}

impl Provider {
    fn start(home: &Home) -> Self {
        let dir = home
            .root
            .join(format!("provider-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        for (name, bytes) in [
            (
                "provider_server.py",
                &include_bytes!("fixtures/jev-tls/provider_server.py")[..],
            ),
            (
                "server.pem",
                &include_bytes!("fixtures/jev-tls/server.pem")[..],
            ),
            (
                "server.key",
                &include_bytes!("fixtures/jev-tls/server.key")[..],
            ),
        ] {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let mut command = Command::new(python());
        command
            .arg(dir.join("provider_server.py"))
            .arg("useful")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        system_environment(&mut command);
        let mut child = command.spawn().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        let mut hello = String::new();
        lines.read_line(&mut hello).unwrap();
        let hello: Value = serde_json::from_str(&hello).unwrap();
        let port = u16::try_from(hello["port"].as_u64().unwrap()).unwrap();
        Self { child, lines, port }
    }

    /// Ends the stub and returns how many provider requests it served.
    fn finish(mut self) -> usize {
        let mut done = std::net::TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        done.write_all(b"DONE").unwrap();
        drop(done);
        let mut served = 0;
        loop {
            let mut line = String::new();
            assert!(
                self.lines.read_line(&mut line).unwrap() > 0,
                "provider ended early"
            );
            let value: Value = serde_json::from_str(&line).unwrap();
            if value["done"] == true {
                break;
            }
            served += usize::from(value["handshake_rejected"] != true);
        }
        let _ = self.child.wait();
        served
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn shadow_without_a_recordable_ledger_sends_no_provider_requests() {
    let home = Home::new();
    home.config("[network]\nenabled = true\n");
    let provider = Provider::start(&home);
    let port = provider.port;
    // No ledger was initialized; on Windows none can be.
    let reason = if cfg!(windows) {
        "cannot host the ledger"
    } else {
        "no ledger is initialized"
    };
    // A large payload is still read: the harness must not write into a
    // closed pipe, which would fail this test's own write.
    let large = format!("{PROMPT} {}", "padding ".repeat(64 * 1024));
    let turns = [
        home.hook_turn(port, &[]),
        home.hook_turn(port, &["--shadow"]),
        home.hook_turn_with(port, &[], &large),
    ];
    assert_eq!(provider.finish(), 0, "shadow turns sent provider requests");
    for turn in &turns {
        assert_skipped(turn, reason);
    }
}

#[test]
fn shadow_with_recording_disabled_sends_no_provider_requests() {
    let home = Home::new();
    home.config("[network]\nenabled = true\n");
    #[cfg(unix)]
    {
        // A ready ledger does not matter once recording is disabled.
        let init = home
            .command(1, &["ledger", "init", "--json"])
            .output()
            .unwrap();
        assert!(init.status.success(), "{}", describe(&init));
    }
    let provider = Provider::start(&home);
    let port = provider.port;
    let turns = ["--no-ledger", "--no-persist"].map(|flag| home.hook_turn(port, &[flag]));
    assert_eq!(provider.finish(), 0, "shadow turns sent provider requests");
    for turn in &turns {
        assert_skipped(turn, "recording is disabled");
    }
    #[cfg(unix)]
    assert_eq!(home.ranking_events(), 0);
}

#[test]
fn advisory_mode_ranks_even_when_nothing_can_be_recorded() {
    let home = Home::new();
    home.config("[network]\nenabled = true\n[hook]\nmode = \"advisory\"\n");
    let provider = Provider::start(&home);
    let port = provider.port;
    let out = home.hook_turn(port, &["--no-ledger"]);
    assert_eq!(out.status.code(), Some(0), "{}", describe(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("skipped ranking"),
        "{}",
        describe(&out)
    );
    let published: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("advisory published nothing: {}", describe(&out)));
    assert!(
        published["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|text| text.contains("rust-repair")),
        "{}",
        describe(&out)
    );
    // Wide and rerank.
    assert_eq!(provider.finish(), 2);
}

#[cfg(unix)]
#[test]
fn shadow_with_a_ready_ledger_ranks_and_records() {
    let home = Home::new();
    home.config("[network]\nenabled = true\n");
    let init = home
        .command(1, &["ledger", "init", "--json"])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", describe(&init));
    let provider = Provider::start(&home);
    let out = home.hook_turn(provider.port, &[]);
    assert_quiet(&out);
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("skipped ranking"),
        "{}",
        describe(&out)
    );
    assert_eq!(provider.finish(), 2);
    assert_eq!(home.ranking_events(), 1);
}
