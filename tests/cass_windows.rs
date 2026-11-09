//! `sr rank --session PATH` on native Windows against a real, qualified cass
//! build (sr-winpar.11). Windows runs only exact `.exe` images, so the Unix
//! suites' `/bin/sh` fake cannot stand in: these cases use the real cass named
//! by `SKILLRANKER_TEST_CASS_EXE` (a `cass.exe` of a version in
//! `QUALIFIED_VERSIONS`), copied into the fixture profile's `.local\bin`.
//! Without it, the real-cass cases print why they did not run; they are not a
//! pass. The cass database holds one synthetic Claude Code session, indexed by
//! that cass from a fixture `CLAUDE_CONFIG_DIR` with `index --watch-once`, so
//! no real session is read. Fixtures are retained under the temporary folder.
#![cfg(windows)]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SESSION_ID: &str = "11111111-2222-3333-4444-555555555555";

fn qualified_cass() -> Option<PathBuf> {
    match std::env::var_os("SKILLRANKER_TEST_CASS_EXE") {
        Some(path) if Path::new(&path).is_file() => Some(PathBuf::from(path)),
        _ => {
            eprintln!(
                "not run: set SKILLRANKER_TEST_CASS_EXE to a qualified cass.exe to exercise real cass"
            );
            None
        }
    }
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sr-cass-windows-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let skill = root.join(r"workspace\.claude\skills\alpha");
        fs::create_dir_all(&skill).unwrap();
        fs::write(
            skill.join("SKILL.md"),
            "---\ndescription: alpha helps with rust tests.\n---\nBody.\n",
        )
        .unwrap();
        for directory in [r"home\.local\bin", r"config\sr", r"claude\projects\probe"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        Self { root }
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn session(&self) -> PathBuf {
        self.root
            .join(r"claude\projects\probe")
            .join(format!("{SESSION_ID}.jsonl"))
    }

    /// Install the real cass into the fixture profile and index one session
    /// of this workspace, asking for skill `alpha`, into `database`.
    fn install(&self, cass: &Path, database: &Path) {
        let installed = self.root.join(r"home\.local\bin\cass.exe");
        fs::copy(cass, &installed).unwrap();
        let record = serde_json::json!({
            "type": "user", "uuid": "u1", "parentUuid": null, "sessionId": SESSION_ID,
            "cwd": self.workspace(), "timestamp": "2026-11-08T10:00:00.000Z",
            "message": {"role": "user", "content": "Please use skill alpha to fix this."}
        });
        fs::write(self.session(), format!("{record}\n")).unwrap();
        fs::create_dir_all(database.parent().unwrap()).unwrap();
        let output = Command::new(&installed)
            .arg("--db")
            .arg(database)
            .args(["index", "--watch-once"])
            .arg(self.session())
            .arg("--json")
            .env("CLAUDE_CONFIG_DIR", self.root.join("claude"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "cass index: {output:?}");
    }

    fn rank(&self, session: &Path, extra_env: &[(&str, PathBuf)]) -> (Option<i32>, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sr"));
        command
            .env_clear()
            .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("local"))
            .current_dir(self.workspace())
            .stdin(Stdio::null())
            .args(["rank", "--session"])
            .arg(session)
            .arg("--json");
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON ({error}): {} / {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), value)
    }
}

#[test]
fn a_profile_without_cass_reports_where_it_was_looked_for() {
    let f = Fixture::new();
    let (code, value) = f.rank(&f.session(), &[]);
    assert_eq!(value["error"]["kind"], "unsupported-source-mode", "{value}");
    assert_eq!(code, value["error"]["code"].as_i64().map(|c| c as i32));
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains(r".local\bin\cass.exe"), "{message}");
}

#[test]
fn a_real_cass_session_of_this_workspace_is_ranked() {
    let Some(cass) = qualified_cass() else { return };
    let f = Fixture::new();
    let database = f.root.join(r"db\agent_search.db");
    f.install(&cass, &database);
    // cass reports the session in verbatim form (\\?\C:\...); both the plain
    // and the verbatim spelling select it.
    let mut verbatim = std::ffi::OsString::from(r"\\?\");
    verbatim.push(f.session().as_os_str());
    for session in [f.session(), PathBuf::from(verbatim)] {
        let (code, value) = f.rank(&session, &[("CASS_DB_PATH", database.clone())]);
        assert_eq!(code, Some(0), "{value}");
        assert_eq!(value["decision"], "explicit", "{value}");
        assert_eq!(value["harness"], "claude_code", "{value}");
        assert_eq!(value["skills"][0]["invocation_name"], "alpha", "{value}");
        assert_eq!(value["usage"]["requests"], 0, "{value}");
    }
}

#[test]
fn a_session_the_real_cass_does_not_record_for_this_workspace_is_refused() {
    let Some(cass) = qualified_cass() else { return };
    let f = Fixture::new();
    let database = f.root.join(r"db\agent_search.db");
    f.install(&cass, &database);
    let other = f.root.join(r"claude\projects\probe\other.jsonl");
    let (code, value) = f.rank(&other, &[("CASS_DB_PATH", database)]);
    assert_eq!(code, Some(3), "{value}");
    assert_eq!(value["error"]["kind"], "missing-session", "{value}");
}

#[test]
fn without_cass_db_path_the_real_cass_default_under_appdata_is_used() {
    let Some(cass) = qualified_cass() else { return };
    let f = Fixture::new();
    let app_data = f.root.join(r"roaming");
    let database = app_data.join(r"coding-agent-search\coding-agent-search\data\agent_search.db");
    f.install(&cass, &database);
    let (code, value) = f.rank(&f.session(), &[("APPDATA", app_data)]);
    assert_eq!(code, Some(0), "{value}");
    assert_eq!(value["skills"][0]["invocation_name"], "alpha", "{value}");
}
