//! The `sr` binary on Windows: skill discovery through links and reserved names,
//! the `USERPROFILE` fallback, the Claude hook's stdin and output, hook
//! installation, and the stateful commands that must refuse rather than emulate.
#![cfg(windows)]

use serde_json::{Value, json};
use skillranker::privacy::TrustedAbsoluteRoot;
use std::fs;
use std::io::Write;
use std::os::windows::fs::symlink_dir;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static SEQUENCE: AtomicU32 = AtomicU32::new(0);
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sr-windows-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in [
            "workspace/.claude/skills",
            "profile/.claude/skills",
            "xdg/sr",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        Self { root }
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn profile(&self) -> PathBuf {
        self.root.join("profile")
    }

    fn skills(&self) -> PathBuf {
        self.workspace().join(".claude").join("skills")
    }

    /// No `HOME`: the environment Windows gives a process by default.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sr"));
        command
            .args(args)
            .current_dir(self.workspace())
            .env_clear()
            .env("USERPROFILE", self.profile())
            .env("XDG_CONFIG_HOME", self.root.join("xdg"));
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).stdin(Stdio::null()).output().unwrap()
    }

    fn roster(&self) -> Value {
        let output = self.run(&["roster", "--json"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn advisory(&self) {
        fs::write(
            self.root.join("xdg/sr/config.toml"),
            "[hook]\nmode = \"advisory\"\n",
        )
        .unwrap();
    }

    fn hook(&self, stdin: &[u8]) -> Output {
        let mut child = self
            .command(&["hook", "claude"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    fn prompt(&self, prompt: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session_id": "11111111-1111-4111-8111-111111111111",
            "transcript_path": self.workspace().join("missing.jsonl"),
            "cwd": self.workspace(),
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
        }))
        .unwrap()
    }
}

fn skill(directory: &Path, name: &str) {
    let verbatim = PathBuf::from(format!(r"\\?\{}", directory.display()).replace('/', r"\"));
    fs::create_dir_all(&verbatim).unwrap();
    fs::write(
        verbatim.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: Windows fixture skill {name}.\n---\n\n# {name}\n"),
    )
    .unwrap();
}

fn names(roster: &Value) -> Vec<String> {
    let mut names: Vec<String> = roster["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

fn kind(output: &Output) -> String {
    let value: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    value["error"]["kind"].as_str().unwrap().to_owned()
}

#[test]
fn userprofile_supplies_personal_skills_only_when_home_is_unset() {
    let f = Fixture::new();
    skill(&f.skills().join("project-skill"), "project-skill");
    skill(&f.profile().join(".claude/skills/user-skill"), "user-skill");
    assert_eq!(names(&f.roster()), ["project-skill", "user-skill"]);

    let elsewhere = f.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let output = f
        .command(&["roster", "--json"])
        .env("HOME", &elsewhere)
        .output()
        .unwrap();
    let roster: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        names(&roster),
        ["project-skill"],
        "HOME stays authoritative"
    );
}

#[test]
fn junctioned_and_symlinked_skill_folders_are_skipped_and_reported() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    skill(&outside.join("junctioned"), "junctioned");
    skill(&outside.join("symlinked"), "symlinked");
    skill(&f.skills().join("real-skill"), "real-skill");
    let junction = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(f.skills().join("junctioned"))
        .arg(outside.join("junctioned"))
        .output()
        .unwrap();
    assert!(junction.status.success(), "{junction:?}");
    let mut expected = 1;
    match symlink_dir(outside.join("symlinked"), f.skills().join("symlinked")) {
        Ok(()) => expected += 1,
        Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
            eprintln!("symbolic link case skipped: needs Developer Mode or elevation");
        }
        Err(error) => panic!("{error}"),
    }

    let roster = f.roster();
    assert_eq!(names(&roster), ["real-skill"]);
    assert_eq!(roster["partial"], true);
    assert_eq!(
        roster["source_causes"]["symlinked-directory-skipped"],
        expected
    );
}

#[test]
fn reserved_and_rewritten_skill_folder_names_are_refused() {
    let f = Fixture::new();
    skill(&f.skills().join("real-skill"), "real-skill");
    let refused = ["CON", "nul.txt", "COM1", "trail.", "space "];
    for name in refused {
        skill(&f.skills().join(name), "refused");
    }
    let roster = f.roster();
    assert_eq!(names(&roster), ["real-skill"]);
    assert_eq!(
        roster["source_causes"]["entry-unreadable"],
        refused.len(),
        "{roster}"
    );
}

#[test]
fn identical_runs_list_identical_skill_ids_with_native_separators() {
    let f = Fixture::new();
    skill(&f.skills().join("real-skill"), "real-skill");
    let (first, second) = (f.roster(), f.roster());
    assert_eq!(first["records"], second["records"]);
    assert_eq!(first["snapshot"], second["snapshot"]);
}

#[test]
fn rewritten_transcript_and_roster_names_are_refused_before_any_open() {
    let f = Fixture::new();
    skill(&f.skills().join("real-skill"), "real-skill");
    let workspace = f.workspace();
    let transcript = workspace.join("t.jsonl");
    fs::write(
        &transcript,
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n",
    )
    .unwrap();
    fs::write(workspace.join("x.md"), "visible").unwrap();
    fs::write(workspace.join("x.md:stream"), "hidden").unwrap();
    let rank = |path: &Path| {
        f.run(&[
            "rank",
            "--offline",
            "--transcript",
            path.to_str().unwrap(),
            "--harness",
            "claude_code",
            "--json",
        ])
    };

    // The honest twin reads the transcript and stops at the offline cache miss.
    assert_eq!(kind(&rank(&transcript)), "cache-miss");
    for name in ["t.jsonl.", "t.jsonl ", "x.md:stream", "CON", "nul.txt"] {
        let output = rank(&workspace.join(name));
        assert_eq!(output.status.code(), Some(7), "{name}: {output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Transcript snapshot failed"),
            "{name}: {value}"
        );
    }

    let context = workspace.join("context.json");
    fs::write(
        &context,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "harness": "claude_code",
            "producer_id": null,
            "workspace_root": workspace,
            "session_id": "session-windows-1",
            "agent_id": null,
            "branch_id": null,
            "context_epoch": null,
            "current_request": {
                "event_id": null,
                "text": "Help with this.",
                "attachments_omitted": false,
                "essential_attachment_missing": false
            },
            "events": [],
            "explicit_skill_references": [],
            "supplied_loads": []
        }))
        .unwrap(),
    )
    .unwrap();
    for name in ["x.md:stream", "CON", "x.md."] {
        let output = f.run(&[
            "rank",
            "--offline",
            "--context",
            context.to_str().unwrap(),
            "--roster",
            workspace.join(name).to_str().unwrap(),
            "--json",
        ]);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["decision"], "unavailable", "{name}: {value}");
        assert_eq!(output.status.code(), Some(5), "{name}: {value}");
    }
}

#[test]
fn trusted_roots_must_be_absolute_in_the_windows_sense() {
    assert!(TrustedAbsoluteRoot::parse(r"C:\team\skills").is_ok());
    assert!(TrustedAbsoluteRoot::parse("C:/team/skills").is_ok());
    assert!(TrustedAbsoluteRoot::parse("/team/skills").is_err());
    assert!(TrustedAbsoluteRoot::parse(r"team\skills").is_err());
    assert!(TrustedAbsoluteRoot::parse(r"C:team\skills").is_err());
}

#[test]
fn the_hook_reads_piped_stdin_and_publishes_an_explicit_request() {
    let f = Fixture::new();
    f.advisory();
    skill(&f.skills().join("real-skill"), "real-skill");

    let output = f.hook(&f.prompt("/use-skill real-skill please"));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let published: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        published["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    assert!(
        published["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .contains("real-skill")
    );
}

#[test]
fn piped_rank_input_needs_an_explicit_mode_and_is_read_with_one() {
    let f = Fixture::new();
    let run = |args: &[&str]| {
        let mut child = f
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"not json").unwrap();
        let output = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let without_mode = run(&["rank", "--offline", "--json"]);
    assert!(
        without_mode.contains("explicit input mode"),
        "{without_mode}"
    );
    let with_mode = run(&["rank", "--offline", "--context", "-", "--json"]);
    assert!(
        with_mode.contains("Invalid normalized context"),
        "{with_mode}"
    );
}

#[test]
fn shadow_mode_stays_silent_and_failures_never_block_the_prompt() {
    let f = Fixture::new();
    skill(&f.skills().join("real-skill"), "real-skill");
    let shadow = f.hook(&f.prompt("/use-skill real-skill please"));
    assert_eq!(shadow.status.code(), Some(0), "{shadow:?}");
    assert!(shadow.stdout.is_empty());

    f.advisory();
    for (input, diagnostic) in [
        (b"not json".to_vec(), "Invalid hook input"),
        (vec![b'x'; 1024 * 1024 + 1], "exceeds 1 MiB"),
    ] {
        let output = f.hook(&input);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(diagnostic), "{stderr}");
    }
}

#[test]
fn a_stalled_stdin_ends_at_the_deadline_while_the_writer_stays_open() {
    let f = Fixture::new();
    let started = Instant::now();
    let mut child = f
        .command(&["hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let held_open = child.stdin.take();
    let output = child.wait_with_output().unwrap();
    drop(held_open);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty());
    // Only a deadline ends this run, since the writer stays open. The bound leaves
    // room for spawn contention under parallel tests; alone it takes about 2.8 s.
    assert!(started.elapsed() < Duration::from_secs(20), "{started:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("deadline"));
}

#[test]
fn installing_writes_a_command_git_bash_can_run_and_removing_restores_settings() {
    let f = Fixture::new();
    let settings = f.root.join("settings.json");
    fs::write(&settings, r#"{"model":"keep-me"}"#).unwrap();
    let path = settings.to_str().unwrap();

    let preview = f.run(&["install-hook", "claude", "--settings-file", path]);
    assert_eq!(preview.status.code(), Some(0), "{preview:?}");
    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        r#"{"model":"keep-me"}"#
    );
    let text = String::from_utf8_lossy(&preview.stdout);
    assert!(text.contains("Windows builds have no ledger"), "{text}");
    assert!(!text.contains("sr ledger init"), "{text}");

    for _ in 0..2 {
        let apply = f.run(&["install-hook", "claude", "--settings-file", path, "--apply"]);
        assert_eq!(apply.status.code(), Some(0), "{apply:?}");
    }
    let installed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(installed["model"], "keep-me");
    let entries = installed["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "repeating --apply adds nothing");
    let command = entries[0]["hooks"][0]["command"].as_str().unwrap();
    assert!(command.starts_with('"') && command.ends_with("\" hook claude"));
    assert!(
        !command.contains('\\'),
        "Git Bash would eat this: {command}"
    );

    let remove = f.run(&[
        "uninstall-hook",
        "claude",
        "--settings-file",
        path,
        "--apply",
    ]);
    assert_eq!(remove.status.code(), Some(0), "{remove:?}");
    let removed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(removed, json!({"model": "keep-me"}));
}

#[test]
fn stateful_commands_refuse_instead_of_emulating_a_private_store() {
    let f = Fixture::new();
    let snapshot = f.root.join("snapshot.json");
    for args in [
        vec!["ledger", "status", "--json"],
        vec!["ledger", "init", "--json"],
        vec!["stats", "--json"],
        vec![
            "budget",
            "--max-attempts",
            "5",
            "--window",
            "1h",
            "--apply",
            "--json",
        ],
        vec!["roster", "--snapshot", snapshot.to_str().unwrap()],
    ] {
        let output = f.run(&args);
        assert_eq!(output.status.code(), Some(9), "{args:?}: {output:?}");
        assert_eq!(kind(&output), "storage-failure", "{args:?}");
    }
    assert!(!snapshot.exists());
    assert!(!f.profile().join(".local").exists(), "no state was created");
}
