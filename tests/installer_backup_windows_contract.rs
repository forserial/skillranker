//! Native Windows owner-only hook-installer backups (sr-winpar.7). The backup
//! of the user's Claude settings is written to
//! `%LOCALAPPDATA%\skillranker\backups` as a file only the user and SYSTEM can
//! open, or the settings change is refused and the settings stay untouched.
//! Fixtures change ACLs with the system's `icacls` and make junctions with
//! `mklink /J`, never by repairing what sr refused.
#![cfg(windows)]

mod support;

use serde_json::Value;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

const SETTINGS: &str = r#"{"model":"keep-me","env":{"TOKEN":"synthetic-secret-canary"}}"#;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = support::tmp_root().join(format!(
            "sr-backup-windows-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in ["workspace", "profile", "xdg", "local"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("settings.json"), SETTINGS).unwrap();
        Self { root }
    }

    fn settings(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    fn local_app_data(&self) -> PathBuf {
        self.root.join("local")
    }

    fn backups(&self) -> PathBuf {
        self.local_app_data().join("skillranker").join("backups")
    }

    fn install(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sr"))
            .args(["install-hook", "claude", "--settings-file"])
            .arg(self.settings())
            .arg("--apply")
            .current_dir(self.root.join("workspace"))
            .env_clear()
            .env("USERPROFILE", self.root.join("profile"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("LOCALAPPDATA", self.local_app_data())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The install was refused before the settings changed.
    fn assert_refused(&self, output: &Output) {
        assert_eq!(output.status.code(), Some(9), "{output:?}");
        let error: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!("{}", String::from_utf8_lossy(&output.stdout));
        });
        assert_eq!(error["error"]["kind"], "storage-failure", "{error}");
        let message = error["error"]["message"].as_str().unwrap();
        assert!(message.contains("settings were not changed"), "{message}");
        assert!(!message.contains("synthetic-secret-canary"));
        assert_eq!(fs::read_to_string(self.settings()).unwrap(), SETTINGS);
    }
}

fn files(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[test]
fn a_backup_is_created_owner_only_before_the_settings_change() {
    let f = Fixture::new();
    let output = f.install();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let installed: Value =
        serde_json::from_str(&fs::read_to_string(f.settings()).unwrap()).unwrap();
    assert_eq!(installed["model"], "keep-me");
    let backups = files(&f.backups());
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), SETTINGS);
    support::assert_owner_only_file(&backups[0]);
    // The backups folder sr created is protected from inheritance (rule 7).
    let folder = fs::OpenOptions::new()
        .access_mode(0x0002_0000)
        .custom_flags(sr_win_sys::windows::FILE_FLAG_BACKUP_SEMANTICS)
        .open(f.backups())
        .unwrap();
    let descriptor = sr_win_sys::windows::security_of(&folder).unwrap();
    assert!(descriptor.dacl_protected(), "{descriptor:?}");
}

#[test]
fn a_backups_folder_with_a_foreign_entry_is_refused_and_not_repaired() {
    let f = Fixture::new();
    support::create_private_dir(f.local_app_data().join("skillranker"));
    support::create_private_dir(f.backups());
    // Everyone may read the existing backups: not private (rule 2).
    let output = Command::new("icacls")
        .arg(f.backups())
        .args(["/grant", "*S-1-1-0:(R)"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    f.assert_refused(&f.install());
    assert!(files(&f.backups()).is_empty());
    let output = Command::new("icacls").arg(f.backups()).output().unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Everyone"),
        "the foreign entry was left as it was: {output:?}"
    );
}

#[test]
fn an_ancestor_others_can_replace_is_refused() {
    let f = Fixture::new();
    // Everyone may rename or delete what is inside LOCALAPPDATA (rule 3).
    support::share_with_everyone(f.local_app_data());
    f.assert_refused(&f.install());
    assert!(!f.local_app_data().join("skillranker").exists());
}

#[test]
fn a_junction_in_the_backup_path_is_refused() {
    let f = Fixture::new();
    let elsewhere = f.root.join("elsewhere");
    support::create_private_dir(&elsewhere);
    support::create_private_dir(elsewhere.join("backups"));
    support::junction(f.local_app_data().join("skillranker"), &elsewhere);
    f.assert_refused(&f.install());
    assert!(files(&elsewhere.join("backups")).is_empty());
}

#[test]
fn without_local_app_data_the_change_is_refused() {
    let f = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_sr"))
        .args(["install-hook", "claude", "--settings-file"])
        .arg(f.settings())
        .arg("--apply")
        .current_dir(f.root.join("workspace"))
        .env_clear()
        .env("USERPROFILE", f.root.join("profile"))
        .env("XDG_CONFIG_HOME", f.root.join("xdg"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    f.assert_refused(&output);
    // No fallback location was used.
    assert!(!f.root.join("profile").join(".local").exists());
}
