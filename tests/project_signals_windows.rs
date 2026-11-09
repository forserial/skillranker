#![cfg(windows)]
//! Git `dirty_paths` and the tool inventory on native Windows (sr-winpar.10):
//! Git for Windows from the trusted `%ProgramFiles%` roots, run through the
//! owned-subprocess boundary with `-C <workspace>`, never a planted or `PATH`
//! copy. The Windows twin of tests/project_signals.rs.

#[path = "support/links.rs"]
mod links;
use skillranker::context::signals::{DIRTY_PATH_LIMIT, Omission, ProjectSignals, collect};
use skillranker::runtime::ProcessInvocation;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// One case at a time. The signals stage has 250 ms for `git --version` and
/// `git status` (43 ms p50, 69 ms p95 alone on the evidence machine); five
/// cases spawning fixture and probe Git processes at once can exhaust it and
/// report `Budget`, which says nothing about trust or parsing.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn temp() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sr-signals-windows-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

/// The roots the pipeline trusts on Windows, in its order.
fn trusted_roots() -> Vec<PathBuf> {
    let base = PathBuf::from(std::env::var_os("ProgramFiles").expect("ProgramFiles is set"));
    [
        r"Git\ucrt64\bin",
        r"Git\mingw64\bin",
        r"Git\clangarm64\bin",
        r"Git\cmd",
        "nodejs",
        r"Go\bin",
        r"CMake\bin",
    ]
    .iter()
    .map(|relative| base.join(relative))
    .filter(|root| root.is_dir())
    .collect()
}

fn git_exe() -> PathBuf {
    trusted_roots()
        .into_iter()
        .map(|root| root.join("git.exe"))
        .find(|git| git.is_file())
        .expect("these cases need Git for Windows under %ProgramFiles%\\Git")
}

/// Fixture Git with an isolated global configuration.
fn git(dir: &Path, args: &[&str]) {
    let output = Command::new(git_exe())
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture git {args:?} failed: {output:?}"
    );
}

fn repository() -> PathBuf {
    let dir = temp();
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.email", "synthetic@example.invalid"]);
    git(&dir, &["config", "user.name", "Synthetic"]);
    dir
}

fn commit_all(dir: &Path) {
    git(dir, &["-c", "core.fsmonitor=false", "add", "-A"]);
    git(
        dir,
        &["-c", "core.fsmonitor=false", "commit", "-qm", "fixture"],
    );
}

fn collect_at(dir: &Path, roots: &[PathBuf]) -> ProjectSignals {
    let invocation = ProcessInvocation::enter().unwrap();
    let cx = invocation.request_cx().unwrap();
    let result = invocation
        .runtime()
        .block_on(collect(&cx, &invocation.clock(), dir, roots));
    let _ = invocation.shutdown();
    result
}

fn paths(result: &ProjectSignals) -> Vec<String> {
    let dirty = result.dirty_paths.as_ref().expect("dirty paths collected");
    let mut paths: Vec<String> = dirty.paths.iter().map(|p| p.as_str().to_owned()).collect();
    paths.sort();
    paths
}

#[test]
fn modified_added_deleted_and_non_ascii_paths_are_repository_relative() {
    let _serial = serial();
    let dir = repository();
    std::fs::create_dir(dir.join("src")).unwrap();
    for name in [
        "Cargo.toml",
        "src/lib.rs",
        "gone.txt",
        "zażółć.txt",
        "same.txt",
    ] {
        std::fs::write(dir.join(name), "synthetic\n").unwrap();
    }
    commit_all(&dir);
    let clean = collect_at(&dir, &trusted_roots());
    assert_eq!(clean.git_omission, None, "{clean:?}");
    assert!(paths(&clean).is_empty(), "{clean:?}");
    assert!(clean.tools_on_path.contains(&"git"));
    assert!(clean.filenames.contains(&"Cargo.toml"));

    std::fs::write(dir.join("src/lib.rs"), "changed\n").unwrap();
    std::fs::remove_file(dir.join("gone.txt")).unwrap();
    std::fs::write(dir.join("zażółć.txt"), "changed\n").unwrap();
    std::fs::write(dir.join("added.txt"), "new\n").unwrap();
    git(&dir, &["-c", "core.fsmonitor=false", "add", "added.txt"]);
    let result = collect_at(&dir, &trusted_roots());
    assert_eq!(result.git_omission, None, "{result:?}");
    assert_eq!(
        paths(&result),
        ["added.txt", "gone.txt", "src/lib.rs", "zażółć.txt"]
    );
    let dirty = result.dirty_paths.unwrap();
    assert_eq!((dirty.omitted_non_utf8, dirty.omitted_unsafe), (0, 0));
    assert!(!dirty.truncated);
}

#[test]
fn more_than_the_limit_is_truncated_at_the_limit() {
    let _serial = serial();
    let dir = repository();
    for i in 0..=DIRTY_PATH_LIMIT {
        std::fs::write(dir.join(format!("f{i:03}.txt")), "synthetic\n").unwrap();
    }
    commit_all(&dir);
    for i in 0..=DIRTY_PATH_LIMIT {
        std::fs::write(dir.join(format!("f{i:03}.txt")), "changed\n").unwrap();
    }
    let result = collect_at(&dir, &trusted_roots());
    assert_eq!(result.git_omission, None, "{result:?}");
    let dirty = result.dirty_paths.unwrap();
    assert_eq!(dirty.paths.len(), DIRTY_PATH_LIMIT);
    assert!(dirty.truncated);
}

#[test]
fn a_configured_fsmonitor_hook_never_runs() {
    let _serial = serial();
    let dir = repository();
    std::fs::write(dir.join("Cargo.toml"), "synthetic\n").unwrap();
    commit_all(&dir);
    let marker = dir.join("monitor-ran");
    let hook = dir.join("monitor");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\necho invoked > '{}'\n", marker.display()).replace('\\', "/"),
    )
    .unwrap();
    git(
        &dir,
        &[
            "config",
            "core.fsmonitor",
            &hook.to_string_lossy().replace('\\', "/"),
        ],
    );
    std::fs::write(dir.join("Cargo.toml"), "changed\n").unwrap();
    // Control: an ordinary status does run the hook in this repository.
    let _ = Command::new(git_exe())
        .current_dir(&dir)
        .env("HOME", &dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(
        marker.exists(),
        "the control status did not run the fsmonitor hook"
    );
    std::fs::remove_file(&marker).unwrap();

    let result = collect_at(&dir, &trusted_roots());
    assert_eq!(result.git_omission, None, "{result:?}");
    assert_eq!(paths(&result), ["Cargo.toml"]);
    assert!(
        !marker.exists(),
        "collect ran the repository's fsmonitor hook"
    );
}

#[test]
fn missing_git_is_an_omission_not_a_failure() {
    let _serial = serial();
    let dir = repository();
    let empty_root = temp();
    let result = collect_at(&dir, &[empty_root]);
    assert_eq!(result.git_omission, Some(Omission::Unavailable));
    assert!(result.dirty_paths.is_none());
    assert!(!result.inventory_partial, "the inventory itself completed");
    assert!(result.tools_on_path.is_empty());
}

#[test]
fn a_git_exe_planted_in_the_workspace_is_never_trusted() {
    let _serial = serial();
    let dir = repository();
    let planted = dir.join("tools");
    std::fs::create_dir(&planted).unwrap();
    // Any .exe named git.exe would do; refusing its root means it never runs.
    let system32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
    std::fs::copy(system32.join("findstr.exe"), planted.join("git.exe")).unwrap();

    // A root inside the workspace is refused outright.
    let result = collect_at(&dir, std::slice::from_ref(&planted));
    assert_eq!(result.git_omission, Some(Omission::InvalidAuthority));
    assert!(result.dirty_paths.is_none());

    // So is a junction outside it that leads back in.
    let junction = temp().join("leads-in");
    let made = Command::new(system32.join("cmd.exe"))
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&planted)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let result = collect_at(&dir, &[junction]);
    assert_eq!(result.git_omission, Some(Omission::InvalidAuthority));

    // The trusted roots ignore it and find Git for Windows.
    let result = collect_at(&dir, &trusted_roots());
    assert_eq!(result.git_omission, None, "{result:?}");
}

/// sr-cd14: a link in a trusted root counts for presence when it reaches a
/// regular `.exe`, as rustup's symlinked `cargo.exe` does; Git is executed only
/// from an image inside a trusted root, so a linked Git elsewhere is present
/// but never run, and a later root's Git for Windows is used instead.
#[test]
fn a_linked_tool_is_present_but_a_linked_git_outside_the_roots_never_runs() {
    if !links::available() {
        return;
    }
    let _serial = serial();
    let dir = repository();
    let root = temp();
    let store = temp();
    let system32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
    // Any .exe would do: run as Git, findstr would fail the version probe.
    for name in ["cargo-real.exe", "git-real.exe"] {
        std::fs::copy(system32.join("findstr.exe"), store.join(name)).unwrap();
    }
    links::symlink(store.join("cargo-real.exe"), root.join("cargo.exe")).unwrap();
    links::symlink(store.join("git-real.exe"), root.join("git.exe")).unwrap();

    let result = collect_at(&dir, std::slice::from_ref(&root));
    assert!(result.tools_on_path.contains(&"cargo"), "{result:?}");
    assert!(result.tools_on_path.contains(&"git"), "{result:?}");
    // Unavailable, not UnsupportedGit: the linked image was never started.
    assert_eq!(result.git_omission, Some(Omission::Unavailable));

    let mut roots = vec![root];
    roots.extend(trusted_roots());
    let result = collect_at(&dir, &roots);
    assert_eq!(result.git_omission, None, "{result:?}");
}
