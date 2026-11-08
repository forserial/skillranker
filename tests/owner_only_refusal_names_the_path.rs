//! An owner-only storage refusal has to say which path is wrong (sr-488b; on
//! Windows sr-winpar.27, where it names the folder, what its access list holds
//! and the `icacls` command that fixes it).
//!
//! The refusal used to read, in full: "Failed to initialize ledger: cache path does not satisfy
//! owner-only permissions", with the hint "Use sr --help; inspect trusted-user and project
//! configuration." Neither names a path, and the hint points at configuration when the fix is a
//! chmod on one directory. Two separate reviews lost several attempts each to it, both times on a
//! directory the harness itself had just created, which is the ordinary case rather than an exotic
//! one.
//!
//! These cases drive the built binary, because the wording is what a person reads.
mod support;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use support::PlatformEnv;

fn temp_root(label: &str) -> PathBuf {
    // Linux's root-owned sticky /tmp is the one ancestor the store accepts, so a test that wants a
    // REJECTED ancestor has to create it here itself. Windows: %LOCALAPPDATA%\sr-tests.
    let root = support::tmp_root().join(format!(
        "sr-owner-refusal-{}-{}",
        label,
        support::unique_suffix()
    ));
    support::private_dir(&root);
    root
}

fn run(root: &Path, dir: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sr"))
        .env_clear()
        .platform_env()
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .args(["ledger", "init", "--dir", dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[cfg(unix)]
#[test]
fn a_group_writable_ancestor_is_named_with_its_mode_and_the_chmod_that_fixes_it() {
    let root = temp_root("ancestor");
    let shared = root.join("shared");
    std::fs::DirBuilder::new()
        .mode(0o775)
        .recursive(true)
        .create(&shared)
        .unwrap();
    // Some umasks clear the group bit on create, so set it explicitly rather than trusting mode().
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
    let store = shared.join("ledger");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&store)
        .unwrap();

    let (ok, stdout) = run(&root, &store);
    assert!(!ok, "a group-writable ancestor must still be refused");
    assert!(
        stdout.contains(shared.to_str().unwrap()),
        "the refusal must name the offending directory; got: {stdout}"
    );
    assert!(
        stdout.contains("0775"),
        "the refusal must state the mode it found; got: {stdout}"
    );
    assert!(
        stdout.contains("chmod go-w"),
        "the refusal must give the command that fixes it, not point at configuration; got: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn a_store_directory_with_the_wrong_mode_is_named_with_the_mode_it_must_have() {
    let root = temp_root("leaf");
    let store = root.join("ledger");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .recursive(true)
        .create(&store)
        .unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (ok, stdout) = run(&root, &store);
    assert!(!ok, "a 0755 store directory must be refused");
    assert!(
        stdout.contains(store.to_str().unwrap()),
        "the refusal must name the store directory; got: {stdout}"
    );
    assert!(
        stdout.contains("0700"),
        "the refusal must state the required mode; got: {stdout}"
    );
    assert!(
        stdout.contains("chmod 700"),
        "the refusal must give the fix; got: {stdout}"
    );
}

#[test]
fn a_healthy_tree_still_initializes_and_says_nothing_extra() {
    // The honest counterpart: the diagnosis must not attach itself to a success, and must not
    // appear for refusals that are not about permissions.
    let root = temp_root("healthy");
    let store = root.join("ledger");
    support::private_dir(&store);
    let (ok, stdout) = run(&root, &store);
    assert!(ok, "an owner-only tree must initialize: {stdout}");
    assert!(
        !stdout.contains("chmod") && !stdout.contains("icacls"),
        "a success must not carry a remedy; got: {stdout}"
    );
}

/// The refusal's text, with the JSON string unescaped so Windows paths read as
/// written.
#[cfg(windows)]
fn message(stdout: &str) -> String {
    let value: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|_| panic!("{stdout}"));
    value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Run the `icacls` command a refusal suggested, exactly as printed.
#[cfg(windows)]
fn apply_fix(message: &str) {
    let command = message
        .split("Fix with: ")
        .nth(1)
        .unwrap_or_else(|| panic!("no fix in: {message}"))
        .trim();
    // As typed at a prompt: `raw_arg` passes the quotes through unescaped.
    use std::os::windows::process::CommandExt;
    let output = Command::new("cmd")
        .arg("/C")
        .raw_arg(command)
        .output()
        .unwrap();
    assert!(output.status.success(), "{command}: {output:?}");
}

#[cfg(windows)]
#[test]
fn a_store_folder_with_a_foreign_entry_is_named_with_the_entry_and_the_icacls_that_removes_it() {
    let root = temp_root("foreign");
    let store = root.join("ledger");
    support::private_dir(&store);
    let output = Command::new("icacls")
        .arg(&store)
        .args(["/grant", "*S-1-1-0:(RX)"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let (ok, stdout) = run(&root, &store);
    assert!(!ok, "a store folder Everyone can read must be refused");
    let text = message(&stdout);
    assert!(text.contains(store.to_str().unwrap()), "{text}");
    assert!(text.contains("grants Everyone (S-1-1-0)"), "{text}");
    assert!(text.contains("/remove:g *S-1-1-0"), "{text}");
    // The suggested command is the whole fix.
    apply_fix(&text);
    let (ok, stdout) = run(&root, &store);
    assert!(
        ok,
        "after the suggested fix the store must initialize: {stdout}"
    );
}

#[cfg(windows)]
#[test]
fn an_inherited_store_folder_is_named_with_the_icacls_that_makes_it_private() {
    let root = temp_root("inherited");
    let store = root.join("ledger");
    // A plain folder inherits its parent's entries: only you and SYSTEM here,
    // but not protected from what the parent may later grant.
    std::fs::create_dir(&store).unwrap();

    let (ok, stdout) = run(&root, &store);
    assert!(!ok, "an unprotected store folder must be refused");
    let text = message(&stdout);
    assert!(text.contains(store.to_str().unwrap()), "{text}");
    assert!(text.contains("inherits access entries"), "{text}");
    assert!(text.contains("/inheritance:r"), "{text}");
    apply_fix(&text);
    let (ok, stdout) = run(&root, &store);
    assert!(
        ok,
        "after the suggested fix the store must initialize: {stdout}"
    );
}

#[cfg(windows)]
#[test]
fn a_store_folder_owned_by_another_principal_is_named_without_a_command() {
    // %ProgramData% is owned by SYSTEM; the refusal happens before anything
    // is written there.
    let root = temp_root("owner");
    let program_data =
        PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()));
    let (ok, stdout) = run(&root, &program_data);
    assert!(!ok, "a folder another principal owns must be refused");
    let text = message(&stdout);
    assert!(text.contains(program_data.to_str().unwrap()), "{text}");
    assert!(text.contains("is owned by"), "{text}");
    assert!(
        !text.contains("Fix with"),
        "changing an owner needs that owner or an administrator: {text}"
    );
}

#[cfg(windows)]
#[test]
fn an_ancestor_others_can_modify_is_named_with_the_entry_and_its_fix() {
    let root = temp_root("ancestor");
    let shared = root.join("shared");
    support::private_dir(&shared);
    support::share_with_everyone(&shared);
    let store = shared.join("ledger");
    support::private_dir(&store);

    let (ok, stdout) = run(&root, &store);
    assert!(!ok, "an ancestor Everyone can modify must be refused");
    let text = message(&stdout);
    assert!(text.contains(shared.to_str().unwrap()), "{text}");
    assert!(
        text.contains("lets Everyone (S-1-1-0) rename or delete what it contains (modify)"),
        "{text}"
    );
    apply_fix(&text);
    let (ok, stdout) = run(&root, &store);
    assert!(
        ok,
        "after the suggested fix the store must initialize: {stdout}"
    );
}
