//! Native Windows owner-only exports (sr-winpar.6): the twins of
//! tests/export_contract.rs. Fixtures change ACLs with the system's `icacls`
//! and make junctions with `mklink /J`, never by repairing what sr refused.
#![cfg(windows)]

mod support;

use skillranker::storage::export::{ExportConfig, ExportError, export_private_atomic};
use sr_win_sys::windows::{FILE_FLAG_BACKUP_SEMANTICS, security_of};
use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

static NEXT: AtomicU64 = AtomicU64::new(0);

// Retain real fixtures; the repository does not authorize deleting test trees.
fn tree() -> PathBuf {
    let path = support::tmp_root().join(format!(
        "sr-export-windows-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    support::private_dir(&path);
    path
}

fn icacls(path: &Path, args: &[&str]) {
    let output = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "icacls {args:?}: {output:?}");
}

fn entries(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn safe_export_keeps_content_permissions_and_existing_targets() {
    let root = tree();
    let target = root.join("snapshot.json");
    export_private_atomic(&target, b"public test content", ExportConfig::default()).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"public test content");
    support::assert_owner_only_file(&target);
    assert!(matches!(
        export_private_atomic(&target, b"replacement", ExportConfig::default()),
        Err(ExportError::TargetAlreadyExists(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"public test content");
    assert_eq!(entries(&root), ["snapshot.json"]);
}

#[test]
fn an_existing_directory_or_dangling_junction_at_the_target_is_kept() {
    let root = tree();
    fs::create_dir(root.join("taken")).unwrap();
    support::junction(root.join("dangling"), root.join("missing"));
    for name in ["taken", "dangling"] {
        assert!(matches!(
            export_private_atomic(&root.join(name), b"content", ExportConfig::default()),
            Err(ExportError::TargetAlreadyExists(_))
        ));
    }
    assert!(fs::symlink_metadata(root.join("dangling")).is_ok());
    assert!(!root.join("missing").exists());
    assert_eq!(entries(&root), ["dangling", "taken"]);
}

#[test]
fn concurrent_exporters_publish_exactly_one_winner() {
    let root = tree();
    let target = root.join("raced.json");
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let target = target.clone();
            std::thread::spawn(move || {
                let content = format!("writer {index}");
                barrier.wait();
                export_private_atomic(&target, content.as_bytes(), ExportConfig::default())
                    .map(|()| content)
            })
        })
        .collect();
    let mut winners = Vec::new();
    for handle in handles {
        match handle.join().unwrap() {
            Ok(content) => winners.push(content),
            Err(ExportError::TargetAlreadyExists(_)) => {}
            Err(error) => panic!("unexpected export error: {error}"),
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    assert_eq!(fs::read_to_string(&target).unwrap(), winners[0]);
    support::assert_owner_only_file(&target);
    // Every loser removed its temporary file.
    assert_eq!(entries(&root), ["raced.json"]);
}

#[test]
fn untrusted_ancestor_cannot_redirect_a_private_export() {
    let root = tree();
    let shared = root.join("shared");
    support::private_dir(&shared);
    // Everyone may rename or delete the children of `shared` (rule 3).
    icacls(&shared, &["/grant", "*S-1-1-0:(M)"]);
    let private = shared.join("private");
    support::private_dir(&private);
    let target = private.join("snapshot.json");
    let error = export_private_atomic(&target, b"private test content", ExportConfig::default())
        .unwrap_err();
    assert!(matches!(error, ExportError::Permissions(_)), "{error}");
    assert!(!target.exists());
    assert!(entries(&private).is_empty());
}

#[test]
fn a_destination_others_can_write_is_refused() {
    let root = tree();
    let leaf = root.join("writable");
    support::private_dir(&leaf);
    // Everyone may add files, though not delete or re-permission: the Windows
    // reading of a group/other write bit on the destination directory.
    icacls(&leaf, &["/grant", "*S-1-1-0:(W)"]);
    let error = export_private_atomic(
        &leaf.join("snapshot.json"),
        b"content",
        ExportConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ExportError::Permissions(_)), "{error}");
    assert!(entries(&leaf).is_empty());
    // A destination others may only read is a configuration directory, as a
    // Unix 0755 directory is.
    let readable = root.join("readable");
    support::private_dir(&readable);
    icacls(&readable, &["/grant", "*S-1-1-0:(RX)"]);
    export_private_atomic(
        &readable.join("snapshot.json"),
        b"content",
        ExportConfig::default(),
    )
    .unwrap();
    support::assert_owner_only_file(readable.join("snapshot.json"));
}

#[test]
fn a_junction_in_the_destination_path_is_not_an_export_authority() {
    let root = tree();
    let actual = root.join("actual");
    support::private_dir(&actual);
    let inner = actual.join("inner");
    support::private_dir(&inner);
    support::junction(root.join("alias"), &actual);
    let error = export_private_atomic(
        &root.join(r"alias\inner\snapshot.json"),
        b"private test content",
        ExportConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ExportError::InvalidDirectory(_)), "{error}");
    // A junction as the destination directory itself is refused too.
    let error = export_private_atomic(
        &root.join(r"alias\snapshot.json"),
        b"private test content",
        ExportConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ExportError::InvalidDirectory(_)), "{error}");
    assert!(entries(&inner).is_empty());
    assert_eq!(entries(&actual), ["inner"]);
}

#[test]
fn a_missing_destination_directory_is_not_created() {
    let root = tree();
    let error = export_private_atomic(
        &root.join(r"missing\snapshot.json"),
        b"content",
        ExportConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ExportError::InvalidDirectory(_)), "{error}");
    assert!(entries(&root).is_empty());
}

#[test]
fn oversized_content_is_refused_before_any_effect() {
    let root = tree();
    let target = root.join("big.json");
    let error =
        export_private_atomic(&target, &[b'x'; 17], ExportConfig { max_bytes: 16 }).unwrap_err();
    assert!(
        matches!(error, ExportError::Oversized { len: 17, max: 16 }),
        "{error}"
    );
    assert!(entries(&root).is_empty());
}

#[test]
fn valid_long_target_name_does_not_overflow_the_temporary_name() {
    let root = tree();
    // A 240-unit name puts the full path past MAX_PATH.
    let target = root.join("x".repeat(240));
    assert!(target.as_os_str().len() > 260);
    export_private_atomic(&target, b"long-name content", ExportConfig::default()).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"long-name content");
    support::assert_owner_only_file(&target);
    assert_eq!(entries(&root).len(), 1);
}

#[test]
fn reserved_device_names_are_not_targets() {
    let root = tree();
    for name in ["CON", "nul.json", "COM1", "trailing."] {
        let error = export_private_atomic(&root.join(name), b"content", ExportConfig::default())
            .unwrap_err();
        assert!(
            matches!(error, ExportError::InvalidDirectory(_)),
            "{name}: {error}"
        );
    }
    assert!(entries(&root).is_empty());
}

#[test]
fn relative_destinations_and_parent_components_keep_their_win32_meaning() {
    const CHILD: &str = "SKILLRANKER_EXPORT_RELATIVE_FIXTURE";
    if let Some(root) = std::env::var_os(CHILD) {
        // The child runs only this test; changing directory cannot race
        // sibling tests.
        std::env::set_current_dir(&root).unwrap();
        export_private_atomic(
            Path::new("relative.json"),
            b"relative content",
            ExportConfig::default(),
        )
        .unwrap();
        // Win32 resolves `..` lexically, so `child\..` is the current
        // directory even when `child` is a junction elsewhere.
        export_private_atomic(
            Path::new(r"child\..\parent.json"),
            b"parent content",
            ExportConfig::default(),
        )
        .unwrap();
        return;
    }
    let root = tree();
    let elsewhere = root.join("elsewhere");
    support::private_dir(&elsewhere);
    let cwd = root.join("cwd");
    support::private_dir(&cwd);
    support::junction(cwd.join("child"), &elsewhere);
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "relative_destinations_and_parent_components_keep_their_win32_meaning",
            "--nocapture",
        ])
        .env(CHILD, &cwd)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "isolated child failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(cwd.join("relative.json")).unwrap(),
        b"relative content"
    );
    assert_eq!(
        fs::read(cwd.join("parent.json")).unwrap(),
        b"parent content"
    );
    support::assert_owner_only_file(cwd.join("parent.json"));
    assert!(entries(&elsewhere).is_empty());
}

#[test]
fn an_inherited_descriptor_is_not_what_an_export_produces() {
    // Control for assert_owner_only: a file created normally in a private
    // directory inherits its entries but is not protected, so the export's
    // protected descriptor is something the export itself applied.
    let root = tree();
    let plain = root.join("plain.json");
    File::create(&plain).unwrap();
    let file = OpenOptions::new()
        .access_mode(0x0002_0000)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&plain)
        .unwrap();
    assert!(!security_of(&file).unwrap().dacl_protected());
}
