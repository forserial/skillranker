//! Native Windows private-storage admission for the response cache
//! (sr-winpar.3), one refusal and one honest success per rule of
//! docs/windows-private-storage.md. Fixtures change ACLs with the system's
//! `icacls`, never by repairing what sr refused.
#![cfg(windows)]

mod support;

use skillranker::runtime::ProcessInvocation;
use skillranker::storage::{
    CACHE_FILE, CACHE_QUOTA_BYTES, CacheAccess, CacheLocation, CacheOpen, CacheStore, StoreError,
    open_cache,
};
use sr_win_sys::windows::{FILE_FLAG_BACKUP_SEMANTICS, security_of, token_user_sid};
use sr_win_sys::{AceKind, Sid};
use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn open(path: &Path, access: CacheAccess) -> Result<CacheOpen, StoreError> {
    let invocation = ProcessInvocation::enter().unwrap();
    let cx = invocation.request_cx().unwrap();
    let result = open_cache(
        &invocation,
        &cx,
        access,
        CacheLocation::Directory(path.to_owned()),
    );
    assert!(invocation.shutdown());
    result
}

fn ready(path: &Path) -> CacheStore {
    match open(path, CacheAccess::Initialize).unwrap() {
        CacheOpen::Ready(store) => *store,
        other => panic!("expected an initialized cache: {other:?}"),
    }
}

fn refused(path: &Path, access: CacheAccess) -> StoreError {
    match open(path, access) {
        Err(error) => error,
        Ok(other) => panic!("expected a refusal, got {other:?}"),
    }
}

/// A fresh ordinary (inheriting) directory under the shared test root.
fn parent(case: &str) -> PathBuf {
    let path = support::private_store_dir(case);
    // private_store_dir makes it private; tests below need an ordinary parent
    // whose ACL they can change, so they work one level down.
    let child = path.join("tree");
    fs::create_dir(&child).unwrap();
    child
}

fn icacls(path: &Path, args: &[&str]) {
    let system = std::env::var_os("SystemRoot").expect("SystemRoot");
    let status = Command::new(Path::new(&system).join(r"System32\icacls.exe"))
        .arg(path)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "icacls {} {args:?}", path.display());
}

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap()
}

fn user() -> Sid {
    token_user_sid().unwrap()
}

fn only_user_and_system(path: &Path) {
    let file = if path.is_dir() {
        open_dir(path)
    } else {
        File::open(path).unwrap()
    };
    let descriptor = security_of(&file).unwrap();
    assert_eq!(descriptor.owner, user(), "{}", path.display());
    let aces = descriptor.dacl.unwrap();
    assert!(
        aces.iter().all(|ace| ace.kind == AceKind::Allowed
            && ace
                .sid
                .as_ref()
                .is_some_and(|sid| *sid == user() || sid.is_local_system())),
        "{}: {aces:?}",
        path.display()
    );
}

#[test]
fn rule_7_a_fresh_store_is_created_private_and_reopens() {
    let root = parent("fresh");
    let path = root.join("sr").join("cache");
    let store = ready(&path);
    let stamp = store.stamp();
    drop(store);
    // Both created components carry the explicit descriptor, not the parent's.
    for dir in [root.join("sr"), path.clone()] {
        let descriptor = security_of(&open_dir(&dir)).unwrap();
        assert!(descriptor.dacl_protected(), "{}", dir.display());
        only_user_and_system(&dir);
    }
    only_user_and_system(&path.join(CACHE_FILE));
    match open(&path, CacheAccess::ExistingOnly).unwrap() {
        CacheOpen::Ready(store) => assert_eq!(store.stamp(), stamp),
        other => panic!("{other:?}"),
    }
    // SQLite's WAL sidecars inherit the store's entries and are admitted.
    let observer = rusqlite::Connection::open(path.join(CACHE_FILE)).unwrap();
    let mode: String = observer
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    for suffix in ["-wal", "-shm"] {
        let sidecar = path.join(format!("{CACHE_FILE}{suffix}"));
        if sidecar.exists() {
            only_user_and_system(&sidecar);
        }
    }
    drop(observer);
    assert_eq!(ready(&path).stamp(), stamp);
}

#[test]
fn rules_2_and_7_an_existing_inheriting_directory_is_refused_not_repaired() {
    let root = parent("inheriting");
    let path = root.join("cache");
    fs::create_dir(&path).unwrap();
    let before = security_of(&open_dir(&path)).unwrap();
    assert!(!before.dacl_protected());
    assert_eq!(
        refused(&path, CacheAccess::Initialize),
        StoreError::Permissions
    );
    assert_eq!(security_of(&open_dir(&path)).unwrap(), before);
    assert!(!path.join(CACHE_FILE).exists());
}

#[test]
fn rule_2_foreign_entries_and_enabled_inheritance_on_the_store_are_refused() {
    let root = parent("foreign");
    let path = root.join("cache");
    drop(ready(&path));
    // Users (S-1-5-32-545) may read.
    icacls(&path, &["/grant", "*S-1-5-32-545:(R)"]);
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::Permissions
    );
    icacls(&path, &["/remove:g", "*S-1-5-32-545"]);
    drop(ready(&path));

    // Inheritance switched back on brings the parent's entries in.
    icacls(&path, &["/inheritance:e"]);
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::Permissions
    );
    icacls(&path, &["/inheritance:r"]);
    drop(ready(&path));
}

#[test]
fn rule_2_a_capability_sid_is_refused_on_the_store_but_not_on_an_ancestor() {
    let capability = "*S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681";
    let root = parent("capability");
    let path = root.join("cache");
    drop(ready(&path));
    icacls(&root, &["/grant", &format!("{capability}:(F)")]);
    drop(ready(&path));
    icacls(&path, &["/grant", &format!("{capability}:(R)")]);
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::Permissions
    );
}

#[test]
fn rule_2_a_store_file_with_a_foreign_entry_is_refused() {
    let root = parent("file-acl");
    let path = root.join("cache");
    drop(ready(&path));
    let file = path.join(CACHE_FILE);
    icacls(&file, &["/grant", "*S-1-5-32-545:(R)"]);
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::Permissions
    );
    icacls(&file, &["/remove:g", "*S-1-5-32-545"]);
    drop(ready(&path));
}

#[test]
fn rule_3_replace_capable_rights_on_an_ancestor_are_refused_create_rights_are_not() {
    let root = parent("ancestor");
    let path = root.join("cache");
    drop(ready(&path));
    // Users may add files and subdirectories: cannot replace the store.
    icacls(&root, &["/grant", "*S-1-5-32-545:(AD,WD)"]);
    drop(ready(&path));
    // Users may delete children of the ancestor: could replace the store.
    icacls(&root, &["/grant", "*S-1-5-32-545:(DC)"]);
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::Permissions
    );
    icacls(&root, &["/remove:g", "*S-1-5-32-545"]);
    drop(ready(&path));
    // Inherit-only rights do not apply to the ancestor itself.
    icacls(&root, &["/grant", "*S-1-5-32-545:(OI)(CI)(IO)(F)"]);
    // The store's DACL is protected, so nothing reaches it either.
    drop(ready(&path));
}

#[test]
fn rule_3_a_junction_on_the_path_is_refused() {
    let root = parent("junction");
    let target = root.join("target");
    drop(ready(&target.join("cache")));
    let junction = root.join("alias");
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        refused(&junction.join("cache"), CacheAccess::ExistingOnly),
        StoreError::UnsafePath
    );
    assert_eq!(
        refused(&junction.join("new"), CacheAccess::Initialize),
        StoreError::UnsafePath
    );
    assert!(!target.join("new").exists());
    drop(ready(&target.join("cache")));
}

#[test]
fn rule_4_a_second_hard_link_to_the_database_is_refused() {
    let root = parent("hardlink");
    let path = root.join("cache");
    drop(ready(&path));
    let outside = root.join("copy.sqlite3");
    fs::hard_link(path.join(CACHE_FILE), &outside).unwrap();
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::UnsafePath
    );
    // A plain file left beside the store is an ordinary ancestor child.
    let fresh = root.join("other");
    drop(ready(&fresh));
}

#[test]
fn rule_4_a_directory_inside_the_store_is_refused() {
    let root = parent("subdir");
    let path = root.join("cache");
    drop(ready(&path));
    fs::create_dir(path.join("nested")).unwrap();
    assert_eq!(
        refused(&path, CacheAccess::ExistingOnly),
        StoreError::UnsafePath
    );
}

#[test]
fn rule_5_network_paths_are_refused_before_any_open() {
    let root = parent("unc");
    let local = root.join("cache");
    let text = local.to_str().unwrap();
    let drive = &text[..1];
    let unc = PathBuf::from(format!(r"\\localhost\{drive}$\{}", &text[3..]));
    assert_eq!(
        refused(&unc, CacheAccess::Initialize),
        StoreError::UnsupportedFilesystem
    );
    assert!(!local.exists());
    drop(ready(&local));
}

#[test]
fn rule_6_relative_and_device_paths_are_refused() {
    for path in [
        r"relative\cache",
        r"\\.\pipe\sr-cache",
        r"\\?\GLOBALROOT\Device\Null",
    ] {
        assert_eq!(
            refused(Path::new(path), CacheAccess::Initialize),
            StoreError::UnsafePath,
            "{path}"
        );
    }
}

#[test]
fn rule_8_an_oversized_store_is_refused_before_sqlite_runs() {
    let root = parent("quota");
    let path = root.join("cache");
    drop(ready(&path));
    let file = OpenOptions::new()
        .write(true)
        .open(path.join(CACHE_FILE))
        .unwrap();
    let before = file.metadata().unwrap().len();
    let filler = path.join("filler");
    let filler_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&filler)
        .unwrap();
    filler_file.set_len(CACHE_QUOTA_BYTES).unwrap();
    drop(filler_file);
    assert_eq!(refused(&path, CacheAccess::Initialize), StoreError::Quota);
    assert_eq!(file.metadata().unwrap().len(), before);
}

fn advance(
    store: CacheStore,
    expected: skillranker::storage::CacheStamp,
) -> Result<CacheStore, StoreError> {
    let invocation = ProcessInvocation::enter().unwrap();
    let cx = invocation.request_cx().unwrap();
    let result = store.advance_generation(&invocation, &cx, expected);
    assert!(invocation.shutdown());
    result
}

#[test]
fn rule_9_a_store_replaced_through_a_renamed_ancestor_is_detected() {
    let root = parent("ancestor-rename");
    let tree = root.join("tree");
    let path = tree.join("cache");
    let store = ready(&path);
    let stamp = store.stamp();
    // The store directory is held; its parent is not, as on Unix.
    match fs::rename(&tree, root.join("retained-original")) {
        Ok(()) => {
            eprintln!("ancestor-rename: renamed; checking StoreReplaced");
            let replacement = ready(&path);
            let replacement_stamp = replacement.stamp();
            drop(replacement);
            assert_eq!(
                advance(store, stamp).unwrap_err(),
                StoreError::StoreReplaced
            );
            assert_eq!(ready(&path).stamp(), replacement_stamp);
        }
        // Windows also refuses renaming a directory with an open
        // descendant; then nothing could be replaced and the store advances.
        Err(error) => {
            eprintln!("ancestor-rename: refused ({error}); store advances");
            assert_eq!(advance(store, stamp).unwrap().stamp().generation(), 1);
        }
    }
}

#[test]
fn rule_9_a_held_store_cannot_be_renamed_and_a_replaced_one_is_detected() {
    let root = parent("replace");
    let path = root.join("cache");
    let store = ready(&path);
    // Held without FILE_SHARE_DELETE: Windows refuses the rename.
    assert!(fs::rename(&path, root.join("moved")).is_err());
    drop(store);
    // Released, it can move; a new store at the old path is a new store.
    let first = ready(&path);
    let stamp = first.stamp();
    drop(first);
    fs::rename(&path, root.join("moved")).unwrap();
    let second = ready(&path);
    assert_ne!(second.stamp(), stamp);
}
