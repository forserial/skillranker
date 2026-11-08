//! Native reads against real NTFS objects (sr-winpar.2 spike).
#![cfg(windows)]

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sr_win_sys::acl::{CONTAINER_INHERIT, INHERITED, OBJECT_INHERIT};
use sr_win_sys::windows::{
    DRIVE_FIXED, FILE_FLAG_BACKUP_SEMANTICS, free_bytes_for_caller, security_of, token_user_sid,
    volume_of,
};
use sr_win_sys::{AceKind, Sid};

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sr-win-sys-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap()
}

fn icacls(path: &Path, args: &[&str]) {
    let system = std::env::var_os("SystemRoot").expect("SystemRoot");
    let status = Command::new(Path::new(&system).join(r"System32\icacls.exe"))
        .arg(path)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "icacls {args:?}");
}

#[test]
fn token_user_is_a_domain_or_local_account() {
    let user = token_user_sid().unwrap();
    assert_eq!(user.authority(), 5);
    assert!(!user.is_local_system() && !user.is_builtin_administrators());
    assert_eq!(Sid::from_bytes(&user.to_bytes()).unwrap(), user);
}

#[test]
fn fresh_temp_directory_inherits_an_unprotected_dacl() {
    let dir = scratch("fresh");
    let descriptor = security_of(&open_dir(&dir)).unwrap();
    let user = token_user_sid().unwrap();
    // A non-elevated token's default owner is the user; an elevated one may
    // make Administrators the owner.
    assert!(
        descriptor.owner == user || descriptor.owner.is_builtin_administrators(),
        "owner {}",
        descriptor.owner
    );
    assert!(!descriptor.dacl_protected());
    let aces = descriptor.dacl.expect("a DACL, not NULL");
    assert!(!aces.is_empty());
    assert!(aces.iter().all(|ace| ace.flags & INHERITED != 0));
    assert!(aces.iter().any(|ace| ace.kind == AceKind::Allowed));
}

#[test]
fn protected_explicit_dacl_and_deny_entries_are_read_back() {
    let dir = scratch("protected");
    let user = token_user_sid().unwrap();
    let grant = format!("*{user}:(OI)(CI)F");
    icacls(&dir, &["/inheritance:r", "/grant:r", &grant]);
    icacls(&dir, &["/deny", "*S-1-5-32-546:(DE)"]);

    let descriptor = security_of(&open_dir(&dir)).unwrap();
    assert!(descriptor.dacl_protected());
    let aces = descriptor.dacl.unwrap();
    assert_eq!(aces.len(), 2, "{aces:?}");
    let denied = aces.iter().find(|ace| ace.kind == AceKind::Denied).unwrap();
    assert_eq!(denied.mask, 0x0001_0000, "DELETE");
    assert_eq!(denied.sid.as_ref().unwrap().to_string(), "S-1-5-32-546");
    assert!(denied.applies_to_object());
    let allowed = aces
        .iter()
        .find(|ace| ace.kind == AceKind::Allowed)
        .unwrap();
    assert_eq!(allowed.sid.as_ref(), Some(&user));
    assert_eq!(allowed.flags, OBJECT_INHERIT | CONTAINER_INHERIT);
    assert_eq!(allowed.mask, 0x001F_01FF, "FILE_ALL_ACCESS");

    // A file created inside inherits only the user's entry.
    let file_path = dir.join("store.sqlite3");
    fs::write(&file_path, b"x").unwrap();
    let file = security_of(&File::open(&file_path).unwrap()).unwrap();
    let inherited = file.dacl.unwrap();
    assert_eq!(inherited.len(), 1);
    assert_eq!(inherited[0].sid.as_ref(), Some(&user));
    assert!(inherited[0].is_inherited());
    icacls(&dir, &["/remove:d", "*S-1-5-32-546"]);
}

#[test]
fn temp_volume_is_a_local_fixed_ntfs_or_refs_volume() {
    let dir = scratch("volume");
    let file = open_dir(&dir);
    let volume = volume_of(&file).unwrap();
    assert!(
        matches!(volume.filesystem.as_str(), "NTFS" | "ReFS"),
        "{}",
        volume.filesystem
    );
    assert_eq!(volume.drive_type, Some(DRIVE_FIXED));
    assert!(volume.guid_root.is_some());
    assert!(
        volume.remote_protocol.is_err(),
        "local file reported remote"
    );
    let final_path = volume.final_path.to_string_lossy().to_lowercase();
    assert!(final_path.starts_with(r"\\?\"), "{final_path}");
    assert!(final_path.ends_with(&dir.file_name().unwrap().to_string_lossy().to_lowercase()));
    assert!(free_bytes_for_caller(&file).unwrap() > 0);
}
