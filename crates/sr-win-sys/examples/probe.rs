//! Prints a sanitized summary of a directory's owner, DACL and volume
//! (sr-winpar.2 spike): `cargo run -p sr-win-sys --example probe [DIR]`.
//! The default is %LOCALAPPDATA%. SIDs are printed by role, never in full.

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    use sr_win_sys::Sid;
    use sr_win_sys::acl::{CONTAINER_INHERIT, INHERIT_ONLY, INHERITED, OBJECT_INHERIT};
    use sr_win_sys::windows::{
        FILE_FLAG_BACKUP_SEMANTICS, free_bytes_for_caller, security_of, token_user_sid, volume_of,
    };

    let path = std::env::args_os()
        .nth(1)
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .expect("pass a directory or set LOCALAPPDATA");
    let user = token_user_sid()?;
    let role = |sid: &Sid| -> String {
        if *sid == user {
            "user".into()
        } else if sid.is_local_system() {
            "SYSTEM".into()
        } else if sid.is_builtin_administrators() {
            "Administrators".into()
        } else if sid.is_trusted_installer() {
            "TrustedInstaller".into()
        } else if sid.is_capability() {
            "capability S-1-15-3-…".into()
        } else if sid.authority() == 5 && sid.sub_authorities().first() == Some(&32) {
            format!("builtin {sid}")
        } else if sid.authority() == 1 || sid.authority() == 5 && sid.sub_authorities().len() == 1 {
            format!("well-known {sid}")
        } else {
            "other account".into()
        }
    };

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&path)?;
    let descriptor = security_of(&dir)?;
    println!("owner: {}", role(&descriptor.owner));
    println!("dacl protected: {}", descriptor.dacl_protected());
    match &descriptor.dacl {
        None => println!("dacl: NULL (everyone full access)"),
        Some(aces) => {
            for ace in aces {
                let mut flags = Vec::new();
                for (bit, name) in [
                    (INHERITED, "inherited"),
                    (INHERIT_ONLY, "inherit-only"),
                    (OBJECT_INHERIT, "OI"),
                    (CONTAINER_INHERIT, "CI"),
                ] {
                    if ace.flags & bit != 0 {
                        flags.push(name);
                    }
                }
                let who = ace.sid.as_ref().map_or_else(|| "-".to_string(), &role);
                println!(
                    "ace: {:?} mask=0x{:08X} [{}] {who}",
                    ace.kind,
                    ace.mask,
                    flags.join(",")
                );
            }
        }
    }
    let volume = volume_of(&dir)?;
    println!(
        "volume: fs={} drive_type={:?} guid_root={} remote_protocol={:?} flags=0x{:08X}",
        volume.filesystem,
        volume.drive_type,
        volume.guid_root.is_some(),
        volume.remote_protocol,
        volume.flags
    );
    println!(
        "free for caller: {} GiB",
        free_bytes_for_caller(&dir)? >> 30
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("probe reads Windows security descriptors; nothing to do here");
}
