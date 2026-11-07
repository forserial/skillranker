//! Symbolic links for test fixtures on every platform (sr-winpar.25). Include
//! with `#[path = "support/links.rs"] mod links;`.
//!
//! Unix has one kind of symbolic link. Windows has file and directory links,
//! chosen when the link is made: a target that is (or, relative to the link,
//! resolves to) a directory gets a directory link, anything else, including a
//! dangling target, a file link. Creating them needs Developer Mode or an
//! elevated token on Windows; `available()` lets a case skip with that reason
//! instead of failing, as tests/windows_platform.rs does.

// Each including test uses only some of these helpers.
#![allow(dead_code)]

use std::io;
use std::path::Path;

/// Create `link` pointing at `target` (absolute, or relative to `link`'s
/// directory), with the link kind the platform needs.
pub fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let (target, link) = (target.as_ref(), link.as_ref());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        let resolved = if target.is_absolute() {
            target.to_path_buf()
        } else {
            link.parent().unwrap_or(Path::new(".")).join(target)
        };
        if resolved.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }
}

/// Remove a symbolic link itself (never its target). Windows deletes a
/// directory link with `remove_dir`, so `remove_file` alone would fail there.
pub fn remove(link: impl AsRef<Path>) -> io::Result<()> {
    let link = link.as_ref();
    match std::fs::remove_file(link) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(_) if std::fs::symlink_metadata(link).is_ok_and(|m| m.file_type().is_symlink()) => {
            std::fs::remove_dir(link)
        }
        Err(error) => Err(error),
    }
}

/// Whether this process may create symbolic links. Always true on Unix; on
/// Windows, probed once. When false, the caller prints the reason and returns.
pub fn available() -> bool {
    #[cfg(unix)]
    {
        true
    }
    #[cfg(windows)]
    {
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
            let probe = std::env::temp_dir().join(format!(
                "sr-link-probe-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            // Intentionally retained, like other fixtures: repository policy
            // forbids automatic deletion.
            match std::os::windows::fs::symlink_file("target", &probe) {
                Ok(()) => true,
                Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
                    eprintln!("skipped: creating symbolic links needs Developer Mode or elevation");
                    false
                }
                Err(error) => panic!("probe symbolic link creation: {error}"),
            }
        })
    }
}
