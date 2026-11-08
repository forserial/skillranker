//! Shared test support.
//!
//! Per-invocation private stores so integration tests never touch the
//! operator's platform-default state (sr-ksjn): a `None` cache or ledger
//! directory resolves the real user store, and several pipeline tests were
//! recording events into the maintainer's actual ledger.

// Each including test uses only some of these helpers.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
pub fn base_store_root() -> &'static std::path::Path {
    use nix::sys::statfs::{TMPFS_MAGIC, statfs};
    let tmp = std::path::Path::new("/tmp");
    let var_tmp = std::path::Path::new("/var/tmp");
    if matches!(statfs(tmp), Ok(stat) if stat.filesystem_type() == TMPFS_MAGIC) && var_tmp.is_dir()
    {
        var_tmp
    } else {
        tmp
    }
}

#[cfg(target_os = "macos")]
pub fn base_store_root() -> &'static std::path::Path {
    std::path::Path::new("/tmp")
}

/// Windows: `%LOCALAPPDATA%\sr-tests`. `%TEMP%` cannot be used: it may grant
/// other local accounts (sandbox users, for one) rights to delete or rename
/// its children, which the private-storage ancestor rule refuses.
#[cfg(windows)]
pub fn base_store_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root =
            PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA")).join("sr-tests");
        std::fs::create_dir_all(&root).expect("create test store root");
        root
    })
}

/// Create `path` as a private store directory: mode 0700 on Unix; on Windows
/// owned by this user with a protected DACL for the user and SYSTEM, applied
/// at creation as sr itself does.
pub fn create_private_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("create private test store");
    }
    #[cfg(windows)]
    {
        let user = sr_win_sys::windows::token_user_sid().expect("token user");
        sr_win_sys::windows::create_directory_with(
            path,
            &format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
        )
        .expect("create private test store");
    }
}

/// A fresh owner-only directory for one store consumer. Each call returns a
/// unique path under root-owned sticky /tmp (or /var/tmp when /tmp is tmpfs on
/// Linux; `%LOCALAPPDATA%\sr-tests` on Windows), so parallel tests cannot share, lock, or contaminate one another's
/// stores, and nothing reaches the operator's platform-default cache or ledger.
pub fn private_store_dir(label: &str) -> PathBuf {
    let dir = base_store_root().join(format!(
        "sr-test-store-{}-{}-{}",
        std::process::id(),
        STORE_COUNTER.fetch_add(1, Ordering::Relaxed),
        label
    ));
    create_private_dir(&dir);
    dir
}
