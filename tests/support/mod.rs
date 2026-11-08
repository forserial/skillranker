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
pub fn create_private_dir(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("create private test store");
    }
    // Recursive like the Unix builder: missing parents are created first
    // (inheriting from their own parent), then `path` itself privately; an
    // existing directory is left as it is.
    #[cfg(windows)]
    {
        if path.is_dir() {
            return;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create test store parent");
        }
        let user = sr_win_sys::windows::token_user_sid().expect("token user");
        sr_win_sys::windows::create_directory_with(
            path,
            &format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
        )
        .expect("create private test store");
    }
}

/// The root under which suites name their own private fixture trees:
/// root-owned sticky `/tmp` on Unix (exactly as those suites always used);
/// `%LOCALAPPDATA%\sr-tests` on Windows, since `%TEMP%` may let other
/// local accounts replace its children.
pub fn tmp_root() -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from("/tmp");
    #[cfg(windows)]
    return base_store_root().to_path_buf();
}

/// Create `path` (whose parent exists) as an owner-only directory: exactly
/// `DirBuilder::new().mode(0o700).create(path)` on Unix; on Windows owned by
/// this user with a protected DACL for the user and SYSTEM.
pub fn private_dir(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .expect("create private test directory");
    }
    #[cfg(windows)]
    {
        let user = sr_win_sys::windows::token_user_sid().expect("token user");
        sr_win_sys::windows::create_directory_with(
            path,
            &format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
        )
        .expect("create private test directory");
    }
}

/// Make an existing file owner-only the way a fixture expects: mode 0600 on
/// Unix. On Windows a file in a private directory already inherits entries for
/// the user and SYSTEM only, which is owner-only, so there is nothing to do.
pub fn restrict_to_owner(path: impl AsRef<std::path::Path>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))
            .expect("restrict fixture to owner");
    }
    #[cfg(windows)]
    let _ = path;
}

/// Make a file or directory writable by every local user: mode 0666 (files)
/// or 0777 (directories) on Unix; on Windows an Everyone Modify entry, added
/// with the system's `icacls`.
pub fn share_with_everyone(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o777 } else { 0o666 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("share fixture with everyone");
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-1-0:(M)"])
            .output()
            .expect("run icacls");
        assert!(output.status.success(), "icacls: {output:?}");
    }
}

/// Assert that `path` is an owner-only file as `sr` exports one: mode 0600 on
/// Unix; on Windows owned by this user, with a protected DACL that allows only
/// this user and SYSTEM (docs/windows-private-storage.md rules 1 and 2).
pub fn assert_owner_only_file(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .access_mode(0x0002_0000 | 0x0080)
            .custom_flags(sr_win_sys::windows::FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        let descriptor = sr_win_sys::windows::security_of(&file).unwrap();
        let user = sr_win_sys::windows::token_user_sid().unwrap();
        assert_eq!(descriptor.owner, user, "{}", path.display());
        assert!(descriptor.dacl_protected(), "{descriptor:?}");
        let aces = descriptor.dacl.as_ref().unwrap();
        assert!(!aces.is_empty(), "{descriptor:?}");
        for ace in aces {
            assert_eq!(ace.kind, sr_win_sys::AceKind::Allowed, "{descriptor:?}");
            let sid = ace.sid.as_ref().unwrap();
            assert!(sid == &user || sid.is_local_system(), "{descriptor:?}");
        }
    }
}

/// Whether `text` names `path`, as written or JSON-escaped (Windows paths
/// carry backslashes, which JSON doubles).
pub fn mentions_path(text: &str, path: &std::path::Path) -> bool {
    let raw = path.to_str().unwrap();
    let escaped = serde_json::to_string(raw).unwrap();
    text.contains(raw) || text.contains(escaped.trim_matches('"'))
}

/// Make `link` a directory junction to `target` with the system's `mklink /J`.
/// Junctions need no privilege, unlike Windows symbolic links. `mklink` reads
/// `/` as an option prefix, so both paths are passed with `\` separators.
#[cfg(windows)]
pub fn junction(link: impl AsRef<std::path::Path>, target: impl AsRef<std::path::Path>) {
    let native = |path: &std::path::Path| path.to_str().unwrap().replace('/', "\\");
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(native(link.as_ref()))
        .arg(native(target.as_ref()))
        .output()
        .expect("run mklink");
    assert!(output.status.success(), "mklink /J: {output:?}");
}

/// `OpenOptions::owner_only`: mode 0600 for a new file on Unix. On Windows a
/// file created in a private directory inherits its user and SYSTEM entries,
/// so there is nothing to set.
pub trait OwnerOnly {
    fn owner_only(&mut self) -> &mut Self;
}

impl OwnerOnly for std::fs::OpenOptions {
    fn owner_only(&mut self) -> &mut Self {
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600);
        self
    }
}

/// Where `sr` keeps its ledger given the directory a test passes as
/// `XDG_DATA_HOME` (Unix: `<data>/sr`) and, on Windows, as `LOCALAPPDATA`
/// (`<data>\skillranker\ledger`).
pub fn ledger_under(data: &std::path::Path) -> PathBuf {
    #[cfg(unix)]
    return data.join("sr");
    #[cfg(windows)]
    return data.join("skillranker").join("ledger");
}

/// The workspace spelling sr sees: canonical on Unix; on Windows the fixture
/// path itself, since canonical Windows paths are verbatim (`\\?\C:\...`).
pub fn canonical(path: &std::path::Path) -> PathBuf {
    #[cfg(unix)]
    return std::fs::canonicalize(path).unwrap();
    #[cfg(windows)]
    return path.to_path_buf();
}

/// Claude Code's project directory name for a workspace path: separators
/// become `-` on Unix; on Windows every character that is not ASCII
/// alphanumeric (separators and the drive colon) does.
pub fn claude_project_name(workspace: &str) -> String {
    #[cfg(unix)]
    return workspace.replace('/', "-");
    #[cfg(windows)]
    return workspace
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
}

/// `Command::platform_env`: what a spawned `sr` needs beyond a cleared
/// environment on this platform. Windows needs `SystemRoot` to start Winsock;
/// Unix needs nothing.
pub trait PlatformEnv {
    fn platform_env(&mut self) -> &mut Self;
}

impl PlatformEnv for std::process::Command {
    fn platform_env(&mut self) -> &mut Self {
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            self.env("SystemRoot", root);
        }
        self
    }
}

/// A fresh owner-only directory for one store consumer. Each call returns a
/// unique path under root-owned sticky /tmp (or /var/tmp when /tmp is tmpfs on
/// Linux; `%LOCALAPPDATA%\sr-tests` on Windows), so parallel tests cannot
/// share, lock, or contaminate one another's stores, and nothing reaches the
/// operator's platform-default cache or ledger.
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
