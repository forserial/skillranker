//! Platform-specific admission, shared by cache and ledger descriptor walks.

#[cfg(unix)]
pub(super) use crate::filesystem_policy::local_filesystem;
pub(crate) use crate::platform_path::storage_path;

#[cfg(unix)]
pub(super) type DirectoryIdentity = (nix::libc::dev_t, nix::libc::ino_t);
/// Volume serial number and file index.
#[cfg(windows)]
pub(super) type DirectoryIdentity = super::windows_private::Identity;
