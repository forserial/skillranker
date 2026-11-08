//! Private, local cache directory admission. All opens walk trusted descriptors.

#[cfg(unix)]
use super::platform::local_filesystem;
#[cfg(any(unix, windows))]
use super::platform::{DirectoryIdentity, storage_path};
#[cfg(any(unix, windows))]
use super::{
    CACHE_FILE, CACHE_QUOTA_BYTES, CacheCapacityReport, MAINTENANCE_RESERVE_BYTES,
    MUTATION_RESERVE_BYTES, StoreError, check_work,
};
#[cfg(any(unix, windows))]
use crate::runtime::EntryClock;
#[cfg(any(unix, windows))]
use asupersync::Cx;
#[cfg(unix)]
use nix::dir::Dir;
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::fcntl::{AtFlags, OFlag, open, openat};
#[cfg(unix)]
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat, mkdirat};
#[cfg(unix)]
use nix::sys::statfs::fstatfs;
#[cfg(unix)]
use nix::sys::statvfs::fstatvfs;
#[cfg(any(unix, windows))]
use std::fs::File;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

// Bound metadata work even when many empty files consume no byte quota. The
// normal cache has only its database and SQLite sidecars. No file is removed
// when this limit is exceeded; optional caching is refused instead.
#[cfg(any(unix, windows))]
const MAX_CACHE_DIRECTORY_ENTRIES: usize = 4096;

/// Inspect the held directory, not a second pathname that may name a different
/// directory. Open a fresh directory stream: dup/try_clone would share an offset
/// with the held descriptor and concurrent or repeated scans could skip files.
/// Names remain OS bytes all the way from readdir to no-follow fstatat.
#[cfg(unix)]
fn inspect_directory(
    handle: &File,
    max_entries: usize,
    quota_bytes: u64,
    mut checkpoint: impl FnMut() -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    checkpoint()?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = openat(handle, c".", flags, Mode::empty()).map_err(io_error)?;
    let mut directory = Dir::from_fd(fd).map_err(io_error)?;
    let mut entries = directory.iter();
    let uid = nix::unistd::geteuid().as_raw();
    let mut seen = 0_usize;
    let mut bytes = 0_u64;
    loop {
        checkpoint()?;
        let Some(entry) = entries.next() else {
            // The final readdir may itself have consumed the remaining budget.
            checkpoint()?;
            return Ok(bytes);
        };
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if seen >= max_entries {
            return Err(StoreError::Quota);
        }
        seen += 1;
        checkpoint()?;
        match fstatat(handle, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                owned_regular(&stat, uid)?;
                bytes = bytes
                    .checked_add(u64::try_from(stat.st_size).map_err(|_| StoreError::Quota)?)
                    .filter(|total| *total <= quota_bytes)
                    .ok_or(StoreError::Quota)?;
            }
            // SQLite may remove a sidecar during inspection. Count the visited
            // name against the work cap even when it has just disappeared.
            Err(Errno::ENOENT) => {}
            Err(error) => return Err(io_error(error)),
        }
    }
}

/// Walk from `/` to the owner-only directory `path` through no-follow
/// descriptors: every ancestor root- or user-owned and not group- or
/// other-writable (root-owned sticky directories excepted), the leaf owned by
/// the user with mode 0700. Missing components are created with mode 0700 when
/// `create`, after checking that the parent is on an admitted local filesystem
/// when `require_local`. Existing directories are never repaired. Returns the
/// held leaf and its identity.
#[cfg(unix)]
fn walk_private(
    path: &Path,
    create: bool,
    require_local: bool,
    mut checkpoint: impl FnMut() -> Result<(), StoreError>,
) -> Result<(File, DirectoryIdentity), StoreError> {
    // Bound path parsing before collecting components or making syscalls.
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(StoreError::UnsafePath);
    }
    let components: Vec<_> = path.components().collect();
    if components.len() < 2
        || components.len() > 128
        || components
            .iter()
            .skip(1)
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(StoreError::UnsafePath);
    }
    let uid = nix::unistd::geteuid().as_raw();
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut handle = open(Path::new("/"), flags, Mode::empty()).map_err(io_error)?;
    trusted_ancestor(&fstat(&handle).map_err(io_error)?, uid, false)?;
    for (i, component) in components.iter().enumerate().skip(1) {
        checkpoint()?;
        let name = component.as_os_str();
        let opened = match openat(&handle, name, flags, Mode::empty()) {
            Err(Errno::ENOENT) if create => {
                if require_local && !local_filesystem(&fstatfs(&handle).map_err(io_error)?) {
                    return Err(StoreError::UnsupportedFilesystem);
                }
                match mkdirat(&handle, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(error) => return Err(io_error(error)),
                }
                openat(&handle, name, flags, Mode::empty()).map_err(io_error)?
            }
            result => result.map_err(io_error)?,
        };
        trusted_ancestor(
            &fstat(&opened).map_err(io_error)?,
            uid,
            i + 1 == components.len(),
        )?;
        handle = opened;
    }
    let stat = fstat(&handle).map_err(io_error)?;
    Ok((handle.into(), (stat.st_dev, stat.st_ino)))
}

/// Write `bytes` to the new owner-only file `name` in the owner-only directory
/// `path`, such as an installer settings backup (sr-winpar.7). The directory is
/// walked and created by [`walk_private`] on any filesystem, as exports accept
/// any filesystem. The file is created exclusively without following links,
/// set to mode 0600 (a failure is an error, not ignored), written, flushed,
/// checked as a single-link 0600 regular file owned by the user, and the
/// directory is flushed and revalidated. A partly written file of ours is
/// removed; nothing existing is repaired or replaced.
#[cfg(unix)]
pub(crate) fn write_private_file(
    path: &Path,
    name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<PathBuf, StoreError> {
    use nix::sys::stat::fchmod;
    use nix::unistd::{UnlinkatFlags, unlinkat};
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(StoreError::UnsafePath);
    }
    let path = storage_path(path.to_owned());
    let (directory, identity) = walk_private(&path, true, false, || Ok(()))?;
    let fd = openat(
        &directory,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(io_error)?;
    let mut file = File::from(fd);
    let written = (|| {
        // Exact mode on our own descriptor, whatever the umask.
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(io_error)?;
        file.write_all(bytes).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        owned_regular(
            &fstat(&file).map_err(io_error)?,
            nix::unistd::geteuid().as_raw(),
        )?;
        directory.sync_all().map_err(|_| StoreError::Io)?;
        let (_, current) = walk_private(&path, false, false, || Ok(()))?;
        if current != identity {
            return Err(StoreError::StoreReplaced);
        }
        Ok(())
    })();
    if let Err(error) = written {
        drop(file);
        let _ = unlinkat(&directory, name, UnlinkatFlags::NoRemoveDir);
        return Err(error);
    }
    Ok(path.join(name))
}

#[cfg(unix)]
pub(super) struct PrivateDirectory {
    pub path: PathBuf,
    handle: File,
    identity: DirectoryIdentity,
}

#[cfg(unix)]
fn io_error(error: Errno) -> StoreError {
    match error {
        Errno::ENOENT => StoreError::Missing,
        Errno::ELOOP | Errno::ENOTDIR => StoreError::UnsafePath,
        Errno::EACCES | Errno::EPERM => StoreError::Permissions,
        _ => StoreError::Io,
    }
}

#[cfg(unix)]
fn owned_regular(stat: &FileStat, uid: u32) -> Result<(), StoreError> {
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG || stat.st_nlink != 1 {
        return Err(StoreError::UnsafePath);
    }
    if stat.st_uid != uid || stat.st_mode & 0o7777 != 0o600 {
        return Err(StoreError::Permissions);
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_ancestor(stat: &FileStat, uid: u32, leaf: bool) -> Result<(), StoreError> {
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(StoreError::UnsafePath);
    }
    if leaf {
        if stat.st_uid != uid || stat.st_mode & 0o7777 != 0o700 {
            return Err(StoreError::Permissions);
        }
    } else if (stat.st_uid != 0 && stat.st_uid != uid)
        || (stat.st_mode & 0o022 != 0 && !(stat.st_uid == 0 && stat.st_mode & 0o1000 != 0))
    {
        // Root-owned sticky /tmp is safe for an owner-only child. Arbitrary
        // shared writable ancestors can rename the child and are refused.
        return Err(StoreError::Permissions);
    }
    Ok(())
}

/// What an owner-only refusal was actually about.
///
/// `StoreError::Permissions` stays a unit variant: it is matched in a dozen places and compared
/// directly in tests, and widening it would ripple for no benefit. This walks the same chain
/// `PrivateDirectory::open` walks and applies the same two predicates, then reports the FIRST path
/// that fails and what it must be, so a person is told which directory to chmod instead of being
/// pointed at their configuration (sr-488b).
///
/// Diagnosis only: it opens nothing for writing and changes nothing. It re-stats by path rather
/// than reusing the trusted descriptor walk, which is acceptable precisely because it is not the
/// admission decision — the refusal has already happened, and this only explains it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRefusal {
    pub path: PathBuf,
    pub actual_mode: u32,
    pub required: RequiredMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredMode {
    /// The store's own directory: owned by this user and exactly 0o700.
    OwnerOnlyDirectory,
    /// The store's file: owned by this user and exactly 0o600.
    OwnerOnlyFile,
    /// An ancestor: not group- or other-writable, unless it is root-owned and sticky as /tmp is.
    NotSharedWritable,
    /// Owned by neither this user nor root.
    OwnedByAnotherUser,
}

impl PermissionRefusal {
    /// The one line a person needs: which path, what it is now, what it must be.
    pub fn describe(&self) -> String {
        match self.required {
            RequiredMode::OwnerOnlyDirectory => format!(
                "{} is mode {:04o}; the store directory must be owned by you and mode 0700",
                self.path.display(),
                self.actual_mode
            ),
            RequiredMode::OwnerOnlyFile => format!(
                "{} is mode {:04o}; the store file must be owned by you and mode 0600",
                self.path.display(),
                self.actual_mode
            ),
            RequiredMode::NotSharedWritable => format!(
                "{} is mode {:04o} and is writable by group or others; every directory above the \
                 store must be owner-only, or root-owned and sticky as /tmp is",
                self.path.display(),
                self.actual_mode
            ),
            RequiredMode::OwnedByAnotherUser => format!(
                "{} is owned by another user; the store and every directory above it must be owned \
                 by you or by root",
                self.path.display()
            ),
        }
    }

    /// The command that fixes it, which is what the old hint should have said.
    pub fn remedy(&self) -> Option<String> {
        match self.required {
            RequiredMode::OwnerOnlyDirectory => Some(format!("chmod 700 {}", self.path.display())),
            RequiredMode::OwnerOnlyFile => Some(format!("chmod 600 {}", self.path.display())),
            RequiredMode::NotSharedWritable => Some(format!("chmod go-w {}", self.path.display())),
            RequiredMode::OwnedByAnotherUser => None,
        }
    }
}

/// Names the first path in the chain that fails the owner-only rules, or `None` when the chain is
/// fine and the refusal came from somewhere else — a read-only filesystem, for instance. `None` is
/// not a claim that nothing is wrong; it means this is not the thing that was wrong.
#[cfg(unix)]
pub fn diagnose_owner_only(path: &Path) -> Option<PermissionRefusal> {
    use std::os::unix::fs::MetadataExt;
    let uid = nix::unistd::getuid().as_raw();
    let mut walked = PathBuf::from("/");
    let components: Vec<_> = path.components().collect();
    let last = components.len().saturating_sub(1);
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => walked.push(part),
            // A relative or unnormalized path is not this function's business to interpret.
            _ => return None,
        }
        let Ok(meta) = std::fs::symlink_metadata(&walked) else {
            // A path that does not exist yet is not a permission problem.
            return None;
        };
        let mode = meta.mode() & 0o7777;
        let owner = meta.uid();
        let leaf = index == last;
        if meta.is_file() {
            if owner != uid {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::OwnedByAnotherUser,
                });
            }
            if mode != 0o600 {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::OwnerOnlyFile,
                });
            }
            continue;
        }
        if leaf {
            if owner != uid {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::OwnedByAnotherUser,
                });
            }
            if mode != 0o700 {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::OwnerOnlyDirectory,
                });
            }
        } else {
            if owner != 0 && owner != uid {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::OwnedByAnotherUser,
                });
            }
            let sticky_root = owner == 0 && mode & 0o1000 != 0;
            if mode & 0o022 != 0 && !sticky_root {
                return Some(PermissionRefusal {
                    path: walked,
                    actual_mode: mode,
                    required: RequiredMode::NotSharedWritable,
                });
            }
        }
    }
    None
}

#[cfg(any(unix, windows))]
fn recording_capacity(bytes: u64, available: u128) -> Result<(), StoreError> {
    if bytes > CACHE_QUOTA_BYTES - MAINTENANCE_RESERVE_BYTES - MUTATION_RESERVE_BYTES {
        return Err(StoreError::Quota);
    }
    if available < u128::from(MAINTENANCE_RESERVE_BYTES + MUTATION_RESERVE_BYTES) {
        return Err(StoreError::InsufficientSpace);
    }
    Ok(())
}

// `platform_support::PRIVATE_STORAGE` reports which open below this build has.
#[cfg(any(unix, windows))]
const _: () = assert!(crate::platform_support::PRIVATE_STORAGE);
#[cfg(not(any(unix, windows)))]
const _: () = assert!(!crate::platform_support::PRIVATE_STORAGE);

#[cfg(unix)]
impl PrivateDirectory {
    pub fn open(
        path: PathBuf,
        create: bool,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<Self, StoreError> {
        let path = storage_path(path);
        let (handle, identity) = walk_private(&path, create, true, || check_work(clock, cx))?;
        let directory = Self {
            path,
            handle,
            identity,
        };
        if create {
            directory.admit_space_with(|| check_work(clock, cx))?;
        } else {
            directory.inspect_files_with(|| check_work(clock, cx))?;
        }
        Ok(directory)
    }

    pub fn database_path(&self) -> PathBuf {
        self.path.join(CACHE_FILE)
    }

    pub fn revalidate(&self, clock: EntryClock, cx: &Cx) -> Result<(), StoreError> {
        // SQLite opens a pathname, not our directory descriptor. Reject any
        // changed ancestor or leaf before each effect; NOFOLLOW also protects
        // its main-file open. Same-uid hostile filesystem mutation is outside
        // this owner-only boundary, as it can already modify private contents.
        let (_, identity) = walk_private(&self.path, false, true, || check_work(clock, cx))?;
        if identity != self.identity {
            return Err(StoreError::StoreReplaced);
        }
        Ok(())
    }

    pub fn inspect_files(&self) -> Result<u64, StoreError> {
        self.inspect_files_with(|| Ok(()))
    }

    fn inspect_files_with(
        &self,
        checkpoint: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<u64, StoreError> {
        inspect_directory(
            &self.handle,
            MAX_CACHE_DIRECTORY_ENTRIES,
            CACHE_QUOTA_BYTES,
            checkpoint,
        )
    }

    pub fn capacity_report(&self) -> Result<CacheCapacityReport, StoreError> {
        let occupied_bytes = self.inspect_files()?;
        let stat = fstatvfs(&self.handle).map_err(io_error)?;
        let available_disk_bytes =
            u64::try_from(u128::from(stat.blocks_available()) * u128::from(stat.fragment_size()))
                .unwrap_or(u64::MAX);

        let recording_ceiling_bytes = CACHE_QUOTA_BYTES
            .saturating_sub(MAINTENANCE_RESERVE_BYTES)
            .saturating_sub(MUTATION_RESERVE_BYTES);

        let usable_recording_bytes = recording_ceiling_bytes.saturating_sub(occupied_bytes);

        let is_recording_admitted = occupied_bytes <= recording_ceiling_bytes
            && (available_disk_bytes as u128)
                >= u128::from(MAINTENANCE_RESERVE_BYTES + MUTATION_RESERVE_BYTES);

        Ok(CacheCapacityReport {
            total_quota_bytes: CACHE_QUOTA_BYTES,
            maintenance_reserve_bytes: MAINTENANCE_RESERVE_BYTES,
            mutation_reserve_bytes: MUTATION_RESERVE_BYTES,
            recording_ceiling_bytes,
            occupied_bytes,
            usable_recording_bytes,
            available_disk_bytes,
            is_recording_admitted,
        })
    }

    pub fn admit_space(&self) -> Result<(), StoreError> {
        self.admit_space_with(|| Ok(()))
    }

    fn admit_space_with(
        &self,
        mut checkpoint: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        checkpoint()?;
        if !local_filesystem(&fstatfs(&self.handle).map_err(io_error)?) {
            return Err(StoreError::UnsupportedFilesystem);
        }
        let bytes = self.inspect_files_with(&mut checkpoint)?;
        checkpoint()?;
        let stat = fstatvfs(&self.handle).map_err(io_error)?;
        let available = u128::from(stat.blocks_available()) * u128::from(stat.fragment_size());
        recording_capacity(bytes, available)
    }

    pub fn open_database_file(
        &self,
        create: bool,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<File, StoreError> {
        self.revalidate(clock, cx)?;
        if create {
            self.admit_space_with(|| check_work(clock, cx))?;
        } else {
            self.inspect_files_with(|| check_work(clock, cx))?;
        }
        let flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let fd = match openat(&self.handle, CACHE_FILE, flags, Mode::empty()) {
            Err(Errno::ENOENT) if create => match openat(
                &self.handle,
                CACHE_FILE,
                flags | OFlag::O_CREAT | OFlag::O_EXCL,
                Mode::from_bits_truncate(0o600),
            ) {
                Err(Errno::EEXIST) => {
                    openat(&self.handle, CACHE_FILE, flags, Mode::empty()).map_err(io_error)?
                }
                result => result.map_err(io_error)?,
            },
            result => result.map_err(io_error)?,
        };
        owned_regular(
            &fstat(&fd).map_err(io_error)?,
            nix::unistd::geteuid().as_raw(),
        )?;
        Ok(fd.into())
    }

    pub fn verify_database_file(
        &self,
        file: &File,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<(), StoreError> {
        self.revalidate(clock, cx)?;
        self.inspect_files_with(|| check_work(clock, cx))?;
        let held = fstat(file).map_err(io_error)?;
        let current =
            fstatat(&self.handle, CACHE_FILE, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io_error)?;
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino) {
            return Err(StoreError::StoreReplaced);
        }
        Ok(())
    }
}

/// Windows: the same admission under docs/windows-private-storage.md, through
/// `windows_private` (owner, protected DACL, trusted ancestors, single-link
/// files, local fixed NTFS/ReFS). The store directory is held without
/// `FILE_SHARE_DELETE`, so it cannot be renamed or replaced while open.
#[cfg(windows)]
pub(super) struct PrivateDirectory {
    pub path: PathBuf,
    held: super::windows_private::HeldDirectory,
    identity: DirectoryIdentity,
}

#[cfg(windows)]
impl PrivateDirectory {
    pub fn open(
        path: PathBuf,
        create: bool,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<Self, StoreError> {
        let path = storage_path(path);
        let held = super::windows_private::walk(&path, create, || check_work(clock, cx))?;
        let directory = Self {
            path,
            identity: held.identity,
            held,
        };
        if create {
            directory.admit_space_with(|| check_work(clock, cx))?;
        } else {
            directory.inspect_files_with(|| check_work(clock, cx))?;
        }
        Ok(directory)
    }

    pub fn database_path(&self) -> PathBuf {
        self.path.join(CACHE_FILE)
    }

    /// SQLite opens a pathname, as on Unix: before each effect the store's
    /// path must still name the held, admitted directory
    /// (`windows_private::revalidate`).
    pub fn revalidate(&self, clock: EntryClock, cx: &Cx) -> Result<(), StoreError> {
        check_work(clock, cx)?;
        debug_assert_eq!(self.identity, self.held.identity);
        super::windows_private::revalidate(&self.held, super::windows_private::Leaf::Store)
    }

    pub fn inspect_files(&self) -> Result<u64, StoreError> {
        self.inspect_files_with(|| Ok(()))
    }

    fn inspect_files_with(
        &self,
        checkpoint: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<u64, StoreError> {
        super::windows_private::inspect(
            &self.held,
            MAX_CACHE_DIRECTORY_ENTRIES,
            CACHE_QUOTA_BYTES,
            checkpoint,
        )
    }

    pub fn capacity_report(&self) -> Result<CacheCapacityReport, StoreError> {
        let occupied_bytes = self.inspect_files()?;
        let available_disk_bytes = super::windows_private::available_bytes(&self.held.file)?;
        let recording_ceiling_bytes = CACHE_QUOTA_BYTES
            .saturating_sub(MAINTENANCE_RESERVE_BYTES)
            .saturating_sub(MUTATION_RESERVE_BYTES);
        let usable_recording_bytes = recording_ceiling_bytes.saturating_sub(occupied_bytes);
        let is_recording_admitted = occupied_bytes <= recording_ceiling_bytes
            && u128::from(available_disk_bytes)
                >= u128::from(MAINTENANCE_RESERVE_BYTES + MUTATION_RESERVE_BYTES);
        Ok(CacheCapacityReport {
            total_quota_bytes: CACHE_QUOTA_BYTES,
            maintenance_reserve_bytes: MAINTENANCE_RESERVE_BYTES,
            mutation_reserve_bytes: MUTATION_RESERVE_BYTES,
            recording_ceiling_bytes,
            occupied_bytes,
            usable_recording_bytes,
            available_disk_bytes,
            is_recording_admitted,
        })
    }

    pub fn admit_space(&self) -> Result<(), StoreError> {
        self.admit_space_with(|| Ok(()))
    }

    fn admit_space_with(
        &self,
        mut checkpoint: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        checkpoint()?;
        super::windows_private::volume_admitted(&self.held.file, self.held.drive)?;
        let bytes = self.inspect_files_with(&mut checkpoint)?;
        checkpoint()?;
        let available = super::windows_private::available_bytes(&self.held.file)?;
        recording_capacity(bytes, u128::from(available))
    }

    pub fn open_database_file(
        &self,
        create: bool,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<File, StoreError> {
        self.revalidate(clock, cx)?;
        if create {
            self.admit_space_with(|| check_work(clock, cx))?;
        } else {
            self.inspect_files_with(|| check_work(clock, cx))?;
        }
        super::windows_private::open_file(&self.held, CACHE_FILE, create)
    }

    pub fn verify_database_file(
        &self,
        file: &File,
        clock: EntryClock,
        cx: &Cx,
    ) -> Result<(), StoreError> {
        self.revalidate(clock, cx)?;
        self.inspect_files_with(|| check_work(clock, cx))?;
        let held = super::windows_private::identity(file)?;
        let current = super::windows_private::inspect_entry(&self.path, CACHE_FILE.as_ref())
            .map_err(|error| super::windows_private::io_error(&error))?;
        if held != super::windows_private::identity(&current)? {
            return Err(StoreError::StoreReplaced);
        }
        Ok(())
    }
}

/// Other targets: no owner-only directory admission exists, so no private
/// directory can be admitted. Opening reports `UnsupportedFilesystem`; the
/// value is uninhabited, so no other method can run.
#[cfg(not(any(unix, windows)))]
#[allow(dead_code)] // Mirrors the Unix surface; uninhabited here.
pub(super) struct PrivateDirectory {
    pub path: PathBuf,
    never: std::convert::Infallible,
}

#[cfg(not(any(unix, windows)))]
#[allow(dead_code)] // Mirrors the Unix surface; uninhabited here.
impl PrivateDirectory {
    pub fn open(
        _: PathBuf,
        _: bool,
        _: crate::runtime::EntryClock,
        _: &asupersync::Cx,
    ) -> Result<Self, super::StoreError> {
        Err(super::StoreError::UnsupportedFilesystem)
    }

    pub fn database_path(&self) -> PathBuf {
        match self.never {}
    }

    pub fn revalidate(
        &self,
        _: crate::runtime::EntryClock,
        _: &asupersync::Cx,
    ) -> Result<(), super::StoreError> {
        match self.never {}
    }

    pub fn inspect_files(&self) -> Result<u64, super::StoreError> {
        match self.never {}
    }

    pub fn capacity_report(&self) -> Result<super::CacheCapacityReport, super::StoreError> {
        match self.never {}
    }

    pub fn admit_space(&self) -> Result<(), super::StoreError> {
        match self.never {}
    }

    pub fn open_database_file(
        &self,
        _: bool,
        _: crate::runtime::EntryClock,
        _: &asupersync::Cx,
    ) -> Result<std::fs::File, super::StoreError> {
        match self.never {}
    }

    pub fn verify_database_file(
        &self,
        _: &std::fs::File,
        _: crate::runtime::EntryClock,
        _: &asupersync::Cx,
    ) -> Result<(), super::StoreError> {
        match self.never {}
    }
}

/// No owner-only chain is checked on this platform, so there is nothing to
/// point at; `None` is the documented "not this" answer.
#[cfg(not(unix))]
pub fn diagnose_owner_only(_: &Path) -> Option<PermissionRefusal> {
    None
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    // Unix mode and owner metadata; the Windows owner and DACL predicates are
    // tested in storage::windows_private.
    #[cfg(unix)]
    #[test]
    fn foreign_owner_is_rejected_by_the_same_metadata_admission() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let mut metadata = fstat(&file).unwrap();
        metadata.st_mode = SFlag::S_IFREG.bits() | 0o600;
        metadata.st_nlink = 1;
        let uid = nix::unistd::geteuid().as_raw();
        metadata.st_uid = uid;
        assert_eq!(owned_regular(&metadata, uid), Ok(()));
        metadata.st_uid = uid.wrapping_add(1);
        assert_eq!(owned_regular(&metadata, uid), Err(StoreError::Permissions));
    }
    #[test]
    fn capacity_keeps_both_mutation_and_maintenance_headroom() {
        let ceiling = CACHE_QUOTA_BYTES - MAINTENANCE_RESERVE_BYTES - MUTATION_RESERVE_BYTES;
        let required = u128::from(MAINTENANCE_RESERVE_BYTES + MUTATION_RESERVE_BYTES);
        assert_eq!(recording_capacity(ceiling, required), Ok(()));
        assert_eq!(
            recording_capacity(ceiling + 1, required),
            Err(StoreError::Quota)
        );
        assert_eq!(
            recording_capacity(0, required - 1),
            Err(StoreError::InsufficientSpace)
        );
    }
}

#[cfg(all(test, unix))]
mod scan_tests;
