//! Guard control files on Windows (sr-winpar.5): the same contract as the Unix
//! `guard_file` module, through `storage::windows_private`.
//!
//! - The guard's directory is a configuration directory: a trusted owner,
//!   ancestors no one else can rename or re-permission, and no write right for
//!   anyone else (it may be readable, like a Unix 0755 configuration
//!   directory). Missing components are created with the private descriptor.
//! - The guard, its lock and temporary files are owner-only single-link
//!   regular files (only the user and SYSTEM), created with that descriptor.
//! - The lock is `LockFileEx` (`File::try_lock`), exclusive and non-blocking,
//!   retried within the caller's budget like the Unix `flock`.
//! - Publication writes and flushes a temporary file, then replaces the guard
//!   with `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`: one rename that never
//!   leaves the guard missing. Unix adds a directory `fsync`; Windows documents
//!   no directory-entry flush for a rename within one folder, so the renamed
//!   entry's durability rests on NTFS/ReFS metadata logging
//!   (docs/windows-private-storage.md, "Exports").
//! - Volume admission (local fixed NTFS/ReFS) happens in the walk, which is the
//!   Windows form of `require_persistent`: removable, remote and RAM disks are
//!   refused.
//!
//! A hostile process running as the same user can edit the guard itself, as on
//! Unix. Revalidation still rejects ordinary replacement races.

use super::{AllowanceError, AllowancePaths, COUNTER, GUARD_FILE_MAX_BYTES, Guard, state};
use crate::storage::StoreError;
use crate::storage::windows_private::{
    self as win, HeldDirectory, Leaf, admitted_file, identity, inspect_entry,
};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, TryLockError};
use std::io::{Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn unavailable() -> AllowanceError {
    state("the guard or lock is not an owned, safe regular-file location")
}

struct Parent {
    path: PathBuf,
    held: HeldDirectory,
}

impl Parent {
    /// None means a genuinely absent component. Read-only checks never create
    /// even a missing parent.
    fn open(path: &Path, create: bool) -> Result<Option<(Self, OsString)>, AllowanceError> {
        let path = crate::platform_path::storage_path(path.to_path_buf());
        let name = path.file_name().ok_or_else(unavailable)?.to_owned();
        let parent_path = path.parent().ok_or_else(unavailable)?.to_owned();
        match win::walk_with(&parent_path, create, || Ok(()), Leaf::Config) {
            Ok(held) => Ok(Some((
                Self {
                    path: parent_path,
                    held,
                },
                name,
            ))),
            Err(StoreError::Missing) if !create => Ok(None),
            Err(_) => Err(unavailable()),
        }
    }

    fn revalidate(&self) -> Result<(), AllowanceError> {
        win::revalidate(&self.held, Leaf::Config).map_err(|_| unavailable())
    }

    /// Whether `name` exists as an admitted owner-only file.
    fn inspect(&self, name: &OsStr) -> Result<bool, AllowanceError> {
        match inspect_entry(&self.path, name) {
            Ok(file) => {
                admitted_file(&file).map_err(|_| unavailable())?;
                Ok(true)
            }
            Err(error) if win::io_error(&error) == StoreError::Missing => Ok(false),
            Err(_) => Err(unavailable()),
        }
    }

    fn verify(&self, name: &OsStr, file: &File) -> Result<(), AllowanceError> {
        self.revalidate()?;
        let named = inspect_entry(&self.path, name).map_err(|_| unavailable())?;
        admitted_file(file).map_err(|_| unavailable())?;
        admitted_file(&named).map_err(|_| unavailable())?;
        if identity(file).map_err(|_| unavailable())?
            != identity(&named).map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Open the existing admitted file `name`, or create it owner-only when
    /// `create` and it is absent.
    fn open_file(&self, name: &OsStr, write: bool, create: bool) -> Result<File, AllowanceError> {
        match win::open_store_file(&self.path, name, write) {
            Ok(file) => Ok(file),
            Err(StoreError::Missing) if create => match win::create_store_file(&self.path, name) {
                Ok(file) => Ok(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    win::open_store_file(&self.path, name, write).map_err(|_| unavailable())
                }
                Err(_) => Err(unavailable()),
            },
            Err(_) => Err(unavailable()),
        }
    }
}

struct Reader {
    parent: Parent,
    name: OsString,
    file: File,
    before: Metadata,
}

impl Reader {
    fn open(path: &Path) -> Result<Option<Self>, AllowanceError> {
        let Some((parent, name)) = Parent::open(path, false)? else {
            return Ok(None);
        };
        if !parent.inspect(&name)? {
            parent.revalidate()?;
            return Ok(None);
        }
        let file = parent.open_file(&name, false, false)?;
        parent.verify(&name, &file)?;
        let before = file.metadata().map_err(|_| unavailable())?;
        if before.len() > GUARD_FILE_MAX_BYTES {
            return Err(state("the guard exceeds its byte limit"));
        }
        Ok(Some(Self {
            parent,
            name,
            file,
            before,
        }))
    }

    fn read(mut self) -> Result<Guard, AllowanceError> {
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(GUARD_FILE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| state("the guard file cannot be read"))?;
        if bytes.len() as u64 > GUARD_FILE_MAX_BYTES {
            return Err(state("the guard exceeds its byte limit"));
        }
        self.parent.verify(&self.name, &self.file)?;
        let after = self.file.metadata().map_err(|_| unavailable())?;
        let version = |m: &Metadata| (m.len(), m.last_write_time(), m.creation_time());
        if version(&self.before) != version(&after) || after.len() != bytes.len() as u64 {
            return Err(state("the guard changed while it was being read"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| state("the guard is not UTF-8"))?;
        Guard::decode(text)
    }
}

pub(super) fn read(path: &Path) -> Result<Option<Guard>, AllowanceError> {
    Reader::open(path)?.map(Reader::read).transpose()
}

/// This lock file is never renamed or deleted by sr. The same opened file is
/// retried; the lock is released when the handle closes.
pub(super) struct GuardLock {
    _file: File,
}

impl GuardLock {
    pub(super) fn acquire(
        paths: &AllowancePaths,
        budget: Duration,
    ) -> Result<Self, AllowanceError> {
        let started = Instant::now();
        let (parent, name) = Parent::open(&paths.lock_path(), true)?.ok_or_else(unavailable)?;
        parent.inspect(&name)?;
        let file = parent.open_file(&name, true, true)?;
        parent.verify(&name, &file)?;
        loop {
            match file.try_lock() {
                Ok(()) => {
                    parent.verify(&name, &file)?;
                    return Ok(Self { _file: file });
                }
                Err(TryLockError::WouldBlock) => {
                    let remaining = budget.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        return Err(state("the guard lock is busy"));
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(2)));
                    // A delayed wake must not authorize work outside the lock budget.
                    if started.elapsed() >= budget {
                        return Err(state("the guard lock is busy"));
                    }
                    parent.verify(&name, &file)?;
                }
                Err(TryLockError::Error(_)) => {
                    return Err(state("the guard lock cannot be acquired"));
                }
            }
        }
    }
}

/// Durable replacement under the caller's GuardLock. Failure cleanup removes
/// only our own still-named temporary file, never a collision or the target.
pub(super) fn publish(paths: &AllowancePaths, guard: &Guard) -> Result<(), AllowanceError> {
    let bytes = guard.encode().into_bytes();
    if bytes.len() as u64 > GUARD_FILE_MAX_BYTES {
        return Err(state("the guard exceeds its byte limit"));
    }
    let (parent, name) = Parent::open(&paths.guard, false)?.ok_or_else(unavailable)?;
    parent.inspect(&name)?;
    let tmp = format!(
        "allowance.toml.sr-tmp.{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    publish_named(&parent, &name, OsStr::new(&tmp), &bytes)
}

fn publish_named(
    parent: &Parent,
    name: &OsStr,
    tmp: &OsStr,
    bytes: &[u8],
) -> Result<(), AllowanceError> {
    parent.revalidate()?;
    let mut file = win::create_store_file(&parent.path, tmp).map_err(|_| unavailable())?;
    let result = (|| {
        parent.verify(tmp, &file)?;
        file.write_all(bytes)
            .map_err(|_| state("the guard cannot be written"))?;
        file.sync_all()
            .map_err(|_| state("the guard cannot be flushed"))?;
        parent.verify(tmp, &file)?;
        parent.inspect(name)?;
        sr_win_sys::windows::replace_file(&parent.path.join(tmp), &parent.path.join(name))
            .map_err(|_| state("the guard cannot be replaced"))?;
        parent.verify(name, &file)
    })();
    if result.is_err() && parent.verify(tmp, &file).is_ok() {
        let _ = std::fs::remove_file(parent.path.join(tmp));
    }
    result
}
