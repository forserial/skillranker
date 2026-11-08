//! Accounting file admission on Windows (sr-winpar.5): the Unix `Files`
//! contract through `storage::windows_private`. The accounting folder is a
//! private store folder (rules 1–3, created with the private descriptor), the
//! database and its sidecars are owner-only single-link files on the same
//! volume, and every check repeats before each SQLite step. Volume admission
//! (local fixed NTFS/ReFS) in the walk is the Windows `require_persistent`.

use super::super::admission_budget::{AdmissionBudget, checkpoint};
use super::super::{ACCOUNTING_MAX_BYTES, AllowanceError};
use super::{FAMILY_MAX_BYTES, capacity, refused};
use crate::storage::StoreError;
use crate::storage::windows_private::{self as win, HeldDirectory, Leaf, admitted_file, identity};
use std::cell::RefCell;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Walk to the accounting folder, keeping the admission budget's own error
/// when it runs out between components.
fn parent(
    path: &Path,
    create: bool,
    budget: Option<AdmissionBudget>,
) -> Result<Option<HeldDirectory>, AllowanceError> {
    checkpoint(budget)?;
    let directory = path.parent().ok_or_else(refused)?;
    let stopped = RefCell::new(None);
    let walked = win::walk(directory, create, || {
        checkpoint(budget).map_err(|error| {
            *stopped.borrow_mut() = Some(error);
            StoreError::Cancelled
        })
    });
    if let Some(error) = stopped.into_inner() {
        return Err(error);
    }
    match walked {
        Ok(held) => {
            checkpoint(budget)?;
            Ok(Some(held))
        }
        Err(StoreError::Missing) if !create => Ok(None),
        Err(_) => Err(refused()),
    }
}

/// The admitted size of `name`, or `None` when absent.
fn size(directory: &Path, name: &str) -> Result<Option<u64>, AllowanceError> {
    win::entry_size(directory, name).map_err(|_| refused())
}

/// Retain admitted identities for the complete lifetime of the SQLite connection.
pub(in crate::allowance) struct Files {
    pub(in crate::allowance) path: PathBuf,
    held: HeldDirectory,
    file: File,
    budget: Option<AdmissionBudget>,
}

impl Files {
    pub(super) fn open(
        path: &Path,
        create: bool,
        writable: bool,
    ) -> Result<Option<Self>, AllowanceError> {
        Self::open_with_budget(path, create, writable, None)
    }

    pub(super) fn open_with_budget(
        path: &Path,
        create: bool,
        writable: bool,
        budget: Option<AdmissionBudget>,
    ) -> Result<Option<Self>, AllowanceError> {
        checkpoint(budget)?;
        let path = crate::platform_path::storage_path(path.to_path_buf());
        let Some(held) = parent(&path, create, budget)? else {
            return Ok(None);
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(refused)?
            .to_owned();
        let exists = match size(&held.path, &name)? {
            Some(bytes) if bytes > ACCOUNTING_MAX_BYTES as u64 => return Err(capacity()),
            Some(_) => true,
            None => false,
        };
        // Orphaned WAL/journal files may contain enforcement history. Never
        // attach them to a newly created empty database or call them absence.
        for suffix in ["-wal", "-shm", "-journal"] {
            checkpoint(budget)?;
            if let Some(bytes) = size(&held.path, &format!("{name}{suffix}"))? {
                if !exists {
                    return Err(refused());
                }
                if bytes > FAMILY_MAX_BYTES as u64 {
                    return Err(capacity());
                }
            }
        }
        if !exists && !create {
            win::revalidate(&held, Leaf::Store).map_err(|_| refused())?;
            return Ok(None);
        }
        checkpoint(budget)?;
        let file = if exists {
            win::open_store_file(&held.path, name.as_ref(), writable).map_err(|_| refused())?
        } else {
            // Another first-time creator is not overwritten. The next
            // invocation can retry after inspecting whatever it published.
            win::create_store_file(&held.path, name.as_ref()).map_err(|_| refused())?
        };
        let files = Self {
            path,
            held,
            file,
            budget,
        };
        files.verify()?;
        Ok(Some(files))
    }

    pub(in crate::allowance) fn verify(&self) -> Result<(), AllowanceError> {
        checkpoint(self.budget)?;
        win::revalidate(&self.held, Leaf::Store).map_err(|_| refused())?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(refused)?;
        let named = win::inspect_entry(&self.held.path, name.as_ref()).map_err(|_| refused())?;
        let held_bytes = admitted_file(&self.file).map_err(|_| refused())?;
        admitted_file(&named).map_err(|_| refused())?;
        let held_identity = identity(&self.file).map_err(|_| refused())?;
        if held_identity != identity(&named).map_err(|_| refused())? {
            return Err(refused());
        }
        if held_bytes > ACCOUNTING_MAX_BYTES as u64 {
            return Err(capacity());
        }
        let mut bytes = held_bytes;
        for suffix in ["-wal", "-shm", "-journal"] {
            checkpoint(self.budget)?;
            let sidecar = format!("{name}{suffix}");
            match win::inspect_entry(&self.held.path, sidecar.as_ref()) {
                Ok(found) => {
                    let found_bytes = admitted_file(&found).map_err(|_| refused())?;
                    // Sidecars are ordinary siblings on the held folder's volume.
                    if identity(&found).map_err(|_| refused())?.0 != self.held.identity.0 {
                        return Err(refused());
                    }
                    bytes = bytes.checked_add(found_bytes).ok_or_else(capacity)?;
                    if bytes > FAMILY_MAX_BYTES as u64 {
                        return Err(capacity());
                    }
                }
                Err(error) if win::io_error(&error) == StoreError::Missing => {}
                Err(_) => return Err(refused()),
            }
        }
        checkpoint(self.budget)
    }
}
