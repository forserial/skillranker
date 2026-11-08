//! Enforced allowance state on platforms without its storage boundary.
//!
//! Unix and Windows have audited guard and accounting files (Windows since
//! sr-winpar.5). Any other target has none, so enforcement fails closed: an absent guard means no
//! allowance is configured (exactly as on Unix), while any existing guard or
//! accounting state, or any attempt to create one, is refused. A refused guard
//! withholds provider requests rather than admitting them unaccounted.

use super::{AllowanceError, AllowancePaths, Guard, state};
use std::path::Path;

fn unsupported() -> AllowanceError {
    state("enforced request allowance is not supported on this platform")
}

/// Absent means a genuinely missing name; anything else, including a path
/// that cannot be inspected, is state this platform cannot verify.
fn absent(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

pub(super) mod guard_file {
    use super::{AllowanceError, AllowancePaths, Guard, absent, unsupported};
    use std::path::Path;
    use std::time::Duration;

    pub(in crate::allowance) fn read(path: &Path) -> Result<Option<Guard>, AllowanceError> {
        if absent(path) {
            Ok(None)
        } else {
            Err(unsupported())
        }
    }

    /// Uninhabited: no lock can be held, so no guarded step can run.
    pub(in crate::allowance) enum GuardLock {}

    /// Mirrors the Unix lock, which releases on drop.
    impl Drop for GuardLock {
        fn drop(&mut self) {
            match *self {}
        }
    }

    impl GuardLock {
        pub(in crate::allowance) fn acquire(
            _: &AllowancePaths,
            _: Duration,
        ) -> Result<Self, AllowanceError> {
            Err(unsupported())
        }
    }

    pub(in crate::allowance) fn publish(
        _: &AllowancePaths,
        _: &Guard,
    ) -> Result<(), AllowanceError> {
        Err(unsupported())
    }
}

pub(super) mod accounting {
    use super::super::admission_budget::AdmissionBudget;
    use super::{AllowanceError, absent, unsupported};
    use rusqlite::Connection;
    use std::path::Path;

    /// Uninhabited: a `Store` can never be constructed on this platform.
    pub(in crate::allowance) enum Files {}

    impl Files {
        pub(in crate::allowance) fn verify(&self) -> Result<(), AllowanceError> {
            match *self {}
        }
    }

    pub(in crate::allowance) struct Store {
        pub(in crate::allowance) connection: Connection,
        pub(in crate::allowance) files: Files,
    }

    impl std::ops::Deref for Store {
        type Target = Connection;
        fn deref(&self) -> &Connection {
            &self.connection
        }
    }

    impl std::ops::DerefMut for Store {
        fn deref_mut(&mut self) -> &mut Connection {
            &mut self.connection
        }
    }

    pub(in crate::allowance) fn read<T>(
        path: &Path,
        _: impl FnOnce(&Connection) -> Result<T, AllowanceError>,
    ) -> Result<Option<T>, AllowanceError> {
        if absent(path) {
            Ok(None)
        } else {
            Err(unsupported())
        }
    }

    pub(in crate::allowance) fn open_writer(_: &Path, _: bool) -> Result<Store, AllowanceError> {
        Err(unsupported())
    }

    pub(in crate::allowance) fn open_writer_with_budget(
        _: &Path,
        _: bool,
        _: Option<AdmissionBudget>,
    ) -> Result<Store, AllowanceError> {
        Err(unsupported())
    }
}
