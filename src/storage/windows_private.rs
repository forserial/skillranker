//! Windows owner-only private storage: the rules of
//! docs/windows-private-storage.md applied to the facts `sr-win-sys` reads.
//!
//! This module is safe code. Every security descriptor, volume fact and
//! creation-time descriptor comes from `sr_win_sys::windows`, the one audited
//! package allowed unsafe code (sr-winpar.2). Deciding whether those facts
//! satisfy the policy happens here.
//!
//! Windows has no `openat`. The walk opens each component by path with
//! `FILE_FLAG_OPEN_REPARSE_POINT` (no-follow) and without `FILE_SHARE_DELETE`,
//! as `authorized_read` does, so a held directory cannot be renamed, deleted or
//! replaced while it is held. Only the current directory is held between
//! components, as on Unix; ancestors may be renamed only by principals rule 3
//! trusts (the user, SYSTEM, Administrators, TrustedInstaller), which is the
//! same-user territory the Unix boundary also leaves out (rule 9). SQLite and
//! directory enumeration use the store's path for the same reason, and
//! revalidation compares the store's identity before each effect.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::OnceLock;

use sr_win_sys::windows::{
    DRIVE_FIXED, create_directory_with, create_new_file_with, free_bytes_for_caller, security_of,
    token_user_sid, volume_of,
};
use sr_win_sys::{AceKind, Descriptor, Sid};

use super::StoreError;

/// `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `FILE_DELETE_CHILD`, and the generic
/// or maximal rights that can include them: the rights that let a principal
/// rename, delete or re-permission a child of an ancestor (rule 3).
const REPLACE_CAPABLE: u32 =
    0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x0000_0040 | 0x1000_0000 | 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
/// `READ_CONTROL | FILE_READ_ATTRIBUTES`: enough to classify an entry and read
/// its descriptor without contending with SQLite's own opens.
const INSPECT_ACCESS: u32 = 0x0002_0000 | 0x0080;
/// What `FileRemoteProtocolInfo` returns for a local file (observed on NTFS,
/// sr-winpar.2). Any other outcome, success included, is not local.
const ERROR_INVALID_PARAMETER: i32 = 87;

/// A directory's identity: volume serial number and file index.
pub(crate) type Identity = (u64, u64);

/// The current process's token user, read once.
pub(crate) fn user() -> Result<&'static Sid, StoreError> {
    static USER: OnceLock<Option<Sid>> = OnceLock::new();
    USER.get_or_init(|| token_user_sid().ok())
        .as_ref()
        .ok_or(StoreError::Permissions)
}

pub(crate) fn io_error(error: &io::Error) -> StoreError {
    match error.raw_os_error() {
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
        Some(2 | 3) => return StoreError::Missing,
        // ERROR_INVALID_NAME, ERROR_DIRECTORY, ERROR_CANT_ACCESS_FILE,
        // ERROR_CANT_RESOLVE_FILENAME
        Some(123 | 267 | 1920 | 1921) => return StoreError::UnsafePath,
        _ => {}
    }
    match error.kind() {
        io::ErrorKind::NotFound => StoreError::Missing,
        io::ErrorKind::PermissionDenied => StoreError::Permissions,
        _ => StoreError::Io,
    }
}

fn trusted_owner(sid: &Sid, user: &Sid) -> bool {
    sid == user
        || sid.is_local_system()
        || sid.is_builtin_administrators()
        || sid.is_trusted_installer()
}

/// Rule 3: an ancestor is owned by a trusted owner, and no one else holds
/// replace-capable rights through an entry that applies to the ancestor
/// itself. Capability SIDs count as the user here. Deny entries only remove
/// rights; any other entry type is refused because it cannot be read safely.
pub(crate) fn ancestor_admitted(descriptor: &Descriptor, user: &Sid) -> Result<(), StoreError> {
    if !trusted_owner(&descriptor.owner, user) {
        return Err(StoreError::Permissions);
    }
    let Some(aces) = &descriptor.dacl else {
        // A NULL DACL grants everyone full control.
        return Err(StoreError::Permissions);
    };
    for ace in aces.iter().filter(|ace| ace.applies_to_object()) {
        match ace.kind {
            AceKind::Denied => {}
            AceKind::Allowed => {
                let trustee = ace.sid.as_ref().ok_or(StoreError::Permissions)?;
                if ace.mask & REPLACE_CAPABLE != 0
                    && !trusted_owner(trustee, user)
                    && !trustee.is_capability()
                {
                    return Err(StoreError::Permissions);
                }
            }
            AceKind::Other(_) => return Err(StoreError::Permissions),
        }
    }
    Ok(())
}

fn only_user_and_system(descriptor: &Descriptor, user: &Sid) -> Result<(), StoreError> {
    if &descriptor.owner != user {
        return Err(StoreError::Permissions);
    }
    let aces = descriptor.dacl.as_ref().ok_or(StoreError::Permissions)?;
    let private = aces.iter().all(|ace| {
        ace.kind == AceKind::Allowed
            && ace
                .sid
                .as_ref()
                .is_some_and(|sid| sid == user || sid.is_local_system())
    });
    if private {
        Ok(())
    } else {
        Err(StoreError::Permissions)
    }
}

/// Rules 1 and 2 for the store directory: owned by the user, with a protected
/// DACL of allow entries for the user and SYSTEM only.
pub(crate) fn store_directory_admitted(
    descriptor: &Descriptor,
    user: &Sid,
) -> Result<(), StoreError> {
    if !descriptor.dacl_protected() {
        return Err(StoreError::Permissions);
    }
    only_user_and_system(descriptor, user)
}

/// Rules 1 and 2 for a store file: owned by the user, with allow entries for
/// the user and SYSTEM only, explicit or inherited from the store directory.
pub(crate) fn store_file_admitted(descriptor: &Descriptor, user: &Sid) -> Result<(), StoreError> {
    only_user_and_system(descriptor, user)
}

/// Rule 7: the descriptor `sr` applies when it creates a store directory.
pub(crate) fn directory_sddl(user: &Sid) -> String {
    format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
}

/// Rule 7: the descriptor `sr` applies when it creates a store file.
pub(crate) fn file_sddl(user: &Sid) -> String {
    format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)")
}

/// Rule 5: a local, fixed NTFS or ReFS volume, reached through the drive the
/// path names (a `SUBST` or mapped drive reports a different final drive).
pub(crate) fn volume_admitted(file: &File, drive: u8) -> Result<(), StoreError> {
    let volume = volume_of(file).map_err(|error| io_error(&error))?;
    if admitted_volume(&volume, drive) {
        Ok(())
    } else {
        Err(StoreError::UnsupportedFilesystem)
    }
}

/// The pure part of rule 5, separate so every refusal can be tested without a
/// FAT volume, a network share or a `SUBST` drive.
fn admitted_volume(volume: &sr_win_sys::windows::Volume, drive: u8) -> bool {
    let final_drive = volume
        .final_path
        .to_str()
        .and_then(|path| path.strip_prefix(r"\\?\"))
        .and_then(|rest| {
            let bytes = rest.as_bytes();
            (bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\').then(|| bytes[0])
        });
    matches!(volume.filesystem.as_str(), "NTFS" | "ReFS")
        && volume.drive_type == Some(DRIVE_FIXED)
        && volume.remote_protocol == Err(ERROR_INVALID_PARAMETER)
        && final_drive.is_some_and(|letter| letter.eq_ignore_ascii_case(&drive))
}

/// Bytes available to this user on the volume holding `file` (rule 8).
pub(crate) fn available_bytes(file: &File) -> Result<u64, StoreError> {
    free_bytes_for_caller(file).map_err(|error| io_error(&error))
}

pub(crate) fn identity(file: &File) -> Result<Identity, StoreError> {
    let information = winapi_util::file::information(file).map_err(|error| io_error(&error))?;
    Ok((information.volume_serial_number(), information.file_index()))
}

/// A drive letter and the plain components below its root, or the refusal.
fn parse(path: &Path) -> Result<(u8, Vec<OsString>), StoreError> {
    if path.as_os_str().len() > 4096 {
        return Err(StoreError::UnsafePath);
    }
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) if letter.is_ascii_alphabetic() => letter,
            // Network shares are refused as filesystems (rule 5).
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {
                return Err(StoreError::UnsupportedFilesystem);
            }
            _ => return Err(StoreError::UnsafePath),
        },
        _ => return Err(StoreError::UnsafePath),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(StoreError::UnsafePath);
    }
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(StoreError::UnsafePath);
        };
        if name == "." || name == ".." || !crate::authorized_read::valid_component(name) {
            return Err(StoreError::UnsafePath);
        }
        names.push(name.to_os_string());
    }
    if names.is_empty() || names.len() > 127 {
        return Err(StoreError::UnsafePath);
    }
    Ok((drive, names))
}

fn open_directory(path: &Path) -> io::Result<File> {
    crate::authorized_read::open_windows(path, false, true)
}

/// A plain directory, not a reparse point of any kind (rule 3).
fn plain_directory(file: &File) -> Result<Identity, StoreError> {
    let metadata = file.metadata().map_err(|error| io_error(&error))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StoreError::UnsafePath);
    }
    identity(file)
}

fn descriptor(file: &File) -> Result<Descriptor, StoreError> {
    security_of(file).map_err(|error| io_error(&error))
}

/// A held, admitted store directory.
#[derive(Debug)]
pub(crate) struct HeldDirectory {
    pub(crate) file: File,
    pub(crate) path: PathBuf,
    pub(crate) drive: u8,
    pub(crate) identity: Identity,
}

/// Rights that let a principal add, change or remove a directory's entries,
/// or re-permission it: the Windows reading of a group/other write bit.
const WRITE_ANY: u32 =
    REPLACE_CAPABLE | 0x0000_0002 | 0x0000_0004 | 0x0000_0010 | 0x0000_0100 | 0x4000_0000;

/// What the final directory of a walk must be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Leaf {
    /// A private store directory (rules 1 and 2).
    Store,
    /// A configuration directory holding owner-only files, such as the
    /// allowance guard's: like a Unix directory that may be searchable (0755)
    /// but never writable by another user. A trusted owner, and no one else
    /// holds any write right through an entry that applies to it. Capability
    /// SIDs count as the user, as on ancestors.
    Config,
}

/// The configuration-directory rule ([`Leaf::Config`]).
pub(crate) fn config_directory_admitted(
    descriptor: &Descriptor,
    user: &Sid,
) -> Result<(), StoreError> {
    ancestor_admitted(descriptor, user)?;
    let aces = descriptor.dacl.as_ref().ok_or(StoreError::Permissions)?;
    for ace in aces.iter().filter(|ace| ace.applies_to_object()) {
        if ace.kind == AceKind::Allowed
            && ace.mask & WRITE_ANY != 0
            && ace
                .sid
                .as_ref()
                .is_some_and(|sid| !trusted_owner(sid, user) && !sid.is_capability())
        {
            return Err(StoreError::Permissions);
        }
    }
    Ok(())
}

/// Walk from the volume root to `path`, admitting each ancestor (rule 3) and
/// the final directory as a store directory (rules 1 and 2), creating missing
/// components with the private descriptor when `create` (rule 7). Existing
/// directories are never repaired.
pub(crate) fn walk(
    path: &Path,
    create: bool,
    checkpoint: impl FnMut() -> Result<(), StoreError>,
) -> Result<HeldDirectory, StoreError> {
    walk_with(path, create, checkpoint, Leaf::Store)
}

/// [`walk`] with the final directory admitted by `leaf`.
pub(crate) fn walk_with(
    path: &Path,
    create: bool,
    mut checkpoint: impl FnMut() -> Result<(), StoreError>,
    leaf: Leaf,
) -> Result<HeldDirectory, StoreError> {
    let (drive, names) = parse(path)?;
    let user = user()?;
    let mut current = PathBuf::from(format!("{}:\\", char::from(drive)));
    let mut handle = open_directory(&current).map_err(|error| io_error(&error))?;
    plain_directory(&handle)?;
    volume_admitted(&handle, drive)?;
    ancestor_admitted(&descriptor(&handle)?, user)?;
    let last = names.len() - 1;
    let mut identity = None;
    for (index, name) in names.iter().enumerate() {
        checkpoint()?;
        current.push(name);
        let opened = match open_directory(&current) {
            Err(error) if create && io_error(&error) == StoreError::Missing => {
                match create_directory_with(&current, &directory_sddl(user)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(io_error(&error)),
                }
                open_directory(&current).map_err(|error| io_error(&error))?
            }
            result => result.map_err(|error| io_error(&error))?,
        };
        let opened_identity = plain_directory(&opened)?;
        let found = descriptor(&opened)?;
        if index == last {
            match leaf {
                Leaf::Store => store_directory_admitted(&found, user)?,
                Leaf::Config => config_directory_admitted(&found, user)?,
            }
            identity = Some(opened_identity);
        } else {
            ancestor_admitted(&found, user)?;
        }
        handle = opened;
    }
    Ok(HeldDirectory {
        file: handle,
        path: current,
        drive,
        identity: identity.ok_or(StoreError::UnsafePath)?,
    })
}

/// Revalidate a held directory before an effect: its own path must still name
/// the same object (volume serial and file index), and that object must still
/// satisfy `leaf`. The ancestors were walked in full when it was opened; by
/// rule 3 no principal outside the boundary can rename or re-permission an
/// ancestor in between, so walking them again could only detect same-user or
/// administrator changes, which rule 9 leaves outside the boundary. On Windows
/// each component open costs about 0.3 ms (filter drivers), and the full re-walk
/// before every effect pushed one allowance admission past 60 ms.
pub(crate) fn revalidate(held: &HeldDirectory, leaf: Leaf) -> Result<(), StoreError> {
    let current = open_directory(&held.path).map_err(|error| io_error(&error))?;
    if plain_directory(&current)? != held.identity {
        return Err(StoreError::StoreReplaced);
    }
    let found = descriptor(&current)?;
    let user = user()?;
    match leaf {
        Leaf::Store => store_directory_admitted(&found, user),
        Leaf::Config => config_directory_admitted(&found, user),
    }
}

/// Rule 4 plus rules 1 and 2 for a held store file: a regular single-link
/// file, not a reparse point, owned by the user with a private DACL.
pub(crate) fn admitted_file(file: &File) -> Result<u64, StoreError> {
    let metadata = file.metadata().map_err(|error| io_error(&error))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StoreError::UnsafePath);
    }
    let information = winapi_util::file::information(file).map_err(|error| io_error(&error))?;
    if information.number_of_links() != 1 {
        return Err(StoreError::UnsafePath);
    }
    store_file_admitted(&descriptor(file)?, user()?)?;
    Ok(metadata.len())
}

/// Rules 1 and 2 for a single owner-only file outside a store, such as a
/// captured replay case: owned by the user, with allow entries for the user
/// and SYSTEM only. Links are the caller's check, as `O_NOFOLLOW` is on Unix.
pub(crate) fn owner_only_file(file: &File) -> Result<(), StoreError> {
    store_file_admitted(&descriptor(file)?, user()?)
}

/// Open `name` in `directory` only to classify it: no-follow, shared with
/// every other opener, and without data access.
pub(crate) fn inspect_entry(directory: &Path, name: &std::ffi::OsStr) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(INSPECT_ACCESS)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join(name))
}

/// Open the store file `name` for reading and writing, creating it with the
/// private descriptor when `create`; an existing file is admitted, never
/// repaired.
pub(crate) fn open_file(
    directory: &HeldDirectory,
    name: &str,
    create: bool,
) -> Result<File, StoreError> {
    let path = directory.path.join(name);
    let open = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
    };
    let file = match open() {
        Err(error) if create && io_error(&error) == StoreError::Missing => {
            match create_new_file_with(&path, &file_sddl(user()?)) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    open().map_err(|error| io_error(&error))?
                }
                Err(error) => return Err(io_error(&error)),
            }
        }
        result => result.map_err(|error| io_error(&error))?,
    };
    admitted_file(&file)?;
    Ok(file)
}

/// Enumerate the store directory, admitting every entry as a store file and
/// summing their sizes. Entries that vanish during the scan are counted
/// against `max_entries` but not admitted.
pub(crate) fn inspect(
    directory: &HeldDirectory,
    max_entries: usize,
    quota_bytes: u64,
    checkpoint: impl FnMut() -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    inspect_with(directory, max_entries, quota_bytes, checkpoint, None)
}

/// [`inspect`], also admitting one named subdirectory (the ledger's
/// `policy-revisions`): a plain directory owned by the user whose entries
/// allow only the user and SYSTEM, explicit or inherited from the protected
/// store directory, holding only store files, whose sizes count too. Any
/// other directory is refused, as on Unix.
pub(crate) fn inspect_with(
    directory: &HeldDirectory,
    max_entries: usize,
    quota_bytes: u64,
    mut checkpoint: impl FnMut() -> Result<(), StoreError>,
    nested: Option<&str>,
) -> Result<u64, StoreError> {
    checkpoint()?;
    // The path still names the held directory unless a trusted principal
    // renamed an ancestor; refuse rather than count a different directory.
    let current = open_directory(&directory.path).map_err(|error| io_error(&error))?;
    if plain_directory(&current)? != directory.identity {
        return Err(StoreError::StoreReplaced);
    }
    let entries = std::fs::read_dir(&directory.path).map_err(|error| io_error(&error))?;
    let mut bytes = 0_u64;
    for (seen, entry) in entries.enumerate() {
        checkpoint()?;
        let entry = entry.map_err(|error| io_error(&error))?;
        if seen >= max_entries {
            return Err(StoreError::Quota);
        }
        let name = entry.file_name();
        let file = match inspect_entry(&directory.path, &name) {
            Ok(file) => file,
            Err(error) if io_error(&error) == StoreError::Missing => continue,
            Err(error) => return Err(io_error(&error)),
        };
        let size = if nested.is_some_and(|nested| name == nested)
            && file.metadata().is_ok_and(|metadata| metadata.is_dir())
        {
            nested_directory(&directory.path.join(&name), &mut checkpoint)?
        } else {
            admitted_file(&file)?
        };
        bytes = bytes
            .checked_add(size)
            .filter(|total| *total <= quota_bytes)
            .ok_or(StoreError::Quota)?;
    }
    checkpoint()?;
    Ok(bytes)
}

/// The total size of the store files in a nested private directory.
fn nested_directory(
    path: &Path,
    checkpoint: &mut impl FnMut() -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    let held = open_directory(path).map_err(|error| io_error(&error))?;
    plain_directory(&held)?;
    store_file_admitted(&descriptor(&held)?, user()?)?;
    let mut bytes = 0_u64;
    for entry in std::fs::read_dir(path).map_err(|error| io_error(&error))? {
        checkpoint()?;
        let entry = entry.map_err(|error| io_error(&error))?;
        let file = match inspect_entry(path, &entry.file_name()) {
            Ok(file) => file,
            Err(error) if io_error(&error) == StoreError::Missing => continue,
            Err(error) => return Err(io_error(&error)),
        };
        bytes = bytes
            .checked_add(admitted_file(&file)?)
            .ok_or(StoreError::Quota)?;
    }
    Ok(bytes)
}

/// The size of the admitted store file `name` in `directory`, or `None` when
/// it does not exist.
pub(crate) fn entry_size(directory: &Path, name: &str) -> Result<Option<u64>, StoreError> {
    match inspect_entry(directory, name.as_ref()) {
        Ok(file) => admitted_file(&file).map(Some),
        Err(error) if io_error(&error) == StoreError::Missing => Ok(None),
        Err(error) => Err(io_error(&error)),
    }
}

/// Admit `path` itself as a private store directory (rules 1-3 for the
/// directory, without walking its ancestors), for a writer that only needs
/// to refuse a shared or replaced directory, as the hook counter does.
pub(crate) fn private_directory(path: &Path) -> Result<File, StoreError> {
    let held = open_directory(path).map_err(|error| io_error(&error))?;
    plain_directory(&held)?;
    store_directory_admitted(&descriptor(&held)?, user()?)?;
    Ok(held)
}

/// Open the existing store file `name` in `directory` without following a
/// link, for reading or appending, and admit it (rules 1, 2 and 4).
pub(crate) fn open_existing(
    directory: &Path,
    name: &str,
    write: bool,
    create: bool,
) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .read(!write)
        .append(write)
        .create(create)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join(name))
        .map_err(|error| io_error(&error))?;
    admitted_file(&file)?;
    Ok(file)
}

/// Open the existing store file `name` in `directory` without following a
/// link, for reading or for reading and writing, shared with every other
/// opener, and admit it (rules 1, 2 and 4).
pub(crate) fn open_store_file(
    directory: &Path,
    name: &std::ffi::OsStr,
    write: bool,
) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join(name))
        .map_err(|error| io_error(&error))?;
    admitted_file(&file)?;
    Ok(file)
}

/// Create the new store file `name` in `directory` with the private file
/// descriptor (rule 7), never opening an existing name. `AlreadyExists` is
/// returned as is, so a caller can tell a raced-in creator apart.
pub(crate) fn create_store_file(directory: &Path, name: &std::ffi::OsStr) -> io::Result<File> {
    let user = user().map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "token user"))?;
    create_new_file_with(&directory.join(name), &file_sddl(user))
}

/// A root for unit-test stores: `%LOCALAPPDATA%\sr-tests`. `%TEMP%` may grant
/// other local accounts the right to replace its children, which rule 3
/// refuses.
#[cfg(test)]
pub(crate) fn test_root() -> PathBuf {
    let root =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA")).join("sr-tests");
    std::fs::create_dir_all(&root).expect("create the unit-test store root");
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use sr_win_sys::Ace;
    use sr_win_sys::acl::{CONTAINER_INHERIT, INHERIT_ONLY, INHERITED, OBJECT_INHERIT};

    fn user_sid() -> Sid {
        Sid::new(5, &[21, 1, 2, 3, 1001]).unwrap()
    }
    fn sid(subs: &[u32]) -> Sid {
        Sid::new(5, subs).unwrap()
    }
    fn allow(sid: Sid, flags: u8, mask: u32) -> Ace {
        Ace {
            kind: AceKind::Allowed,
            flags,
            mask,
            sid: Some(sid),
        }
    }
    fn descriptor(owner: Sid, protected: bool, aces: Vec<Ace>) -> Descriptor {
        Descriptor {
            owner,
            control: if protected { 0x9004 } else { 0x8004 },
            dacl: Some(aces),
        }
    }
    const FULL: u32 = 0x001F_01FF;
    const READ_EXECUTE: u32 = 0x0012_00A9;
    /// `FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE`-style create rights.
    const CREATE_CHILDREN: u32 = 0x0000_0006;

    #[test]
    fn default_drive_root_and_local_app_data_are_admitted_ancestors() {
        let user = user_sid();
        let authenticated_users = sid(&[11]);
        let installer = Sid::new(
            5,
            &[
                80,
                956_008_885,
                3_418_522_649,
                1_831_038_044,
                1_853_292_631,
                2_271_478_464,
            ],
        )
        .unwrap();
        // C:\ : TrustedInstaller owner; Authenticated Users may create
        // directories and hold Modify only inherit-only.
        let root = descriptor(
            installer,
            true,
            vec![
                allow(sid(&[32, 544]), 0, FULL),
                allow(sid(&[18]), 0, FULL),
                allow(sid(&[32, 545]), 0, READ_EXECUTE),
                allow(authenticated_users.clone(), 0, CREATE_CHILDREN),
                allow(
                    authenticated_users,
                    INHERIT_ONLY | OBJECT_INHERIT | CONTAINER_INHERIT,
                    0x0001_0000 | FULL,
                ),
            ],
        );
        assert_eq!(ancestor_admitted(&root, &user), Ok(()));
        // %LOCALAPPDATA%: capability SIDs with full control count as the user.
        let capability = Sid::new(15, &[3, 1024, 7]).unwrap();
        let local = descriptor(
            user.clone(),
            false,
            vec![
                allow(capability, INHERITED, FULL),
                allow(
                    user.clone(),
                    INHERITED | OBJECT_INHERIT | CONTAINER_INHERIT,
                    FULL,
                ),
                allow(sid(&[21, 9, 9, 9, 1016]), INHERITED, READ_EXECUTE),
            ],
        );
        assert_eq!(ancestor_admitted(&local, &user), Ok(()));
    }

    #[test]
    fn replace_capable_rights_for_others_refuse_an_ancestor() {
        let user = user_sid();
        let users = sid(&[32, 545]);
        for mask in [
            0x0000_0040,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x1000_0000,
        ] {
            let shared = descriptor(user.clone(), false, vec![allow(users.clone(), 0, mask)]);
            assert_eq!(
                ancestor_admitted(&shared, &user),
                Err(StoreError::Permissions),
                "{mask:#x}"
            );
        }
        let foreign_owner = descriptor(sid(&[21, 9, 9, 9, 2000]), false, vec![]);
        assert_eq!(
            ancestor_admitted(&foreign_owner, &user),
            Err(StoreError::Permissions)
        );
        let null = Descriptor {
            owner: user.clone(),
            control: 0x8004,
            dacl: None,
        };
        assert_eq!(
            ancestor_admitted(&null, &user),
            Err(StoreError::Permissions)
        );
        let other_type = descriptor(
            user.clone(),
            false,
            vec![Ace {
                kind: AceKind::Other(5),
                flags: 0,
                mask: 0,
                sid: None,
            }],
        );
        assert_eq!(
            ancestor_admitted(&other_type, &user),
            Err(StoreError::Permissions)
        );
        let denied = descriptor(
            user.clone(),
            false,
            vec![Ace {
                kind: AceKind::Denied,
                flags: 0,
                mask: FULL,
                sid: Some(users),
            }],
        );
        assert_eq!(ancestor_admitted(&denied, &user), Ok(()));
    }

    #[test]
    fn store_directory_needs_owner_protection_and_only_user_and_system() {
        let user = user_sid();
        let system = sid(&[18]);
        let private = |protected, aces| descriptor(user.clone(), protected, aces);
        let good = vec![
            allow(user.clone(), OBJECT_INHERIT | CONTAINER_INHERIT, FULL),
            allow(system.clone(), OBJECT_INHERIT | CONTAINER_INHERIT, FULL),
        ];
        assert_eq!(
            store_directory_admitted(&private(true, good.clone()), &user),
            Ok(())
        );
        assert_eq!(
            store_directory_admitted(&private(false, good.clone()), &user),
            Err(StoreError::Permissions),
            "inheritance enabled"
        );
        let mut admins = good.clone();
        admins.push(allow(sid(&[32, 544]), 0, FULL));
        assert_eq!(
            store_directory_admitted(&private(true, admins), &user),
            Err(StoreError::Permissions)
        );
        let mut capability = good.clone();
        capability.push(allow(Sid::new(15, &[3, 1]).unwrap(), 0, FULL));
        assert_eq!(
            store_directory_admitted(&private(true, capability), &user),
            Err(StoreError::Permissions),
            "capability SIDs are never accepted on the store"
        );
        let owned_by_admins = descriptor(sid(&[32, 544]), true, good.clone());
        assert_eq!(
            store_directory_admitted(&owned_by_admins, &user),
            Err(StoreError::Permissions)
        );
        let null = Descriptor {
            owner: user.clone(),
            control: 0x9004,
            dacl: None,
        };
        assert_eq!(
            store_directory_admitted(&null, &user),
            Err(StoreError::Permissions)
        );
        // Files may inherit their entries from the store directory.
        let inherited = descriptor(
            user.clone(),
            false,
            vec![
                allow(user.clone(), INHERITED, FULL),
                allow(system, INHERITED, FULL),
            ],
        );
        assert_eq!(store_file_admitted(&inherited, &user), Ok(()));
    }

    #[test]
    fn a_config_directory_may_be_readable_but_not_writable_by_others() {
        let user = user_sid();
        let users = sid(&[32, 545]);
        let readable = descriptor(
            user.clone(),
            false,
            vec![
                allow(user.clone(), 0, FULL),
                allow(users.clone(), 0, READ_EXECUTE),
            ],
        );
        assert_eq!(config_directory_admitted(&readable, &user), Ok(()));
        for mask in [0x2, 0x4, 0x10, 0x100, 0x4000_0000, 0x0001_0000] {
            let writable = descriptor(user.clone(), false, vec![allow(users.clone(), 0, mask)]);
            assert_eq!(
                config_directory_admitted(&writable, &user),
                Err(StoreError::Permissions),
                "{mask:#x}"
            );
        }
        // Inherit-only write rights do not apply to the directory itself.
        let inherit_only = descriptor(
            user.clone(),
            false,
            vec![allow(users, INHERIT_ONLY | OBJECT_INHERIT, FULL)],
        );
        assert_eq!(config_directory_admitted(&inherit_only, &user), Ok(()));
    }

    #[test]
    fn paths_outside_plain_drive_paths_are_refused_before_any_open() {
        assert_eq!(
            parse(Path::new(r"\\server\share\sr")),
            Err(StoreError::UnsupportedFilesystem)
        );
        assert_eq!(
            parse(Path::new(r"\\?\UNC\server\share\sr")),
            Err(StoreError::UnsupportedFilesystem)
        );
        for path in [
            r"relative\sr",
            r"C:relative",
            r"C:\",
            r"C:\a\..\b",
            r"C:\a\con",
            r"C:\a\b:stream",
            r"\\?\GLOBALROOT\Device\X",
            r"\\.\pipe\x",
        ] {
            assert_eq!(
                parse(Path::new(path)),
                Err(StoreError::UnsafePath),
                "{path}"
            );
        }
        let (drive, names) = parse(Path::new(r"c:\Users\me\cache")).unwrap();
        // Path parsing reports the drive letter in upper case.
        assert_eq!(drive, b'C');
        assert_eq!(names, ["Users", "me", "cache"]);
    }

    fn volume(
        filesystem: &str,
        drive_type: u32,
        remote: Result<(), i32>,
        path: &str,
    ) -> sr_win_sys::windows::Volume {
        sr_win_sys::windows::Volume {
            filesystem: filesystem.to_owned(),
            serial: 1,
            flags: 0,
            final_path: path.into(),
            guid_root: Some(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\".into()),
            drive_type: Some(drive_type),
            remote_protocol: remote,
        }
    }

    #[test]
    fn only_local_fixed_ntfs_or_refs_through_the_named_drive_is_admitted() {
        let local = Err(ERROR_INVALID_PARAMETER);
        let path = r"\\?\C:\Users\me\cache";
        assert!(admitted_volume(
            &volume("NTFS", DRIVE_FIXED, local, path),
            b'C'
        ));
        assert!(admitted_volume(
            &volume("ReFS", DRIVE_FIXED, local, path),
            b'c'
        ));
        for filesystem in ["FAT32", "exFAT", "FAT", "UDF", "CDFS", "ntfs", ""] {
            let candidate = volume(filesystem, DRIVE_FIXED, local, path);
            assert!(!admitted_volume(&candidate, b'C'), "{filesystem}");
        }
        // DRIVE_REMOVABLE, DRIVE_REMOTE, DRIVE_CDROM, DRIVE_RAMDISK, unknown.
        for drive_type in [2, 4, 5, 6, 0] {
            let candidate = volume("NTFS", drive_type, local, path);
            assert!(!admitted_volume(&candidate, b'C'), "{drive_type}");
        }
        // A file that answers FileRemoteProtocolInfo, or fails it otherwise.
        assert!(!admitted_volume(
            &volume("NTFS", DRIVE_FIXED, Ok(()), path),
            b'C'
        ));
        assert!(!admitted_volume(
            &volume("NTFS", DRIVE_FIXED, Err(5), path),
            b'C'
        ));
        // `SUBST S: C:\...`: the handle's final drive is not the named one.
        assert!(!admitted_volume(
            &volume("NTFS", DRIVE_FIXED, local, path),
            b'S'
        ));
        // A UNC final path names no drive.
        let unc = r"\\?\UNC\server\share\cache";
        assert!(!admitted_volume(
            &volume("NTFS", DRIVE_FIXED, local, unc),
            b'C'
        ));
    }

    #[test]
    fn creation_descriptors_name_only_the_user_and_system() {
        let user = user_sid();
        assert_eq!(
            directory_sddl(&user),
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FA;;;SY)"
        );
        assert_eq!(
            file_sddl(&user),
            "O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;FA;;;SY)"
        );
    }
}
