//! The Win32 calls. This is the only module in SkillRanker that contains
//! unsafe code.
//!
//! Audit rules (docs/windows-private-storage.md, "Mechanism"):
//! - Every call takes a handle borrowed from a live `&File`, the process's own
//!   pseudo-handle, or a token handle owned by an `OwnedHandle` here, so no
//!   handle outlives its owner and none is closed twice.
//! - Reads never re-resolve a caller's path: object identity comes from the
//!   handle. The one path a read uses ([`free_bytes_for_caller`]) is the volume
//!   GUID root that Windows reports for that handle. The two creation calls
//!   ([`create_directory_with`], [`create_new_file_with`]) and
//!   [`replace_file`] take the paths the caller names, because Win32 creates
//!   and renames by name; the caller holds the checked parent open so those
//!   names still denote children of it.
//! - Buffers are Rust-owned with lengths passed in units Windows expects;
//!   memory Windows allocates (`GetSecurityInfo`,
//!   `ConvertStringSecurityDescriptorToSecurityDescriptorW`) is freed by a guard
//!   before returning, after its bytes have been copied into owned values or
//!   the call that used it has returned.
//! - Raw memory is only read as byte slices whose lengths Windows reported
//!   (`GetLengthSid`, `ACE_HEADER.AceSize`); all interpretation happens in the
//!   safe parsers in `sid` and `acl`.
//! - The one thread call ([`cancel_synchronous_io`], sr-winpar.15) takes a
//!   thread handle borrowed from its live owner (a `JoinHandle`) and only
//!   asks Windows to abort that thread's pending synchronous read.
//! - One unsafe operation per block, each with its SAFETY argument.

use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileRemoteProtocolInfo, GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, VOLUME_NAME_DOS, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::acl::{Ace, Descriptor};
use crate::sid::Sid;

/// `FILE_FLAG_BACKUP_SEMANTICS`, needed to open a directory as a `File`.
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// `DRIVE_FIXED` from `GetDriveTypeW`.
pub const DRIVE_FIXED: u32 = 3;

fn raw(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Copies `length` bytes at `pointer`.
///
/// # Safety
/// `pointer` must be valid for reads of `length` bytes for the duration of
/// the call.
unsafe fn copy_bytes(pointer: *const c_void, length: usize) -> Vec<u8> {
    // SAFETY: the caller guarantees `length` readable bytes at `pointer`;
    // u8 has no alignment requirement.
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }.to_vec()
}

/// Copies the SID at `sid`.
///
/// # Safety
/// `sid` must point to a valid SID that stays alive during the call.
unsafe fn copy_sid(sid: PSID) -> io::Result<Sid> {
    if sid.is_null() {
        return Err(invalid("Windows returned no SID"));
    }
    // SAFETY: the caller guarantees `sid` is a valid SID.
    let length = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: GetLengthSid reports the byte length of the valid SID at `sid`.
    let bytes = unsafe { copy_bytes(sid, length) };
    Sid::from_bytes(&bytes).map_err(|_| invalid("Windows returned a malformed SID"))
}

/// The user SID of the current process's token.
pub fn token_user_sid() -> io::Result<Sid> {
    // SAFETY: GetCurrentProcess has no preconditions; its pseudo-handle needs
    // no closing.
    let process = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = null_mut();
    // SAFETY: `process` is this process's pseudo-handle; `token` is a valid
    // out-pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    // SAFETY: OpenProcessToken succeeded, so `token` is an open handle this
    // function now owns; OwnedHandle closes it exactly once.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 only queries the needed size into
    // `needed`, a valid out-pointer.
    let sized = unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
    };
    // SAFETY: GetLastError has no preconditions.
    if sized != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
        return Err(invalid("token user size query failed"));
    }
    // u64 storage gives TOKEN_USER (pointer-aligned) a suitably aligned buffer.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let length = (buffer.len() * 8) as u32;
    // SAFETY: `buffer` is writable for `length` bytes and outlives the call.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error());
    }
    // SAFETY: the call filled `buffer` with a TOKEN_USER, whose alignment the
    // u64 buffer satisfies; it is read by value and its SID points into
    // `buffer`, which lives until the copy below.
    let user = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read() };
    // SAFETY: `user.User.Sid` points into `buffer`, still alive here.
    unsafe { copy_sid(user.User.Sid) }
}

/// Frees memory `GetSecurityInfo` allocated.
struct LocalAllocation(PSECURITY_DESCRIPTOR);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from GetSecurityInfo, which documents
            // freeing it with LocalFree, and is freed only here.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// The owner and DACL of the object `file` refers to. `file` must have been
/// opened with read access (which includes `READ_CONTROL`).
pub fn security_of(file: &File) -> io::Result<Descriptor> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `file` keeps the handle open for the call; the out-pointers are
    // valid and the unused group/SACL out-pointers are null, as allowed.
    let status = unsafe {
        GetSecurityInfo(
            raw(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // `owner` and `dacl` point into `descriptor`, freed when this drops.
    let _allocation = LocalAllocation(descriptor);

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the live descriptor GetSecurityInfo returned;
    // both out-pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(last_error());
    }
    // SAFETY: `owner` points to the owner SID inside the live descriptor.
    let owner = unsafe { copy_sid(owner) }?;
    let dacl = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` is the live DACL inside `descriptor`.
        Some(unsafe { entries(dacl) }?)
    };
    Ok(Descriptor {
        owner,
        control,
        dacl,
    })
}

/// Copies and parses every entry of `acl`.
///
/// # Safety
/// `acl` must point to a valid ACL that stays alive during the call.
unsafe fn entries(acl: *const ACL) -> io::Result<Vec<Ace>> {
    let mut size = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: `acl` is valid per the caller; `size` is writable for the
    // length passed.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error());
    }
    let mut aces = Vec::with_capacity(size.AceCount as usize);
    for index in 0..size.AceCount {
        let mut entry: *mut c_void = null_mut();
        // SAFETY: `acl` is valid and `index` is below its AceCount.
        if unsafe { GetAce(acl, index, &mut entry) } == 0 {
            return Err(last_error());
        }
        // SAFETY: GetAce returned a pointer to an entry inside the live ACL,
        // which starts with a 4-byte ACE_HEADER.
        let header = unsafe { copy_bytes(entry, 4) };
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 4 {
            return Err(invalid("ACE header reports an impossible size"));
        }
        // SAFETY: AceSize is the byte length of this entry inside the ACL.
        let bytes = unsafe { copy_bytes(entry, length) };
        aces.push(Ace::parse(&bytes).map_err(|_| invalid("Windows returned a malformed ACE"))?);
    }
    Ok(aces)
}

/// What Windows reports about the volume holding a handle's object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Volume {
    /// `GetVolumeInformationByHandleW`'s filesystem name, e.g. `NTFS`.
    pub filesystem: String,
    pub serial: u32,
    /// `FILE_SUPPORTS_*` / `FILE_*` filesystem flags.
    pub flags: u32,
    /// The handle's final path with a DOS volume name (`\\?\C:\…` or
    /// `\\?\UNC\server\share\…`).
    pub final_path: OsString,
    /// `\\?\Volume{GUID}\`, when the volume has one (network volumes do not).
    pub guid_root: Option<OsString>,
    /// `GetDriveTypeW` of `guid_root`, when there is one.
    pub drive_type: Option<u32>,
    /// `Ok(())` when `FileRemoteProtocolInfo` succeeded (a remote file);
    /// otherwise the Win32 error it returned.
    pub remote_protocol: Result<(), i32>,
}

/// The handle's final path in the requested volume-name form.
fn final_path(file: &File, flags: u32) -> io::Result<Vec<u16>> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: `buffer` is writable for `buffer.len()` UTF-16 units.
        let written = unsafe {
            GetFinalPathNameByHandleW(raw(file), buffer.as_mut_ptr(), buffer.len() as u32, flags)
        } as usize;
        if written == 0 {
            return Err(last_error());
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(buffer);
        }
        // `written` is the needed size including the terminator.
        if written > 32_768 {
            return Err(invalid("final path exceeds the Win32 path limit"));
        }
        buffer.resize(written, 0);
    }
}

fn guid_root(path: &[u16]) -> Option<Vec<u16>> {
    let text = String::from_utf16(path).ok()?;
    let end = text.strip_prefix(r"\\?\Volume{")?.find("}\\")? + r"\\?\Volume{".len() + 2;
    Some(path[..end].to_vec())
}

fn terminated(path: &[u16]) -> Vec<u16> {
    path.iter().copied().chain(std::iter::once(0)).collect()
}

/// Volume facts for the object `file` refers to.
pub fn volume_of(file: &File) -> io::Result<Volume> {
    let mut name = [0u16; 261];
    let mut serial = 0u32;
    let mut component = 0u32;
    let mut flags = 0u32;
    // SAFETY: `file` keeps the handle open; the volume-name buffer is omitted
    // (null, 0) and `name` is writable for its length.
    if unsafe {
        GetVolumeInformationByHandleW(
            raw(file),
            null_mut(),
            0,
            &mut serial,
            &mut component,
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    let filesystem = String::from_utf16(&name[..length])
        .map_err(|_| invalid("filesystem name is not UTF-16"))?;

    let final_path = OsString::from_wide(&final_path(file, VOLUME_NAME_DOS)?);
    let guid_root = final_path_guid_root(file);
    let drive_type = guid_root.as_ref().map(|root| {
        let root = terminated(root);
        // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call.
        unsafe { GetDriveTypeW(root.as_ptr()) }
    });

    // SAFETY: an all-zero FILE_REMOTE_PROTOCOL_INFO (integers and unions of
    // integers) is a valid value.
    let mut info: FILE_REMOTE_PROTOCOL_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is writable for the size passed and outlives the call.
    let remote = unsafe {
        GetFileInformationByHandleEx(
            raw(file),
            FileRemoteProtocolInfo,
            (&raw mut info).cast(),
            size_of::<FILE_REMOTE_PROTOCOL_INFO>() as u32,
        )
    };
    let remote_protocol = if remote != 0 {
        Ok(())
    } else {
        Err(last_error().raw_os_error().unwrap_or(-1))
    };

    Ok(Volume {
        filesystem,
        serial,
        flags,
        final_path,
        guid_root: guid_root.map(|root| OsString::from_wide(&root)),
        drive_type,
        remote_protocol,
    })
}

fn final_path_guid_root(file: &File) -> Option<Vec<u16>> {
    guid_root(&final_path(file, VOLUME_NAME_GUID).ok()?)
}

/// Bytes available to this user (honoring disk quotas) on the volume holding
/// `file`'s object, queried through the volume's GUID root.
pub fn free_bytes_for_caller(file: &File) -> io::Result<u64> {
    let root = final_path_guid_root(file)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "volume has no GUID root"))?;
    let root = terminated(&root);
    let mut available = 0u64;
    // SAFETY: `root` is NUL-terminated and outlives the call; the two unused
    // totals are null, as allowed.
    if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut available, null_mut(), null_mut()) } == 0 {
        return Err(last_error());
    }
    Ok(available)
}

/// A NUL-terminated UTF-16 copy of `path`; an interior NUL is refused.
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    Ok(terminated(&long_path(wide)))
}

/// Paths of `MAX_PATH` or more reach the file system only with the `\\?\`
/// prefix, as `std` adds for its own calls. The prefix turns off Win32
/// normalization, so it is added only to a plain drive path (`X:\...`) with
/// backslash separators and no `.` or `..` component, whose meaning it keeps.
/// The 248-unit threshold is `CreateDirectoryW`'s, which reserves room for an
/// 8.3 name.
fn long_path(wide: Vec<u16>) -> Vec<u16> {
    const BACKSLASH: u16 = b'\\' as u16;
    let plain_drive = wide.len() >= 3
        && u8::try_from(wide[0]).is_ok_and(|letter| letter.is_ascii_alphabetic())
        && wide[1] == u16::from(b':')
        && wide[2] == BACKSLASH;
    let plain_components = !wide.contains(&u16::from(b'/'))
        && wide[3.min(wide.len())..]
            .split(|unit| *unit == BACKSLASH)
            .all(|component| component != [u16::from(b'.')] && component != [u16::from(b'.'); 2]);
    if wide.len() < 248 || !plain_drive || !plain_components {
        return wide;
    }
    let mut prefixed: Vec<u16> = r"\\?\".encode_utf16().collect();
    prefixed.extend(wide);
    prefixed
}

/// A security descriptor converted from SDDL, freed on drop.
fn descriptor_from_sddl(sddl: &str) -> io::Result<LocalAllocation> {
    if sddl.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SDDL contains NUL",
        ));
    }
    let text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `text` is NUL-terminated and outlives the call; `descriptor` is a
    // valid out-pointer and the optional size out-pointer is null.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(LocalAllocation(descriptor))
}

fn attributes(descriptor: &LocalAllocation) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

/// Creates the directory `path` with the security descriptor `sddl` applied
/// at creation (owner and DACL), instead of one inherited from its parent.
/// Fails with `AlreadyExists` when anything already has that name.
pub fn create_directory_with(path: &Path, sddl: &str) -> io::Result<()> {
    let path = wide_path(path)?;
    let descriptor = descriptor_from_sddl(sddl)?;
    let attributes = attributes(&descriptor);
    // SAFETY: `path` is NUL-terminated; `attributes` and the descriptor it
    // points to outlive the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Creates the new file `path` (never opening an existing one, link or not)
/// with the security descriptor `sddl` applied at creation, opened for read
/// and write and shared for read, write and delete as an ordinary file is.
pub fn create_new_file_with(path: &Path, sddl: &str) -> io::Result<File> {
    let path = wide_path(path)?;
    let descriptor = descriptor_from_sddl(sddl)?;
    let attributes = attributes(&descriptor);
    // SAFETY: `path` is NUL-terminated; `attributes` and its descriptor
    // outlive the call; no template handle is passed.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: CreateFileW returned a valid handle that this function owns;
    // the File closes it exactly once.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Atomically replaces `to` with `from` (both in the same directory), the
/// Windows counterpart of `renameat` followed by a directory `fsync`:
/// `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, so an existing target is
/// replaced in one rename and never left missing, and `MOVEFILE_WRITE_THROUGH`,
/// which asks for the move to be flushed (documented for a move performed as
/// copy and delete; no directory-entry flush is documented for a rename within
/// one directory, unlike a Unix directory `fsync`). A target that
/// is a link is replaced, not followed. Fails if `from` is open without
/// `FILE_SHARE_DELETE` or `to` is open by a process that did not share delete.
pub fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    let from = wide_path(from)?;
    let to = wide_path(to)?;
    // SAFETY: both paths are NUL-terminated and outlive the call.
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(())
}

/// Renames `from` to `to` (both in the same directory) only if `to` does not
/// exist, the Windows counterpart of `renameat2(RENAME_NOREPLACE)` followed by
/// a directory `fsync`: `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`, so
/// the file system refuses an existing or raced-in target of any kind (file,
/// directory or link) in the same operation that renames, with
/// `ERROR_ALREADY_EXISTS` (`io::ErrorKind::AlreadyExists`); and with
/// `MOVEFILE_WRITE_THROUGH`, with the same documented limits as
/// [`replace_file`]. A failed call leaves both names as they were.
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let from = wide_path(from)?;
    let to = wide_path(to)?;
    // SAFETY: both paths are NUL-terminated and outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Asks Windows to abort the synchronous I/O call `thread` is blocked in
/// (`CancelSynchronousIo`); the call then fails in that thread with
/// `ERROR_OPERATION_ABORTED`. `Ok(false)` means the thread had no pending
/// synchronous call (`ERROR_NOT_FOUND`): it has not entered its read yet, or
/// has left it, so a caller that needs the thread out of its read retries
/// until the thread finishes. Used for the stdin helper (sr-winpar.15).
pub fn cancel_synchronous_io(thread: &impl AsRawHandle) -> io::Result<bool> {
    // SAFETY: the thread handle is borrowed from its live owner, which keeps it
    // open for the duration of the call; CancelSynchronousIo only reads it.
    if unsafe { CancelSynchronousIo(thread.as_raw_handle() as HANDLE) } != 0 {
        return Ok(true);
    }
    let error = last_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{guid_root, long_path};

    #[test]
    fn only_long_plain_drive_paths_get_the_verbatim_prefix() {
        let long = format!(r"C:\{}\name", "d".repeat(250));
        assert_eq!(
            String::from_utf16(&long_path(wide(&long))).unwrap(),
            format!(r"\\?\{long}")
        );
        for unchanged in [
            r"C:\short\name".to_owned(),
            format!(r"C:\{}\..\name", "d".repeat(250)),
            format!(r"C:\{}\.\name", "d".repeat(250)),
            format!(r"C:/{}/name", "d".repeat(250)),
            format!(r"\\?\C:\{}\name", "d".repeat(250)),
            format!(r"\\server\share\{}", "d".repeat(250)),
        ] {
            assert_eq!(
                String::from_utf16(&long_path(wide(&unchanged))).unwrap(),
                unchanged
            );
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn guid_root_keeps_only_the_volume_prefix() {
        let path = wide(r"\\?\Volume{0a1b2c3d-0000-0000-0000-100000000000}\Users\x");
        assert_eq!(
            guid_root(&path),
            Some(wide(r"\\?\Volume{0a1b2c3d-0000-0000-0000-100000000000}\"))
        );
        assert_eq!(guid_root(&wide(r"\\?\C:\Users")), None);
        assert_eq!(guid_root(&wide(r"\\?\Volume{abc")), None);
    }
}
