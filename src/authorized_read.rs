//! Descriptor-based authorized reads of bounded regular files.
//!
//! Every component is opened relative to an authorized root's directory
//! descriptor with `O_NOFOLLOW`, so a path that is swapped between the check
//! and the open cannot redirect the read: the object whose type is verified is
//! the object that is read. Symlinks are followed only into explicitly
//! authorized roots, under a hop bound that terminates cycles. Content hashes
//! come from exactly the bytes returned, never from size or modification time.
//!
//! Discovery walks, frontmatter parsing and roster revalidation are separate
//! boundaries; this module only opens, validates and reads one file. Callers
//! run these blocking leaves under their own deadline admission.

use crate::identity::ContentHash;
use crate::limits::ResourceLimit;
use crate::privacy::{TrustedAbsoluteRoot, WorkspaceRelativeRoot};
use crate::roster::LocalPath;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Component, Path, PathBuf};
use sys::{Descriptor, Stat};

/// Symlink hops permitted while resolving one request; cycles end here.
pub const MAX_SYMLINK_HOPS: u32 = 16;
/// Total component openings permitted while resolving one request.
pub const MAX_RESOLUTION_STEPS: usize = 512;
/// Bound for one symlink target read from the filesystem.
pub const MAX_LINK_TARGET_BYTES: usize = 4096;

/// The type of an object that was opened, for diagnostics without paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
    Unknown,
}

impl FileKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "regular file",
            Self::Directory => "directory",
            Self::Symlink => "symbolic link",
            Self::Fifo => "FIFO",
            Self::Socket => "socket",
            Self::CharacterDevice => "character device",
            Self::BlockDevice => "block device",
            Self::Unknown => "unsupported file type",
        }
    }
}

/// Filesystem identity of an opened object. Two names for one file (a hard
/// alias) share it, so callers can deduplicate without comparing paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    /// Build an identity from a caller's own stat of the same object, so
    /// enumeration and reads can be compared without a second open.
    pub const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    pub const fn device(self) -> u64 {
        self.device
    }

    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// Failures are reported without paths, link targets or file content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    InvalidRelativePath,
    TooManyComponents,
    NotFound,
    PermissionDenied,
    NotADirectory,
    NotRegularFile(FileKind),
    EscapesAuthorizedRoots,
    SymlinkLoop,
    LinkTargetTooLong,
    TooLarge { limit: usize },
    RootUnavailable,
    Io,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelativePath => f.write_str("request is not a valid relative path"),
            Self::TooManyComponents => f.write_str("path resolution exceeded its component bound"),
            Self::NotFound => f.write_str("no such file under the authorized root"),
            Self::PermissionDenied => f.write_str("permission denied under the authorized root"),
            Self::NotADirectory => f.write_str("a path component is not a directory"),
            Self::NotRegularFile(kind) => {
                write!(
                    f,
                    "refusing to read a {}; only regular files are read",
                    kind.as_str()
                )
            }
            Self::EscapesAuthorizedRoots => f.write_str("path escapes every authorized root"),
            Self::SymlinkLoop => f.write_str("symbolic links exceeded the hop bound"),
            Self::LinkTargetTooLong => f.write_str("symbolic link target exceeds its byte bound"),
            Self::TooLarge { limit } => write!(f, "file exceeds its {limit} byte bound"),
            Self::RootUnavailable => f.write_str("authorized root is unavailable"),
            Self::Io => f.write_str("filesystem read failed"),
        }
    }
}

impl std::error::Error for ReadError {}

/// What opening one name below a held directory found.
enum Opened {
    /// The object itself, opened without following a final link.
    Object(Descriptor, Stat),
    /// A symbolic link (on Windows, a name-surrogate reparse point) that the
    /// walk must resolve itself, within its authorized roots.
    Link,
}

/// A directory descriptor that anchors every read. Holding the descriptor binds
/// later operations to this exact directory, even if its name is replaced.
#[derive(Debug)]
pub struct AuthorizedRoot {
    directory: Descriptor,
    absolute: PathBuf,
    identity: FileIdentity,
}

impl AuthorizedRoot {
    /// Open a trusted absolute root. Symlinks inside the granted path itself
    /// are resolved by the kernel once, here; later reads never follow a link
    /// out of the opened directory.
    pub fn open_absolute(path: &Path) -> Result<Self, ReadError> {
        if !path.is_absolute() {
            return Err(ReadError::InvalidRelativePath);
        }
        let (directory, stat) = sys::open_root(path)?;
        if sys::kind(&stat) != FileKind::Directory {
            return Err(ReadError::NotADirectory);
        }
        Ok(Self {
            directory,
            absolute: path.to_path_buf(),
            identity: sys::identity(&stat),
        })
    }

    /// Open a root granted by trusted user configuration.
    pub fn open_trusted(root: &TrustedAbsoluteRoot) -> Result<Self, ReadError> {
        Self::open_absolute(root.as_path())
    }

    /// Open a workspace-relative root without leaving this root. Components are
    /// opened one at a time, so a replaced directory cannot redirect the walk.
    pub fn open_workspace_relative(
        &self,
        relative: &WorkspaceRelativeRoot,
    ) -> Result<Self, ReadError> {
        let roots = AuthorizedRoots::single(self.try_clone()?);
        let components = split_components(relative.as_path())?;
        if components.is_empty() {
            return self.try_clone();
        }
        let resolved = Walk::new(&roots, 0)?.resolve(components, Want::Directory)?;
        Ok(Self {
            identity: sys::identity(&resolved.stat),
            directory: resolved.descriptor,
            absolute: resolved.absolute,
        })
    }

    pub fn try_clone(&self) -> Result<Self, ReadError> {
        Ok(Self {
            directory: self
                .directory
                .try_clone()
                .map_err(|_| ReadError::RootUnavailable)?,
            absolute: self.absolute.clone(),
            identity: self.identity,
        })
    }

    pub fn absolute_path(&self) -> &Path {
        &self.absolute
    }

    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[cfg(unix)]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }
}

/// The complete set of roots a symlink may resolve into.
#[derive(Debug)]
pub struct AuthorizedRoots {
    roots: Vec<AuthorizedRoot>,
}

impl AuthorizedRoots {
    pub fn new(roots: Vec<AuthorizedRoot>) -> Self {
        Self { roots }
    }

    pub fn single(root: AuthorizedRoot) -> Self {
        Self { roots: vec![root] }
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&AuthorizedRoot> {
        self.roots.get(index)
    }

    /// Longest-prefix match of an absolute path against the authorized roots.
    fn locate(&self, absolute: &Path) -> Option<(usize, Vec<OsString>)> {
        let mut best: Option<(usize, Vec<OsString>)> = None;
        for (index, root) in self.roots.iter().enumerate() {
            let Ok(rest) = absolute.strip_prefix(&root.absolute) else {
                continue;
            };
            let depth = root.absolute.components().count();
            if best.as_ref().is_none_or(|(current, _)| {
                depth > self.roots[*current].absolute.components().count()
            }) {
                let components: Vec<OsString> = rest
                    .components()
                    .map(|component| component.as_os_str().to_os_string())
                    .collect();
                best = Some((index, components));
            }
        }
        best
    }

    /// Read a bounded regular file below `root_index`.
    pub fn read_bounded(
        &self,
        root_index: usize,
        relative: &Path,
        limit: ResourceLimit,
    ) -> Result<BoundedRead, ReadError> {
        let components = split_components(relative)?;
        if components.is_empty() {
            return Err(ReadError::InvalidRelativePath);
        }
        let resolved = Walk::new(self, root_index)?.resolve(components, Want::File)?;
        read_opened(resolved, limit)
    }

    /// Open an authorized regular file for a caller that performs bounded tail
    /// reads. The returned descriptor is the object checked by the safe walk;
    /// callers must not reopen its path after authorization.
    pub(crate) fn open_absolute_file(&self, absolute: &Path) -> Result<File, ReadError> {
        if !absolute.is_absolute() {
            return Err(ReadError::InvalidRelativePath);
        }
        let (index, components) = self
            .locate(absolute)
            .ok_or(ReadError::EscapesAuthorizedRoots)?;
        if components.is_empty() {
            return Err(ReadError::NotRegularFile(FileKind::Directory));
        }
        let mut walk = Walk::new(self, index)?;
        walk.require_existing_link_targets = true;
        let resolved = walk.resolve(components, Want::File)?;
        Ok(sys::into_file(resolved.descriptor))
    }

    /// Read a bounded regular file named by an absolute path that must lie
    /// within an authorized root.
    pub fn read_absolute(
        &self,
        absolute: &Path,
        limit: ResourceLimit,
    ) -> Result<BoundedRead, ReadError> {
        if !absolute.is_absolute() {
            return Err(ReadError::InvalidRelativePath);
        }
        let (index, components) = self
            .locate(absolute)
            .ok_or(ReadError::EscapesAuthorizedRoots)?;
        if components.is_empty() {
            return Err(ReadError::NotRegularFile(FileKind::Directory));
        }
        let resolved = Walk::new(self, index)?.resolve(components, Want::File)?;
        read_opened(resolved, limit)
    }
}

/// Bytes read from one authorized file, with the hash of those exact bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedRead {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    identity: FileIdentity,
    path: LocalPath,
}

impl BoundedRead {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derived from `bytes`, never from metadata, so a same-size same-mtime
    /// rewrite produces a different hash.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Native path bytes of the object actually opened; kept local.
    pub fn path(&self) -> &LocalPath {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for BoundedRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedRead")
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Want {
    File,
    Directory,
}

struct Resolved {
    descriptor: Descriptor,
    stat: Stat,
    absolute: PathBuf,
}

fn split_components(path: &Path) -> Result<Vec<OsString>, ReadError> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReadError::InvalidRelativePath);
            }
        }
    }
    Ok(components)
}

/// A descriptor stack walk. `..` inside a symlink target pops the stack and can
/// never rise above the root the walk is currently anchored to.
struct Walk<'a> {
    roots: &'a AuthorizedRoots,
    root: usize,
    stack: Vec<Descriptor>,
    names: Vec<OsString>,
    hops: u32,
    require_existing_link_targets: bool,
    steps: usize,
}

impl<'a> Walk<'a> {
    fn new(roots: &'a AuthorizedRoots, root: usize) -> Result<Self, ReadError> {
        let base = roots.get(root).ok_or(ReadError::RootUnavailable)?;
        Ok(Self {
            roots,
            root,
            stack: vec![
                base.directory
                    .try_clone()
                    .map_err(|_| ReadError::RootUnavailable)?,
            ],
            names: Vec::new(),
            hops: 0,
            require_existing_link_targets: false,
            steps: 0,
        })
    }

    fn top(&self) -> Result<&Descriptor, ReadError> {
        self.stack.last().ok_or(ReadError::EscapesAuthorizedRoots)
    }

    fn absolute(&self, last: &OsStr) -> PathBuf {
        let mut path = self.roots.roots[self.root].absolute.clone();
        for name in &self.names {
            path.push(name);
        }
        path.push(last);
        path
    }

    fn resolve(mut self, components: Vec<OsString>, want: Want) -> Result<Resolved, ReadError> {
        let mut queue: VecDeque<OsString> = components.into();
        while let Some(name) = queue.pop_front() {
            self.steps += 1;
            if self.steps > MAX_RESOLUTION_STEPS {
                return Err(ReadError::TooManyComponents);
            }
            if name.as_os_str() == OsStr::new(".") {
                continue;
            }
            if name.as_os_str() == OsStr::new("..") {
                if self.names.pop().is_none() {
                    return Err(ReadError::EscapesAuthorizedRoots);
                }
                self.stack.pop();
                continue;
            }
            let last = queue.is_empty();
            match sys::open_child(self.top()?, name.as_os_str(), last) {
                Ok(Opened::Object(descriptor, stat)) => {
                    let kind = sys::kind(&stat);
                    if last {
                        let acceptable = match want {
                            Want::File => kind == FileKind::Regular,
                            Want::Directory => kind == FileKind::Directory,
                        };
                        if !acceptable {
                            return Err(ReadError::NotRegularFile(kind));
                        }
                        let absolute = self.absolute(name.as_os_str());
                        return Ok(Resolved {
                            descriptor,
                            stat,
                            absolute,
                        });
                    }
                    if kind != FileKind::Directory {
                        return Err(ReadError::NotADirectory);
                    }
                    self.stack.push(descriptor);
                    self.names.push(name);
                }
                Ok(Opened::Link) => {
                    let target = self.follow(name.as_os_str())?;
                    for component in target.into_iter().rev() {
                        queue.push_front(component);
                    }
                }
                Err(ReadError::NotFound) if self.hops > 0 && self.require_existing_link_targets => {
                    return Err(ReadError::InvalidRelativePath);
                }
                Err(error) => return Err(error),
            }
        }
        Err(ReadError::InvalidRelativePath)
    }

    /// Read one link target and re-anchor the walk. An absolute target must
    /// land inside an authorized root; a relative target stays in this walk.
    fn follow(&mut self, name: &OsStr) -> Result<Vec<OsString>, ReadError> {
        self.hops += 1;
        if self.hops > MAX_SYMLINK_HOPS {
            return Err(ReadError::SymlinkLoop);
        }
        let target = sys::read_link(self.top()?, name)?;
        if target.as_encoded_bytes().len() > MAX_LINK_TARGET_BYTES {
            return Err(ReadError::LinkTargetTooLong);
        }
        let target = PathBuf::from(target);
        if !target.is_absolute() {
            return relative_components(&target);
        }
        let (index, components) = self
            .roots
            .locate(&target)
            .ok_or(ReadError::EscapesAuthorizedRoots)?;
        let base = self.roots.get(index).ok_or(ReadError::RootUnavailable)?;
        self.root = index;
        self.stack = vec![
            base.directory
                .try_clone()
                .map_err(|_| ReadError::RootUnavailable)?,
        ];
        self.names.clear();
        Ok(components)
    }
}

fn relative_components(target: &Path) -> Result<Vec<OsString>, ReadError> {
    let mut components = Vec::new();
    for component in target.components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::ParentDir => components.push(OsString::from("..")),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(ReadError::EscapesAuthorizedRoots);
            }
        }
    }
    Ok(components)
}

fn read_opened(resolved: Resolved, limit: ResourceLimit) -> Result<BoundedRead, ReadError> {
    let Resolved {
        descriptor,
        stat,
        absolute,
    } = resolved;
    let cap = limit.cap_plus_one().map_err(|_| ReadError::Io)?;
    let mut file = sys::into_file(descriptor);
    let mut bytes = Vec::with_capacity(cap.min(64 * 1024));
    file.by_ref()
        .take(cap as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadError::Io)?;
    if bytes.len() > limit.max() {
        return Err(ReadError::TooLarge { limit: limit.max() });
    }
    Ok(BoundedRead {
        content_hash: ContentHash::from_bytes(&bytes),
        bytes,
        identity: sys::identity(&stat),
        path: LocalPath::new(absolute),
    })
}

/// The four operating-system primitives the walk needs. Everything above this
/// module is shared; only how one name is opened below a held directory differs.
#[cfg(unix)]
mod sys {
    use super::{FileIdentity, FileKind, Opened, ReadError};
    use nix::errno::Errno;
    use nix::fcntl::{AtFlags, OFlag, open, openat, readlinkat};
    use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    pub(super) type Descriptor = OwnedFd;
    pub(super) type Stat = FileStat;

    pub(super) fn map_errno(errno: Errno) -> ReadError {
        match errno {
            Errno::ENOENT => ReadError::NotFound,
            Errno::EACCES | Errno::EPERM => ReadError::PermissionDenied,
            Errno::ENOTDIR => ReadError::NotADirectory,
            Errno::ELOOP | Errno::EMLINK => ReadError::SymlinkLoop,
            Errno::ENAMETOOLONG => ReadError::InvalidRelativePath,
            Errno::EINVAL => ReadError::InvalidRelativePath,
            _ => ReadError::Io,
        }
    }

    pub(super) fn kind(stat: &FileStat) -> FileKind {
        let bits = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        match bits {
            SFlag::S_IFREG => FileKind::Regular,
            SFlag::S_IFDIR => FileKind::Directory,
            SFlag::S_IFLNK => FileKind::Symlink,
            SFlag::S_IFIFO => FileKind::Fifo,
            SFlag::S_IFSOCK => FileKind::Socket,
            SFlag::S_IFCHR => FileKind::CharacterDevice,
            SFlag::S_IFBLK => FileKind::BlockDevice,
            _ => FileKind::Unknown,
        }
    }

    // `dev_t`/`ino_t` widths differ by platform: the casts are identity on
    // Linux and widening on macOS.
    #[allow(clippy::unnecessary_cast)]
    pub(super) fn identity(stat: &FileStat) -> FileIdentity {
        FileIdentity::new(stat.st_dev as u64, stat.st_ino as u64)
    }

    pub(super) fn open_root(path: &Path) -> Result<(OwnedFd, FileStat), ReadError> {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let directory = open(path, flags, Mode::empty()).map_err(map_errno)?;
        let stat = fstat(&directory).map_err(map_errno)?;
        Ok((directory, stat))
    }

    pub(super) fn open_child(
        directory: &OwnedFd,
        name: &OsStr,
        last: bool,
    ) -> Result<Opened, ReadError> {
        let mut flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        if last {
            // Opening a FIFO must not block waiting for a writer.
            flags |= OFlag::O_NONBLOCK;
        } else {
            flags |= OFlag::O_DIRECTORY;
        }
        match openat(directory, name, flags, Mode::empty()) {
            Ok(descriptor) => {
                let stat = fstat(&descriptor).map_err(map_errno)?;
                Ok(Opened::Object(descriptor, stat))
            }
            Err(errno) => {
                // O_NOFOLLOW reports a symlink as ELOOP (ENOTDIR on some
                // platforms when O_DIRECTORY is also set). Confirm the type
                // from the link itself before following it.
                let is_link = matches!(errno, Errno::ELOOP | Errno::EMLINK | Errno::ENOTDIR)
                    && matches!(
                        fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW),
                        Ok(stat) if kind(&stat) == FileKind::Symlink
                    );
                if is_link {
                    Ok(Opened::Link)
                } else {
                    Err(map_errno(errno))
                }
            }
        }
    }

    pub(super) fn read_link(directory: &OwnedFd, name: &OsStr) -> Result<OsString, ReadError> {
        readlinkat(directory, name).map_err(|error| {
            // The confirmed link can become a regular file before readlinkat.
            // EINVAL here is a filesystem race, not an invalid caller path.
            if error == Errno::EINVAL {
                ReadError::Io
            } else {
                map_errno(error)
            }
        })
    }

    pub(super) fn into_file(descriptor: OwnedFd) -> File {
        File::from(descriptor)
    }
}

/// Windows has no `openat`, so each held directory carries the path it was
/// opened by. Every directory on the walk's stack stays open without
/// `FILE_SHARE_DELETE`, which makes Windows refuse to rename, delete or replace
/// it (for example with a junction) while the walk holds it: the path of the
/// next child therefore still names a child of the object that was checked.
/// Final components are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so a link
/// is inspected rather than followed, mirroring `O_NOFOLLOW`.
#[cfg(windows)]
mod sys {
    use super::{FileIdentity, FileKind, Opened, ReadError};
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Component, Path, PathBuf, Prefix};

    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_INVALID_NAME: i32 = 123;
    const ERROR_DIRECTORY: i32 = 267;
    const ERROR_CANT_ACCESS_FILE: i32 = 1920;
    const ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;

    #[derive(Debug)]
    pub(crate) struct Descriptor {
        file: File,
        path: PathBuf,
    }

    impl Descriptor {
        pub(crate) fn try_clone(&self) -> io::Result<Self> {
            Ok(Self {
                file: self.file.try_clone()?,
                path: self.path.clone(),
            })
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Stat {
        kind: FileKind,
        identity: FileIdentity,
    }

    impl Stat {
        pub(crate) const fn kind(&self) -> FileKind {
            self.kind
        }

        pub(crate) const fn identity(&self) -> FileIdentity {
            self.identity
        }
    }

    pub(super) fn map_io(error: &io::Error) -> ReadError {
        match error.raw_os_error() {
            Some(ERROR_PATH_NOT_FOUND) => return ReadError::NotFound,
            Some(ERROR_DIRECTORY) => return ReadError::NotADirectory,
            Some(ERROR_INVALID_NAME) => return ReadError::InvalidRelativePath,
            Some(ERROR_CANT_ACCESS_FILE | ERROR_CANT_RESOLVE_FILENAME) => {
                return ReadError::SymlinkLoop;
            }
            _ => {}
        }
        match error.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            io::ErrorKind::PermissionDenied => ReadError::PermissionDenied,
            io::ErrorKind::NotADirectory => ReadError::NotADirectory,
            io::ErrorKind::InvalidFilename => ReadError::InvalidRelativePath,
            _ => ReadError::Io,
        }
    }

    pub(super) const fn kind(stat: &Stat) -> FileKind {
        stat.kind
    }

    pub(super) const fn identity(stat: &Stat) -> FileIdentity {
        stat.identity
    }

    /// Classify an opened handle. Only name-surrogate reparse points
    /// (symbolic links and junctions) are links; other reparse points such
    /// as cloud placeholders are ordinary files or directories.
    pub(crate) fn stat(file: &File) -> Result<Stat, ReadError> {
        let metadata = file.metadata().map_err(|error| map_io(&error))?;
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Directory
        } else if file_type.is_file() {
            FileKind::Regular
        } else {
            FileKind::Unknown
        };
        let information = winapi_util::file::information(file).map_err(|error| map_io(&error))?;
        Ok(Stat {
            kind,
            identity: FileIdentity::new(
                information.volume_serial_number(),
                information.file_index(),
            ),
        })
    }

    /// Win32 rewrites or reinterprets some names: `a:b` opens an alternate
    /// data stream, trailing dots/spaces are stripped, and device names such
    /// as `CON` or `nul.txt` open devices in any directory. None of them can
    /// name an ordinary child, so they are refused before any open.
    pub(crate) fn valid_component(name: &OsStr) -> bool {
        let Some(name) = name.to_str() else {
            // Unpaired surrogates cannot be checked against the rules below.
            return false;
        };
        if name.is_empty()
            || name.ends_with(['.', ' '])
            || name.chars().any(|c| {
                c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            })
        {
            return name == "." || name == "..";
        }
        let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
        let upper = stem.to_ascii_uppercase();
        let reserved = matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && stem.chars().count() == 4
            && stem
                .chars()
                .nth(3)
                .is_some_and(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³')));
        !reserved
    }

    pub(crate) fn open(path: &Path, follow: bool, directory: bool) -> io::Result<File> {
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        let mut share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        if !directory {
            // Files are bound by their handle, not their name: leave them as
            // shareable as an ordinary reader would.
            share |= FILE_SHARE_DELETE;
        }
        OpenOptions::new()
            .read(true)
            .share_mode(share)
            .custom_flags(flags)
            .open(path)
    }

    pub(super) fn open_root(path: &Path) -> Result<(Descriptor, Stat), ReadError> {
        let file = open(path, true, true).map_err(|error| map_io(&error))?;
        let stat = stat(&file)?;
        Ok((
            Descriptor {
                file,
                path: path.to_path_buf(),
            },
            stat,
        ))
    }

    pub(super) fn open_child(
        directory: &Descriptor,
        name: &OsStr,
        last: bool,
    ) -> Result<Opened, ReadError> {
        if !valid_component(name) {
            return Err(ReadError::InvalidRelativePath);
        }
        let path = directory.path.join(name);
        let file = open(&path, false, !last).map_err(|error| map_io(&error))?;
        let stat = stat(&file)?;
        if stat.kind == FileKind::Symlink {
            return Ok(Opened::Link);
        }
        Ok(Opened::Object(Descriptor { file, path }, stat))
    }

    /// Read a link target. Junction and symlink targets are often stored in
    /// verbatim form (`\\?\C:\...`); the plain drive form is what authorized
    /// roots are matched against, so only that one prefix is rewritten. Any
    /// other prefix (UNC, device, volume GUID) is left to fail root matching.
    pub(super) fn read_link(directory: &Descriptor, name: &OsStr) -> Result<OsString, ReadError> {
        if !valid_component(name) {
            return Err(ReadError::InvalidRelativePath);
        }
        let target = std::fs::read_link(directory.path.join(name)).map_err(|error| {
            // The confirmed link can become an ordinary file before it is read.
            if error.kind() == io::ErrorKind::InvalidInput {
                ReadError::Io
            } else {
                map_io(&error)
            }
        })?;
        let mut components = target.components();
        if let Some(Component::Prefix(prefix)) = components.next()
            && let Prefix::VerbatimDisk(drive) = prefix.kind()
        {
            let mut plain = PathBuf::from(format!("{}:\\", char::from(drive)));
            for component in components {
                if component != Component::RootDir {
                    plain.push(component);
                }
            }
            return Ok(plain.into_os_string());
        }
        Ok(target.into_os_string())
    }

    pub(super) fn into_file(descriptor: Descriptor) -> File {
        descriptor.file
    }
}

#[cfg(windows)]
pub(crate) use sys::{open as open_windows, stat as stat_windows, valid_component};

#[cfg(windows)]
impl AuthorizedRoot {
    /// The held root directory handle, for walks that enumerate it by path.
    pub(crate) fn windows_handle(&self) -> &sys::Descriptor {
        &self.directory
    }
}
