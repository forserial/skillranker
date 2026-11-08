# Windows private storage policy

This is the policy the Windows storage port implements (sr-winpar.1). It defines
what "owner-only private storage" means on Windows, rule by rule, with the Unix
rule each one mirrors and what it refuses. `.3` (cache), `.4` (ledger and hook
counter), `.5` (enforced allowance), `.6` (exports, snapshots, replay cases) and
`.7` (installer backups) implement it; `.2` chose how `sr` reads and sets
security descriptors under `#![forbid(unsafe_code)]`
([Mechanism](#mechanism-sr-winpar2)). The response cache implements it
([Cache](#cache-sr-winpar3)); every other Windows store open still reports
`UnsupportedFilesystem` until its issue lands
([platform boundary](platform-boundary.md#windows-stateless-ranking)).

The user approved the defaults on 2026-11-07 and, after the observation below,
the two refinements marked *(refined)*. The approvals are quoted on sr-winpar.1.

## Observed on a real machine

Windows 11 Pro 10.0.26300, NTFS `C:` (fixed), a non-elevated token that is not a
member of BUILTIN\Administrators; the token's default owner for new objects is
the user's SID. A fresh directory created directly under `%LOCALAPPDATA%`, and a
file inside it, got:

| Object | Owner | DACL |
|---|---|---|
| `%LOCALAPPDATA%\<new>` | user | not protected; all inherited: user Full Control, SYSTEM Full Control, Administrators Full Control, a local `CodexSandboxUsers` group Read & Execute, and two AppContainer capability SIDs (`S-1-15-3-…`) Full Control |
| file inside it | user | the same, inherited |
| `%LOCALAPPDATA%` | user | inherited from `AppData` |
| `AppData` | Administrators | user Full Control (explicit), two capability SIDs Full Control (explicit), plus inherited entries |
| `C:\Users\<user>` | SYSTEM | protected: SYSTEM, Administrators, user Full Control; one capability SID traverse only |
| `C:\Users` | SYSTEM | protected: Everyone and Users read and execute |
| `C:\` | TrustedInstaller | Authenticated Users may create directories (and inherit-only rights on what they create); Users read; SYSTEM and Administrators Full Control |

Conclusions that shaped the rules: a default directory is not owner-only (other
groups and sandbox capabilities can read or change it), so `sr` must apply an
explicit, protected DACL when it creates a store; `C:\` grants every user the
right to create directories, so "any write right on an ancestor" cannot be the
test; and sandbox tooling on this machine granted capability SIDs Full Control on
`AppData` and `%LOCALAPPDATA%`. The elevated-token case (default owner
Administrators) could not be observed here.

## Rules

Terms: *the user* is the token user SID of the running process. *Trusted owners*
are the user, SYSTEM (`S-1-5-18`), BUILTIN\Administrators (`S-1-5-32-544`) and
TrustedInstaller (`S-1-5-80-956008885-…`). *Replace-capable rights* are
`DELETE`, `WRITE_DAC`, `WRITE_OWNER` and `FILE_DELETE_CHILD`, including when
granted through `GENERIC_ALL`. An ACE *applies to an object* unless it is
inherit-only.

### 1. Owner

Mirrors: the leaf store directory and its files are owned by the effective uid.

The store directory and every store file are owned by the user's SID. An owner of
BUILTIN\Administrators, SYSTEM or anyone else is refused with `Permissions`. When
`sr` creates a store it sets the owner to the user's SID explicitly, so an
elevated process (whose default owner may be Administrators) still creates a
conforming store. An existing store owned by Administrators is refused, not
repaired.

### 2. DACL of the store directory and files

Mirrors: exact `0700` directory and `0600` files.

The store directory's DACL is protected (`SE_DACL_PROTECTED`: nothing inherits
from its parent) and contains only access-allowed ACEs for the user and SYSTEM.
Any other ACE, including Administrators, capability SIDs, Everyone, Users or a
deny ACE for another principal, is refused with `Permissions`; so is an
unprotected DACL or a missing (NULL) DACL, which grants everyone access.

Store files may carry only access-allowed ACEs for the user and SYSTEM, either
explicit or inherited from the store directory. Inheritance is accepted for files
because SQLite creates its `-wal` and `-shm` sidecars itself, and they inherit from
the protected store directory, whose own rule already excludes everyone else.

### 3. Ancestors *(refined)*

Mirrors: every ancestor is owned by root or the effective uid and is not group- or
other-writable, except a root-owned sticky directory such as `/tmp`.

Every ancestor from the volume root to the store directory's parent must be a
directory (not a reparse point) owned by a trusted owner. No principal other than
a trusted owner may hold replace-capable rights through an ACE that applies to the
ancestor itself, because those rights let it rename, delete or re-permission the
path to the store. Rights to create files or subdirectories are allowed: they
cannot replace an existing child, which is the same reason Unix accepts sticky
`/tmp`, and a default `C:\` grants them to Authenticated Users.

AppContainer capability SIDs (`S-1-15-3-…`) are treated like the user on
ancestors: they belong to sandboxed processes the user runs, which is the same-user
territory Unix leaves outside the boundary (rule 9). They are never accepted on
the store directory or its files (rule 2).

### 4. Store files

Mirrors: a regular file, `st_nlink == 1`, owned by the effective uid, mode `0600`.

Each store file is a regular file, not a directory and not a reparse point (any
reparse point is refused, whether a link or not), with `number_of_links() == 1`,
and satisfies rules 1 and 2. A second hard link or a reparse point is
`UnsafePath`.

### 5. Admitted filesystems

Mirrors: Linux ext4, btrfs and XFS (tmpfs only for volatile caches) and macOS
APFS and HFS; network, FUSE, overlay and ramfs refused; the allowance additionally
requires persistent storage.

The volume holding the store, read from the held directory handle, must report
the filesystem name `NTFS` or `ReFS` (Dev Drive volumes are ReFS and qualify) and
must be local: a remote file (one that reports remote protocol information) or a
volume whose drive type is not fixed (removable, remote, optical or RAM disk) is
refused with `UnsupportedFilesystem`. FAT, exFAT and every other name are refused.
A path through a `SUBST` drive or a mapped network drive is refused: the drive
letter of the requested path must match the drive of the handle's final path.
Volumes mounted in folders are reached through a reparse point and are already
refused by rule 3. RAM disks are refused for every store, so the allowance's
persistence requirement needs no separate list on Windows.

### 6. Location

Mirrors: `XDG_DATA_HOME`, `XDG_CACHE_HOME` and their `~/.local/share` and
`~/.cache` defaults.

On Windows the stores live under `%LOCALAPPDATA%\skillranker`: `cache\` (the
response cache and the allowance accounting, as `$XDG_CACHE_HOME/sr` holds both),
`ledger\` (the ledger and hook counter, as `$XDG_DATA_HOME/sr`) and
`state\backups\` (installer backups, as `$XDG_STATE_HOME/sr/backups`). The
location comes from the `LOCALAPPDATA` environment variable, as Unix takes `HOME`
from the environment, and must be absolute; XDG variables are not honored on
Windows. An explicit directory (`--dir`, `LedgerLocation::Directory`,
`CacheLocation::Directory`) is accepted only if it satisfies the same rules.
Machine-wide or roaming locations are not used: the stores are per user and per
machine.

The cache, the provider breaker state and the allowance accounting resolve
`%LOCALAPPDATA%\skillranker\cache` since sr-winpar.3
(`platform_path::windows_store_dir`, used by `user_cache_root`,
`CacheLocation::Platform` and `AllowancePaths::for_user`). The others still
resolve elsewhere until their issues change them: `default_ledger_directory`
gives `%USERPROFILE%\.local\share\sr`, and `resolve_backup_dir` gives
`%USERPROFILE%\.local\state\sr\backups`.

### 7. Creation

Mirrors: creating missing components with mode `0700` and files with `0600`.

When `sr` creates a missing store directory or file, it applies an explicit
security descriptor at creation instead of inheriting: owner the user's SID; a
protected DACL with access-allowed ACEs for the user and SYSTEM (container and
object inherit on directories, so SQLite's sidecars inherit only those). It never
widens or repairs an existing descriptor: an existing object that fails rule 1, 2
or 4 is refused, as Unix refuses wrong modes instead of `chmod`-ing them. Each
missing directory on the requested path is created with the same private
descriptor, as Unix creates each missing component `0700`; as a created
ancestor it is owned by the user, so rule 3 admits it.

### 8. Capacity

Mirrors: `fstatvfs` free space against the quota and the maintenance and mutation
reserves (`recording_capacity`, `admit_space_with`).

Free space is the bytes available to the calling user on the store's volume
(`GetDiskFreeSpaceExW` "available to caller", which honors NTFS disk quotas),
measured for the validated store directory and compared against the same quota and
reserves as on Unix.

### 9. Outside the boundary

Mirrors: `revalidate`'s same-user note.

A hostile process running as the same user, including a sandboxed process holding
a capability SID that rule 3 accepts on ancestors, can change or replace the store
and is outside this boundary, as same-uid processes are on Unix. Revalidation still
detects ordinary replacement between checks: the walk holds each directory open
without `FILE_SHARE_DELETE`, records volume serial and file index, and rechecks
them before each effect, as `authorized_read` already does.

## Test matrix for the implementing issues

Each rule needs at least one refusal and one honest success. "Native" means a real
NTFS volume on Windows, not a cross-compile or Wine.

| Rule | Refusal case | Expected | Success case | Issue |
|---|---|---|---|---|
| 1 Owner | store directory owned by Administrators (set by an elevated fixture, or skipped with its reason) | `Permissions` | fresh store created by `sr`, owner = user | .3 .4 .5 |
| 2 DACL | an extra ACE for `Users`; an inherited ACE (protection off); a NULL DACL; a capability SID on the store | `Permissions` | `sr`-created protected user+SYSTEM DACL, reopened | .3 .4 .5 |
| 2 Files | a store file with an ACE for `Users` | `Permissions` | SQLite `-wal`/`-shm` sidecars inheriting the store DACL | .3 .4 |
| 3 Ancestors | an ancestor granting `Users` `FILE_DELETE_CHILD`; an ancestor owned by a non-trusted SID | `Permissions` | default `C:\` (create-directories for Authenticated Users) and capability SIDs on `%LOCALAPPDATA%` admitted | .3 .4 .5 .6 |
| 3 Reparse | a junction or directory symlink on the path | `UnsafePath` | plain directories | .3 .4 .5 .6 |
| 4 Links | a second hard link to the database; the database replaced by a file symlink | `UnsafePath` | single-link regular file | .3 .4 .5 |
| 5 Filesystem | a FAT32/exFAT volume (VHD fixture, or skipped with reason); a network share path; a `SUBST` drive | `UnsupportedFilesystem` | NTFS `C:`; ReFS where available | .3 .5 |
| 6 Location | relative `LOCALAPPDATA`; `--dir` failing rule 2 | refused before creation | `%LOCALAPPDATA%\skillranker\…` and a conforming `--dir` | .3 .4 .5 .7 |
| 7 Creation | a pre-existing store directory with inherited ACEs is not repaired | `Permissions`, descriptor unchanged | missing store created with the explicit descriptor | .3 .4 .5 |
| 8 Capacity | simulated low free space | `InsufficientSpace` / `Quota` | normal volume | .3 .4 |
| 9 Revalidation | store directory renamed or replaced between checks (where Windows allows it) | `StoreReplaced` | unchanged store revalidates | .3 .4 |
| Exports | target directory failing rule 3; existing target | refused, no clobber | owner-only file with explicit descriptor in a conforming directory | .6 |
| Backups | backup directory failing rule 2 | installer fails instead of writing | owner-only backup | .7 |

## What the implementation needs from Windows

By handle, the owner SID and DACL (including the protected flag and each ACE's
type, flags, mask and SID); creation with an explicit security descriptor; the
volume's filesystem name and remote status; the drive type and final path of a
handle; free bytes available to the caller; and the process token's user SID.
Everything is read from held handles, not by re-resolving paths, so the checks
bind to the objects the walk holds.

## Mechanism (sr-winpar.2)

Decision, approved by the user on 2026-11-07 (option B; quoted on sr-winpar.2):
the Win32 calls live in `crates/sr-win-sys`, a second workspace package and the
only one that may contain unsafe code. `skillranker` keeps
`#![forbid(unsafe_code)]` and the `unsafe_code = "forbid"` lint unchanged. The
root manifest's `default-members` include both packages, so the plain gate
commands (`cargo fmt --check`, `cargo check`, `cargo clippy`, `cargo test`) cover
both.

Why not the alternatives:

- **A, a safe-wrapper crate**: none qualified. `windows-permissions` 0.2.4 (MIT,
  winapi 0.3) reads owner and DACL by handle but has no protected-bit accessor, no
  creation with a security descriptor and no token user SID, and exposes unsafe
  functions itself; `windows-acl` 0.3.0 (MIT, last release January 2021) has no
  owner getter or protected bit; `windows-security` is raw generated bindings; `sddl`
  is GPL-3.0. No crate reads the volume filesystem name or remote status by handle.
  Any combination still needed unsafe calls for the rest.
- **C, one allowed module inside `skillranker`**: would change the crate-root
  `forbid` to `deny`.
- **D, defer**: would leave every store refused on Windows.

Dependency: `windows-sys` `=0.61.2` (MIT OR Apache-2.0, microsoft/windows-rs), a
Windows-only dependency of `sr-win-sys`, already in the Windows graph at this
version through asupersync. Features: `Win32_Foundation`, `Win32_Security`,
`Win32_Security_Authorization`, `Win32_Storage_FileSystem`,
`Win32_System_Threading`. No code is copied, so no third-party notice applies.

API surface (`sr_win_sys::windows`, reads implemented and tested by the spike):

| Function | Win32 calls | Returns |
|---|---|---|
| `token_user_sid()` | `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `GetLengthSid` | the process user `Sid` |
| `security_of(&File)` | `GetSecurityInfo(SE_FILE_OBJECT, OWNER \| DACL)`, `GetSecurityDescriptorControl`, `GetAclInformation`, `GetAce`, `LocalFree` | `Descriptor { owner, control, dacl: Option<Vec<Ace>> }` (`None` is a NULL DACL) |
| `volume_of(&File)` | `GetVolumeInformationByHandleW`, `GetFinalPathNameByHandleW` (DOS and GUID), `GetDriveTypeW`, `GetFileInformationByHandleEx(FileRemoteProtocolInfo)` | filesystem name, serial, flags, final path, GUID root, drive type, remote-protocol outcome |
| `free_bytes_for_caller(&File)` | `GetDiskFreeSpaceExW` on the handle's GUID volume root | bytes available to the caller |

Creation with an explicit descriptor (rule 7) is not in the spike; `.3` adds it
to this package (`CreateDirectoryW`/`CreateFileW` with a `SECURITY_ATTRIBUTES`
holding the protected user+SYSTEM DACL and owner), under the same rules.
`skillranker` does not depend on `sr-win-sys` until `.3` wires it in.

Audit rules for `crates/sr-win-sys`:

1. Unsafe code appears only in `src/windows.rs`; `sid.rs` and `acl.rs` carry
   `#![forbid(unsafe_code)]`, and the whole package forbids it on non-Windows
   targets.
2. One unsafe operation per block, each with a `// SAFETY:` argument
   (`clippy::multiple_unsafe_ops_per_block` and
   `clippy::undocumented_unsafe_blocks` are denied); `unsafe_op_in_unsafe_fn` is
   denied.
3. Calls take handles borrowed from a live `&File`, the process pseudo-handle, or
   an `OwnedHandle` the function owns; no handle outlives its owner or is closed
   twice. No caller path is re-resolved.
4. Memory Windows allocates is freed by a guard after its bytes are copied out.
   Raw memory is read only as byte slices of lengths Windows reports
   (`GetLengthSid`, `AceSize`); all interpretation is in the safe `sid` and `acl`
   parsers, which refuse malformed SIDs and ACEs and report unknown ACE types as
   `AceKind::Other` with no trustee.
5. The package exposes facts, not policy: deciding whether a descriptor or volume
   satisfies the rules above belongs to `skillranker`'s storage code.
6. Every change to `src/windows.rs` needs native Windows tests in
   `crates/sr-win-sys/tests/windows_reads.rs` and review of each new block.

Spike evidence (2026-11-07, this machine): `cargo run -p sr-win-sys --example
probe` on `%LOCALAPPDATA%` printed owner `user`, DACL not protected, eight
inherited allowed entries (user, SYSTEM and Administrators full control; a local
group `0x001200A9` read and execute; capability SIDs full control on the object
plus inherit-only `GENERIC_ALL`), filesystem `NTFS`, drive type `3` (fixed), a
GUID root, and `FileRemoteProtocolInfo` failing with error 87
(`ERROR_INVALID_PARAMETER`) for this local volume. `.3` should treat only that
error as "local" and refuse any other outcome. The native tests read back a
protected DACL set with `icacls` (one explicit `OI|CI` full-control entry for the
user plus a deny entry), its inheritance by a new file, and the volume facts of
the temp directory.

## Cache (sr-winpar.3)

The response cache and its coordinator leases (`cache.sqlite3`) and the
provider breaker state (`breaker.sqlite3`, beside them) implement the rules on
Windows. `src/storage/windows_private.rs` holds the shared pieces the
later ports reuse: the policy predicates (rules 1–3), the volume admission
(rule 5), the walk that creates and admits each directory (rules 3 and 7), the
single-link file check (rule 4), store-file creation with the explicit
descriptor, the directory scan with its entry and byte quotas, and free space
(rule 8). `PrivateDirectory` in `src/storage/filesystem.rs` uses them with the
same methods as on Unix.

How it differs from Unix, and why that stays inside the boundary:

- **Path-based opens.** Windows has no `openat`, so each component is opened by
  path with no-follow semantics and without `FILE_SHARE_DELETE`, and only the
  current directory is held between components, as on Unix. The store directory
  stays held while the store is open, so it cannot be renamed or replaced.
  Windows also refused renaming an ancestor of the held store (access denied) in
  the native test; the identity check before each effect remains for any other
  replacement.
- **Directory scan by path.** The scan enumerates the store's path after
  confirming that the path still names the held directory. An ancestor can be
  renamed only by a principal rule 3 trusts, which is the same-user territory of
  rule 9.
- **Sidecars.** SQLite creates `-wal` and `-shm` itself; they inherit the store
  directory's two entries and are admitted as store files. Their owner is the
  token's default owner. For an elevated token that is Administrators, so an
  elevated `sr` refuses its own sidecars (rule 1). This fails closed.
- **`%TEMP%` is not an admissible ancestor here.** On the evidence machine,
  `%LOCALAPPDATA%\Temp` grants `CodexSandboxUsers` and another local account
  Modify, which includes `DELETE`. Rule 3 refuses it, as it should. Test
  fixtures therefore live under `%LOCALAPPDATA%\sr-tests`.

Native evidence (`tests/cache_windows_contract.rs`, NTFS `C:`, non-elevated):
fresh creation with the explicit descriptor on every created directory and on
the database, reopen, and admitted WAL sidecars; an existing inheriting directory
refused and left unchanged; a foreign entry, enabled inheritance and a
capability SID on the store refused, while a capability SID on an ancestor is
admitted; a foreign entry on the database refused; an ancestor granting `Users`
delete-child refused, while create rights and inherit-only rights are admitted;
a junction on the path refused for opening and for creation; a second hard link
and a directory inside the store refused; a UNC path to the same local folder
refused before any open; relative and device paths refused; an oversized store
refused before SQLite runs; a held store and its ancestor not renameable.

Covered by unit tests only, because staging them natively needs an elevated
token or a machine-wide change: FAT32, exFAT and other filesystem names; removable,
remote, optical and RAM-disk drive types; a file that answers the remote-protocol
query; a `SUBST` drive (the final drive differs from the named one); a store
owned by Administrators; a NULL DACL; unknown entry types.
