# Windows private storage policy

This is the policy the Windows storage port implements (sr-winpar.1). It defines
what "owner-only private storage" means on Windows, rule by rule, with the Unix
rule each one mirrors and what it refuses. `.3` (cache), `.4` (ledger and hook
counter), `.5` (enforced allowance), `.6` (exports, snapshots, replay cases) and
`.7` (installer backups) implement it; `.2` decides how `sr` reads and sets
security descriptors under `#![forbid(unsafe_code)]`. Until those land, every
Windows store open still reports `UnsupportedFilesystem`
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

Today's code does not resolve these yet, which the implementing issues change:
`user_cache_root` and `AllowancePaths::for_user` fall back to
`directories::BaseDirs::cache_dir()`, which is `%LOCALAPPDATA%` on Windows, giving
`%LOCALAPPDATA%\sr`; `default_ledger_directory` gives
`%USERPROFILE%\.local\share\sr`; and `resolve_backup_dir` gives
`%USERPROFILE%\.local\state\sr\backups`.

### 7. Creation

Mirrors: creating missing components with mode `0700` and files with `0600`.

When `sr` creates a missing store directory or file, it applies an explicit
security descriptor at creation instead of inheriting: owner the user's SID; a
protected DACL with access-allowed ACEs for the user and SYSTEM (container and
object inherit on directories, so SQLite's sidecars inherit only those). It never
widens or repairs an existing descriptor: an existing object that fails rule 1, 2
or 4 is refused, as Unix refuses wrong modes instead of `chmod`-ing them. Only the
store directory itself and its files are created; missing ancestors other than
`%LOCALAPPDATA%\skillranker` itself are not created.

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

Recorded for `.2`, which chooses the mechanism: by handle, the owner SID and DACL
(including the protected flag and each ACE's type, flags, mask and SID); creation
with an explicit security descriptor; the volume's filesystem name and remote
status; the drive type and final path of a handle; free bytes available to the
caller. Everything is read from held handles, not by re-resolving paths, so the
checks bind to the objects the walk holds.
