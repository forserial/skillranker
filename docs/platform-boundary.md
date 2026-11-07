# Native portability: the smallest independently compilable boundary

Issue #3 originally crossed seven files, not just the coordinator's SQLite
identity call. Since that report, main gained separate Linux/macOS filesystem
admission and native installer routing. This change preserves those concurrent
changes; it neither broadens filesystem admission nor qualifies a release.

## Boundary

`src/sqlite_engine.rs` owns only linked SQLite identity qualification. It opens an
in-memory connection and checks the minimum, exact numeric version, exact version
text, and exact source ID. Its error preserves typed SQLite failures for adapter
classification while redacting diagnostic details. The existing
`storage::linked_engine()` signature, identity type, and constants remain a
compatibility facade, including the existing StoreError mapping.

`src/platform_path.rs` owns only path spelling. Linux and other non-macOS paths
are unchanged. macOS expands only verified root-owned `/tmp` and `/var` aliases
with their expected link targets. It does not canonicalize user symlinks or erase
parent components. Persistent stores retain their descriptor/no-follow,
ownership, filesystem, quota, schema, and transaction checks.

Callers needing these two operations can use the leaves without importing the
persistent-storage module. A general portable-storage trait would be a much
larger and less useful first boundary: replay, ledger, and command handlers still
need their actual persistence behavior, not successful no-op stubs.

## Isolated native compile slice

On a standalone native Mac with the repository's pinned toolchain and Python
3.11 or newer, run from the checkout:

```sh
python3 scripts/check_platform_boundary.py --native-macos
```

Use `--offline` as well when the dependency cache is populated. On Linux, omit
`--native-macos` to run the corresponding host checks; that is not native macOS
evidence. On a shared build fleet, arrange execution on a native Mac worker using
the existing RCH/DSR infrastructure, not a Linux worker with forged cfg values.

The driver creates a temporary test-only crate that refers to the production
leaf source files by path. It does not include `storage`, replay, ledger, the
coordinator, the CLI, or copied Rust implementations. It mirrors the root
rusqlite dependency settings and projects the reachable lock entries. A
conservative metadata-only Cargo update normalizes the smaller feature graph;
every resulting dependency version, source, and checksum must still match the
root lock before `cargo test --locked` may run. The root manifest and lock are
never rewritten. The temporary crate is not a production workspace split.

The driver prints the host and Rust compiler identity, explicitly selects the
compiler's host target, refuses `--native-macos` on non-Darwin hosts, and refuses
ambient Rust flags that could simulate a cfg. Any resolution/build/test failure
remains a failure; removing qualification checks or `--locked` is not a fallback.

A passing leaf slice does not prove the full library, binary, native filesystem
behavior, or installer is qualified. The next integration gates remain:

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Run these on each claimed native target and execute the existing filesystem,
cache, ledger, and installer tests. Keep issue #3 open until that evidence exists.

## Evidence for this extraction

The Python driver contract tests run independently:

```sh
python3 tests/platform_boundary_contract.py -v
```

Eight driver tests passed in the implementation sandbox, including lock closure,
source/checksum preservation, dependency-change rejection, production-source
references, and refusal of a Linux host as native macOS evidence. Python syntax
checks also passed. These are driver tests, not Rust or filesystem tests.

The sandbox has no Cargo/rustc and is not macOS. Both missing-toolchain and
non-native checks returned explicit failures before compilation. The new Rust
identity, error-adapter, alias-policy, and native symlink tests were added but not
executed there. Neither the isolated Cargo invocation nor full/native checks are
claimed as passed by this document.

## Windows: stateless ranking

Windows builds compile the same library and binary. Ranking, roster
discovery, Claude transcript and session reads, `doctor`, `capabilities`,
`demo` and hook installation work. Every component that depends on an
owner-only private store fails closed instead of being emulated:

| Component | Windows behavior |
|---|---|
| Response cache, ledger, coordinator leases | Store open reports `UnsupportedFilesystem`; optional caching is skipped visibly and commands that require the ledger (`observe`, `feedback`, `stats`, `ledger`, …) fail with their storage error |
| Enforced request allowance | An absent guard means no allowance is configured, as on Unix; an existing guard, accounting store or `sr budget --apply` is refused, which withholds provider requests |
| Hook invocation counter | Never written (it lives beside a ledger) |
| Shadow-mode hooks | Skip ranking before any provider request, since nothing could be recorded; one stderr line says why. Advisory mode ranks and publishes |
| Owner-only exports, roster snapshots and replay case files | Refused: Windows ACLs are not inspected, so owner-only access cannot be established |
| cass sessions (`--session`) | Unsupported source mode. The owned-subprocess boundary it needs runs on Windows (see below); the cass adapter is not ported yet (sr-winpar.11) |
| Hook installer backups, calibration policy files | Written without owner-only protection (sr-winpar.7 for backups) |
| `sr gaps` without `--input` | Reads no ledger and reports zero events |

`sr capabilities --json` reports this table in its `platform` field, from the
same flags the refusing code asserts at compile time; see
[the capability registry](capabilities.md#platform-availability).

### File access without `openat`

`authorized_read` keeps one shared walk; only its four primitives differ by
platform (`sys` module). On Windows each directory on the walk, including a final
directory that becomes a workspace-relative root, is held open without
`FILE_SHARE_DELETE`, so it cannot be renamed, deleted or replaced by
a junction while held, and the next child's path still names a child of the
checked object. Components are opened with `FILE_FLAG_OPEN_REPARSE_POINT`,
mirroring `O_NOFOLLOW`; only name-surrogate reparse points (symbolic links,
junctions) are links, so cloud placeholders remain ordinary files. Link
targets are resolved by the same walk inside authorized roots; a verbatim
`\\?\C:\` prefix is rewritten to its drive form, and every other prefix fails
root matching. Names Win32 would reinterpret are refused before any open:
alternate data streams (`a:b`), trailing dots or spaces, reserved device names
(`CON`, `nul.txt`, `COM1`, …), and reserved characters.

File identity is the volume serial number and file index, read through the
safe `winapi-util` API (already in the Windows dependency graph through
`same-file`), so `#![forbid(unsafe_code)]` is unchanged. Roster discovery,
discovery-scope proofs, roster import, transcript snapshots and session
discovery use the same primitives. Locks for hook installation and snoozes use
`File::try_lock` (`LockFileEx`).

A Claude transcript path with a `..` component is refused on Windows before
anything is opened: Win32 resolves `..` lexically, even through a missing
directory, so the Unix refusal (opening a missing parent fails) would not
happen there.

An absolute path or link target spelled with different case than its authorized
root still matches it, but only by identity: its leading components must equal
the root's ignoring case, and then that prefix is opened and must have the held
root's volume serial and file index. Case folding only selects the candidate,
because a directory can be case-sensitive: there `Root` and `root` are different
directories, and the other spelling is refused. Each candidate costs one open, so
the work is bounded by the number of roots, and any failure refuses the match.
Unix still compares components exactly.

`HOME` remains authoritative when set. Windows normally sets only
`USERPROFILE`, which Claude Code uses for `%USERPROFILE%\.claude`, so it is
the fallback there; Unix still reads only `HOME`.

### Owned subprocesses

`subprocess::run` uses asupersync's `ExactImageCommand` on Windows: `CreateProcessW`
gets the explicit `.exe` image (no `PATH` search, no `.cmd`/`.bat` shims, no
shell), exactly the supplied environment, three private pipes and an explicit
inheritable-handle list, and the child enters a kill-on-close Job Object
atomically (Windows 10 / Server 2016 or newer). The job does not allow breakaway,
so descendants stay in it.

Windows anonymous pipes have no readiness wait, so one worker thread reads stdout,
one reads stderr and one writes stdin; the async loop drains their channel and
checks the deadline and cancellation every pass, as on Unix. When the direct child
exits, the whole job is terminated, as the Unix path kills the process group. On
every exit (success, limit, deadline, cancellation, or an early drop of the
future) the job is terminated first, which closes every write end the tree held,
so blocked reads end and a blocked stdin write fails; then every worker is joined
before `run` returns. A test counts live workers, and a unit test proves `cleanup`
waits for a slow one. If Windows refuses to terminate the job, `run` reports
`Cleanup` without joining, because the join could then wait forever; the
workers hold only pipe handles and end with the process. `sr` spawns processes
only through this module, so no unrestricted `CreateProcess` can inherit the pipe
handles in between.

Two Windows rules for callers: the child receives `SystemRoot` in addition to
the allowed `LANG`, `LC_ALL` and `TZ` (Winsock and parts of the C runtime fail
without it; it carries no routing or credentials), and `directory` must name the
current directory, because the exact-image spawn cannot set one. Another
directory is passed to the program itself (Git's `-C`), never through a shell.
`tests/subprocess_windows.rs` covers output, 512 KiB in both directions, the
output limit, the deadline, cancellation, a grandchild holding the pipes,
a child that never reads its input, the exact environment, and refusal of
scripts, relative paths and other directories.

### Git dirty_paths and the tool inventory

Project signals find tools only in fixed trusted roots, never `PATH`, the user's
profile or the workspace. On Windows (the user's choice for sr-winpar.10) these are
unversioned machine-wide install directories under `%ProgramFiles%`, in this order:
`Git\ucrt64\bin`, `Git\mingw64\bin`, `Git\clangarm64\bin` (Git for Windows' real
`git.exe`), `Git\cmd` (its 44 KB launcher, which starts the real image inside the
same Job Object), `nodejs`, `Go\bin` and `CMake\bin`. Directories that do not exist
are left out; `ProgramFiles` comes from the user's environment, never from the
repository. A tool counts only as a regular `<tool>.exe` that is not a reparse
point and whose canonical path is outside the workspace, so `npm.cmd` and
versioned or per-user installs (Rust under `.cargo`, Python, Java) are not
reported.

Git runs through the owned-subprocess boundary with the Unix protections
(`--no-optional-locks`, `core.fsmonitor=false`, `core.untrackedCache=false`,
porcelain v1 `-z`). Its environment is `LC_ALL=C` plus `SystemRoot`, which is
all Git for Windows needed here. It gets the workspace through `-C`, because
the child starts in `sr`'s current directory. Paths come back repository
relative with `/` separators, and non-ASCII names as UTF-8 (`-z` disables
`core.quotepath` quoting). A
missing Git is an omission, a root inside the workspace (directly or through a
junction) is refused as `InvalidAuthority`, and a repository's fsmonitor hook
never runs. Alone on the evidence machine, `git --version` plus `git status`
took 43 ms (p50) and 69 ms (p95) with the real image, and 84 and 111 ms through
the launcher, inside the stage's 250 ms; under heavy parallel spawning the stage
can run out and report `Budget`, as on any loaded host.

### Other Windows differences

- **Randomness.** Cache keys, lease tokens and sampling seeds come from
  `os_random`: `/dev/urandom` on Unix, `getrandom` (`ProcessPrng`) on Windows.
  Sampling provenance records whichever source drew the seed.
- **Hook command.** Claude Code runs Windows hook commands through Git Bash, so
  `install-hook` writes `"C:/path/sr.exe" hook claude`: forward slashes inside
  double quotes. An unquoted backslash path exits 127 in Bash, and hooks fail
  open, so that failure would look like a quiet hook.
- **Bounded stdin.** Windows pipes have no safe readiness wait. The read runs on a
  helper thread and the caller waits on a channel, so it still stops at the
  cleanup reserve. See the residual limits for what a stalled writer leaves.
- **Main-thread stack.** `build.rs` links `sr.exe` with an 8 MiB stack, matching
  Linux and macOS. The 1 MiB Windows default overflows in `sr eval`.
- **Skill IDs.** Logical keys hash `/` separators on Windows, so discovery and
  roster manifests assign equal IDs.
- **Building from source.** Cargo's checkout of the pinned `asupersync` needs
  `git config --global core.longpaths true`; some of its files exceed 260
  characters. Linking every test binary can exhaust linker memory
  (`LNK1102`), which `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_PROFILE_DEV_DEBUG=0`
  and `CARGO_BUILD_JOBS=6` avoided on the evidence machine.

### Residual limits

- The root of a walk is opened by its trusted absolute path; renaming one of
  its ancestors is not prevented by the held handles.
- A stdin helper thread stalled in its read cannot be cancelled. It holds only
  stdin and at most one chunk, publishes nothing, and ends with the process.
  AGENTS.md's no-detached-workers rule is relaxed for this one leaf, because
  cancelling it would need `unsafe` code the crate forbids.
- `sr roster --snapshot` is refused along with other owner-only exports.
  `--diff` reads a saved snapshot, but Windows cannot write one.
- A full storage port needs an audited owner-only ACL check and an admitted
  filesystem list (NTFS, ReFS) before cache or ledger can be enabled. The
  policy it must implement, with the Unix rule each part mirrors and its test
  matrix, is [Windows private storage](windows-private-storage.md).

### Evidence

Cross-compiled for `x86_64-pc-windows-gnu` (MinGW-w64): `cargo check` and
`cargo clippy -- -D warnings` for the library and binary pass with no warnings.
Linux `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` pass.
The full Linux suite ran 158 test binaries: 1,797 passed, 11 ignored, and one
failed, `every_hand_written_cli_pair_matches_the_documented_mapping`, which fails
identically at the pre-port base `ffff0c6` (an existing `8`/`oversized-input`
pair in `src/cli.rs`).

The MinGW release `sr.exe` was run under Wine 9.0: `--version`,
`capabilities --json` and `demo --case useful --json` exit 0; `roster --json`
discovers a project skill through the ported walk; `ledger status --json`
exits 9 with `storage-failure` ("requires a qualified local filesystem"). Wine
presents host symlinks as plain directories and cannot create junctions, so
link refusal was not exercised there. (Cross-linking with MinGW on Linux needs
a `libKernel32.a` alias for a dependency's capitalized import; MSVC is
unaffected.)

That run did not exercise `rank`, the hook or real links.

#### Native Windows (MSVC)

Windows 11 Pro 10.0.26300, NTFS, `x86_64-pc-windows-msvc`,
`nightly-2026-08-31`, Developer Mode on, not elevated. Claude Code 2.1.302.

| Check | Result |
|---|---|
| `cargo build --release --locked --bin sr` | Pass, after `core.longpaths` for the first dependency checkout |
| `cargo clippy --locked --lib --bins -- -D warnings`, and `--all-targets` | Pass |
| `cargo fmt --check` | Pass |
| `cargo test --locked` (158 binaries) | 965 passed, 0 failed, 1 ignored, with the link-memory settings above |
| `sr --version`, `capabilities --json`, `demo --case useful --json` | Exit 0 |
| `sr roster --json` | Exit 0; finds project and user skills |
| `mklink /D` and `mklink /J` skill folders, in or out of the root | Skipped, reported as `symlinked-directory-skipped` |
| `CON`, `nul.txt`, `COM1`, `trail.`, `space ` skill folders | Refused, reported as `entry-unreadable` |
| `x.md:stream`, `t.jsonl.`, `t.jsonl `, `CON`, `nul.txt` as `--transcript` | Exit 7; the valid twin reaches its cache miss (exit 11) |
| `x.md:stream`, `CON`, `x.md.` as `--roster` | Exit 5 |
| Personal skills with `HOME` unset | Found through `USERPROFILE`; a set `HOME` wins |
| `ledger status`, `ledger init`, `stats`, `budget --apply`, `roster --snapshot` | Exit 9, `storage-failure`, no state created |
| `install-hook` preview, `--apply`, repeat, `uninstall-hook --apply` | One managed entry; a copy of a real settings file round-trips semantically, reformatted rather than byte-identical |
| `sr rank` over TLS to a loopback provider stub | `ranked` through both stages in about 105 ms, debug build |

The hook ran through a real `claude -p` in a temporary settings file, using
`--settings`. Claude Code invoked the installed command through Git Bash, it
exited 0, and:

- Shadow mode published nothing, while the stub served both stages.
- Advisory mode published `hookSpecificOutput.additionalContext` for a ranked
  suggestion from the stub and for a local `/use-skill` request.
- A stalled stdin ended in about 2.8 s with exit 0, and input over 1 MiB failed
  open.

These bugs existed only on real Windows, and are fixed: ranking failed for lack of
`/dev/urandom`; the installed hook exited 127 in Git Bash; the hook could not read
stdin; `sr eval` overflowed the main-thread stack; discovery and manifests derived
different skill IDs; transcript paths skipped the reserved-name refusal; piped
input was not seen as supplied; and a workspace-relative root was not held against
rename.

**What the Windows suite leaves out.**
[`tests/windows_test_matrix.toml`](../tests/windows_test_matrix.toml) is the exact
inventory and the live source for these numbers: each later child removes or
reclassifies the entries it ports. When sr-winpar.16 added it, it listed 165 gates
(72 whole files, 17 modules, 76 single tests), each with a reason and the issue
that lifts it, or a justified permanent exclusion;
`tests/windows_test_matrix.rs` scans `src/` and `tests/` and fails when a gate is
missing from it or an entry is stale. Reconciled with
`cargo test --locked -- --list` on the commit that added it, Windows lists 975
tests and Linux 1,824; all 877 Linux-only tests (175 lib unit tests, 702
integration tests in 98 binaries) fall under those gates. 76 gates wait on the
private store (sr-winpar.3 to .6), 5 on the hook suites (.17), 6 on subprocesses
(.9 to .11), 4 on the provider-stub harness (.24) and 55 on porting fixtures or
auditing suites (.25, .15); 19 are permanent (FIFOs and devices, POSIX signals
and rlimits, Linux-only mechanisms, the Linux half of a twin test).
`tests/authorized_read_windows.rs` and `tests/windows_platform.rs` cover the file
layer and hook natively. Since sr-winpar.24 the loopback TLS provider stubs run on
Windows too (`tests/support/stub_python.rs` finds the interpreter; the stubs listen
on both address families and report through a queue there), so `jev_retry`,
`jev_transport`, `transport_failures` and the library's TLS client tests run
natively. A refused loopback connect takes about 2,050 ms to report on Windows,
so the refusal test gives it a 3,000 ms context there. Symbolic-link cases report a skip on a token without the
privilege; here they ran.

**Not established.** A model turn receiving the injected context: `claude -p`
stopped at login on the evidence machine, after the hook had run. Live Jev
ranking: no `TYPESAFE_API_KEY` was available, so every provider exchange used the
loopback stub. Hook latency targets. Other Windows versions, ReFS, or a token
without symlink rights. `ubs` was not available, so its gate did not run.

`tests/platform_boundary_contract.py` and `scripts/validate_public_contracts.py`
also pass on Windows (Python 3.14, where the launcher is `python` or `py`, not
`python3`). The validator checks shell examples with Git for Windows' own
`usr\bin\bash.exe`, found beside `git`, never the System32 `bash.exe` that
starts WSL, and pipes them as bytes so Windows does not add carriage returns.
Without Git for Windows it fails and says so. The probe driver writes its
`#[path]` attributes as Rust raw strings, which hold Windows paths verbatim.

#### Linux regression run

WSL2 (`openclaw`), the same toolchain, on the Linux filesystem: `cargo fmt --check`,
`cargo clippy --locked --all-targets -- -D warnings` and both Python contract checks
pass. `cargo test --locked` ran 158 binaries: 1,794 passed, 10 failed, 11 ignored.
The ten are multi-process provider tests in `allowance_contract`, `breaker_contract`,
`rank_acceptance` and `real_rank_coordination`. They fail the same way on the
unmodified tree in that distro, so they are not regressions. sr-winpar.18 found
the cause, and a second, intermittent sensitivity:

- All ten spawned `sr` without setting its stdin, so it inherited the test runner's.
  A runner started from a script or agent has a pipe there, and `sr` correctly
  refuses supplied input without an explicit mode (exit 2, `stdin requires an
  explicit input mode`), so the provider was never reached. From a terminal,
  stdin is a TTY and they passed. Their command builders now give `sr` a null
  stdin.
- With stdin fixed, two coordination tests still fail intermittently:
  `follower_nearing_deadline_while_leader_active_makes_zero_provider_attempts`
  and `stale_leader_superseded_cannot_overwrite_newer_cache_or_complete_lease`
  fail when the wall clock steps during the run. WSL2's guest clock runs about
  5% slow and is stepped forward about 1.5 s every 30 s (measured: 4.5 s over
  90 s). Coordination leases expire by wall clock (5 s TTL), so a step shortens
  a live leader's lease: it is superseded and exits 6 instead of 0. Over 20
  runs every failure coincided with a step of 1.48 to 1.56 s and every pass had
  none. These tests need a host whose wall clock is not stepped while they run;
  the same step on a production host makes a second process take over a live
  lease and spend its own provider requests.

`every_hand_written_cli_pair_matches_the_documented_mapping`,
which failed before, now passes. Later edits were limited to `cfg(windows)` code and
Windows-only tests, so this run was not repeated. It is not native macOS evidence.
