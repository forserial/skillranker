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
| Owner-only exports and replay case files | Refused: Windows ACLs are not inspected, so owner-only access cannot be established |
| cass sessions (`--session`), Git `dirty_paths` | Unsupported source mode / omitted signal: subprocesses are Linux/macOS only |

### File access without `openat`

`authorized_read` keeps one shared walk; only its four primitives differ by
platform (`sys` module). On Windows each directory on the walk is held open
without `FILE_SHARE_DELETE`, so it cannot be renamed, deleted or replaced by
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

`HOME` remains authoritative when set. Windows normally sets only
`USERPROFILE`, which Claude Code uses for `%USERPROFILE%\.claude`, so it is
the fallback there; Unix still reads only `HOME`.

### Residual limits

- The root of a walk is opened by its trusted absolute path; renaming one of
  its ancestors is not prevented by the held handles.
- Windows releases are not native-qualified: no test suite has run on real
  Windows, and the Claude Code `UserPromptSubmit` hook on Windows has not been
  exercised end to end.
- A full storage port needs an audited owner-only ACL check and an admitted
  filesystem list (NTFS, ReFS) before cache or ledger can be enabled.

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

Not established: execution on real Windows, the Windows test suite (existing
suites use Unix fixtures such as modes, symlinks and FIFOs and are not gated per
platform), link/junction refusal, and the Claude Code hook end to end.
