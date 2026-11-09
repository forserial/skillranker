# Authorized descriptor-based reads (P2)

`src/authorized_read.rs` opens, validates and reads one bounded regular file
below an authorized root. It does not walk directories for discovery, parse
frontmatter, or revalidate a roster; those are `sr-roadmap-l1i.3.4`, `.3.3` and
`.3.11`. Transcript readers (`.4.3`) consume the same primitive, which is why it
is a top-level module rather than part of `roster/`.

## Roots anchor every read

An `AuthorizedRoot` holds an open directory descriptor, the absolute path it was
opened from, and the `(device, inode)` identity of that directory. Symlinks
inside a granted root path are resolved once by the kernel when the root opens;
after that the descriptor, not the name, anchors reads. Renaming the root or
replacing its name with a symlink does not redirect later reads.

`AuthorizedRoots` is the complete set a symlink may resolve into. A read names
its starting root by index; an absolute request must match a root by
longest-prefix, else it is refused.

## Resolution rules

Requested relative paths accept only ordinary components. `..`, a leading `/`
and Windows-style prefixes are rejected before any filesystem call, so a request
cannot climb out on its own.

Each component is opened with `openat` on its parent descriptor using
`O_NOFOLLOW` and `O_CLOEXEC`; intermediate components add `O_DIRECTORY`, and the
final component adds `O_NONBLOCK` so a FIFO cannot block on a writer that never
arrives. Because the object whose type is checked is the object already open,
there is no check-then-open window: swapping a name between the two cannot
change what was read.

When `O_NOFOLLOW` refuses a component (`ELOOP`, or `ENOTDIR` on platforms that
report it that way with `O_DIRECTORY`), the type is confirmed with
`fstatat(AT_SYMLINK_NOFOLLOW)` before the link is followed:

- A **relative** target continues in the current walk. `..` pops the descriptor
  stack and can never rise above the root the walk is anchored to.
- An **absolute** target must land inside an authorized root, and the walk
  re-anchors to that root's descriptor. Anything else is
  `EscapesAuthorizedRoots`.

### Linked folders (skill roots only)

A root opened with `with_linked_folders()` treats a link **directly in the
root** as one of its own folders (sr-winpar.32): a read of `root/<link>/...`
follows that link one hop, wherever it points, and holds the directory it
reaches. Skill-discovery roots use this, because a harness loads
`<root>/<name>/SKILL.md` through such a link and a skills manager installs
skills that way. Every other root, and every other link, keeps the rules above:
a link below the top level, or a link that is the final component, must still
resolve inside an authorized root. A top-level link that is dangling or reaches
a file is `NotFound` or `NotADirectory`.

On Unix the hop is one `openat` without `O_NOFOLLOW` plus `O_DIRECTORY`, so the
kernel resolves the link chain once and the descriptor is the target. On Windows
the link is opened following reparse points, its final path is opened again
without following one and held without `FILE_SHARE_DELETE`, and the two must be
the same directory (volume serial and file index); later children are opened by
that final path, so retargeting the link cannot redirect them.
`open_linked_folder` returns the held folder as its own root, named by the
link's path. The hop counts toward `MAX_SYMLINK_HOPS`.

### Windows: roots hold their ancestors

Windows has no `openat`: every child is opened by a path that Win32 resolves
again from the volume root. So a root, a workspace-relative root and a linked
folder are each held by their **final path** (no links left in it, opened
without following a reparse point and proven to be the directory first
reached), and every ancestor of that path is held too, from the volume root
down, without `FILE_SHARE_DELETE` (sr-winpar.14). While any clone of the root
exists, none of those folders can be renamed, deleted or replaced, so the path
of the next child still names a child of the checked directory. Ancestors are
opened for traverse access only; an ancestor that cannot be traversed, or that
is a link, fails the open. The cost is about one open per path component, and
for as long as `sr` holds a root (at most its deadline for a hook), other
programs cannot rename those ancestor folders. Their contents stay free to
change. A link *above* the root, such as a junction in the configured path,
may be retargeted; the held root keeps reading the folder it first reached.

Cycles terminate by bound rather than by bookkeeping: at most
`MAX_SYMLINK_HOPS` (16) hops and `MAX_RESOLUTION_STEPS` (512) component openings
per request, with link targets bounded to `MAX_LINK_TARGET_BYTES` (4096).

## What is returned

Only regular files are read; directories, FIFOs, sockets, character and block
devices are refused with their observed kind. A read takes at most the limit
plus one byte and fails with `TooLarge` above the limit, so an oversized file is
never half-consumed into a hash.

`BoundedRead` carries the bytes, the `ContentHash` **of those exact bytes**, the
file's `(device, inode)` identity, and the native path of the object opened.
Because the hash never comes from size or modification time, a same-size
same-mtime rewrite is detected. Two names for one file (a hard alias) share an
identity, so callers can deduplicate a canonical file reached through several
roots while keeping their own aliases.

Paths keep native bytes in a private-`Debug` `LocalPath`, and `BoundedRead`'s
own `Debug` prints a byte count instead of content. No error names a path, a
link target or file content: `ReadError` values are fixed kinds.

## Deliberate limits

- Unix only: descriptor-relative opens use `nix` with the `fs` feature; the
  crate targets Linux and macOS.
- Containment is enforced by the descriptor walk, not by `canonicalize`, which
  is why no resolved-path string is trusted for authorization.
- A read is an observation at a moment. The file may change afterwards; the
  harness still validates its own later load, and roster revalidation
  (`.3.11`) re-checks the evidence a decision used.
- These are blocking filesystem leaves. Callers admit them under their own
  deadline (`src/blocking.rs`); this module performs no timing of its own.

## Verification

`tests/authorized_read_contract.rs` builds real temporary trees and covers:
legitimate reads with hash/identity/bytes bound together, hard aliases, cap and
cap+1 boundaries, a same-size same-mtime rewrite, directory/FIFO/character-device
rejection, relative and absolute links inside roots, escaping links, a symlink
cycle, `..` climbing, an intermediate component swapped for an escaping link
after the root opened, a renamed root whose descriptor still reads the original
tree, a concurrent swap race asserting content never comes from outside,
non-UTF-8 filenames, and diagnostics that never contain a canary, path or
content. Every negative has a successful counterpart in the same test.
