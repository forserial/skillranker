//! Windows behavior of the authorized-read file layer against a real NTFS tree:
//! symbolic links, junctions, Win32 name rewriting and the handles a walk holds.
//!
//! Junctions need no privilege. Directory and file symbolic links need Developer
//! Mode or an elevated token, so those fixtures report a skip instead of failing
//! where the token lacks the right. Unix fixtures live in
//! `authorized_read_contract.rs`.
#![cfg(windows)]

use skillranker::authorized_read::{
    AuthorizedRoot, AuthorizedRoots, BoundedRead, FileKind, ReadError,
};
use skillranker::limits::SKILL_FILE_BYTES;
use skillranker::privacy::WorkspaceRelativeRoot;
use std::fs;
use std::os::windows::fs::{OpenOptionsExt, symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQUENCE: AtomicU32 = AtomicU32::new(0);
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

/// `\\?\` turns off Win32 name rewriting, so fixtures can create the names the
/// layer has to refuse.
fn verbatim(path: &Path) -> PathBuf {
    let mut raw = std::ffi::OsString::from(r"\\?\");
    raw.push(path.as_os_str());
    PathBuf::from(raw)
}

fn temp_tree(name: &str) -> PathBuf {
    let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "sr-authread-win-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary tree");
    // Link targets come back canonical, so roots must be canonical to match.
    let canonical = fs::canonicalize(&path).expect("canonical tree");
    let display = canonical.to_str().expect("utf-8 temp path");
    PathBuf::from(display.strip_prefix(r"\\?\").unwrap_or(display))
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, content).expect("write fixture");
}

fn roots_of(path: &Path) -> AuthorizedRoots {
    AuthorizedRoots::single(AuthorizedRoot::open_absolute(path).expect("open root"))
}

fn read(roots: &AuthorizedRoots, relative: &str) -> Result<BoundedRead, ReadError> {
    roots.read_bounded(0, Path::new(relative), SKILL_FILE_BYTES)
}

fn read_err(roots: &AuthorizedRoots, relative: &str) -> ReadError {
    read(roots, relative).expect_err("read must be refused")
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("run mklink");
    assert!(status.status.success(), "mklink /J failed: {status:?}");
}

/// Create a link, or report that this token may not, in which case the caller skips.
fn linked(result: std::io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
            eprintln!("skipped: creating symbolic links needs Developer Mode or elevation");
            false
        }
        Err(error) => panic!("create symbolic link: {error}"),
    }
}

#[test]
fn regular_reads_bind_bytes_hash_and_a_stable_identity() {
    let tree = temp_tree("regular");
    write(&tree.join("skills/a/SKILL.md"), "# a\n\nbody");
    write(&tree.join("skills/b/SKILL.md"), "# a\n\nbody");
    let roots = roots_of(&tree);

    let first = read(&roots, "skills/a/SKILL.md").expect("read");
    let again = read(&roots, r"skills\a\SKILL.md").expect("native separators");
    let other = read(&roots, "skills/b/SKILL.md").expect("read");

    assert_eq!(first.bytes(), b"# a\n\nbody");
    assert_eq!(first.content_hash(), other.content_hash());
    assert_eq!(first.identity(), again.identity());
    assert_ne!(first.identity(), other.identity(), "distinct files");
    assert_ne!(first.identity().inode(), 0, "NTFS reports a file index");
}

#[test]
fn hard_links_share_the_identity_of_their_file() {
    let tree = temp_tree("hardlink");
    write(&tree.join("a.md"), "body");
    fs::hard_link(tree.join("a.md"), tree.join("b.md")).expect("hard link");
    let roots = roots_of(&tree);
    assert_eq!(
        read(&roots, "a.md").unwrap().identity(),
        read(&roots, "b.md").unwrap().identity()
    );
}

#[test]
fn a_directory_is_refused_as_a_file_and_a_file_as_a_directory() {
    let tree = temp_tree("kinds");
    write(&tree.join("dir/file.md"), "body");
    let roots = roots_of(&tree);
    assert_eq!(
        read_err(&roots, "dir"),
        ReadError::NotRegularFile(FileKind::Directory)
    );
    assert_eq!(read_err(&roots, "dir/file.md/x"), ReadError::NotADirectory);
    assert_eq!(read_err(&roots, "dir/missing.md"), ReadError::NotFound);
    assert_eq!(read_err(&roots, "missing/x.md"), ReadError::NotFound);
}

#[test]
fn requests_cannot_climb_out_or_name_a_drive() {
    let tree = temp_tree("climb");
    write(&tree.join("a.md"), "body");
    let roots = roots_of(&tree);
    for request in ["../a.md", r"..\a.md", r"C:\Windows\win.ini", r"\Windows"] {
        assert_eq!(
            read_err(&roots, request),
            ReadError::InvalidRelativePath,
            "{request}"
        );
    }
}

#[test]
fn win32_rewritten_names_are_refused_even_when_a_real_file_has_that_name() {
    let tree = temp_tree("names");
    write(&tree.join("x.md"), "visible");
    fs::write(tree.join("x.md:stream"), "hidden stream").expect("alternate data stream");
    for name in ["CON", "nul.txt", "COM1", "trail.", "space "] {
        fs::write(verbatim(&tree).join(name), "reserved").expect("reserved-name file");
    }
    let roots = roots_of(&tree);
    for request in [
        "x.md:stream",
        "x.md::$DATA",
        "x.md.",
        "x.md ",
        "CON",
        "con",
        "CON.md",
        "nul.txt",
        "Nul .txt",
        "AUX",
        "PRN",
        "COM1",
        "com9.log",
        "LPT1",
        "COM\u{b9}",
        "CONIN$",
        "CONOUT$",
        "trail.",
        "space ",
        "wild*.md",
        "que?.md",
        "pipe|.md",
        "quote\".md",
        "less<.md",
        "more>.md",
        "ctl\u{1}.md",
    ] {
        assert_eq!(
            read_err(&roots, request),
            ReadError::InvalidRelativePath,
            "{request:?}"
        );
    }
    // Near-misses of the reserved names are ordinary files.
    for name in ["CONSOLE.md", "COM10", "COMX", "LPT", "nullable.txt"] {
        write(&tree.join(name), "ordinary");
        assert_eq!(read(&roots, name).expect(name).bytes(), b"ordinary");
    }
    assert_eq!(read(&roots, "x.md").unwrap().bytes(), b"visible");
}

#[test]
fn absolute_reads_require_an_authorized_root_and_refuse_streams() {
    let tree = temp_tree("absolute");
    let outside = temp_tree("absolute-outside");
    write(&tree.join("a.md"), "inside");
    write(&outside.join("a.md"), "outside");
    fs::write(tree.join("a.md:stream"), "hidden").expect("alternate data stream");
    let roots = roots_of(&tree);
    let limit = SKILL_FILE_BYTES;
    assert_eq!(
        roots
            .read_absolute(&tree.join("a.md"), limit)
            .unwrap()
            .bytes(),
        b"inside"
    );
    assert_eq!(
        roots.read_absolute(&outside.join("a.md"), limit),
        Err(ReadError::EscapesAuthorizedRoots)
    );
    assert_eq!(
        roots.read_absolute(&tree.join("a.md:stream"), limit),
        Err(ReadError::InvalidRelativePath)
    );
    assert_eq!(
        roots.read_absolute(Path::new(r"relative\a.md"), limit),
        Err(ReadError::InvalidRelativePath)
    );
}

#[test]
fn junctions_resolve_inside_authorized_roots_and_never_out_of_them() {
    let tree = temp_tree("junction");
    let outside = temp_tree("junction-outside");
    write(&tree.join("real/SKILL.md"), "inside");
    write(&outside.join("secret/SKILL.md"), "outside");
    junction(&tree.join("inside"), &tree.join("real"));
    junction(&tree.join("escape"), &outside.join("secret"));
    let roots = roots_of(&tree);

    assert_eq!(read(&roots, "inside/SKILL.md").unwrap().bytes(), b"inside");
    assert_eq!(
        read(&roots, "inside/SKILL.md").unwrap().identity(),
        read(&roots, "real/SKILL.md").unwrap().identity()
    );
    assert_eq!(
        read_err(&roots, "escape/SKILL.md"),
        ReadError::EscapesAuthorizedRoots
    );

    let both = AuthorizedRoots::new(vec![
        AuthorizedRoot::open_absolute(&tree).unwrap(),
        AuthorizedRoot::open_absolute(&outside).unwrap(),
    ]);
    assert_eq!(
        both.read_bounded(0, Path::new("escape/SKILL.md"), SKILL_FILE_BYTES)
            .unwrap()
            .bytes(),
        b"outside",
        "a second authorized root admits the target"
    );
}

#[test]
fn a_junction_cannot_supply_a_workspace_root_outside_its_parent() {
    let tree = temp_tree("workspace");
    let outside = temp_tree("workspace-outside");
    write(&tree.join("real/inner/a.md"), "inside");
    write(&outside.join("a.md"), "outside");
    junction(&tree.join("linked"), &outside);
    let root = AuthorizedRoot::open_absolute(&tree).unwrap();

    let inner = root
        .open_workspace_relative(&WorkspaceRelativeRoot::parse("real/inner").unwrap())
        .unwrap();
    assert_eq!(
        read(&AuthorizedRoots::single(inner), "a.md")
            .unwrap()
            .bytes(),
        b"inside"
    );
    assert_eq!(
        root.open_workspace_relative(&WorkspaceRelativeRoot::parse("linked").unwrap())
            .map(|_| ())
            .unwrap_err(),
        ReadError::EscapesAuthorizedRoots
    );
}

#[test]
fn symbolic_links_resolve_only_inside_authorized_roots() {
    let tree = temp_tree("symlink");
    let outside = temp_tree("symlink-outside");
    write(&tree.join("skills/real.md"), "inside");
    write(&outside.join("secret.md"), "outside");
    let skills = tree.join("skills");
    if !linked(symlink_file("real.md", skills.join("relative.md"))) {
        return;
    }
    symlink_file(skills.join("real.md"), skills.join("absolute.md")).unwrap();
    symlink_file(outside.join("secret.md"), skills.join("escape.md")).unwrap();
    symlink_file(r"..\..\..\secret.md", skills.join("climb.md")).unwrap();
    symlink_file("cycle_b.md", skills.join("cycle_a.md")).unwrap();
    symlink_file("cycle_a.md", skills.join("cycle_b.md")).unwrap();
    symlink_file("missing.md", skills.join("dangling.md")).unwrap();
    symlink_dir(&outside, tree.join("linked")).unwrap();
    let roots = roots_of(&tree);

    let direct = read(&roots, "skills/real.md").unwrap();
    for request in ["skills/relative.md", "skills/absolute.md"] {
        let through = read(&roots, request).expect(request);
        assert_eq!(through.bytes(), b"inside");
        assert_eq!(through.identity(), direct.identity());
    }
    assert_eq!(
        read_err(&roots, "skills/escape.md"),
        ReadError::EscapesAuthorizedRoots
    );
    assert_eq!(
        read_err(&roots, "skills/climb.md"),
        ReadError::EscapesAuthorizedRoots
    );
    assert_eq!(
        read_err(&roots, "skills/cycle_a.md"),
        ReadError::SymlinkLoop
    );
    assert_eq!(read_err(&roots, "skills/dangling.md"), ReadError::NotFound);
    assert_eq!(
        read_err(&roots, "linked/secret.md"),
        ReadError::EscapesAuthorizedRoots
    );
}

#[test]
fn verbatim_link_targets_match_their_plain_drive_root() {
    let tree = temp_tree("verbatim");
    write(&tree.join("real.md"), "inside");
    if !linked(symlink_file(
        verbatim(&tree.join("real.md")),
        tree.join("link.md"),
    )) {
        return;
    }
    let roots = roots_of(&tree);
    assert_eq!(read(&roots, "link.md").unwrap().bytes(), b"inside");
}

#[test]
fn other_link_prefixes_fail_root_matching() {
    let tree = temp_tree("prefix");
    if !linked(symlink_file(
        r"\\localhost\C$\Windows\win.ini",
        tree.join("unc.md"),
    )) {
        return;
    }
    symlink_file(r"\Windows\win.ini", tree.join("rooted.md")).unwrap();
    let roots = roots_of(&tree);
    assert_eq!(
        read_err(&roots, "unc.md"),
        ReadError::EscapesAuthorizedRoots
    );
    assert_eq!(
        read_err(&roots, "rooted.md"),
        ReadError::EscapesAuthorizedRoots
    );
}

/// The Windows analog of descriptor binding: a directory the walk holds cannot be
/// renamed away and replaced, because it is open without `FILE_SHARE_DELETE`.
#[test]
fn a_held_root_cannot_be_renamed_or_replaced() {
    let parent = temp_tree("held");
    let tree = parent.join("root");
    write(&tree.join("a.md"), "original");

    let root = AuthorizedRoot::open_absolute(&tree).unwrap();
    assert!(fs::rename(&tree, parent.join("moved")).is_err());
    assert!(fs::remove_dir_all(&tree).is_err() || !tree.join("a.md").exists());
    drop(root);
    fs::rename(&tree, parent.join("moved")).expect("released once the walk ends");
}

#[test]
fn a_workspace_relative_root_is_held_like_every_other_directory() {
    let tree = temp_tree("held-relative");
    write(&tree.join("project/skills/a.md"), "original");
    let root = AuthorizedRoot::open_absolute(&tree).unwrap();
    let skills = root
        .open_workspace_relative(&WorkspaceRelativeRoot::parse("project/skills").unwrap())
        .unwrap();
    drop(root);
    assert!(fs::rename(tree.join("project/skills"), tree.join("project/moved")).is_err());
    assert_eq!(
        read(&AuthorizedRoots::single(skills), "a.md")
            .unwrap()
            .bytes(),
        b"original"
    );
    fs::rename(tree.join("project/skills"), tree.join("project/moved"))
        .expect("released once the root is dropped");
}

/// A file stays as shareable as an ordinary reader leaves it, and the read is of
/// the opened object even when its name moves on.
#[test]
fn files_are_read_while_another_process_keeps_them_open() {
    let tree = temp_tree("shared");
    write(&tree.join("a.md"), "body");
    let _writer = fs::OpenOptions::new()
        .append(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .open(tree.join("a.md"))
        .expect("open for append");
    let roots = roots_of(&tree);
    assert_eq!(read(&roots, "a.md").unwrap().bytes(), b"body");
}

#[test]
fn diagnostics_name_no_paths_or_targets() {
    let tree = temp_tree("diagnostics");
    let outside = temp_tree("diagnostics-outside");
    junction(&tree.join("escape"), &outside);
    write(&outside.join("secret.md"), "outside");
    let roots = roots_of(&tree);
    let error = read_err(&roots, "escape/secret.md").to_string();
    for private in [
        tree.to_str().unwrap(),
        outside.to_str().unwrap(),
        "secret.md",
    ] {
        assert!(!error.contains(private), "{error}");
    }
}
