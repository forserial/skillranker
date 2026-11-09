//! Linked skill folders (sr-winpar.32). A link directly in a skill root that
//! reaches a directory is read as that root's own folder: followed one hop,
//! and held by the directory it reaches, wherever that lies. Every other link
//! keeps the ordinary containment rules, and a root that does not admit linked
//! folders keeps them for its top level too. Fixtures are retained under the
//! system temporary folder.

#[path = "support/links.rs"]
mod links;
use links::symlink;
use skillranker::authorized_read::{AuthorizedRoot, AuthorizedRoots, ReadError};
use skillranker::limits::SKILL_FILE_BYTES;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tree(name: &str) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    #[cfg(unix)]
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    #[cfg(not(unix))]
    let base = std::env::temp_dir();
    let path = base.join(format!(
        "sr-linked-{name}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn skill(folder: &Path, body: &str) {
    fs::create_dir_all(folder).unwrap();
    fs::write(folder.join("SKILL.md"), body).unwrap();
}

fn read(root: &AuthorizedRoot, relative: &str) -> Result<Vec<u8>, ReadError> {
    AuthorizedRoots::single(root.try_clone().unwrap())
        .read_bounded(0, Path::new(relative), SKILL_FILE_BYTES)
        .map(|read| read.bytes().to_vec())
}

#[test]
fn a_top_level_link_is_read_only_when_the_root_admits_linked_folders() {
    if !links::available() {
        return;
    }
    let root = tree("root");
    let store = tree("store");
    skill(&store.join("skill"), "linked-body");
    symlink(store.join("skill"), root.join("absolute")).unwrap();
    let relative_target = Path::new("..")
        .join(store.file_name().unwrap())
        .join("skill");
    symlink(&relative_target, root.join("relative")).unwrap();

    let plain = AuthorizedRoot::open_absolute(&root).unwrap();
    assert!(!plain.follows_linked_folders());
    for name in ["absolute/SKILL.md", "relative/SKILL.md"] {
        assert_eq!(
            read(&plain, name),
            Err(ReadError::EscapesAuthorizedRoots),
            "{name}"
        );
    }

    let linked = plain.try_clone().unwrap().with_linked_folders();
    assert!(linked.follows_linked_folders());
    assert!(linked.try_clone().unwrap().follows_linked_folders());
    let direct = AuthorizedRoots::single(AuthorizedRoot::open_absolute(&store).unwrap())
        .read_bounded(0, Path::new("skill/SKILL.md"), SKILL_FILE_BYTES)
        .unwrap();
    let roots = AuthorizedRoots::single(linked.try_clone().unwrap());
    for name in ["absolute", "relative"] {
        let through = roots
            .read_absolute(&root.join(name).join("SKILL.md"), SKILL_FILE_BYTES)
            .unwrap();
        assert_eq!(through.bytes(), b"linked-body");
        assert_eq!(through.identity(), direct.identity(), "one file");
        assert_eq!(
            through.path().as_path(),
            root.join(name).join("SKILL.md"),
            "named by the link, as the harness loads it"
        );
    }
}

#[test]
fn only_the_top_level_hop_to_a_directory_is_followed() {
    if !links::available() {
        return;
    }
    let root = tree("root");
    let store = tree("store");
    skill(&store.join("skill"), "linked-body");
    fs::create_dir_all(root.join("container")).unwrap();
    symlink(store.join("skill"), root.join("container").join("deeper")).unwrap();
    symlink(store.join("skill").join("SKILL.md"), root.join("file-link")).unwrap();
    symlink(store.join("missing"), root.join("dangling")).unwrap();
    let linked = AuthorizedRoot::open_absolute(&root)
        .unwrap()
        .with_linked_folders();

    // Below the top level, the ordinary rule: an absolute target outside
    // every authorized root is refused.
    assert_eq!(
        read(&linked, "container/deeper/SKILL.md"),
        Err(ReadError::EscapesAuthorizedRoots)
    );
    // A link that is the final component is not a folder.
    assert_eq!(
        read(&linked, "file-link"),
        Err(ReadError::EscapesAuthorizedRoots)
    );
    // A top-level link must reach a directory.
    assert_eq!(
        read(&linked, "file-link/SKILL.md"),
        Err(ReadError::NotADirectory)
    );
    assert_eq!(read(&linked, "dangling/SKILL.md"), Err(ReadError::NotFound));
    assert_eq!(
        linked
            .open_linked_folder("dangling".as_ref())
            .map(|_| ())
            .unwrap_err(),
        ReadError::NotFound
    );
    assert_eq!(
        linked
            .open_linked_folder("container/deeper".as_ref())
            .map(|_| ())
            .unwrap_err(),
        ReadError::InvalidRelativePath
    );
}

#[test]
fn a_held_linked_folder_is_not_redirected_by_a_retarget() {
    if !links::available() {
        return;
    }
    let root = tree("root");
    let store = tree("store");
    skill(&store.join("first"), "first-body");
    skill(&store.join("second"), "second-body");
    let link = root.join("linked");
    symlink(store.join("first"), &link).unwrap();
    let linked = AuthorizedRoot::open_absolute(&root)
        .unwrap()
        .with_linked_folders();
    let held = linked.open_linked_folder("linked".as_ref()).unwrap();
    assert_eq!(held.absolute_path(), link.as_path());
    assert!(!held.follows_linked_folders(), "one hop only");

    fs::rename(&link, root.join("retained-first-link")).unwrap();
    symlink(store.join("second"), &link).unwrap();

    assert_eq!(read(&held, "SKILL.md").unwrap(), b"first-body");
    assert_eq!(read(&linked, "linked/SKILL.md").unwrap(), b"second-body");
}
