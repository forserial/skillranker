//! Recover only names whose direct-layout competitors are accounted for.
//!
//! Discovery diagnostics deliberately carry no paths. They therefore cannot
//! themselves prove which names a skipped subtree or truncated walk could hide.
//! Instead, probe the one supported slot for each observed name in each root.
//! This is metadata-only verification, not a second discovery or read allowance.

use super::{ResolutionError, SkillEntry, budget, path_logical_key};
use crate::authorized_read::{AuthorizedRoot, FileIdentity};
use crate::identity::SkillId;
use crate::limits::DISCOVERY_FILES;
use crate::roster::discovery::{CLAUDE_SKILL_FILE, DiscoveryPlan, SourceKind};
use crate::runtime::EntryClock;
use asupersync::Cx;
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::fcntl::{AtFlags, OFlag, openat};
#[cfg(unix)]
use nix::sys::stat::{Mode, SFlag, fstatat};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Default)]
pub(super) struct NameProof {
    pub(super) withheld: BTreeSet<String>,
    pub(super) limited: BTreeSet<String>,
}

pub(super) fn prove_names(
    plan: &DiscoveryPlan,
    entries: &[SkillEntry],
    already_withheld: &BTreeSet<String>,
    cx: &Cx,
    clock: &EntryClock,
) -> Result<NameProof, ResolutionError> {
    prove_with_limit(
        plan,
        entries,
        already_withheld,
        cx,
        clock,
        DISCOVERY_FILES.max(),
    )
}

fn prove_with_limit(
    plan: &DiscoveryPlan,
    entries: &[SkillEntry],
    already_withheld: &BTreeSet<String>,
    cx: &Cx,
    clock: &EntryClock,
    max_probes: usize,
) -> Result<NameProof, ResolutionError> {
    budget(cx, clock)?;
    let snapshots: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (entry.binding.id.clone(), entry.identity))
        .collect();
    // Stable ordering makes exhaustion deterministic, independent of readdir.
    let names: BTreeSet<_> = entries
        .iter()
        .map(|entry| entry.binding.invocation.as_str())
        .filter(|name| !already_withheld.contains(*name))
        .collect();
    let mut proof = NameProof::default();
    let mut probes = 0usize;
    for name in names {
        budget(cx, clock)?;
        let relative = Path::new(name).join(CLAUDE_SKILL_FILE);
        for planned in plan.roots() {
            budget(cx, clock)?;
            if !matches!(
                planned.spec().kind(),
                SourceKind::Project | SourceKind::User
            ) {
                continue; // This adapter gives unsupported sources no callable names.
            }
            if probes >= max_probes {
                proof.withheld.insert(name.to_owned());
                proof.limited.insert(name.to_owned());
                break;
            }
            probes += 1;
            let Some(root) = planned.root() else {
                proof.withheld.insert(name.to_owned());
                break; // An unreadable root cannot prove even a named absence.
            };
            let key = path_logical_key(&root.absolute_path().join(&relative))?;
            let id = SkillId::from_source(planned.spec().source(), &key);
            let expected = snapshots.get(&id).copied();
            let accounted_for = slot_matches(root, name, expected);
            budget(cx, clock)?;
            if !accounted_for {
                proof.withheld.insert(name.to_owned());
                break;
            }
        }
    }
    budget(cx, clock)?;
    Ok(proof)
}

/// True only for an absent slot with no snapshot binding, or the exact file
/// already read and parsed at this source/path. Finding an unobserved file is
/// NOT permission to admit it or promote another root's definition of its name.
/// A slot directory that is a link is followed one hop only when the root
/// admits linked folders, as discovery does; otherwise, or when the link is
/// dangling, it never proves absence. A dangling SKILL.md link is not an
/// absence: lstat it first, and follow file links only for an existing binding.
#[allow(clippy::unnecessary_cast)] // dev_t/ino_t widths differ on macOS.
#[cfg(unix)]
fn slot_matches(root: &AuthorizedRoot, name: &str, expected: Option<FileIdentity>) -> bool {
    use std::os::fd::AsFd;
    let directory_stat = match fstatat(root.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return expected.is_none(),
        Err(_) => return false,
    };
    let kind = SFlag::from_bits_truncate(directory_stat.st_mode) & SFlag::S_IFMT;
    let linked;
    let plain;
    let directory = if kind == SFlag::S_IFLNK {
        if !root.follows_linked_folders() {
            return false;
        }
        let Ok(folder) = root.open_linked_folder(std::ffi::OsStr::new(name)) else {
            return false;
        };
        linked = folder;
        linked.as_fd()
    } else if kind != SFlag::S_IFDIR {
        return expected.is_none();
    } else {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let Ok(opened) = openat(root.as_fd(), name, flags, Mode::empty()) else {
            return false;
        };
        plain = opened;
        plain.as_fd()
    };
    let stat = match fstatat(directory, CLAUDE_SKILL_FILE, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return expected.is_none(),
        Err(_) => return false,
    };
    let Some(expected) = expected else {
        return false;
    };
    let stat = if (SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT) == SFlag::S_IFLNK {
        let Ok(target) = fstatat(directory, CLAUDE_SKILL_FILE, AtFlags::empty()) else {
            return false;
        };
        target
    } else {
        stat
    };
    (SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT) == SFlag::S_IFREG
        && FileIdentity::new(stat.st_dev as u64, stat.st_ino as u64) == expected
}

/// Windows form of the same proof. The slot directory is held open without
/// `FILE_SHARE_DELETE` while its skill file is inspected, and both are opened
/// without following a final link; a linked slot folder is followed one hop
/// under the Unix rule, and only an existing file binding follows a file link.
#[cfg(windows)]
fn slot_matches(root: &AuthorizedRoot, name: &str, expected: Option<FileIdentity>) -> bool {
    use crate::authorized_read::{FileKind, open_windows, stat_windows, valid_component};
    use std::ffi::OsStr;
    use std::io::ErrorKind;
    if !valid_component(OsStr::new(name)) {
        return false;
    }
    let mut directory_path = root.windows_handle().path().join(name);
    let directory = match open_windows(&directory_path, false, true) {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return expected.is_none(),
        Err(_) => return false,
    };
    let Ok(directory_stat) = stat_windows(&directory) else {
        return false;
    };
    let mut linked = None;
    match directory_stat.kind() {
        FileKind::Symlink if root.follows_linked_folders() => {
            let Ok(folder) = root.open_linked_folder(OsStr::new(name)) else {
                return false;
            };
            directory_path = folder.windows_handle().path().to_path_buf();
            linked = Some(folder);
        }
        FileKind::Symlink => return false,
        FileKind::Directory => {}
        _ => return expected.is_none(),
    }
    let file_path = directory_path.join(CLAUDE_SKILL_FILE);
    let file = match open_windows(&file_path, false, false) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return expected.is_none(),
        Err(_) => return false,
    };
    let Some(expected) = expected else {
        return false;
    };
    let Ok(mut stat) = stat_windows(&file) else {
        return false;
    };
    if stat.kind() == FileKind::Symlink {
        let Ok(target) = open_windows(&file_path, true, false).and_then(|target| {
            stat_windows(&target).map_err(|_| std::io::Error::from(ErrorKind::Other))
        }) else {
            return false;
        };
        stat = target;
    }
    drop(directory);
    drop(linked);
    stat.kind() == FileKind::Regular && stat.identity() == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorized_read::AuthorizedRoots;
    use crate::limits::{DurationMillis, SKILL_FILE_BYTES};
    use crate::roster::discovery::claude_code_plan;
    use crate::roster::resolution::{BindingSpec, claude_invocation};
    use crate::roster::{InvocationRestrictions, Visibility};
    use crate::runtime::ProcessInvocation;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tree() -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sr-discovery-proof-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path // Retained for inspection, like the roster-resolution fixtures.
    }

    #[test]
    fn absence_unseen_file_and_changed_identity_are_distinct() {
        let path = tree();
        let root = AuthorizedRoot::open_absolute(&path).unwrap();
        assert!(slot_matches(&root, "alpha", None));
        fs::create_dir(path.join("alpha")).unwrap();
        assert!(slot_matches(&root, "alpha", None));
        fs::write(path.join("alpha/SKILL.md"), "# Alpha\n\nbody").unwrap();
        assert!(!slot_matches(&root, "alpha", None));
        let roots = AuthorizedRoots::single(root.try_clone().unwrap());
        let read = roots
            .read_bounded(0, Path::new("alpha/SKILL.md"), SKILL_FILE_BYTES)
            .unwrap();
        assert!(slot_matches(&root, "alpha", Some(read.identity())));
        fs::rename(path.join("alpha/SKILL.md"), path.join("old.md")).unwrap();
        assert!(!slot_matches(&root, "alpha", Some(read.identity())));
        fs::write(path.join("alpha/SKILL.md"), "# Replacement\n\nbody").unwrap();
        assert!(!slot_matches(&root, "alpha", Some(read.identity())));
    }

    #[test]
    fn symlinked_directories_and_dangling_file_links_never_prove_absence() {
        #[cfg(unix)]
        use std::os::unix::fs::{symlink as symlink_dir, symlink as symlink_file};
        #[cfg(windows)]
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let path = tree();
        let outside = tree();
        let root = AuthorizedRoot::open_absolute(&path).unwrap();
        match symlink_dir(&outside, path.join("linked")) {
            Ok(()) => {}
            // Windows needs Developer Mode or elevation for symbolic links.
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("skipped: creating symbolic links needs Developer Mode or elevation");
                return;
            }
            Err(error) => panic!("create directory link: {error}"),
        }
        assert!(!slot_matches(&root, "linked", None));
        // A root that admits linked folders follows the slot link one hop: an
        // empty target proves absence, and a skill file there is only
        // accounted for as the exact file already read.
        let linked_root = root.try_clone().unwrap().with_linked_folders();
        assert!(slot_matches(&linked_root, "linked", None));
        fs::write(outside.join(CLAUDE_SKILL_FILE), "# Linked\n\nbody").unwrap();
        assert!(!slot_matches(&linked_root, "linked", None));
        let read = AuthorizedRoots::single(linked_root.try_clone().unwrap())
            .read_bounded(0, Path::new("linked/SKILL.md"), SKILL_FILE_BYTES)
            .unwrap();
        assert!(slot_matches(&linked_root, "linked", Some(read.identity())));
        symlink_dir(outside.join("missing"), path.join("dangling")).unwrap();
        assert!(!slot_matches(&linked_root, "dangling", None));
        fs::create_dir(path.join("broken")).unwrap();
        symlink_file(outside.join("missing"), path.join("broken/SKILL.md")).unwrap();
        assert!(!slot_matches(&root, "broken", None));
    }

    #[test]
    fn proof_limit_keeps_completed_names_and_marks_only_unproven_names() {
        let workspace = tree();
        for name in ["alpha", "beta"] {
            let directory = workspace.join(".claude/skills").join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join(CLAUDE_SKILL_FILE), "# Skill\n\nbody").unwrap();
        }
        let plan = claude_code_plan(
            &workspace,
            None,
            Visibility::Verified {
                contract_version: "test-proof-v1".into(),
            },
        )
        .unwrap();
        let discovery = plan.discover();
        let root = plan.roots()[0].root().unwrap();
        let roots = AuthorizedRoots::single(root.try_clone().unwrap());
        let entries: Vec<_> = discovery
            .candidates()
            .iter()
            .map(|candidate| {
                SkillEntry::from_read(
                    BindingSpec {
                        source: candidate.source().clone(),
                        logical_key: path_logical_key(candidate.path().as_path()).unwrap(),
                        invocation: claude_invocation(candidate.kind(), candidate.relative())
                            .unwrap(),
                        priority: Some(candidate.priority()),
                        visibility: candidate.visibility().clone(),
                        restrictions: InvocationRestrictions {
                            agent_invocable: true,
                            user_invocable: true,
                        },
                    },
                    roots
                        .read_bounded(0, candidate.relative(), SKILL_FILE_BYTES)
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        let clock = EntryClock::capture_with(
            DurationMillis::new("total", 30_000, 30_000).unwrap(),
            DurationMillis::new("cleanup", 200, 30_000).unwrap(),
        )
        .unwrap();
        let runtime = ProcessInvocation::from_clock(clock).unwrap();
        let cx = runtime.request_cx().unwrap();
        let proof = prove_with_limit(&plan, &entries, &BTreeSet::new(), &cx, &clock, 0).unwrap();
        assert_eq!(
            proof.withheld,
            BTreeSet::from(["alpha".to_owned(), "beta".to_owned()])
        );
        assert_eq!(proof.limited, proof.withheld);
        let proof = prove_with_limit(&plan, &entries, &BTreeSet::new(), &cx, &clock, 1).unwrap();
        assert_eq!(proof.withheld, BTreeSet::from(["beta".to_owned()]));
        assert_eq!(proof.limited, proof.withheld);
        let proof = prove_with_limit(&plan, &entries, &BTreeSet::new(), &cx, &clock, 2).unwrap();
        assert!(proof.withheld.is_empty());
        assert!(proof.limited.is_empty());
        assert!(runtime.shutdown());
    }
}
