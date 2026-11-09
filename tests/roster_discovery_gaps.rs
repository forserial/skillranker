//! Issue #4: incomplete enumeration must not erase provably resolved names,
//! and recovering those names must never promote a hidden competitor's loser.
// Part of this suite needs Unix fixtures; those tests and their helpers are gated.
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]

#[path = "support/links.rs"]
mod links;
use links::symlink;
use skillranker::limits::{
    DISCOVERY_FILES, DISCOVERY_PARSED_BYTES, DurationMillis, SKILL_FILE_BYTES,
};
use skillranker::roster::discovery::{Diagnostic, DiscoveryPlan, claude_code_plan};
use skillranker::roster::resolution::{
    ExactResolution, OptionMap, ResolutionError, ResolvedRoster, resolve_claude_plan,
};
use skillranker::roster::revalidation::{self, RevalidationError};
use skillranker::roster::{InvocationKind, Visibility};
use skillranker::runtime::{EntryClock, ProcessInvocation};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tree() -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "sr-discovery-gaps-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path // Retained for inspection, as in tests/roster_resolution.rs.
}

fn skill(root: &Path, name: &str, body: &str) -> PathBuf {
    let directory = root.join(".claude/skills").join(name);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("SKILL.md");
    fs::write(&path, body).unwrap();
    path
}

fn verified() -> Visibility {
    Visibility::Verified {
        contract_version: "test-discovery-gaps-v1".into(),
    }
}

fn invocation() -> (EntryClock, ProcessInvocation, asupersync::Cx) {
    let clock = EntryClock::capture_with(
        DurationMillis::new("total", 30_000, 30_000).unwrap(),
        DurationMillis::new("cleanup", 200, 30_000).unwrap(),
    )
    .unwrap();
    let runtime = ProcessInvocation::from_clock(clock).unwrap();
    let cx = runtime.request_cx().unwrap();
    (clock, runtime, cx)
}

fn resolve(plan: &DiscoveryPlan) -> ResolvedRoster {
    let (clock, runtime, cx) = invocation();
    let roster = resolve_claude_plan(plan, &BTreeMap::new(), &cx, &clock).unwrap();
    assert!(runtime.shutdown());
    roster
}

fn assert_advice(roster: &ResolvedRoster, names: &[&str]) {
    let actual: BTreeSet<_> = roster
        .advisory()
        .map(|skill| skill.binding.invocation.as_str())
        .collect();
    assert_eq!(actual, names.iter().copied().collect());
    let ids: Vec<_> = roster.advisory().map(|s| s.binding.id.clone()).collect();
    for name in names {
        assert!(matches!(
            roster.exact_name(name),
            ExactResolution::Resolved {
                kind: InvocationKind::Agent,
                ..
            }
        ));
    }
    for id in &ids {
        assert!(matches!(
            roster.exact_id(id),
            ExactResolution::Resolved {
                kind: InvocationKind::Agent,
                ..
            }
        ));
    }
    assert_eq!(
        OptionMap::new(roster, &ids).unwrap().entries().len(),
        names.len()
    );
}

fn assert_withheld(roster: &ResolvedRoster, name: &str) {
    assert_eq!(roster.exact_name(name), ExactResolution::Unverified);
    for binding in roster.skills().iter().flat_map(|s| s.bindings()) {
        if binding.invocation.as_str() == name {
            assert_eq!(roster.exact_id(&binding.id), ExactResolution::Unverified);
            assert_eq!(
                OptionMap::new(roster, std::slice::from_ref(&binding.id)).unwrap_err(),
                ResolutionError::IneligibleOption
            );
        }
    }
}

#[test]
fn linked_skill_folder_resolves_under_its_link_name_and_revalidates() {
    if !links::available() {
        return;
    }
    // sr-winpar.32: a link directly in a skills root is a skill folder.
    let workspace = tree();
    let home = tree();
    let store = tree();
    skill(&home, "alpha", "# alpha\n\nUseful skill");
    fs::create_dir_all(store.join("first")).unwrap();
    fs::write(store.join("first/SKILL.md"), "# First\n\nLinked skill").unwrap();
    fs::create_dir_all(store.join("second")).unwrap();
    fs::write(store.join("second/SKILL.md"), "# Second\n\nOther skill").unwrap();
    let link = home.join(".claude/skills/linked");
    symlink(store.join("first"), &link).unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let (clock, runtime, cx) = invocation();
    let roster = resolve_claude_plan(&plan, &BTreeMap::new(), &cx, &clock).unwrap();
    assert_advice(&roster, &["alpha", "linked"]);
    assert!(
        !roster
            .source_diagnostics()
            .iter()
            .any(|d| matches!(d, Diagnostic::SymlinkedDirectorySkipped(_)))
    );
    let ids: Vec<_> = roster.advisory().map(|s| s.binding.id.clone()).collect();
    let captured = revalidation::capture(&roster, &ids, &clock).unwrap();
    assert!(
        revalidation::revalidate_claude(
            &captured,
            &workspace,
            Some(&home),
            verified(),
            &BTreeMap::new(),
            &cx,
            &clock
        )
        .is_ok()
    );
    // Retargeting the link changes the skill's content: publication refuses.
    fs::rename(&link, home.join("retained-first-link")).unwrap();
    symlink(store.join("second"), &link).unwrap();
    assert_eq!(
        revalidation::revalidate_claude(
            &captured,
            &workspace,
            Some(&home),
            verified(),
            &BTreeMap::new(),
            &cx,
            &clock
        )
        .unwrap_err(),
        RevalidationError::Changed
    );
    assert!(runtime.shutdown());
}

#[test]
fn linked_folders_are_one_hop_and_never_descended() {
    if !links::available() {
        return;
    }
    let workspace = tree();
    let home = tree();
    let store = tree();
    skill(&home, "alpha", "# alpha\n\nUseful skill");
    // A linked folder without a skill file is not descended: its nested
    // skill-shaped folders are not skills of this root.
    fs::create_dir_all(store.join("tree/inner")).unwrap();
    fs::write(store.join("tree/inner/SKILL.md"), "# Inner\n\nbody").unwrap();
    symlink(store.join("tree"), home.join(".claude/skills/library")).unwrap();
    // A link below the root's top level is still skipped.
    fs::create_dir_all(store.join("nested")).unwrap();
    fs::write(store.join("nested/SKILL.md"), "# Nested\n\nbody").unwrap();
    fs::create_dir_all(home.join(".claude/skills/container")).unwrap();
    symlink(
        store.join("nested"),
        home.join(".claude/skills/container/nested"),
    )
    .unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let discovery = plan.discover();
    let found: Vec<_> = discovery
        .candidates()
        .iter()
        .map(|c| c.relative().to_path_buf())
        .collect();
    assert_eq!(found, vec![Path::new("alpha").join("SKILL.md")]);
    assert_eq!(
        discovery
            .diagnostics()
            .iter()
            .filter(|d| matches!(d, Diagnostic::SymlinkedDirectorySkipped(_)))
            .count(),
        1
    );
    let roster = resolve(&plan);
    assert_advice(&roster, &["alpha"]);
}

#[test]
fn unrelated_dangling_link_preserves_three_skills_ids_and_option_authority() {
    if !links::available() {
        return;
    }
    let workspace = tree();
    let home = tree();
    let outside = tree();
    for name in ["alpha", "beta", "gamma"] {
        skill(&home, name, &format!("# {name}\n\nUseful skill"));
    }
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let control = resolve(&plan);
    assert_advice(&control, &["alpha", "beta", "gamma"]);
    let ids: BTreeSet<_> = control.advisory().map(|s| s.binding.id.clone()).collect();
    fs::write(outside.join("SKILL.md"), "# Not authorized\n\nbody").unwrap();
    let link = home.join(".claude/skills/linked-private-name");
    // A link reaching nothing is skipped and reported, never guessed at.
    symlink(outside.join("missing"), &link).unwrap();
    let partial = resolve(&plan);
    assert!(partial.is_partial());
    assert_advice(&partial, &["alpha", "beta", "gamma"]);
    assert_eq!(
        partial.exact_name("linked-private-name"),
        ExactResolution::Missing
    );
    assert_eq!(
        ids,
        partial.advisory().map(|s| s.binding.id.clone()).collect()
    );
    assert!(
        partial
            .source_diagnostics()
            .iter()
            .any(|d| matches!(d, Diagnostic::SymlinkedDirectorySkipped(_)))
    );
    assert!(!format!("{:?}", partial.source_diagnostics()).contains("linked-private-name"));
    fs::rename(&link, home.join("retained-link")).unwrap();
    let restored = resolve(&plan);
    assert_advice(&restored, &["alpha", "beta", "gamma"]);
    assert_eq!(
        ids,
        restored.advisory().map(|s| s.binding.id.clone()).collect()
    );
    assert!(
        !restored
            .source_diagnostics()
            .iter()
            .any(|d| matches!(d, Diagnostic::SymlinkedDirectorySkipped(_)))
    );
}

#[test]
fn skipped_directory_and_dangling_skill_link_withhold_only_their_names() {
    if !links::available() {
        return;
    }
    let workspace = tree();
    let home = tree();
    let outside = tree();
    for name in ["helpful", "linked", "broken"] {
        skill(&workspace, name, "# Project skill\n\nbody");
    }
    fs::create_dir_all(home.join(".claude/skills/broken")).unwrap();
    // A dangling linked folder cannot prove its name absent.
    symlink(outside.join("gone"), home.join(".claude/skills/linked")).unwrap();
    symlink(
        outside.join("missing.md"),
        home.join(".claude/skills/broken/SKILL.md"),
    )
    .unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let roster = resolve(&plan);
    assert!(roster.is_partial());
    assert_advice(&roster, &["helpful"]);
    assert_withheld(&roster, "linked");
    assert_withheld(&roster, "broken");
    assert!(
        roster
            .source_diagnostics()
            .iter()
            .any(|d| matches!(d, Diagnostic::EntryUnreadable(_)))
    );
}

#[test]
fn real_entry_ceiling_preserves_names_and_resolves_shallow_personal_overrides() {
    let workspace = tree();
    for name in ["alpha", "beta", "gamma"] {
        skill(&workspace, name, &format!("# {name}\n\nbody"));
    }
    // Breadth-first traversal necessarily observes all direct SKILL.md files
    // before entering this depth-two directory, regardless of readdir order.
    // It sits in a container without a skill file: a skill's own directories
    // are never walked.
    let references = workspace.join(".claude/skills/archive/references");
    fs::create_dir_all(&references).unwrap();
    for index in 0..=DISCOVERY_FILES.max() {
        fs::write(references.join(format!("note-{index:05}.txt")), "note").unwrap();
    }
    let plan = claude_code_plan(&workspace, None, verified()).unwrap();
    let discovery = plan.discover();
    assert_eq!(discovery.candidates().len(), 3);
    assert!(
        discovery
            .diagnostics()
            .contains(&Diagnostic::EntryLimitReached)
    );
    let roster = resolve(&plan);
    assert!(roster.is_partial());
    assert_advice(&roster, &["alpha", "beta", "gamma"]);
    assert!(
        roster
            .source_diagnostics()
            .contains(&Diagnostic::EntryLimitReached)
    );

    // The global queue reaches personal skills before the project's nested
    // support files. Resolve the real winner rather than withholding its name.
    let home = tree();
    skill(
        &home,
        "beta",
        "---\nname: Beta\ndisable-model-invocation: true\n---\nbody",
    );
    skill(&home, "delta", "# Personal only\n\nbody");
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let discovery = plan.discover();
    assert_eq!(discovery.candidates().len(), 5);
    assert_eq!(discovery.entries_examined(), DISCOVERY_FILES.max() + 1);
    assert!(
        discovery
            .diagnostics()
            .contains(&Diagnostic::EntryLimitReached)
    );
    let roster = resolve(&plan);
    assert_advice(&roster, &["alpha", "gamma", "delta"]);
    assert!(matches!(
        roster.exact_name("beta"),
        ExactResolution::Resolved {
            kind: InvocationKind::ManualOnly,
            ..
        }
    ));
    let project_beta = roster
        .skills()
        .iter()
        .flat_map(|s| s.bindings())
        .find(|binding| {
            binding.source.as_str() == "claude_code.project"
                && binding.invocation.as_str() == "beta"
        })
        .unwrap();
    assert_eq!(roster.exact_id(&project_beta.id), ExactResolution::Shadowed);
    assert_eq!(
        OptionMap::new(&roster, std::slice::from_ref(&project_beta.id)).unwrap_err(),
        ResolutionError::IneligibleOption
    );
}

#[test]
fn oversized_file_keeps_clean_names_without_reading_the_rejected_file() {
    let workspace = tree();
    let home = tree();
    skill(&workspace, "helpful", "# Helpful\n\nbody");
    let oversized = skill(&home, "overflow", "");
    fs::OpenOptions::new()
        .write(true)
        .open(oversized)
        .unwrap()
        .set_len(DISCOVERY_PARSED_BYTES.max() as u64 + 1)
        .unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let roster = resolve(&plan);
    assert!(roster.is_partial());
    assert_advice(&roster, &["helpful"]);
    assert_eq!(roster.exact_name("overflow"), ExactResolution::Missing);
    assert!(
        roster
            .diagnostics()
            .iter()
            .any(|(_, e)| *e == ResolutionError::Oversized)
    );
    assert!(
        !roster
            .source_diagnostics()
            .contains(&Diagnostic::ByteLimitReached)
    );
}

#[test]
fn rejected_oversized_competitor_never_promotes_the_lower_priority_binding() {
    let workspace = tree();
    let home = tree();
    skill(&workspace, "helpful", "# Helpful\n\nbody");
    skill(&workspace, "blocked", "# Lower priority\n\nbody");
    let skipped = skill(&home, "blocked", "# Not admitted\n\nbody");
    fs::OpenOptions::new()
        .write(true)
        .open(skipped)
        .unwrap()
        .set_len(DISCOVERY_PARSED_BYTES.max() as u64 + 1)
        .unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let discovery = plan.discover();
    assert_eq!(discovery.candidates().len(), 2);
    assert_eq!(discovery.rejected_candidates().len(), 1);
    assert!(
        !discovery
            .diagnostics()
            .contains(&Diagnostic::ByteLimitReached)
    );
    let roster = resolve(&plan);
    assert!(roster.is_partial());
    assert_advice(&roster, &["helpful"]);
    assert_withheld(&roster, "blocked");
    assert!(
        roster
            .diagnostics()
            .iter()
            .any(|(_, e)| *e == ResolutionError::Oversized)
    );
}

#[test]
fn exhausted_parse_budget_does_not_revoke_already_parsed_names() {
    let workspace = tree();
    let mut body = String::from("# Bounded\n\n");
    body.push_str(&"x".repeat(SKILL_FILE_BYTES.max() - body.len()));
    let count = DISCOVERY_PARSED_BYTES.max() / SKILL_FILE_BYTES.max();
    assert_eq!(count * body.len(), DISCOVERY_PARSED_BYTES.max());
    for index in 0..count {
        skill(&workspace, &format!("a-{index:03}"), &body);
    }
    // Zero declared bytes fit the discovery byte cap, but no parse allowance
    // remains when this final (name-sorted) candidate is reached.
    skill(&workspace, "z-empty", "");
    let plan = claude_code_plan(&workspace, None, verified()).unwrap();
    let roster = resolve(&plan);
    assert_eq!(roster.advisory().count(), count);
    assert!(
        roster
            .diagnostics()
            .iter()
            .any(|(_, e)| *e == ResolutionError::Limit)
    );
    assert!(roster.is_partial());
}

#[test]
fn recovery_preserves_precedence_manual_only_and_authorized_file_aliases() {
    if !links::available() {
        return;
    }
    let workspace = tree();
    let home = tree();
    let outside = tree();
    skill(&workspace, "deploy", "# Project deploy\n\nbody");
    skill(
        &home,
        "deploy",
        "---\nname: Deploy\ndisable-model-invocation: true\n---\nbody",
    );
    let original = skill(&workspace, "original", "# Original\n\nbody");
    fs::create_dir_all(workspace.join(".claude/skills/alias")).unwrap();
    symlink(original, workspace.join(".claude/skills/alias/SKILL.md")).unwrap();
    symlink(outside, home.join(".claude/skills/unrelated")).unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let roster = resolve(&plan);
    assert_eq!(roster.advisory().count(), 1); // One physical target, two aliases.
    assert!(matches!(
        roster.exact_name("deploy"),
        ExactResolution::Resolved {
            kind: InvocationKind::ManualOnly,
            ..
        }
    ));
    for name in ["original", "alias"] {
        assert!(matches!(
            roster.exact_name(name),
            ExactResolution::Resolved {
                kind: InvocationKind::Agent,
                ..
            }
        ));
    }
    let plan = claude_code_plan(&workspace, Some(&home), Visibility::Unverified).unwrap();
    assert_eq!(resolve(&plan).advisory().count(), 0); // A proof never upgrades visibility.
}

#[test]
fn same_diagnostic_count_cannot_hide_a_new_competitor_at_publication() {
    if !links::available() {
        return;
    }
    let workspace = tree();
    let home = tree();
    let outside = tree();
    skill(&workspace, "helpful", "# Helpful\n\nbody");
    fs::create_dir_all(home.join(".claude/skills")).unwrap();
    let link = home.join(".claude/skills/unrelated");
    symlink(outside.join("missing"), &link).unwrap();
    let plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let (clock, runtime, cx) = invocation();
    let initial = resolve_claude_plan(&plan, &BTreeMap::new(), &cx, &clock).unwrap();
    assert_advice(&initial, &["helpful"]);
    let ids: Vec<_> = initial.advisory().map(|s| s.binding.id.clone()).collect();
    let captured = revalidation::capture(&initial, &ids, &clock).unwrap();
    assert!(
        revalidation::revalidate_claude(
            &captured,
            &workspace,
            Some(&home),
            verified(),
            &BTreeMap::new(),
            &cx,
            &clock
        )
        .is_ok()
    );
    fs::rename(link, home.join(".claude/skills/helpful")).unwrap();
    let fresh_plan = claude_code_plan(&workspace, Some(&home), verified()).unwrap();
    let fresh = resolve_claude_plan(&fresh_plan, &BTreeMap::new(), &cx, &clock).unwrap();
    assert_eq!(initial.source_diagnostics(), fresh.source_diagnostics());
    assert_withheld(&fresh, "helpful");
    assert_eq!(
        revalidation::revalidate(&captured, &fresh, &clock).unwrap_err(),
        RevalidationError::Changed
    );
    assert!(runtime.shutdown());
}
