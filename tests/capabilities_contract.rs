//! The capability registry against the real binary: every implemented command
//! runs, every planned command is refused, help and the registry agree, and
//! limits, exit codes and adapters come from their single sources.
use serde_json::Value;
use skillranker::adapter::{CLAUDE_CODE_ID, NORMALIZED_ID, foundation_capabilities};
use skillranker::capabilities::{IMPLEMENTED_COMMANDS, registry};
use skillranker::limits::ALL_DEFAULT_LIMITS;
use skillranker::output::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

// Intentionally retained: repository policy forbids automatic tree deletion.
fn home() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "sr-capabilities-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir_all(root.join("workspace")).unwrap();
    root
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sr"))
        .env_clear()
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .current_dir(root.join("workspace"))
        .args(args)
        .output()
        .unwrap()
}

fn commands(document: &Value) -> Vec<(String, String)> {
    document["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_owned(),
                c["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn the_binary_prints_the_registry_and_runs_exactly_the_implemented_commands() {
    let root = home();
    let output = run(&root, &["capabilities", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, registry());
    assert_eq!(printed["schema"], "sr.capabilities.v1");
    let listed = commands(&printed);
    let implemented: Vec<&str> = listed
        .iter()
        .filter(|(_, status)| status == "implemented")
        .map(|(name, _)| name.as_str())
        .collect();
    for name in IMPLEMENTED_COMMANDS {
        assert!(implemented.contains(name), "{name}");
    }
    assert_eq!(implemented.len(), IMPLEMENTED_COMMANDS.len() + 2);
    // Every implemented subcommand answers --help.
    for name in IMPLEMENTED_COMMANDS {
        let help = run(&root, &[name, "--help"]);
        assert_eq!(help.status.code(), Some(0), "{name} --help");
    }
    // Every planned command is refused as invalid usage, never half-run.
    let planned: Vec<&str> = listed
        .iter()
        .filter(|(_, status)| status == "planned")
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(planned.is_empty());
    assert!(implemented.contains(&"hook"));
    assert!(implemented.contains(&"tui"));
    assert!(implemented.contains(&"gaps"));
    assert!(implemented.contains(&"replay"));
    for name in &planned {
        let refused = run(&root, &[name, "--json"]);
        assert_eq!(refused.status.code(), Some(2), "{name}");
        let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(error["error"]["kind"], "invalid-usage", "{name}");
    }
    // Every foundation command is classified exactly once.
    let foundation = foundation_capabilities().unwrap();
    assert_eq!(listed.len(), foundation.planned_cli.len() + 2);
}

#[test]
fn help_names_implemented_commands_and_no_planned_ones() {
    let root = home();
    let help = String::from_utf8(run(&root, &["--help"]).stdout).unwrap();
    for name in IMPLEMENTED_COMMANDS {
        // Rank is also the bare command, written `sr [rank]`.
        let listed =
            help.contains(&format!("sr {name}")) || (*name == "rank" && help.contains("sr [rank]"));
        assert!(listed, "help lacks {name}");
    }
    for (name, status) in commands(&registry()) {
        if status == "planned" {
            assert!(
                !help.contains(&format!("sr {name}")),
                "help advertises {name}"
            );
        }
    }
    // Implemented flags are advertised in help.
    assert!(help.contains("--save-case"));
    assert!(help.contains("--descriptions"));
    for flag in registry()["planned_flags"].as_array().unwrap() {
        let flag_str = flag["flag"].as_str().unwrap();
        let command = flag["command"].as_str().unwrap();
        let command_help = String::from_utf8(run(&root, &[command, "--help"]).stdout).unwrap();
        assert!(
            !command_help.contains(flag_str),
            "{command} help advertises {flag_str}"
        );
    }
}

#[test]
fn planned_flags_contract() {
    let root = home();
    let planned_flags = registry()["planned_flags"].as_array().unwrap().clone();
    assert!(planned_flags.is_empty());
    // Conflicts are still reported as conflicts.
    let conflict = run(
        &root,
        &["rank", "--dry-run", "--save-case", "case.json", "--json"],
    );
    assert_eq!(conflict.status.code(), Some(2));
}

#[test]
fn bare_sr_ranks_and_fails_without_a_session_source() {
    let root = home();
    let output = run(&root, &["--json"]);
    // Bare sr is rank; with no source it cannot select a session.
    assert_ne!(output.status.code(), Some(0));
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(error["error"]["kind"], "invalid-usage", "{error}");
}

#[test]
fn limits_exit_codes_adapters_and_features_come_from_their_sources() {
    let document = registry();
    let limits = document["limits"].as_array().unwrap();
    assert_eq!(limits.len(), ALL_DEFAULT_LIMITS.len());
    for (listed, limit) in limits.iter().zip(ALL_DEFAULT_LIMITS) {
        assert_eq!(listed["name"], limit.name);
        assert_eq!(listed["max"], limit.max());
    }
    let errors = document["exit_codes"]["errors"].as_array().unwrap();
    assert_eq!(errors.len(), ErrorKind::ALL.len());
    for (listed, kind) in errors.iter().zip(ErrorKind::ALL) {
        assert_eq!(listed["kind"], kind.as_str());
        assert_eq!(listed["exit_code"], kind.exit_code() as u8);
    }
    let adapters = document["adapters"].as_array().unwrap();
    let find = |id: &str| {
        adapters
            .iter()
            .find(|a| a["adapter_id"] == id)
            .unwrap()
            .clone()
    };
    // Normalized context is implemented; the Claude harness stays unverified,
    // with no tested version, so no native advice is claimed.
    assert_eq!(find(NORMALIZED_ID)["support"], "implemented");
    assert_eq!(find(CLAUDE_CODE_ID)["support"], "unverified");
    assert!(
        find(CLAUDE_CODE_ID)["tested_versions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(document["features"]["tui"]["implemented"], true);
    assert_eq!(
        document["features"]["tui"]["compiled"],
        cfg!(feature = "tui")
    );
}

#[test]
fn platform_availability_is_complete_and_internally_consistent() {
    use skillranker::platform_support::{Boundary, COMPONENTS, MODES};
    let document = registry();
    let platform = &document["platform"];
    assert_eq!(platform["os"], std::env::consts::OS);

    let boundaries = platform["boundaries"].as_array().unwrap();
    assert_eq!(boundaries.len(), Boundary::ALL.len());
    for (entry, boundary) in boundaries.iter().zip(Boundary::ALL) {
        assert_eq!(entry["name"], boundary.name());
        assert_eq!(entry["available"], boundary.available());
        // A reason exactly when the boundary is missing.
        assert_eq!(entry["reason"].is_null(), boundary.available(), "{entry}");
    }

    let components = platform["components"].as_array().unwrap();
    assert_eq!(components.len(), COMPONENTS.len());
    let mut names = std::collections::BTreeSet::new();
    for entry in components {
        assert!(names.insert(entry["name"].as_str().unwrap()), "{entry}");
        let boundary = boundaries
            .iter()
            .find(|b| b["name"] == entry["requires"])
            .unwrap_or_else(|| panic!("unknown boundary in {entry}"));
        // A component needs its boundary, and may still wait on its own port.
        if boundary["available"] == false {
            assert_eq!(entry["available"], false, "{entry}");
            assert_eq!(entry["reason"], boundary["reason"], "{entry}");
        }
        assert_eq!(
            entry["reason"].is_null(),
            entry["available"] == true,
            "{entry}"
        );
    }

    let modes = platform["modes"].as_array().unwrap();
    assert_eq!(modes.len(), MODES.len());
    let commands = commands(&document);
    let mut keys = std::collections::BTreeSet::new();
    for entry in modes {
        let component = components
            .iter()
            .find(|c| c["name"] == entry["component"])
            .unwrap_or_else(|| panic!("unknown component in {entry}"));
        assert_eq!(entry["available"], component["available"], "{entry}");
        let command = entry["command"].as_str().unwrap();
        assert!(
            commands
                .iter()
                .any(|(name, status)| name == command && status == "implemented"),
            "{entry}"
        );
        assert!(
            keys.insert((command, entry["mode"].as_str(), entry["component"].as_str())),
            "duplicate {entry}"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_reports_every_unqualified_boundary_as_unavailable() {
    let platform = &registry()["platform"];
    // Owned subprocesses (sr-winpar.9), private storage (sr-winpar.3), the
    // enforced allowance (sr-winpar.5) and owner-only files (sr-winpar.6) run
    // on Windows.
    for boundary in platform["boundaries"].as_array().unwrap() {
        let ported = [
            "owned-subprocess",
            "private-storage",
            "enforced-allowance",
            "owner-only-files",
        ]
        .contains(&boundary["name"].as_str().unwrap());
        assert_eq!(boundary["available"], ported, "{boundary}");
        assert_eq!(boundary["reason"].is_string(), !ported, "{boundary}");
    }
    // Ported components: Git dirty_paths (sr-winpar.10); the response cache,
    // its coordinator leases and provider breaker state (sr-winpar.3); the
    // ledger and hook invocation counter (sr-winpar.4); the enforced request
    // allowance (sr-winpar.5); owner-only exports and replay case reads
    // (sr-winpar.6); installer backups (sr-winpar.7); policy files
    // (sr-winpar.23); cass sessions (sr-winpar.11). A component whose
    // boundary exists but which is not ported says so.
    let ported = [
        "git-dirty-paths",
        "response-cache",
        "coordinator-leases",
        "provider-breaker-state",
        "ledger",
        "hook-invocation-counter",
        "request-allowance",
        "owner-only-exports",
        "replay-case-read",
        "installer-backups",
        "policy-files",
        "cass-sessions",
    ];
    for component in platform["components"].as_array().unwrap() {
        let expected = ported.contains(&component["name"].as_str().unwrap());
        assert_eq!(component["available"], expected, "{component}");
    }
    for mode in platform["modes"].as_array().unwrap() {
        let expected = ported.contains(&mode["component"].as_str().unwrap());
        assert_eq!(mode["available"], expected, "{mode}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn linux_and_macos_report_every_boundary_as_available() {
    let platform = &registry()["platform"];
    for boundary in platform["boundaries"].as_array().unwrap() {
        assert_eq!(boundary["available"], true, "{boundary}");
        assert!(boundary["reason"].is_null(), "{boundary}");
    }
    for mode in platform["modes"].as_array().unwrap() {
        assert_eq!(mode["available"], true, "{mode}");
    }
}

/// One invocation that reaches a component's refusal path.
struct Probe {
    args: &'static [&'static str],
    component: &'static str,
    exit: i32,
    kind: &'static str,
    /// Text only the platform refusal prints, when the refusal has its own
    /// message. Its absence is checked where the component is available.
    platform_phrase: Option<&'static str>,
}

const PROBES: &[Probe] = &[
    Probe {
        args: &["ledger", "status", "--json"],
        component: "ledger",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: None,
    },
    Probe {
        args: &["stats", "--json"],
        component: "ledger",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: None,
    },
    Probe {
        args: &[
            "feedback",
            "evt",
            "--skill",
            "a",
            "--verdict",
            "useful",
            "--json",
        ],
        component: "ledger",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: None,
    },
    Probe {
        args: &["snooze", "evt", "--skill", "a", "--for", "1h", "--json"],
        component: "ledger",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: None,
    },
    Probe {
        args: &[
            "budget",
            "--max-attempts",
            "3",
            "--window",
            "1h",
            "--apply",
            "--json",
        ],
        component: "request-allowance",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: Some("not supported on this platform"),
    },
    Probe {
        args: &["roster", "--snapshot", "snapshot.json", "--json"],
        component: "owner-only-exports",
        exit: 9,
        kind: "storage-failure",
        platform_phrase: Some("not qualified on this platform"),
    },
    Probe {
        args: &["replay", "case.json", "--json"],
        component: "replay-case-read",
        exit: 7,
        kind: "malformed-input",
        platform_phrase: Some("cannot be verified as owner-only on this platform"),
    },
    Probe {
        args: &["rank", "--session", "session.jsonl", "--json"],
        component: "cass-sessions",
        exit: 7,
        kind: "unsupported-source-mode",
        platform_phrase: Some("not supported on this platform"),
    },
];

#[test]
fn refusal_paths_agree_with_their_capability_entries() {
    let platform = registry()["platform"].clone();
    let available = |name: &str| {
        platform["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("probe names unknown component {name}"))["available"]
            .as_bool()
            .unwrap()
    };
    // Every component whose absence refuses a command has a probe.
    for component in platform["components"].as_array().unwrap() {
        if component["when_unavailable"] == "refused" {
            let name = component["name"].as_str().unwrap();
            assert!(
                PROBES.iter().any(|p| p.component == name),
                "no probe for {name}"
            );
        }
    }
    for probe in PROBES {
        let root = home();
        std::fs::write(root.join("workspace/case.json"), b"{}").unwrap();
        let output = run(&root, probe.args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let label = probe.args.join(" ");
        if available(probe.component) {
            if let Some(phrase) = probe.platform_phrase {
                assert!(!text.contains(phrase), "{label}: {text}");
            }
        } else {
            assert_eq!(output.status.code(), Some(probe.exit), "{label}: {text}");
            let error: Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|_| panic!("{label}: {text}"));
            assert_eq!(error["error"]["kind"], probe.kind, "{label}: {text}");
            if let Some(phrase) = probe.platform_phrase {
                assert!(text.contains(phrase), "{label}: {text}");
            }
        }
    }
}
