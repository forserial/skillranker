//! Per-platform availability of the boundaries this build cannot establish on
//! every target, and of the components and command modes that depend on them.
//!
//! Each boundary flag is the same `cfg` predicate that selects the refusing
//! implementation. Every refusing or enabled implementation asserts its flag at
//! compile time (`const { assert!(...) }`), so enabling a component on a new
//! platform without updating this table fails to build, and
//! `sr capabilities --json` cannot drift from the code that refuses.
//!
//! A flag reports whether this platform has an implementation at all. An
//! available boundary can still refuse at run time, for example a Linux store
//! on a filesystem outside the admitted set.

/// A platform boundary that some components need.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boundary {
    /// Owner-only private directories for the cache, ledger, coordinator and
    /// breaker stores (`PrivateDirectory`, `PrivateLedgerDirectory`).
    PrivateStorage,
    /// Owner-only single files: exports and reads of captured replay cases.
    OwnerOnlyFiles,
    /// Owned child processes with bounded pipes, deadlines and tree kill.
    OwnedSubprocess,
    /// Durable enforced request-allowance guard and accounting state.
    EnforcedAllowance,
}

/// Owner-only private store directories (`storage::filesystem`, `storage::ledger`,
/// `storage::hook_entries`, `breaker::store`). Windows since sr-winpar.3
/// (`storage::windows_private`); the stores below port separately.
pub const PRIVATE_STORAGE: bool = cfg!(any(unix, windows));
/// Owner-only exports and private case reads (`storage::export`, `replay`).
pub const OWNER_ONLY_FILES: bool = cfg!(unix);
/// `subprocess::run` spawns children.
pub const OWNED_SUBPROCESS: bool = cfg!(any(target_os = "linux", target_os = "macos", windows));
/// `allowance` has its guard and accounting modules.
pub const ENFORCED_ALLOWANCE: bool = cfg!(unix);

/// Components can also wait on their own port after their boundary exists.
/// The ledger and the hook invocation counter beside it (`storage::ledger`,
/// `storage::hook_entries`) run only on Unix; sr-winpar.4.
pub const LEDGER_STORAGE: bool = cfg!(unix);
/// Provider breaker state (`breaker::store`): Unix, and Windows since
/// sr-winpar.3.
pub const BREAKER_STORAGE: bool = cfg!(any(unix, windows));
/// cass sessions (`pipeline::cass_source`) run only on Unix; sr-winpar.11.
pub const CASS_SESSIONS: bool = cfg!(unix);
/// Git `dirty_paths` (`context::signals`): Unix, and Windows since sr-winpar.10.
pub const GIT_SIGNALS: bool = cfg!(any(unix, windows));

impl Boundary {
    pub const ALL: [Self; 4] = [
        Self::PrivateStorage,
        Self::OwnerOnlyFiles,
        Self::OwnedSubprocess,
        Self::EnforcedAllowance,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::PrivateStorage => "private-storage",
            Self::OwnerOnlyFiles => "owner-only-files",
            Self::OwnedSubprocess => "owned-subprocess",
            Self::EnforcedAllowance => "enforced-allowance",
        }
    }

    pub const fn available(self) -> bool {
        match self {
            Self::PrivateStorage => PRIVATE_STORAGE,
            Self::OwnerOnlyFiles => OWNER_ONLY_FILES,
            Self::OwnedSubprocess => OWNED_SUBPROCESS,
            Self::EnforcedAllowance => ENFORCED_ALLOWANCE,
        }
    }

    /// Why the boundary is missing on this platform, or `None` when present.
    pub const fn unavailable_reason(self) -> Option<&'static str> {
        if self.available() {
            return None;
        }
        Some(match self {
            Self::PrivateStorage => {
                "no audited owner-only directory admission or admitted filesystem list on this platform"
            }
            Self::OwnerOnlyFiles => {
                "owner-only file permissions cannot be verified on this platform"
            }
            Self::OwnedSubprocess => "subprocess containment is not supported on this platform",
            Self::EnforcedAllowance => {
                "enforced request allowance state is not supported on this platform"
            }
        })
    }
}

/// What a component or mode does when its boundary is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fallback {
    /// The command or mode fails with its typed error; nothing is written.
    Refused,
    /// The optional effect is skipped; the command continues without it.
    Skipped,
    /// The signal is left out of the context and reported as an omission.
    Omitted,
    /// The command succeeds with an empty report instead of an error.
    EmptyReport,
    /// The file is still written, without owner-only protection. This is a
    /// known gap (sr-winpar.7 for installer backups), not a fail-closed refusal.
    Unprotected,
}

impl Fallback {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Skipped => "skipped",
            Self::Omitted => "omitted",
            Self::EmptyReport => "empty-report",
            Self::Unprotected => "written-unprotected",
        }
    }
}

/// A component that depends on one boundary.
pub struct Component {
    pub name: &'static str,
    pub requires: Boundary,
    /// Whether the component itself is ported to this platform; `true` unless
    /// it waits on its own work after the boundary exists.
    pub implemented: bool,
    pub when_unavailable: Fallback,
}

impl Component {
    pub const fn available(&self) -> bool {
        self.requires.available() && self.implemented
    }

    /// Why the component is unavailable here, or `None` when it is available.
    pub const fn unavailable_reason(&self) -> Option<&'static str> {
        if let Some(reason) = self.requires.unavailable_reason() {
            return Some(reason);
        }
        if self.implemented {
            None
        } else {
            Some("this component is not yet ported to this platform")
        }
    }
}

pub const COMPONENTS: &[Component] = &[
    Component {
        name: "response-cache",
        requires: Boundary::PrivateStorage,
        implemented: true,
        when_unavailable: Fallback::Skipped,
    },
    Component {
        name: "coordinator-leases",
        requires: Boundary::PrivateStorage,
        implemented: true,
        when_unavailable: Fallback::Skipped,
    },
    Component {
        name: "provider-breaker-state",
        requires: Boundary::PrivateStorage,
        implemented: BREAKER_STORAGE,
        when_unavailable: Fallback::Skipped,
    },
    Component {
        name: "ledger",
        requires: Boundary::PrivateStorage,
        implemented: LEDGER_STORAGE,
        when_unavailable: Fallback::Refused,
    },
    Component {
        name: "hook-invocation-counter",
        requires: Boundary::PrivateStorage,
        implemented: LEDGER_STORAGE,
        when_unavailable: Fallback::Skipped,
    },
    Component {
        name: "request-allowance",
        requires: Boundary::EnforcedAllowance,
        implemented: true,
        when_unavailable: Fallback::Refused,
    },
    Component {
        name: "owner-only-exports",
        requires: Boundary::OwnerOnlyFiles,
        implemented: true,
        when_unavailable: Fallback::Refused,
    },
    Component {
        name: "replay-case-read",
        requires: Boundary::OwnerOnlyFiles,
        implemented: true,
        when_unavailable: Fallback::Refused,
    },
    Component {
        name: "installer-backups",
        requires: Boundary::OwnerOnlyFiles,
        implemented: true,
        when_unavailable: Fallback::Unprotected,
    },
    Component {
        name: "policy-files",
        requires: Boundary::OwnerOnlyFiles,
        implemented: true,
        when_unavailable: Fallback::Unprotected,
    },
    Component {
        name: "cass-sessions",
        requires: Boundary::OwnedSubprocess,
        implemented: CASS_SESSIONS,
        when_unavailable: Fallback::Refused,
    },
    Component {
        name: "git-dirty-paths",
        requires: Boundary::OwnedSubprocess,
        implemented: GIT_SIGNALS,
        when_unavailable: Fallback::Omitted,
    },
];

/// A command or mode whose behavior depends on a component.
pub struct Mode {
    pub command: &'static str,
    /// The flag or condition that selects the dependent behavior; `None` for
    /// the whole command.
    pub mode: Option<&'static str>,
    pub component: &'static str,
    pub when_unavailable: Fallback,
}

pub const MODES: &[Mode] = &[
    Mode {
        command: "ledger",
        mode: None,
        component: "ledger",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "stats",
        mode: None,
        component: "ledger",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "observe",
        mode: None,
        component: "ledger",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "feedback",
        mode: None,
        component: "ledger",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "snooze",
        mode: None,
        component: "ledger",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "gaps",
        mode: Some("without --input"),
        component: "ledger",
        when_unavailable: Fallback::EmptyReport,
    },
    Mode {
        command: "tui",
        mode: Some("--dir"),
        component: "ledger",
        when_unavailable: Fallback::Skipped,
    },
    Mode {
        command: "hook",
        mode: Some("shadow ranking and recording"),
        component: "ledger",
        when_unavailable: Fallback::Skipped,
    },
    Mode {
        command: "hook",
        mode: Some("invocation counter"),
        component: "hook-invocation-counter",
        when_unavailable: Fallback::Skipped,
    },
    Mode {
        command: "rank",
        mode: Some("response cache"),
        component: "response-cache",
        when_unavailable: Fallback::Skipped,
    },
    Mode {
        command: "hook",
        mode: Some("response cache"),
        component: "response-cache",
        when_unavailable: Fallback::Skipped,
    },
    Mode {
        command: "budget",
        mode: Some("--apply"),
        component: "request-allowance",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "rank",
        mode: Some("configured request allowance"),
        component: "request-allowance",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "hook",
        mode: Some("configured request allowance"),
        component: "request-allowance",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "roster",
        mode: Some("--snapshot"),
        component: "owner-only-exports",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "rank",
        mode: Some("--save-case"),
        component: "owner-only-exports",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "replay",
        mode: None,
        component: "replay-case-read",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "install-hook",
        mode: Some("--apply"),
        component: "installer-backups",
        when_unavailable: Fallback::Unprotected,
    },
    Mode {
        command: "uninstall-hook",
        mode: Some("--apply"),
        component: "installer-backups",
        when_unavailable: Fallback::Unprotected,
    },
    Mode {
        command: "calibrate",
        mode: Some("--apply"),
        component: "policy-files",
        when_unavailable: Fallback::Unprotected,
    },
    Mode {
        command: "rank",
        mode: Some("--session"),
        component: "cass-sessions",
        when_unavailable: Fallback::Refused,
    },
    Mode {
        command: "rank",
        mode: Some("dirty_paths signal"),
        component: "git-dirty-paths",
        when_unavailable: Fallback::Omitted,
    },
    Mode {
        command: "hook",
        mode: Some("dirty_paths signal"),
        component: "git-dirty-paths",
        when_unavailable: Fallback::Omitted,
    },
];

/// The component named `name`, if listed.
pub fn component(name: &str) -> Option<&'static Component> {
    COMPONENTS.iter().find(|component| component.name == name)
}

/// The operating system family this build targets, as Rust names it.
pub const fn target_os() -> &'static str {
    std::env::consts::OS
}
