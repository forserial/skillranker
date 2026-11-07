//! The interpreter for the loopback provider stubs in tests/fixtures/jev-tls
//! (sr-winpar.24). Include with `#[path = "support/stub_python.rs"] mod stub_python;`.
//!
//! Unix runs `/usr/bin/python3`. Windows asks `python` on `PATH` once for its
//! real interpreter, because that entry may be an install-manager alias that
//! only works with the user's environment; the interpreter itself then runs
//! with an explicit environment like every other child in these tests.

use std::path::PathBuf;
use std::process::Command;

/// A command for the stub interpreter with an empty environment, except what
/// the platform needs to start it: Winsock fails without `SystemRoot`.
pub fn python_command() -> Command {
    let mut command = Command::new(interpreter());
    command.env_clear();
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command
}

#[cfg(not(windows))]
fn interpreter() -> PathBuf {
    PathBuf::from("/usr/bin/python3")
}

#[cfg(windows)]
fn interpreter() -> PathBuf {
    static INTERPRETER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    INTERPRETER
        .get_or_init(|| {
            let output = Command::new("python")
                .args(["-c", "import sys; print(sys.executable)"])
                .output()
                .expect("the provider stub needs `python` on PATH");
            assert!(output.status.success(), "python failed: {output:?}");
            PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
        })
        .clone()
}
