#![cfg(windows)]
//! The owned-subprocess boundary on native Windows (sr-winpar.9): exact `.exe`
//! images in a Job Object, blocking pipes on joined workers, exact environment,
//! deadline, cancellation and tree termination. The Windows twin of
//! tests/subprocess_contract.rs, using only programs in System32.

use skillranker::limits::DurationMillis;
use skillranker::runtime::{EntryClock, ProcessInvocation};
use skillranker::subprocess::{
    ChildRequest, MAX_PIPE_BYTES, SubprocessError, TrustedExecutable, live_pipe_workers, run,
};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// One case at a time, so the process-wide worker count belongs to it.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn system32() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join("System32")
}

fn request(program: &str, args: &[&str]) -> ChildRequest {
    let image = system32().join(program);
    ChildRequest {
        executable: TrustedExecutable::resolve(&image, &[system32()]).unwrap(),
        args: args.iter().map(Into::into).collect(),
        directory: std::env::current_dir().unwrap(),
        environment: Vec::new(),
        stdin: Vec::new(),
        stdout_limit: 1024,
        stderr_limit: 1024,
    }
}

fn invocation_with(total_ms: u64) -> ProcessInvocation {
    for _ in 0..16 {
        let invocation = ProcessInvocation::from_clock(
            EntryClock::capture_with(
                DurationMillis::new("total", total_ms, 3000).unwrap(),
                DurationMillis::new("cleanup", 200, 3000).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        if invocation.request_cx().is_ok() {
            return invocation;
        }
        let _ = invocation.shutdown();
    }
    panic!("the host left no work budget after building a runtime; not subprocess evidence");
}

fn execute(
    invocation: &ProcessInvocation,
    request: ChildRequest,
) -> Result<skillranker::subprocess::ChildOutput, SubprocessError> {
    let cx = invocation.request_cx().unwrap();
    let result = invocation
        .runtime()
        .block_on(run(&cx, &invocation.clock(), request));
    assert_eq!(live_pipe_workers(), 0, "a pipe worker outlived run");
    result
}

#[test]
fn output_status_and_exact_lines_are_returned() {
    let _serial = serial();
    let invocation = invocation_with(2800);
    let output = execute(&invocation, request("cmd.exe", &["/c", "echo", "hello"])).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello\r\n");
    assert!(output.stderr.is_empty());
    assert!(!output.stdin_closed_early);
    assert!(invocation.shutdown());
}

#[test]
fn large_input_and_output_move_together_without_deadlock() {
    let _serial = serial();
    let invocation = invocation_with(3000);
    // 512 KiB through findstr, far beyond the default pipe buffer both ways.
    let line = format!("{}\r\n", "x".repeat(126));
    let input = line.repeat(4096).into_bytes();
    let mut child = request("findstr.exe", &["/R", "^"]);
    child.stdin = input.clone();
    child.stdout_limit = MAX_PIPE_BYTES;
    let output = execute(&invocation, child).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout.len(), input.len());
    assert!(output.stdout == input, "the echo differs from the input");
    assert!(!output.stdin_closed_early);
    assert!(invocation.shutdown());
}

#[test]
fn output_over_its_limit_is_refused() {
    let _serial = serial();
    let invocation = invocation_with(2800);
    let mut child = request("findstr.exe", &["/R", "^"]);
    child.stdin = b"0123456789\r\n".repeat(1024);
    child.stdout_limit = 1024;
    assert_eq!(
        execute(&invocation, child).unwrap_err(),
        SubprocessError::OutputLimit
    );
    assert!(invocation.shutdown());
}

#[test]
fn a_running_child_is_killed_at_the_deadline() {
    let _serial = serial();
    let invocation = invocation_with(600);
    let start = Instant::now();
    let result = execute(&invocation, request("ping.exe", &["-n", "30", "127.0.0.1"]));
    assert_eq!(result.unwrap_err(), SubprocessError::DeadlineExceeded);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    assert!(invocation.shutdown_within(Duration::from_secs(1)));
}

#[test]
fn cancellation_terminates_a_child_mid_read() {
    let _serial = serial();
    let invocation = ProcessInvocation::enter().unwrap();
    let cx = invocation.request_cx().unwrap();
    let canceller = cx.clone();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        canceller.set_cancel_requested(true);
    });
    let start = Instant::now();
    let result = invocation.runtime().block_on(run(
        &cx,
        &invocation.clock(),
        request("ping.exe", &["-n", "30", "127.0.0.1"]),
    ));
    cancel.join().unwrap();
    assert_eq!(result.unwrap_err(), SubprocessError::Cancelled);
    assert_eq!(live_pipe_workers(), 0, "a pipe worker outlived run");
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(invocation.shutdown());
}

#[test]
fn a_grandchild_holding_the_pipes_is_terminated_with_the_tree() {
    let _serial = serial();
    let invocation = invocation_with(3000);
    let ping = system32().join("PING.EXE");
    let ping = ping.to_str().unwrap();
    // cmd starts ping without waiting and exits; ping keeps cmd's stdout and
    // stderr. Without the job kill, run would wait 30 s for end-of-file.
    let child = request(
        "cmd.exe",
        &["/c", "start", "/b", ping, "-n", "30", "127.0.0.1"],
    );
    let start = Instant::now();
    let output = execute(&invocation, child).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    assert!(invocation.shutdown());
}

#[test]
fn a_child_that_never_reads_reports_its_input_as_incomplete() {
    let _serial = serial();
    let invocation = invocation_with(3000);
    let mut child = request("cmd.exe", &["/c", "exit", "0"]);
    child.stdin = vec![b'x'; MAX_PIPE_BYTES];
    let output = execute(&invocation, child).unwrap();
    assert!(output.status.success());
    assert!(output.stdin_closed_early);
    assert!(invocation.shutdown());
}

#[test]
fn the_child_sees_exactly_the_supplied_environment() {
    let _serial = serial();
    let invocation = invocation_with(2800);
    let mut child = request("cmd.exe", &["/c", "set"]);
    child.environment = vec![("LANG".into(), "C".into())];
    child.stdout_limit = 64 * 1024;
    let output = execute(&invocation, child).unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    assert!(names.contains(&"LANG"), "{text}");
    assert!(names.contains(&"SYSTEMROOT"), "{text}");
    // Present in this test process, never forwarded.
    for inherited in [
        "PATH",
        "USERPROFILE",
        "TEMP",
        "USERNAME",
        "CARGO_MANIFEST_DIR",
    ] {
        assert!(
            !names.contains(&inherited),
            "{inherited} was inherited: {text}"
        );
    }
    assert!(invocation.shutdown());
}

#[test]
fn scripts_relative_paths_and_other_directories_are_refused_before_spawning() {
    let _serial = serial();
    let dir = std::env::temp_dir().join(format!("sr-subprocess-windows-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("shim.cmd");
    std::fs::write(&script, "@echo shim\r\n").unwrap();

    let invocation = invocation_with(2800);
    let mut shim = request("cmd.exe", &[]);
    shim.executable = TrustedExecutable::resolve(&script, std::slice::from_ref(&dir)).unwrap();
    assert_eq!(
        execute(&invocation, shim).unwrap_err(),
        SubprocessError::InvalidRequest
    );

    assert_eq!(
        TrustedExecutable::resolve(Path::new(r"System32\cmd.exe"), &[system32()]).unwrap_err(),
        SubprocessError::InvalidRequest
    );

    let mut elsewhere = request("cmd.exe", &["/c", "cd"]);
    elsewhere.directory = dir.clone();
    assert_eq!(
        execute(&invocation, elsewhere).unwrap_err(),
        SubprocessError::InvalidRequest
    );
    assert!(invocation.shutdown());
}
