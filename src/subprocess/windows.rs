//! Owned Windows subprocesses: asupersync's `ExactImageCommand` with a
//! kill-on-close Job Object, and blocking pipes serviced by joined workers.
//!
//! `CreateProcessW` receives the explicit `.exe` image (no `PATH` search, no
//! shell), exactly the supplied environment, and three private pipes, and puts
//! the child in a Job Object atomically; descendants stay in that job, since it
//! does not allow breakaway. Windows anonymous pipes have no readiness wait, so
//! one worker thread reads stdout, one reads stderr and one writes stdin. The
//! async loop drains their channel and checks the deadline and cancellation as
//! the Unix loop does.
//!
//! No worker outlives `run`. Every exit, including an early drop of the future,
//! terminates the whole job first. That closes every write end the tree held,
//! so blocked reads return end-of-file and a blocked stdin write fails with a
//! broken pipe; then each worker is joined. If Windows refuses to terminate the
//! job, the workers are not joined (that could wait forever): `run` reports
//! `Cleanup`, and they end with the process.

use super::{ChildOutput, ChildRequest, SubprocessError, check_work};
use crate::runtime::EntryClock;
use asupersync::Cx;
use asupersync::process::{ExactImageChild, ExactImageCommand, ExitStatus, ProcessError};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread::JoinHandle;
use std::time::Duration;

const CHUNK: usize = 8192;

/// Pipe workers alive in this process. Tests use it to prove that no worker
/// outlives `run`.
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub fn live_pipe_workers() -> usize {
    LIVE_WORKERS.load(Ordering::SeqCst)
}

/// Counts one worker from before its thread starts until its closure ends.
struct Live;
impl Live {
    fn new() -> Self {
        LIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

enum Event {
    Data(Stream, Vec<u8>),
    End(Stream),
    /// Bytes written, and whether the pipe closed before all were written.
    InputDone {
        written: usize,
        broken: bool,
    },
    Failed,
}

/// `directory` must name the current directory: `ExactImageCommand` cannot set
/// one, so the child starts where `sr` runs. Callers that need another
/// directory pass it to the program (for example Git's `-C`), never via a shell.
fn same_directory(directory: &Path) -> bool {
    let (Ok(current), Ok(requested)) = (
        std::env::current_dir().and_then(|d| d.canonicalize()),
        directory.canonicalize(),
    ) else {
        return false;
    };
    current == requested
}

/// A drive-letter verbatim path (`\\?\C:\...`, what `canonicalize` returns)
/// rewritten to its drive form; any other prefix is kept as is.
fn image_path(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// The child's complete environment: the caller's allowed scalars, plus
/// `SystemRoot`, without which Winsock and parts of the C runtime cannot
/// start. It names a system directory and carries no routing or credentials.
fn environment(request: &ChildRequest) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env = request.environment.clone();
    if let Some(root) = std::env::var_os("SystemRoot") {
        env.push(("SystemRoot".into(), root));
    }
    env
}

struct Owner {
    child: ExactImageChild,
    workers: Vec<JoinHandle<()>>,
    done: bool,
}

impl Owner {
    fn kill_tree(&mut self) -> Result<(), SubprocessError> {
        match self.child.kill_process_tree() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SubprocessError::Cleanup),
        }
    }

    /// Terminate the tree, join every worker, then reap the direct child.
    fn cleanup(&mut self) -> Result<(), SubprocessError> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.kill_tree()?;
        let mut joined = Ok(());
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                joined = Err(SubprocessError::Cleanup);
            }
        }
        self.child.wait().map_err(|_| SubprocessError::Cleanup)?;
        joined
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn spawn_worker(
    name: &str,
    body: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, SubprocessError> {
    let live = Live::new();
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _live = live;
            body();
        })
        .map_err(|_| SubprocessError::Spawn)
}

fn reader(
    mut pipe: impl Read + Send + 'static,
    stream: Stream,
    cap: usize,
    events: Sender<Event>,
) -> impl FnOnce() + Send + 'static {
    move || {
        let mut buffer = vec![0u8; CHUNK];
        let mut total = 0usize;
        loop {
            // One byte past the cap is enough to prove an overflow.
            let want = CHUNK.min(cap.saturating_sub(total).saturating_add(1));
            match pipe.read(&mut buffer[..want]) {
                Ok(0) => {
                    let _ = events.send(Event::End(stream));
                    return;
                }
                Ok(n) => {
                    total += n;
                    if events
                        .send(Event::Data(stream, buffer[..n].to_vec()))
                        .is_err()
                        || total > cap
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                // Every write end closed: the tree exited or was terminated.
                Err(error) if error.kind() == ErrorKind::BrokenPipe => {
                    let _ = events.send(Event::End(stream));
                    return;
                }
                Err(_) => {
                    let _ = events.send(Event::Failed);
                    return;
                }
            }
        }
    }
}

fn writer(
    mut pipe: impl Write + Send + 'static,
    input: Vec<u8>,
    events: Sender<Event>,
) -> impl FnOnce() + Send + 'static {
    move || {
        let mut written = 0usize;
        let mut broken = false;
        while written < input.len() {
            let end = input.len().min(written + CHUNK);
            match pipe.write(&input[written..end]) {
                Ok(0) => {
                    let _ = events.send(Event::Failed);
                    return;
                }
                Ok(n) => written += n,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if error.kind() == ErrorKind::BrokenPipe => {
                    broken = true;
                    break;
                }
                Err(_) => {
                    let _ = events.send(Event::Failed);
                    return;
                }
            }
        }
        // Closing the write end is the child's end-of-file.
        drop(pipe);
        let _ = events.send(Event::InputDone { written, broken });
    }
}

pub(super) async fn run(
    cx: &Cx,
    clock: &EntryClock,
    request: ChildRequest,
) -> Result<ChildOutput, SubprocessError> {
    let image = image_path(&request.executable.0);
    if !image
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        || !same_directory(&request.directory)
    {
        return Err(SubprocessError::InvalidRequest);
    }
    check_work(cx, clock)?;
    let mut command = ExactImageCommand::new(&image);
    command.args(&request.args).envs(environment(&request));
    let child = command.spawn().map_err(|error| match error {
        ProcessError::InvalidConfiguration(_) => SubprocessError::InvalidRequest,
        _ => SubprocessError::Spawn,
    })?;
    let mut owner = Owner {
        child,
        workers: Vec::new(),
        done: false,
    };
    let (events, inbox) = channel();
    let started = start_workers(&mut owner, &request, &events);
    drop(events);
    let mut input = None;
    let result = match started {
        Ok(()) => drive(cx, clock, &mut owner, &inbox, &request, &mut input).await,
        Err(error) => Err(error),
    };
    owner.cleanup()?;
    let (status, stdout, stderr) = result?;
    // The writer has been joined, so a report it sent late is in the channel.
    while let Ok(event) = inbox.try_recv() {
        if let Event::InputDone { written, broken } = event {
            input = Some((written, broken));
        }
    }
    let stdin_closed_early = match input {
        Some((written, broken)) => broken || written < request.stdin.len(),
        None => !request.stdin.is_empty(),
    };
    check_work(cx, clock)?;
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
        stdin_closed_early,
    })
}

fn start_workers(
    owner: &mut Owner,
    request: &ChildRequest,
    events: &Sender<Event>,
) -> Result<(), SubprocessError> {
    let stdout = owner.child.take_stdout().ok_or(SubprocessError::Io)?;
    let stderr = owner.child.take_stderr().ok_or(SubprocessError::Io)?;
    let stdin = owner.child.take_stdin().ok_or(SubprocessError::Io)?;
    owner.workers.push(spawn_worker(
        "sr-subprocess-stdout",
        reader(stdout, Stream::Stdout, request.stdout_limit, events.clone()),
    )?);
    owner.workers.push(spawn_worker(
        "sr-subprocess-stderr",
        reader(stderr, Stream::Stderr, request.stderr_limit, events.clone()),
    )?);
    owner.workers.push(spawn_worker(
        "sr-subprocess-stdin",
        writer(stdin, request.stdin.clone(), events.clone()),
    )?);
    Ok(())
}

async fn drive(
    cx: &Cx,
    clock: &EntryClock,
    owner: &mut Owner,
    inbox: &Receiver<Event>,
    request: &ChildRequest,
    input: &mut Option<(usize, bool)>,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), SubprocessError> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_open, mut err_open) = (true, true);
    let mut status = None;
    loop {
        check_work(cx, clock)?;
        let mut moved = false;
        loop {
            match inbox.try_recv() {
                Ok(Event::Data(stream, bytes)) => {
                    let (buffer, cap) = match stream {
                        Stream::Stdout => (&mut out, request.stdout_limit),
                        Stream::Stderr => (&mut err, request.stderr_limit),
                    };
                    if bytes.len() > cap.saturating_sub(buffer.len()) {
                        return Err(SubprocessError::OutputLimit);
                    }
                    buffer.extend_from_slice(&bytes);
                    moved = true;
                }
                Ok(Event::End(Stream::Stdout)) => out_open = false,
                Ok(Event::End(Stream::Stderr)) => err_open = false,
                Ok(Event::InputDone { written, broken }) => *input = Some((written, broken)),
                Ok(Event::Failed) => return Err(SubprocessError::Io),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        if status.is_none() {
            match owner.child.try_wait() {
                Ok(Some(exit)) => {
                    status = Some(exit);
                    // Descendants may still hold the pipes; end them now, as the
                    // Unix path kills the process group once the parent exits.
                    owner.kill_tree()?;
                }
                Ok(None) => {}
                Err(_) => return Err(SubprocessError::Io),
            }
        }
        if let Some(exit) = status
            && !out_open
            && !err_open
        {
            return Ok((exit, out, err));
        }
        if moved {
            asupersync::runtime::yield_now().await;
        } else {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cleanup` returns only after every worker has ended: a worker still
    /// running when the job dies is joined, not left to finish on its own.
    #[test]
    fn cleanup_joins_a_worker_that_outlasts_the_tree() {
        let system32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let mut command = ExactImageCommand::new(system32.join("cmd.exe"));
        command.args(["/c", "exit", "0"]);
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        let mut owner = Owner {
            child: command.spawn().unwrap(),
            workers: Vec::new(),
            done: false,
        };
        let before = live_pipe_workers();
        owner.workers.push(
            spawn_worker("sr-subprocess-test", || {
                std::thread::sleep(Duration::from_millis(300));
            })
            .unwrap(),
        );
        assert_eq!(live_pipe_workers(), before + 1);
        owner.cleanup().unwrap();
        assert_eq!(
            live_pipe_workers(),
            before,
            "cleanup returned before its worker ended"
        );
    }
}
