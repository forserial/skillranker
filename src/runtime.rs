//! Process-owned Asupersync runtime, entry deadline, and publication gate.
//!
//! Capture the monotonic entry clock before stdin, configuration, or discovery.
//! Owned work uses an explicit `&Cx` and remaining-time budget. Results that
//! complete in the cleanup reserve or after expiry cannot be published.

use crate::limits::{
    DEFAULT_INVOCATION_DEADLINE_MS, DEFAULT_OUTPUT_CLEANUP_RESERVE_MS, DurationMillis,
    InvocationDeadline, LimitError, MonotonicMillis,
};
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::{Budget, CancelKind, Cx};
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    RuntimeUnavailable,
    Deadline(LimitError),
    LateResultSuppressed,
    Cancelled,
    StdinTimeout,
    StdinIo,
    UnboundedLeaf,
    BlockingPoolUnavailable,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeUnavailable => f.write_str("asupersync runtime could not be constructed"),
            Self::Deadline(err) => write!(f, "{err}"),
            Self::LateResultSuppressed => {
                f.write_str("late result suppressed after cleanup reserve or expiry")
            }
            Self::Cancelled => f.write_str("invocation cancelled"),
            Self::StdinTimeout => f.write_str("stdin read reached the cleanup reserve"),
            Self::StdinIo => f.write_str("stdin read I/O error"),
            Self::UnboundedLeaf => {
                f.write_str("uninterruptible blocking leaf is not admitted on the hook path")
            }
            Self::BlockingPoolUnavailable => f.write_str("blocking pool could not admit the leaf"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<LimitError> for RuntimeError {
    fn from(err: LimitError) -> Self {
        Self::Deadline(err)
    }
}

/// Clock captured at invocation entry (process entry for the CLI), before
/// argument parsing or I/O.
#[derive(Clone, Copy, Debug)]
pub struct EntryClock {
    started: Instant,
    deadline: InvocationDeadline,
    entry_wall_clock_unix_ms: u64,
    invocation_sequence: u64,
}

impl EntryClock {
    pub fn capture() -> Result<Self, RuntimeError> {
        let started = Instant::now();
        let deadline = InvocationDeadline::default_from_start(MonotonicMillis::from_millis(0))?;
        Ok(Self::from_entry(started, deadline))
    }

    pub fn capture_with(
        total: DurationMillis,
        cleanup_reserve: DurationMillis,
    ) -> Result<Self, RuntimeError> {
        let started = Instant::now();
        let deadline =
            InvocationDeadline::new(MonotonicMillis::from_millis(0), total, cleanup_reserve)?;
        Ok(Self::from_entry(started, deadline))
    }

    fn from_entry(started: Instant, deadline: InvocationDeadline) -> Self {
        static NEXT_INVOCATION: AtomicU64 = AtomicU64::new(0);
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Self {
            started,
            deadline,
            entry_wall_clock_unix_ms: wall.saturating_sub(elapsed),
            invocation_sequence: NEXT_INVOCATION.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// One conversion base for all of this invocation's monotonic attempt times.
    pub(crate) const fn entry_wall_clock_unix_ms(self) -> u64 {
        self.entry_wall_clock_unix_ms
    }

    /// Local row discriminator, not a credential. Separate entry clocks in one
    /// process need distinct marks; copies and deadline projections retain it.
    pub(crate) fn invocation_row_mark(self) -> String {
        format!(
            "{:x}-{}-{:x}",
            self.entry_wall_clock_unix_ms,
            std::process::id(),
            self.invocation_sequence,
        )
    }

    /// The same entry instant with another total deadline, for a deadline
    /// chosen by configuration read after entry. Expiry is still measured from
    /// process entry, and the cleanup reserve is unchanged.
    pub fn with_total(self, total: DurationMillis) -> Result<Self, RuntimeError> {
        let deadline = InvocationDeadline::new(
            MonotonicMillis::from_millis(0),
            total,
            self.deadline.cleanup_reserve(),
        )?;
        Ok(Self { deadline, ..self })
    }

    /// The same deadline with half of the cleanup reserve returned to work, for recording
    /// that this invocation failed.
    ///
    /// A run that fails at its work deadline has nothing left to record the failure with, so
    /// every timeout used to vanish from the ledger, and timeouts are exactly the operational
    /// failures an availability measure has to count (sr-73b6). Finalizing one typed
    /// `unavailable` row is cleanup, not new work: it publishes no result, and the other half
    /// of the reserve stays for output and runtime shutdown. Nothing else may use this clock.
    pub fn for_failure_finalization(self) -> Self {
        let reserve = self.deadline.cleanup_reserve().as_millis();
        let deadline = DurationMillis::new(
            "failure_finalization_reserve",
            (reserve / 2).max(1),
            reserve,
        )
        .and_then(|reserve| {
            InvocationDeadline::new(self.deadline.start(), self.deadline.total(), reserve)
        })
        .expect("half of a valid cleanup reserve is a valid cleanup reserve");
        Self { deadline, ..self }
    }

    /// [`Self::for_failure_finalization`] for a run that overran its total
    /// deadline: a window of `grace_ms` from now, never ending more than
    /// `limit_ms` past the original deadline, which callers keep inside the
    /// harness's outer timeout. It admits only a failed run's own ledger row,
    /// so an overrun is recorded as its failure instead of staying
    /// `in-flight` (sr-9fzp); nothing recorded under it is published.
    pub fn for_late_failure_record(self, grace_ms: u64, limit_ms: u64) -> Self {
        let reserve = self.deadline.cleanup_reserve().as_millis();
        let original = self.deadline.total().as_millis();
        let total = self
            .now()
            .as_millis()
            .saturating_add(grace_ms)
            .min(original.saturating_add(limit_ms))
            .max(original);
        let deadline = DurationMillis::new("late_failure_record_total", total, u64::MAX)
            .and_then(|total| {
                let reserve = DurationMillis::new(
                    "failure_finalization_reserve",
                    (reserve / 2).max(1),
                    reserve,
                )?;
                InvocationDeadline::new(self.deadline.start(), total, reserve)
            })
            .unwrap_or(self.deadline);
        Self { deadline, ..self }
    }

    pub fn now(&self) -> MonotonicMillis {
        let elapsed = self.started.elapsed();
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        MonotonicMillis::from_millis(ms)
    }

    pub const fn deadline(self) -> InvocationDeadline {
        self.deadline
    }

    pub fn admit_new_work(&self) -> Result<MonotonicMillis, RuntimeError> {
        let now = self.now();
        self.deadline.ensure_can_start_work(now, "runtime_work")?;
        Ok(now)
    }

    pub fn remaining_before_cleanup(&self) -> DurationMillis {
        self.deadline.remaining_before_cleanup(self.now())
    }

    pub fn remaining_until_expiry(&self) -> DurationMillis {
        self.deadline.remaining_until_expiry(self.now())
    }

    pub fn work_budget(&self) -> Result<Budget, RuntimeError> {
        let now = self.admit_new_work()?;
        let remaining = self.deadline.remaining_before_cleanup(now);
        Ok(budget_until(remaining))
    }

    pub fn cleanup_budget(&self) -> Budget {
        let now = self.now();
        let remaining = self.deadline.remaining_until_expiry(now);
        if remaining.as_millis() == 0 {
            Budget::MINIMAL
        } else {
            budget_until(remaining)
        }
    }
}

fn budget_until(remaining: DurationMillis) -> Budget {
    // Asupersync's native timers share a process epoch, not EntryClock's
    // invocation epoch. Convert the remaining duration using the timer clock.
    Budget::new().with_timeout(
        asupersync::time::wall_now(),
        Duration::from_millis(remaining.as_millis()),
    )
}

/// Decide whether a completed result may be emitted.
///
/// New work stops at the cleanup reserve. A result whose completion timestamp
/// is already in that reserve, or after expiry, is suppressed even if emission
/// is still in progress.
pub fn admit_publication(
    deadline: InvocationDeadline,
    completed_at: MonotonicMillis,
    now: MonotonicMillis,
) -> Result<(), RuntimeError> {
    if now >= deadline.expires_at() || completed_at >= deadline.latest_work_time() {
        return Err(RuntimeError::LateResultSuppressed);
    }
    Ok(())
}

/// One invocation: entry clock plus an owned current-thread runtime.
pub struct ProcessInvocation {
    clock: EntryClock,
    runtime: Runtime,
}

impl ProcessInvocation {
    /// Build the runtime after the entry clock is already running.
    pub fn enter() -> Result<Self, RuntimeError> {
        let clock = EntryClock::capture()?;
        Self::from_clock(clock)
    }

    pub fn from_clock(clock: EntryClock) -> Result<Self, RuntimeError> {
        // An invocation need not submit a blocking leaf. Keep the pool
        // available, but let Asupersync start its first worker on submission
        // instead of spending the entry budget starting an idle thread.
        Self::from_clock_with_blocking_pool(clock, 0, 4)
    }

    pub fn from_clock_with_blocking_pool(
        clock: EntryClock,
        min_threads: usize,
        max_threads: usize,
    ) -> Result<Self, RuntimeError> {
        // Runtime allocation and eager worker startup are work too. In
        // particular, never spend the cleanup reserve constructing a runtime
        // that cannot admit even its first request.
        clock.admit_new_work()?;
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(min_threads, max_threads.max(1))
            .build()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(Self { clock, runtime })
    }

    pub const fn clock(&self) -> EntryClock {
        self.clock
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn request_cx(&self) -> Result<Cx, RuntimeError> {
        Ok(self
            .runtime
            .request_cx_with_budget(self.clock.work_budget()?))
    }

    pub fn request_cleanup_cx(&self) -> Cx {
        self.runtime
            .request_cx_with_budget(self.clock.cleanup_budget())
    }

    pub fn cancel_user(&self, cx: &Cx) {
        cx.cancel_with(CancelKind::User, Some("process cancellation"));
    }

    /// Drive `work` on the invocation's runtime, routing SIGTERM and SIGINT to
    /// user cancellation of `cx`, so the work drains and finalizes on its own
    /// cancellation paths instead of dying mid-flight. Claude's hook timeout
    /// sends SIGTERM and kills only about 1.2 s later; a signalled turn is then
    /// recorded, not left in flight (sr-c4v6). The signal streams are polled
    /// beside the work, never spawned, so nothing outlives the invocation.
    /// Where a signal stream is unavailable, the work simply runs.
    pub fn block_on_cancellable<F: std::future::Future>(&self, cx: &Cx, work: F) -> F::Output {
        use asupersync::signal::{SignalKind, signal};
        use std::future::Future;
        use std::task::Poll;
        self.runtime.block_on(async {
            let mut signals: Vec<_> = [SignalKind::terminate(), SignalKind::interrupt()]
                .into_iter()
                .filter_map(|kind| signal(kind).ok())
                .collect();
            let mut work = std::pin::pin!(work);
            let mut cancelled = false;
            std::future::poll_fn(|task| {
                if let Poll::Ready(output) = work.as_mut().poll(task) {
                    return Poll::Ready(output);
                }
                if !cancelled {
                    // `recv` is cancel-safe and the delivery count lives on
                    // the stream, so a fresh receive per poll misses nothing.
                    let signalled = signals
                        .iter_mut()
                        .any(|stream| std::pin::pin!(stream.recv()).poll(task).is_ready());
                    if signalled {
                        cancelled = true;
                        self.cancel_user(cx);
                        // Let the work observe the cancellation now.
                        return work.as_mut().poll(task);
                    }
                }
                Poll::Pending
            })
            .await
        })
    }

    pub fn shutdown(self) -> bool {
        let remaining = self.clock.remaining_until_expiry();
        let bound = Duration::from_millis(remaining.as_millis().max(1));
        self.drain_and_shutdown(bound)
    }

    fn drain_and_shutdown(self, bound: Duration) -> bool {
        let started = Instant::now();
        // Thread teardown alone aborts pending tasks without running their
        // cancellation cleanup. Request cancellation and drive the owned root
        // region first; both phases share this single remaining-time bound.
        let drained = self.runtime.drain_root_region(bound) == RootDrainOutcome::Quiescent;
        let stopped = self
            .runtime
            .shutdown_timeout(bound.saturating_sub(started.elapsed()));
        drained && stopped
    }

    /// Shut the owned runtime down within an explicit wall-clock bound rather
    /// than the invocation's remaining budget. Production paths use
    /// `shutdown()`, which keeps the process-entry deadline semantics; this
    /// variant exists for test harnesses that need a fresh, bounded drain
    /// window after a scenario deliberately consumed nearly all of its own
    /// budget — a shared CI worker cannot guarantee scheduler time inside a
    /// remainder measured in tens of milliseconds. A genuinely wedged runtime
    /// still fails: it will not drain within any honest bound.
    pub fn shutdown_within(self, bound: Duration) -> bool {
        self.drain_and_shutdown(bound.max(Duration::from_millis(1)))
    }
}

/// Pure bounded decoder from a generic synchronous reader bounded by the clock's
/// work deadline and `max_bytes`.
///
/// Validates admission before and after reading, ensures completion time before
/// returning `Ok(())`, and validates EOF when exactly `max_bytes` have been read.
pub fn decode_bounded<R: Read>(
    clock: &EntryClock,
    reader: &mut R,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    clock
        .admit_new_work()
        .map_err(|_| RuntimeError::StdinTimeout)?;
    buf.clear();

    if max_bytes == 0 {
        let mut probe = [0u8; 1];
        loop {
            clock
                .admit_new_work()
                .map_err(|_| RuntimeError::StdinTimeout)?;
            match reader.read(&mut probe) {
                Ok(0) => {
                    clock
                        .admit_new_work()
                        .map_err(|_| RuntimeError::StdinTimeout)?;
                    return Ok(());
                }
                Ok(_) => {
                    return Err(LimitError::AboveLimit {
                        name: "hook_stdin",
                        observed: 1,
                        limit: 0,
                        unit: crate::limits::LimitUnit::Bytes,
                    }
                    .into());
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    return Err(RuntimeError::StdinTimeout);
                }
                Err(_) => return Err(RuntimeError::StdinIo),
            }
        }
    }

    let mut chunk = [0_u8; 8 * 1024];
    loop {
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;

        if buf.len() == max_bytes {
            let mut probe = [0u8; 1];
            loop {
                clock
                    .admit_new_work()
                    .map_err(|_| RuntimeError::StdinTimeout)?;
                match reader.read(&mut probe) {
                    Ok(0) => {
                        clock
                            .admit_new_work()
                            .map_err(|_| RuntimeError::StdinTimeout)?;
                        return Ok(());
                    }
                    Ok(n) => {
                        return Err(LimitError::AboveLimit {
                            name: "hook_stdin",
                            observed: (max_bytes + n) as u128,
                            limit: max_bytes as u128,
                            unit: crate::limits::LimitUnit::Bytes,
                        }
                        .into());
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                        return Err(RuntimeError::StdinTimeout);
                    }
                    Err(_) => return Err(RuntimeError::StdinIo),
                }
            }
        }

        let want = chunk.len().min(max_bytes.saturating_sub(buf.len()));
        match reader.read(&mut chunk[..want]) {
            Ok(0) => {
                clock
                    .admit_new_work()
                    .map_err(|_| RuntimeError::StdinTimeout)?;
                return Ok(());
            }
            Ok(n) => {
                clock
                    .admit_new_work()
                    .map_err(|_| RuntimeError::StdinTimeout)?;
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                return Err(RuntimeError::StdinTimeout);
            }
            Err(_) => return Err(RuntimeError::StdinIo),
        }
    }
}

/// Bound a stdin read by the remaining work window. Partial reads that stop
/// because the cleanup reserve arrived are reported as timeout, not as a
/// complete document.
pub fn read_stdin_before_cleanup<R: Read>(
    clock: &EntryClock,
    reader: &mut R,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    decode_bounded(clock, reader, max_bytes, buf)
}

/// Read from an owned or borrowed Unix file descriptor (like stdin or a pipe),
/// polling for readability bounded by the remaining work deadline before each read
/// so that waits can be interrupted and never exceed the cleanup reserve.
#[cfg(unix)]
pub fn read_fd_before_cleanup<F: std::os::fd::AsFd>(
    clock: &EntryClock,
    fd: F,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::unistd::read;

    clock
        .admit_new_work()
        .map_err(|_| RuntimeError::StdinTimeout)?;
    buf.clear();

    let raw_fd = fd.as_fd();

    let poll_readable = |clock: &EntryClock| -> Result<(), RuntimeError> {
        loop {
            clock
                .admit_new_work()
                .map_err(|_| RuntimeError::StdinTimeout)?;
            let remaining_ms = clock.remaining_before_cleanup().as_millis();
            if remaining_ms == 0 {
                return Err(RuntimeError::StdinTimeout);
            }
            let timeout_ms = u64::min(remaining_ms, i32::MAX as u64) as i32;
            let timeout =
                PollTimeout::try_from(timeout_ms).map_err(|_| RuntimeError::StdinTimeout)?;
            let mut pfd = PollFd::new(
                raw_fd,
                PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
            );
            match poll(std::slice::from_mut(&mut pfd), timeout) {
                Ok(0) => return Err(RuntimeError::StdinTimeout),
                Ok(_) => {
                    clock
                        .admit_new_work()
                        .map_err(|_| RuntimeError::StdinTimeout)?;
                    return Ok(());
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return Err(RuntimeError::StdinIo),
            }
        }
    };

    if max_bytes == 0 {
        poll_readable(clock)?;
        let mut probe = [0u8; 1];
        let n = loop {
            match read(raw_fd, &mut probe) {
                Ok(n) => break n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return Err(RuntimeError::StdinIo),
            }
        };
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;
        if n == 0 {
            return Ok(());
        } else {
            return Err(LimitError::AboveLimit {
                name: "hook_stdin",
                observed: 1,
                limit: 0,
                unit: crate::limits::LimitUnit::Bytes,
            }
            .into());
        }
    }

    let mut chunk = [0_u8; 8 * 1024];
    loop {
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;

        if buf.len() == max_bytes {
            poll_readable(clock)?;
            let mut probe = [0u8; 1];
            let n = loop {
                match read(raw_fd, &mut probe) {
                    Ok(n) => break n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => return Err(RuntimeError::StdinIo),
                }
            };
            clock
                .admit_new_work()
                .map_err(|_| RuntimeError::StdinTimeout)?;
            if n == 0 {
                return Ok(());
            } else {
                return Err(LimitError::AboveLimit {
                    name: "hook_stdin",
                    observed: (max_bytes + n) as u128,
                    limit: max_bytes as u128,
                    unit: crate::limits::LimitUnit::Bytes,
                }
                .into());
            }
        }

        poll_readable(clock)?;
        let want = chunk.len().min(max_bytes.saturating_sub(buf.len()));
        let n = loop {
            match read(raw_fd, &mut chunk[..want]) {
                Ok(n) => break n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return Err(RuntimeError::StdinIo),
            }
        };
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Read from standard input on supported Unix platforms with deadline-bounded polling.
#[cfg(unix)]
pub fn read_stdin_platform_before_cleanup(
    clock: &EntryClock,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    read_fd_before_cleanup(clock, io::stdin(), max_bytes, buf)
}

/// Read standard input where it cannot be polled: Windows pipes have no safe
/// readiness wait, so the blocking read lives on a helper thread.
#[cfg(not(unix))]
pub fn read_stdin_platform_before_cleanup(
    clock: &EntryClock,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    read_on_helper_before_cleanup(clock, io::stdin(), max_bytes, buf)
}

/// How the stdin helper thread ended once its caller returned.
#[cfg(any(not(unix), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelperEnd {
    /// The thread left its read and was joined.
    Joined,
    /// The thread was still blocked when the bound ran out and is detached.
    Detached,
}

/// How long a returning caller waits for the helper to leave its read.
#[cfg(any(not(unix), test))]
const HELPER_STOP_BOUND_MS: u64 = 50;

/// Deadline-bounded read of a reader whose blocking `read` has no readiness
/// wait. The caller waits on a channel, so it never waits past the cleanup
/// reserve. However the caller returns, the helper is then stopped: on Windows
/// its pending read is cancelled (`CancelSynchronousIo`, sr-winpar.15) and the
/// thread joined within a short bound. A reader that ignores cancellation
/// leaves the helper parked in its read, holding only this reader and at most
/// one chunk, until the process exits.
#[cfg(any(not(unix), test))]
fn read_on_helper_before_cleanup<R: Read + Send + 'static>(
    clock: &EntryClock,
    reader: R,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    read_on_helper(clock, reader, max_bytes, buf).0
}

#[cfg(any(not(unix), test))]
fn read_on_helper<R: Read + Send + 'static>(
    clock: &EntryClock,
    mut reader: R,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> (Result<(), RuntimeError>, Option<HelperEnd>) {
    if clock.admit_new_work().is_err() {
        return (Err(RuntimeError::StdinTimeout), None);
    }
    buf.clear();

    // One byte past the bound is enough to report an overflow.
    let readable = max_bytes.saturating_add(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel::<io::Result<Vec<u8>>>(1);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = std::sync::Arc::clone(&stop);
    let spawned = std::thread::Builder::new()
        .name("sr-stdin".to_owned())
        .spawn(move || {
            let mut total = 0_usize;
            while total < readable && !stopped.load(std::sync::atomic::Ordering::SeqCst) {
                let mut chunk = vec![0_u8; (8 * 1024).min(readable - total)];
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        chunk.truncate(n);
                        if sender.send(Ok(chunk)).is_err() {
                            return;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        let _ = sender.send(Err(err));
                        return;
                    }
                }
            }
            // Dropping the sender is the end-of-input signal.
        });
    let Ok(helper) = spawned else {
        return (Err(RuntimeError::StdinIo), None);
    };

    let result = receive_helper_chunks(clock, &receiver, max_bytes, buf);
    // However the read ended, the helper must not outlive it: ask it to stop,
    // let a blocked `send` fail, and cancel a blocked read.
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(receiver);
    let end = stop_helper(helper, clock);
    (result, Some(end))
}

#[cfg(any(not(unix), test))]
fn receive_helper_chunks(
    clock: &EntryClock,
    receiver: &std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    loop {
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;
        let remaining =
            std::time::Duration::from_millis(clock.remaining_before_cleanup().as_millis());
        let chunk = match receiver.recv_timeout(remaining) {
            Ok(Ok(chunk)) => chunk,
            Ok(Err(_)) => return Err(RuntimeError::StdinIo),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(RuntimeError::StdinTimeout);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                clock
                    .admit_new_work()
                    .map_err(|_| RuntimeError::StdinTimeout)?;
                return Ok(());
            }
        };
        clock
            .admit_new_work()
            .map_err(|_| RuntimeError::StdinTimeout)?;
        let observed = buf.len() + chunk.len();
        if observed > max_bytes {
            return Err(LimitError::AboveLimit {
                name: "hook_stdin",
                observed: observed as u128,
                limit: max_bytes as u128,
                unit: crate::limits::LimitUnit::Bytes,
            }
            .into());
        }
        buf.extend_from_slice(&chunk);
    }
}

/// Join the helper once it leaves its read, cancelling a pending read on
/// Windows until it does. Bounded by `HELPER_STOP_BOUND_MS` and by the time
/// left before the invocation expires; past that the helper is detached.
#[cfg(any(not(unix), test))]
fn stop_helper(helper: std::thread::JoinHandle<()>, clock: &EntryClock) -> HelperEnd {
    let bound = std::time::Duration::from_millis(
        HELPER_STOP_BOUND_MS.min(clock.remaining_until_expiry().as_millis()),
    );
    let started = std::time::Instant::now();
    while !helper.is_finished() {
        // A thread not yet in its read reports nothing to cancel; it sees the
        // stop flag next, or is cancelled on a later pass.
        #[cfg(windows)]
        let _ = sr_win_sys::windows::cancel_synchronous_io(&helper);
        if started.elapsed() >= bound {
            return HelperEnd::Detached;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = helper.join();
    HelperEnd::Joined
}

pub const fn default_deadline_ms() -> u64 {
    DEFAULT_INVOCATION_DEADLINE_MS
}

pub const fn default_cleanup_reserve_ms() -> u64 {
    DEFAULT_OUTPUT_CLEANUP_RESERVE_MS
}

#[cfg(test)]
mod helper_read_tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Instant;

    fn read(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        let clock = EntryClock::capture().unwrap();
        let mut buf = vec![0xff];
        read_on_helper_before_cleanup(&clock, Cursor::new(input.to_vec()), max_bytes, &mut buf)?;
        Ok(buf)
    }

    #[test]
    fn reads_complete_input_up_to_the_exact_bound() {
        assert_eq!(read(b"", 8).unwrap(), b"");
        assert_eq!(read(b"", 0).unwrap(), b"");
        assert_eq!(read(b"12345678", 8).unwrap(), b"12345678");
        let large = vec![7_u8; 100 * 1024];
        assert_eq!(read(&large, large.len()).unwrap(), large);
    }

    #[test]
    fn input_past_the_bound_is_an_overflow_not_a_truncated_document() {
        for (input, max_bytes) in [(&b"123456789"[..], 8), (&b"x"[..], 0)] {
            assert!(matches!(
                read(input, max_bytes),
                Err(RuntimeError::Deadline(LimitError::AboveLimit { .. }))
            ));
        }
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }

    #[test]
    fn a_read_failure_is_not_end_of_input() {
        let clock = EntryClock::capture().unwrap();
        let mut buf = Vec::new();
        assert_eq!(
            read_on_helper_before_cleanup(&clock, Failing, 8, &mut buf),
            Err(RuntimeError::StdinIo)
        );
    }

    /// Never returns while its keeper is alive, like stdin from a stalled writer.
    struct Stalled(std::sync::mpsc::Receiver<()>);

    impl Read for Stalled {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn a_stalled_writer_times_out_at_the_cleanup_reserve() {
        let clock = EntryClock::capture().unwrap();
        let (keeper, stalled) = std::sync::mpsc::channel();
        let started = Instant::now();
        let mut buf = Vec::new();
        // A reader that ignores cancellation (this one waits on a channel, not
        // in a system read) is the documented detached case.
        assert_eq!(
            read_on_helper(&clock, Stalled(stalled), 8, &mut buf),
            (Err(RuntimeError::StdinTimeout), Some(HelperEnd::Detached))
        );
        assert!(started.elapsed().as_millis() < u128::from(default_deadline_ms()));
        drop(keeper);
    }

    #[test]
    fn ended_input_and_overflow_join_the_helper() {
        let clock = EntryClock::capture().unwrap();
        let mut buf = Vec::new();
        assert_eq!(
            read_on_helper(&clock, Cursor::new(b"1234".to_vec()), 8, &mut buf),
            (Ok(()), Some(HelperEnd::Joined))
        );
        let large = vec![7_u8; 100 * 1024];
        let (result, end) = read_on_helper(&clock, Cursor::new(large), 8 * 1024, &mut buf);
        assert!(matches!(
            result,
            Err(RuntimeError::Deadline(LimitError::AboveLimit { .. }))
        ));
        assert_eq!(end, Some(HelperEnd::Joined));
        assert_eq!(
            read_on_helper(&clock, Failing, 8, &mut buf),
            (Err(RuntimeError::StdinIo), Some(HelperEnd::Joined))
        );
    }

    /// sr-winpar.15: a real pipe whose writer neither writes more nor closes.
    /// The read is cancelled at the deadline and the helper joined, so no
    /// thread outlives the invocation.
    #[cfg(windows)]
    #[test]
    fn a_stalled_windows_pipe_read_is_cancelled_and_joined() {
        use std::io::Write;
        for prefix in [&b""[..], &b"partial"[..]] {
            let (reader, mut writer) = std::io::pipe().unwrap();
            writer.write_all(prefix).unwrap();
            let clock = EntryClock::capture_with(
                DurationMillis::new("total", 600, 30_000).unwrap(),
                DurationMillis::new("cleanup", 200, 30_000).unwrap(),
            )
            .unwrap();
            let started = Instant::now();
            let mut buf = Vec::new();
            assert_eq!(
                read_on_helper(&clock, reader, 64, &mut buf),
                (Err(RuntimeError::StdinTimeout), Some(HelperEnd::Joined))
            );
            assert!(
                started.elapsed().as_millis() < 600,
                "{:?}",
                started.elapsed()
            );
            // The writer is still open: the helper ended by cancellation.
            writer.write_all(b"late").unwrap_or(());
            drop(writer);
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_pipe_that_closes_is_read_to_its_end() {
        use std::io::Write;
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"{\"ok\":true}").unwrap();
        drop(writer);
        let clock = EntryClock::capture().unwrap();
        let mut buf = Vec::new();
        assert_eq!(
            read_on_helper(&clock, reader, 64, &mut buf),
            (Ok(()), Some(HelperEnd::Joined))
        );
        assert_eq!(buf, b"{\"ok\":true}");
    }
}

#[cfg(test)]
mod owned_drain_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    fn pending_child(
        invocation: &ProcessInvocation,
        cooperate: bool,
    ) -> (asupersync::runtime::TaskHandle<()>, Arc<AtomicBool>) {
        let started = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let child_started = started.clone();
        let child_cleaned = cleaned.clone();
        let cx = invocation.request_cx().unwrap();
        let child = cx
            .spawn(move |child_cx| async move {
                std::future::poll_fn(move |_| {
                    child_started.store(true, Ordering::Release);
                    if cooperate && child_cx.is_cancel_requested() {
                        child_cleaned.store(true, Ordering::Release);
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await
            })
            .unwrap();
        invocation.runtime().block_on(std::future::poll_fn(|task| {
            if started.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                task.waker().wake_by_ref();
                Poll::Pending
            }
        }));
        (child, cleaned)
    }

    #[test]
    fn shutdown_runs_owned_cancellation_cleanup_before_returning_success() {
        let invocation = ProcessInvocation::enter().unwrap();
        let (child, cleaned) = pending_child(&invocation, true);
        assert!(invocation.shutdown());
        assert!(
            cleaned.load(Ordering::Acquire),
            "dropping a pending task is not execution of its cancellation cleanup"
        );
        drop(child);
    }

    #[test]
    fn shutdown_never_reports_undrained_owned_work_as_success() {
        let clock = EntryClock::capture_with(
            DurationMillis::new("test", 1_000, 3_000).unwrap(),
            DurationMillis::new("cleanup", 200, 3_000).unwrap(),
        )
        .unwrap();
        let invocation = ProcessInvocation::from_clock(clock).unwrap();
        let (child, cleaned) = pending_child(&invocation, false);
        assert!(!invocation.shutdown());
        assert!(!cleaned.load(Ordering::Acquire));
        drop(child);
    }
}

#[cfg(test)]
mod late_failure_record_tests {
    use super::*;

    fn clock(total_ms: u64, reserve_ms: u64) -> EntryClock {
        EntryClock::capture_with(
            DurationMillis::new("test", total_ms, 60_000).unwrap(),
            DurationMillis::new("cleanup", reserve_ms, 60_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn clock_projections_preserve_one_invocation_accounting_identity() {
        let entry = EntryClock::capture().unwrap();
        let other = clock(3_000, 200);
        let mark = entry.invocation_row_mark();
        assert_ne!(mark, other.invocation_row_mark());
        for projected in [
            entry,
            entry
                .with_total(DurationMillis::new("test", 6_000, 60_000).unwrap())
                .unwrap(),
            entry.for_failure_finalization(),
            entry.for_late_failure_record(300, 600),
        ] {
            assert_eq!(projected.started, entry.started);
            assert_eq!(projected.invocation_row_mark(), mark);
            assert_eq!(
                projected.entry_wall_clock_unix_ms(),
                entry.entry_wall_clock_unix_ms()
            );
        }
    }

    #[test]
    fn an_overrun_run_gets_a_short_window_from_now() {
        let clock = clock(40, 10);
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(clock.for_failure_finalization().admit_new_work().is_err());
        assert!(
            clock
                .for_late_failure_record(200, 1_000)
                .admit_new_work()
                .is_ok()
        );
    }

    #[test]
    fn the_window_never_ends_past_its_limit() {
        let clock = clock(20, 10);
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Anchored to now it would reach 400 ms, but the limit ends it at
        // 50 ms, already past.
        assert!(
            clock
                .for_late_failure_record(300, 30)
                .admit_new_work()
                .is_err()
        );
    }
}
