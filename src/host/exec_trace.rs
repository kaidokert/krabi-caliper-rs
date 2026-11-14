//! Instruction counting from QEMU execution traces.
//!
//! QEMU's TCG can log every translated block it executes (`-d exec`). With one instruction per
//! block (`-accel tcg,one-insn-per-tb=on`) and no block chaining (`nochain`), every executed
//! instruction appears as one `Trace` line, so the log is the exact sequence of program
//! counters. [`QemuExecTrace`] captures such a log, [`ExecTracePcs`] streams its PCs, and
//! [`marker_intervals`] cuts out the instructions executed between two marker functions or
//! addresses.
//!
//! The counts are an instruction-count proxy: QEMU models no pipeline, caches or wait states.
//! `one-insn-per-tb` needs QEMU 8.1 or later, and the log format can change between QEMU
//! versions, so record the QEMU version with the counts.
//!
//! PCs and marker addresses are compared with bit 0 cleared, for Arm Thumb images. The log's
//! CPU index is ignored, so use single-core machines: PCs from several cores would be read as
//! one sequence.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::format;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::string::String;
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use super::backends::{CommandError, CommandRunner, CommandSpec};

/// How much of the last failed attempt's output an error keeps.
const OUTPUT_TAIL_BYTES: usize = 4096;

/// A failure to capture or read an execution trace.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecTraceError {
    /// Reading, removing or opening `path` failed.
    #[non_exhaustive]
    Io { path: PathBuf, source: io::Error },
    /// Every attempt failed to start, timed out, exited unsuccessfully, or wrote no trace.
    /// `last` describes the last attempt with the tail of its output; `source` is set when it
    /// could not be started or waited for.
    #[non_exhaustive]
    Capture {
        attempts: u32,
        last: String,
        source: Option<CommandError>,
    },
    /// A `Trace` line whose PC field could not be read (1-based line number).
    #[non_exhaustive]
    MalformedLine { path: PathBuf, line: u64 },
    /// The trace ended inside a begin marker or an interval, after `completed` complete
    /// intervals.
    #[non_exhaustive]
    IncompleteInterval { completed: usize },
    /// The trace held no complete interval: `begin` was never reached.
    NoInterval,
}

impl fmt::Display for ExecTraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Capture { attempts, last, .. } => write!(
                formatter,
                "QEMU execution trace failed after {attempts} attempt(s): {last}"
            ),
            Self::MalformedLine { path, line } => write!(
                formatter,
                "{}:{line}: Trace line without a readable PC",
                path.display()
            ),
            Self::IncompleteInterval { completed } => write!(
                formatter,
                "trace ended before the end marker of an interval (after {completed} complete)"
            ),
            Self::NoInterval => formatter.write_str("trace never reached the begin marker"),
        }
    }
}

impl std::error::Error for ExecTraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Capture {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

/// The QEMU arguments that make `-D <trace>` an exact per-instruction log.
pub fn exec_trace_args(trace: impl AsRef<OsStr>) -> Vec<OsString> {
    vec![
        "-accel".into(),
        "tcg,one-insn-per-tb=on".into(),
        "-d".into(),
        "exec,nochain".into(),
        "-D".into(),
        trace.as_ref().to_os_string(),
    ]
}

/// A QEMU run that writes an execution trace.
///
/// `args` are the machine arguments, including `-kernel <image>` (for example the arguments of
/// a QEMU runner preset); [`exec_trace_args`] is appended. A run succeeds when QEMU exits
/// successfully within `timeout` and the trace file exists. The image must exit on its own
/// (for example through semihosting); a run that does not is killed at the timeout, which also
/// bounds how large the trace grows.
///
/// Every failure is retried up to `attempts` runs in all, deterministic ones included: retries
/// are for hosts where QEMU occasionally dies under load. Each attempt removes a stale trace
/// first, and a trace left by the last failed attempt is removed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct QemuExecTrace {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// The directory QEMU runs in; a relative trace path is resolved against it.
    pub cwd: Option<PathBuf>,
    /// Runs before giving up; at least 1.
    pub attempts: u32,
    /// Per attempt; 60 seconds by default.
    pub timeout: Duration,
}

impl QemuExecTrace {
    /// One attempt of `program args...` with a 60-second timeout.
    pub fn new<I, S>(program: impl Into<OsString>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            cwd: None,
            attempts: 1,
            timeout: Duration::from_secs(60),
        }
    }

    /// Retries a failed run up to `attempts` runs in all.
    pub fn attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    /// Runs QEMU in `directory`.
    pub fn cwd(mut self, directory: impl Into<PathBuf>) -> Self {
        self.cwd = Some(directory.into());
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Where the trace for `trace` is written: relative paths resolve against
    /// [`QemuExecTrace::cwd`].
    pub fn trace_path(&self, trace: &Path) -> PathBuf {
        match &self.cwd {
            Some(directory) if trace.is_relative() => directory.join(trace),
            _ => trace.to_path_buf(),
        }
    }

    /// The command for one attempt, writing to [`QemuExecTrace::trace_path`].
    pub fn spec(&self, trace: &Path) -> CommandSpec {
        let cwd = self.cwd.clone().unwrap_or_else(|| PathBuf::from("."));
        CommandSpec::new(self.program.clone(), cwd)
            .args(self.args.iter().cloned())
            .args(exec_trace_args(self.trace_path(trace)))
            .timeout(self.timeout)
            .silent(true)
    }

    /// Runs QEMU, retrying failed runs, until the trace is written. Returns the path written
    /// (see [`QemuExecTrace::trace_path`]) and the number of attempts used.
    pub fn capture(&self, trace: &Path) -> Result<(PathBuf, u32), ExecTraceError> {
        let path = self.trace_path(trace);
        let remove_stale = || -> Result<(), ExecTraceError> {
            match fs::remove_file(&path) {
                Err(source) if source.kind() != io::ErrorKind::NotFound => {
                    Err(ExecTraceError::Io {
                        path: path.clone(),
                        source,
                    })
                }
                _ => Ok(()),
            }
        };
        let attempts = self.attempts.max(1);
        let spec = self.spec(trace);
        let mut last = String::new();
        let mut last_source = None;
        for attempt in 1..=attempts {
            remove_stale()?;
            match CommandRunner.run(&spec) {
                Ok(output) if output.success() && path.is_file() => return Ok((path, attempt)),
                Ok(output) => {
                    let outcome = if output.timed_out {
                        format!("timed out after {:?}", self.timeout)
                    } else {
                        match output.status {
                            Some(status) if status.success() => {
                                String::from("exited successfully but wrote no trace")
                            }
                            Some(status) => format!("{status}"),
                            None => String::from("no exit status"),
                        }
                    };
                    last = format!(
                        "attempt {attempt}/{attempts}, {outcome}: {}",
                        tail(&output.combined_lossy())
                    );
                    last_source = None;
                }
                Err(error) => {
                    last = format!("attempt {attempt}/{attempts}: {error}");
                    last_source = Some(error);
                }
            }
        }
        remove_stale()?;
        Err(ExecTraceError::Capture {
            attempts,
            last,
            source: last_source,
        })
    }
}

fn tail(text: &str) -> &str {
    let mut start = text.len().saturating_sub(OUTPUT_TAIL_BYTES);
    while !text.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    text.get(start..).unwrap_or_default()
}

/// The program counter of one `-d exec` `Trace` line, unchanged: the second `/`-separated
/// field of the first `[...]` group (`Trace 0: 0x7f... [00000000/00000136/00000000/ff200000]
/// symbol`). `None` for any other line; `Some(Err(()))` for a `Trace` line without a readable
/// PC.
pub fn parse_exec_trace_line(line: &[u8]) -> Option<Result<u64, ()>> {
    if !line.starts_with(b"Trace") {
        return None;
    }
    Some(trace_line_pc(line).ok_or(()))
}

fn trace_line_pc(line: &[u8]) -> Option<u64> {
    let open = line.iter().position(|byte| *byte == b'[')?;
    let rest = line.get(open.saturating_add(1)..)?;
    let close = rest.iter().position(|byte| *byte == b']')?;
    let field = rest.get(..close)?.split(|byte| *byte == b'/').nth(1)?;
    let field = std::str::from_utf8(field).ok()?.trim();
    let field = field.strip_prefix("0x").unwrap_or(field);
    u64::from_str_radix(field, 16).ok()
}

/// Streams the program counters of an execution trace, bit 0 cleared, from its `Trace` lines.
/// Other lines are skipped, and a `Trace` line without a readable PC is an error. The log is
/// read as bytes, one line at a time, so memory use does not grow with the trace and non-UTF-8
/// guest output does not stop the read.
pub struct ExecTracePcs<R> {
    reader: R,
    path: PathBuf,
    buffer: Vec<u8>,
    line: u64,
    failed: bool,
}

impl ExecTracePcs<BufReader<File>> {
    /// Opens the trace at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExecTraceError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| ExecTraceError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self::new(BufReader::new(file), path))
    }
}

impl<R: BufRead> ExecTracePcs<R> {
    /// Reads from `reader`; `path` names it in errors.
    pub fn new(reader: R, path: impl Into<PathBuf>) -> Self {
        Self {
            reader,
            path: path.into(),
            buffer: Vec::new(),
            line: 0,
            failed: false,
        }
    }
}

impl<R: BufRead> Iterator for ExecTracePcs<R> {
    type Item = Result<u64, ExecTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            self.buffer.clear();
            match self.reader.read_until(b'\n', &mut self.buffer) {
                Ok(0) => return None,
                Ok(_) => {
                    self.line = self.line.saturating_add(1);
                    match parse_exec_trace_line(&self.buffer) {
                        None => {}
                        Some(Ok(pc)) => return Some(Ok(pc & !1)),
                        Some(Err(())) => {
                            self.failed = true;
                            return Some(Err(ExecTraceError::MalformedLine {
                                path: self.path.clone(),
                                line: self.line,
                            }));
                        }
                    }
                }
                Err(source) => {
                    self.failed = true;
                    return Some(Err(ExecTraceError::Io {
                        path: self.path.clone(),
                        source,
                    }));
                }
            }
        }
    }
}

/// Where an interval starts or stops: a whole function's address range, or one address. Bit
/// 0 of the addresses is ignored, so Thumb symbol values can be used as they are.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraceMarker {
    Range(Range<u64>),
    Address(u64),
}

impl TraceMarker {
    /// A function's range from its symbol value and size.
    pub fn function(address: u64, size: u64) -> Self {
        let start = address & !1;
        Self::Range(start..start.saturating_add(size))
    }

    pub fn contains(&self, pc: u64) -> bool {
        match self {
            Self::Range(range) => (range.start & !1..range.end & !1).contains(&pc),
            Self::Address(address) => pc == *address & !1,
        }
    }
}

/// The instructions executed between markers, in order of execution.
///
/// - Outside an interval, a PC in `begin` opens one. PCs that stay in `begin` right after it
///   are skipped, so a begin function's own body is not counted; once a PC leaves `begin`,
///   everything is counted, including later returns into `begin`, callees, and interrupt
///   handlers.
/// - While skipping the begin body, `begin` wins over `end`; inside an interval, the first PC
///   in `end` closes it and is not counted. A `begin` hit inside an interval does not restart
///   it. With `begin == end`, an interval runs from leaving one hit to the next.
/// - Reading stops after `limit` intervals (fewer if the trace has fewer).
///
/// A trace that ends inside an interval, or holds no complete interval, is an error.
pub fn marker_intervals<I>(
    pcs: I,
    begin: &TraceMarker,
    end: &TraceMarker,
    limit: Option<usize>,
) -> Result<Vec<Vec<u64>>, ExecTraceError>
where
    I: IntoIterator<Item = Result<u64, ExecTraceError>>,
{
    enum State {
        Outside,
        InBegin,
        Inside(Vec<u64>),
    }
    let mut intervals = Vec::new();
    if limit == Some(0) {
        return Ok(intervals);
    }
    let mut state = State::Outside;
    for pc in pcs {
        let pc = pc?;
        state = match state {
            State::Outside if begin.contains(pc) => State::InBegin,
            State::Outside => State::Outside,
            State::InBegin if begin.contains(pc) => State::InBegin,
            State::InBegin | State::Inside(_) if end.contains(pc) => {
                let pcs = match state {
                    State::Inside(pcs) => pcs,
                    _ => Vec::new(),
                };
                intervals.push(pcs);
                if limit.is_some_and(|limit| intervals.len() >= limit) {
                    return Ok(intervals);
                }
                State::Outside
            }
            State::InBegin => State::Inside(vec![pc]),
            State::Inside(mut pcs) => {
                pcs.push(pc);
                State::Inside(pcs)
            }
        };
    }
    match state {
        State::Outside if intervals.is_empty() => Err(ExecTraceError::NoInterval),
        State::Outside => Ok(intervals),
        State::InBegin | State::Inside(_) => Err(ExecTraceError::IncompleteInterval {
            completed: intervals.len(),
        }),
    }
}

#[cfg(test)]
mod tests;
