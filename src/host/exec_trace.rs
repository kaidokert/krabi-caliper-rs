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
//! `one-insn-per-tb` needs QEMU 8.1 or later, and the log format belongs to QEMU, so record the
//! QEMU version with the counts.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::format;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::String;
use std::vec;
use std::vec::Vec;

/// A failure to capture or read an execution trace.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecTraceError {
    #[non_exhaustive]
    Io { path: PathBuf, source: io::Error },
    /// Every attempt failed to run, exited unsuccessfully, or wrote no trace.
    #[non_exhaustive]
    Capture { attempts: u32, last: String },
    /// The trace ended inside a begin marker or an interval, before the end marker.
    IncompleteInterval,
}

impl fmt::Display for ExecTraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Capture { attempts, last } => write!(
                formatter,
                "QEMU execution trace failed after {attempts} attempt(s): {last}"
            ),
            Self::IncompleteInterval => {
                formatter.write_str("trace ended before the end marker of an interval")
            }
        }
    }
}

impl std::error::Error for ExecTraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
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
/// successfully and the trace file exists. Each attempt first removes a stale trace. There is
/// no timeout, so the image must exit (for example through semihosting).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct QemuExecTrace {
    pub executable: OsString,
    pub args: Vec<OsString>,
    pub current_dir: Option<PathBuf>,
    /// Runs before giving up; at least 1.
    pub attempts: u32,
}

impl QemuExecTrace {
    /// One attempt of `executable args...`.
    pub fn new<I, S>(executable: impl Into<OsString>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            executable: executable.into(),
            args: args.into_iter().map(Into::into).collect(),
            current_dir: None,
            attempts: 1,
        }
    }

    /// Retries a failed run up to `attempts` runs in all.
    pub fn attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    /// Runs QEMU in `directory`.
    pub fn current_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(directory.into());
        self
    }

    /// The command for one attempt.
    pub fn command(&self, trace: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        command.args(&self.args).args(exec_trace_args(trace));
        if let Some(directory) = &self.current_dir {
            command.current_dir(directory);
        }
        command
    }

    /// Runs QEMU, retrying failed runs, until `trace` is written. Returns the number of
    /// attempts used.
    pub fn capture(&self, trace: &Path) -> Result<u32, ExecTraceError> {
        let attempts = self.attempts.max(1);
        let mut last = String::new();
        for attempt in 1..=attempts {
            if trace.exists() {
                fs::remove_file(trace).map_err(|source| ExecTraceError::Io {
                    path: trace.to_path_buf(),
                    source,
                })?;
            }
            match self.command(trace).output() {
                Ok(output) if output.status.success() && trace.is_file() => return Ok(attempt),
                Ok(output) => {
                    last = format!(
                        "attempt {attempt}/{attempts}, {}: {}{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(error) => {
                    last = format!("attempt {attempt}/{attempts}: {error}");
                }
            }
        }
        Err(ExecTraceError::Capture { attempts, last })
    }
}

/// The program counter of one `-d exec` log line, from the second `/`-separated field of the
/// first `[...]` group (`Trace 0: 0x7f... [00000000/00000136/00000000/ff200000] symbol`).
pub fn parse_exec_trace_line(line: &str) -> Option<u64> {
    let open = line.find('[')?;
    let close = line[open + 1..].find(']')? + open + 1;
    let bracket = &line[open + 1..close];
    let field = bracket.split('/').nth(1)?;
    u64::from_str_radix(field.trim().trim_start_matches("0x"), 16).ok()
}

/// Streams the program counters of an execution trace, Thumb bit cleared, skipping lines that
/// are not `Trace` lines. The file is read line by line, so traces of any size are fine.
pub struct ExecTracePcs<R> {
    lines: io::Lines<R>,
    path: PathBuf,
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
            lines: reader.lines(),
            path: path.into(),
        }
    }
}

impl<R: BufRead> Iterator for ExecTracePcs<R> {
    type Item = Result<u64, ExecTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref() {
            match line {
                Ok(line) => {
                    if let Some(pc) = parse_exec_trace_line(&line) {
                        return Some(Ok(pc & !1));
                    }
                }
                Err(source) => {
                    return Some(Err(ExecTraceError::Io {
                        path: self.path.clone(),
                        source,
                    }));
                }
            }
        }
        None
    }
}

/// Where an interval starts or stops: a whole function's address range, or one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceMarker {
    Range(Range<u64>),
    Address(u64),
}

impl TraceMarker {
    /// A function's range from its start address and size.
    pub fn function(address: u64, size: u64) -> Self {
        Self::Range(address..address.saturating_add(size))
    }

    pub fn contains(&self, pc: u64) -> bool {
        match self {
            Self::Range(range) => range.contains(&pc),
            Self::Address(address) => pc == *address,
        }
    }
}

/// The instructions executed between markers, in order of execution.
///
/// An interval opens when a PC hits `begin`; PCs that stay in `begin` are skipped (so a begin
/// function's own body is not counted), and the interval holds every following PC up to, not
/// including, the first PC in `end`. Then the next interval may open. A `begin` hit inside an
/// open interval does not restart it. Reading stops after `limit` intervals, so
/// `Some(1)` reads only as far as the first one. A trace that ends inside an interval is an
/// error; one that never hits `begin` gives no intervals.
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
        State::Outside => Ok(intervals),
        State::InBegin | State::Inside(_) => Err(ExecTraceError::IncompleteInterval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcs(values: &[u64]) -> Vec<Result<u64, ExecTraceError>> {
        values.iter().copied().map(Ok).collect()
    }

    #[test]
    fn parses_trace_lines_and_skips_others() {
        let log = "\
Trace 0: 0x7f0000000100 [00000000/00000136/00000000/ff200000] main
----------------
IN: main
Trace 0: 0x7f0000000140 [00000000/00000139/00000000/ff200000] main
Linking TBs 0x0 [00000136] index 0 -> 0x0 [00000138]
";
        let read = ExecTracePcs::new(log.as_bytes(), "log")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        // The Thumb bit is cleared. The `Linking` line has one bracket field, so no PC.
        assert_eq!(read, [0x136, 0x138]);
        assert_eq!(parse_exec_trace_line("no brackets"), None);
        assert_eq!(parse_exec_trace_line("[zz/qq/00]"), None);
    }

    #[test]
    fn function_markers_skip_the_begin_body_and_exclude_the_end() {
        let begin = TraceMarker::function(0x100, 8);
        let end = TraceMarker::function(0x200, 8);
        let trace = pcs(&[
            0x50, 0x100, 0x102, 0x104, 0x300, 0x302, 0x100, 0x304, 0x200, 0x202, 0x400,
        ]);
        let intervals = marker_intervals(trace, &begin, &end, None).unwrap();
        // A begin hit inside an open interval does not restart it.
        assert_eq!(intervals, [vec![0x300, 0x302, 0x100, 0x304]]);
    }

    #[test]
    fn address_markers_repeat_and_limits_stop_early() {
        let begin = TraceMarker::Address(0x100);
        let end = TraceMarker::Address(0x200);
        let trace = || {
            pcs(&[
                0x100, 0x102, 0x10, 0x200, 0x20, 0x100, 0x200, 0x100, 0x30, 0x31, 0x200, 0x100,
            ])
        };
        assert!(matches!(
            marker_intervals(trace(), &begin, &end, None),
            Err(ExecTraceError::IncompleteInterval)
        ));
        let intervals = marker_intervals(trace(), &begin, &end, Some(3)).unwrap();
        // With an address marker, the rest of the begin function is counted.
        assert_eq!(intervals, [vec![0x102, 0x10], vec![], vec![0x30, 0x31]]);
        assert_eq!(
            marker_intervals(trace(), &begin, &end, Some(1)).unwrap(),
            [vec![0x102, 0x10]]
        );
        assert!(
            marker_intervals(trace(), &begin, &end, Some(0))
                .unwrap()
                .is_empty()
        );
        assert!(
            marker_intervals(pcs(&[1, 2, 3]), &begin, &end, None)
                .unwrap()
                .is_empty()
        );
        // Errors from the source propagate.
        let failing = vec![
            Ok(0x100),
            Err(ExecTraceError::IncompleteInterval),
            Ok(0x200),
        ];
        assert!(marker_intervals(failing, &begin, &end, None).is_err());
    }

    #[test]
    fn trace_arguments_and_commands() {
        let run = QemuExecTrace::new(
            "qemu-system-arm",
            ["-machine", "lm3s6965evb", "-kernel", "app"],
        )
        .attempts(0)
        .current_dir("work");
        assert_eq!(run.attempts, 1);
        let command = run.command(Path::new("trace.log"));
        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "-machine",
                "lm3s6965evb",
                "-kernel",
                "app",
                "-accel",
                "tcg,one-insn-per-tb=on",
                "-d",
                "exec,nochain",
                "-D",
                "trace.log"
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("work")));
    }

    #[test]
    fn capture_reports_every_failed_attempt() {
        let trace = std::env::temp_dir().join(format!(
            "krabi-caliper-exec-trace-{}.log",
            std::process::id()
        ));
        let error = QemuExecTrace::new("krabi-caliper-no-such-qemu", ["-kernel", "app"])
            .attempts(2)
            .capture(&trace)
            .unwrap_err();
        assert!(
            matches!(&error, ExecTraceError::Capture { attempts: 2, last } if last.starts_with("attempt 2/2")),
            "{error}"
        );
        assert!(!trace.exists());
    }
}
