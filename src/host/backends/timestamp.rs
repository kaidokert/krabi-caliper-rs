use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::thread;
use std::time::Instant;

use super::{CommandRunner, CommandSpec};

/// Result of a command whose target-owned boundaries were externally timed.
#[derive(Debug)]
pub struct TimestampedCommandOutput {
    pub status: ExitStatus,
    pub counters_emitted: usize,
}

/// Runs a command and emits a host-monotonic counter after every target
/// `EM_BOUNDARY` line on stdout.
///
/// The original stream is forwarded unchanged. Injected `EM_COUNTER` records
/// use a one-gigahertz timer qualification so their ticks are nanoseconds from
/// wrapper start. The shared command runner owns process-group cleanup.
pub fn run_timestamped_command(
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
    mut stdout_writer: impl Write,
    mut stderr_writer: impl Write + Send + 'static,
) -> io::Result<TimestampedCommandOutput> {
    let spec = CommandSpec::new(program, cwd).args(args.iter());
    let mut child = CommandRunner
        .spawn(&spec, Stdio::piped(), Stdio::piped())
        .map_err(io::Error::other)?;
    let stdout = child
        .inner_mut()
        .stdout
        .take()
        .expect("piped stdout must exist");
    let mut stderr = child
        .inner_mut()
        .stderr
        .take()
        .expect("piped stderr must exist");
    let stderr_thread = thread::spawn(move || io::copy(&mut stderr, &mut stderr_writer));
    let started = Instant::now();
    let counters_emitted =
        timestamp_boundaries(BufReader::new(stdout), &mut stdout_writer, || {
            started.elapsed().as_nanos().min(u64::MAX as u128) as u64
        })?;
    let status = child.wait().map_err(io::Error::other)?;
    stderr_thread
        .join()
        .map_err(|_| io::Error::other("stderr forwarding thread panicked"))??;
    Ok(TimestampedCommandOutput {
        status,
        counters_emitted,
    })
}

fn timestamp_boundaries(
    reader: impl BufRead,
    mut writer: impl Write,
    mut now: impl FnMut() -> u64,
) -> io::Result<usize> {
    let mut counters_emitted = 0;
    for line in reader.lines() {
        let line = line?;
        writeln!(writer, "{line}")?;
        if let Some(boundary) = BoundaryIdentity::parse(&line) {
            writeln!(
                writer,
                "EM_COUNTER schema:1 benchmark:{} trial:{} phase:{} ticks:{} width:64 unit:timer-ticks frequency_hz:1000000000 source:host-monotonic",
                boundary.benchmark,
                boundary.trial,
                boundary.phase,
                now(),
            )?;
            counters_emitted += 1;
            writer.flush()?;
        }
    }
    writer.flush()?;
    Ok(counters_emitted)
}

struct BoundaryIdentity<'a> {
    benchmark: &'a str,
    trial: &'a str,
    phase: &'a str,
}

impl<'a> BoundaryIdentity<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let mut fields = line.split_ascii_whitespace();
        if fields.next()? != "EM_BOUNDARY" {
            return None;
        }
        let mut benchmark = None;
        let mut trial = None;
        let mut phase = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("benchmark:") {
                benchmark = Some(value);
            } else if let Some(value) = field.strip_prefix("trial:") {
                trial = Some(value);
            } else if let Some(value) = field.strip_prefix("phase:") {
                phase = Some(value);
            }
        }
        Some(Self {
            benchmark: benchmark?,
            trial: trial?,
            phase: phase?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn injects_correlated_monotonic_counters_after_boundaries() {
        let input = b"diagnostic\n\
EM_BOUNDARY schema:1 benchmark:portable trial:0 phase:begin\n\
EM_BOUNDARY schema:1 benchmark:portable trial:0 phase:end status:PASS\n\
EM_OUTCOME schema:1 benchmark:portable status:PASS\n";
        let mut output = Vec::new();
        let mut ticks = [100_u64, 145].into_iter();
        let count = timestamp_boundaries(Cursor::new(input), &mut output, || ticks.next().unwrap())
            .unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(count, 2);
        assert!(output.contains(
            "EM_COUNTER schema:1 benchmark:portable trial:0 phase:begin ticks:100 width:64 unit:timer-ticks frequency_hz:1000000000 source:host-monotonic"
        ));
        assert!(output.contains(
            "EM_COUNTER schema:1 benchmark:portable trial:0 phase:end ticks:145 width:64 unit:timer-ticks frequency_hz:1000000000 source:host-monotonic"
        ));
        assert_eq!(output.matches("EM_BOUNDARY").count(), 2);
    }

    #[test]
    fn ignores_incomplete_or_diagnostic_boundary_text() {
        let input = b"prefix EM_BOUNDARY benchmark:x trial:0 phase:begin\n\
EM_BOUNDARY schema:1 benchmark:x trial:0\n";
        let mut output = Vec::new();
        assert_eq!(
            timestamp_boundaries(Cursor::new(input), &mut output, || 1).unwrap(),
            0
        );
    }
}
