use std::eprintln;
use std::ffi::{OsStr, OsString};
use std::format;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::string::String;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::vec::Vec;

use command_group::{CommandGroup, GroupChild};
#[cfg(unix)]
use command_group::{Signal, UnixChildExt};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompletionAction {
    #[default]
    Kill,
    Interrupt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CommandSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
    pub env_remove: Vec<OsString>,
    pub timeout: Duration,
    /// End the command once it has written nothing to stdout or stderr for this long.
    pub idle_timeout: Option<Duration>,
    pub completion_marker: Option<Vec<u8>>,
    pub completion_action: CompletionAction,
    pub silent: bool,
    /// Copy each complete output line to this process's stderr as it arrives, after this prefix.
    pub echo_prefix: Option<String>,
    /// Write stdout to this file as it arrives; created or truncated when the command starts.
    pub stdout_log: Option<PathBuf>,
    /// Write stderr to this file as it arrives; created or truncated when the command starts.
    pub stderr_log: Option<PathBuf>,
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: cwd.into(),
            env: Vec::new(),
            env_remove: Vec::new(),
            timeout: Duration::from_secs(60),
            idle_timeout: None,
            completion_marker: None,
            completion_action: CompletionAction::Kill,
            silent: false,
            echo_prefix: None,
            stdout_log: None,
            stderr_log: None,
        }
    }

    pub fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(value.into());
        self
    }

    pub fn args(mut self, values: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn env_remove(mut self, key: impl Into<OsString>) -> Self {
        self.env_remove.push(key.into());
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub const fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn echo_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.echo_prefix = Some(prefix.into());
        self
    }

    pub fn logs(mut self, stdout: impl Into<PathBuf>, stderr: impl Into<PathBuf>) -> Self {
        self.stdout_log = Some(stdout.into());
        self.stderr_log = Some(stderr.into());
        self
    }

    pub fn completion_marker(mut self, marker: impl Into<Vec<u8>>) -> Self {
        self.completion_marker = Some(marker.into());
        self
    }

    pub const fn completion_action(mut self, action: CompletionAction) -> Self {
        self.completion_action = action;
        self
    }

    /// Suppresses the default command announcement before execution.
    pub const fn silent(mut self, silent: bool) -> Self {
        self.silent = silent;
        self
    }

    pub fn display(&self) -> String {
        let mut command = String::new();
        if !self.env_remove.is_empty() || !self.env.is_empty() {
            command.push_str("env[");
            for (index, key) in self.env_remove.iter().enumerate() {
                if index != 0 {
                    command.push(' ');
                }
                command.push('-');
                command.push_str(&quote(key));
            }
            for (key, value) in &self.env {
                if command.as_bytes().last() != Some(&b'[') {
                    command.push(' ');
                }
                command.push_str(&quote(key));
                command.push('=');
                command.push_str(&quote(value));
            }
            command.push_str("] ");
        }
        command.push_str(&quote(&self.program));
        for argument in &self.args {
            command.push(' ');
            command.push_str(&quote(argument));
        }
        command
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct CommandOutput {
    pub status: Option<ExitStatus>,
    /// The command was ended by its timeout or its idle timeout.
    pub timed_out: bool,
    /// The command was ended by [`CommandSpec::idle_timeout`].
    pub idle_timed_out: bool,
    pub completion_marker_hit: bool,
    pub duration: Duration,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        !self.timed_out
            && (self.completion_marker_hit || self.status.is_some_and(|status| status.success()))
    }

    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn combined_lossy(&self) -> String {
        let mut output = self.stdout_lossy();
        if !output.ends_with('\n') && !output.is_empty() && !self.stderr.is_empty() {
            output.push('\n');
        }
        output.push_str(&self.stderr_lossy());
        output
    }
}

#[derive(Debug)]
pub enum CommandError {
    Spawn {
        command: String,
        source: io::Error,
    },
    Wait {
        command: String,
        source: io::Error,
    },
    Capture {
        stream: &'static str,
        source: io::Error,
    },
    ReaderPanicked {
        stream: &'static str,
    },
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { command, source } => {
                write!(formatter, "failed to spawn {command}: {source}")
            }
            Self::Wait { command, source } => {
                write!(formatter, "failed while waiting for {command}: {source}")
            }
            Self::Capture { stream, source } => {
                write!(formatter, "failed to capture {stream}: {source}")
            }
            Self::ReaderPanicked { stream } => {
                write!(formatter, "{stream} capture thread panicked")
            }
        }
    }
}

impl std::error::Error for CommandError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct CommandRunner;

/// A process-group-owned child used by streaming and interactive backends.
///
/// Dropping it terminates and reaps the complete group, so early-return error
/// paths cannot strand simulator or debug-server descendants.
pub struct ManagedChild {
    display: String,
    child: Option<GroupChild>,
}

impl ManagedChild {
    pub fn display(&self) -> &str {
        &self.display
    }

    pub fn inner_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("managed child must exist")
            .inner()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, CommandError> {
        self.child
            .as_mut()
            .expect("managed child must exist")
            .try_wait()
            .map_err(|source| CommandError::Wait {
                command: self.display.clone(),
                source,
            })
    }

    pub fn wait(&mut self) -> Result<ExitStatus, CommandError> {
        self.child
            .as_mut()
            .expect("managed child must exist")
            .wait()
            .map_err(|source| CommandError::Wait {
                command: self.display.clone(),
                source,
            })
    }

    pub fn terminate(&mut self) -> Result<ExitStatus, CommandError> {
        let child = self.child.as_mut().expect("managed child must exist");
        let _ = child.kill();
        child.wait().map_err(|source| CommandError::Wait {
            command: self.display.clone(),
            source,
        })
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl CommandRunner {
    /// Spawns a managed process group for a streaming or interactive backend.
    pub fn spawn(
        &self,
        spec: &CommandSpec,
        stdout: Stdio,
        stderr: Stdio,
    ) -> Result<ManagedChild, CommandError> {
        let display = spec.display();
        if !spec.silent {
            eprintln!("+ (cd {} && {display})", spec.cwd.display());
        }
        let mut command = configured_command(spec, stdout, stderr);
        let child = command
            .group_spawn()
            .map_err(|source| CommandError::Spawn {
                command: display.clone(),
                source,
            })?;
        Ok(ManagedChild {
            display,
            child: Some(child),
        })
    }

    pub fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, CommandError> {
        let stdout_log = open_log(spec.stdout_log.as_deref(), "stdout")?;
        let stderr_log = open_log(spec.stderr_log.as_deref(), "stderr")?;
        let started = Instant::now();
        let mut child = self.spawn(spec, Stdio::piped(), Stdio::piped())?;
        let display = String::from(child.display());
        let stdout = child
            .inner_mut()
            .stdout
            .take()
            .expect("piped stdout must exist");
        let stderr = child
            .inner_mut()
            .stderr
            .take()
            .expect("piped stderr must exist");
        let stdout_capture = Arc::new(Mutex::new(Vec::new()));
        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
        let last_output = Arc::new(Mutex::new(started));
        let echo = spec.echo_prefix.clone().map(spawn_echo);
        let stdout_thread = spawn_reader(
            stdout,
            Arc::clone(&stdout_capture),
            Observer::new(echo.clone(), stdout_log, &last_output),
        );
        let stderr_thread = spawn_reader(
            stderr,
            Arc::clone(&stderr_capture),
            Observer::new(echo, stderr_log, &last_output),
        );
        let idle = |limit: Duration| last_output.lock().unwrap().elapsed() >= limit;

        let (status, timed_out, mut completion_marker_hit, idle_timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false, false, false),
                Ok(None) if marker_seen(spec, &stdout_capture, &stderr_capture) => {
                    let status = finish_after_marker(
                        child.child.as_mut().expect("managed child must exist"),
                        spec.completion_action,
                        &display,
                    )?;
                    break (Some(status), false, true, false);
                }
                Ok(None) if started.elapsed() >= spec.timeout => {
                    let status = child.terminate()?;
                    break (Some(status), true, false, false);
                }
                Ok(None) if spec.idle_timeout.is_some_and(idle) => {
                    let status = child.terminate()?;
                    break (Some(status), true, false, true);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let _ = child.terminate();
                    return Err(error);
                }
            }
        };
        join_reader(stdout_thread, "stdout")?;
        join_reader(stderr_thread, "stderr")?;
        let stdout = take_capture(stdout_capture);
        let stderr = take_capture(stderr_capture);
        // A short-lived command can exit between the reader observing its
        // final line and the polling thread acquiring the capture lock. Once
        // both pipes are drained, preserve a marker emitted before a normal
        // exit instead of making the result depend on thread scheduling.
        if !timed_out {
            completion_marker_hit |= marker_seen_in_output(spec, &stdout, &stderr);
        }
        Ok(CommandOutput {
            status,
            timed_out,
            idle_timed_out,
            completion_marker_hit,
            duration: started.elapsed(),
            stdout,
            stderr,
        })
    }
}

fn open_log(path: Option<&Path>, stream: &'static str) -> Result<Option<File>, CommandError> {
    path.map(File::create)
        .transpose()
        .map_err(|source| CommandError::Capture { stream, source })
}

/// What a reader thread does with each chunk besides capturing it.
struct Observer {
    echo: Option<SyncSender<Vec<u8>>>,
    pending_line: Vec<u8>,
    log: Option<File>,
    last_output: Arc<Mutex<Instant>>,
}

impl Observer {
    fn new(
        echo: Option<SyncSender<Vec<u8>>>,
        log: Option<File>,
        last_output: &Arc<Mutex<Instant>>,
    ) -> Self {
        Self {
            echo,
            pending_line: Vec::new(),
            log,
            last_output: Arc::clone(last_output),
        }
    }

    fn chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        *self.last_output.lock().unwrap() = Instant::now();
        if let Some(log) = &mut self.log {
            log.write_all(bytes)?;
            log.flush()?;
        }
        if let Some(echo) = &self.echo {
            // Only the new bytes can hold a newline; the pending ones were already searched.
            let mut search = self.pending_line.len();
            self.pending_line.extend_from_slice(bytes);
            let mut line_start = 0;
            while let Some(offset) = self.pending_line[search..]
                .iter()
                .position(|&byte| byte == b'\n')
            {
                let end = search + offset;
                let _ = echo.try_send(self.pending_line[line_start..=end].to_vec());
                line_start = end + 1;
                search = line_start;
            }
            self.pending_line.drain(..line_start);
        }
        Ok(())
    }

    fn finish(&mut self) {
        if let Some(echo) = &self.echo
            && !self.pending_line.is_empty()
        {
            let mut line = core::mem::take(&mut self.pending_line);
            line.push(b'\n');
            let _ = echo.try_send(line);
        }
    }
}

/// Starts the thread that copies echoed lines to stderr after `prefix`, and returns its queue.
///
/// Echo is best effort and must never hold up capture: readers hand lines over without
/// blocking, and a full queue drops them (the log files keep everything). The thread is not
/// joined, so a stderr that stops draining blocks only this thread; it ends once both readers
/// have dropped their senders and the queue is empty.
fn spawn_echo(prefix: String) -> SyncSender<Vec<u8>> {
    let (sender, receiver) = sync_channel::<Vec<u8>>(1024);
    thread::spawn(move || {
        for line in receiver {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(prefix.as_bytes());
            let _ = stderr.write_all(&line);
        }
    });
    sender
}

fn configured_command(spec: &CommandSpec, stdout: Stdio, stderr: Stdio) -> Command {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    for key in &spec.env_remove {
        command.env_remove(key);
    }
    command.envs(spec.env.iter().map(|(key, value)| (key, value)));
    command
}

fn finish_after_marker(
    child: &mut GroupChild,
    action: CompletionAction,
    display: &str,
) -> Result<ExitStatus, CommandError> {
    if action == CompletionAction::Interrupt {
        interrupt(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => break,
                Err(source) => {
                    return Err(CommandError::Wait {
                        command: String::from(display),
                        source,
                    });
                }
            }
        }
    }
    let _ = child.kill();
    child.wait().map_err(|source| CommandError::Wait {
        command: String::from(display),
        source,
    })
}

#[cfg(unix)]
fn interrupt(child: &GroupChild) {
    let _ = child.signal(Signal::SIGINT);
}

#[cfg(not(unix))]
fn interrupt(_child: &GroupChild) {}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
    capture: Arc<Mutex<Vec<u8>>>,
    mut observer: Observer,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        loop {
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                observer.finish();
                return Ok(());
            }
            let bytes = &chunk[..count];
            capture.lock().unwrap().extend_from_slice(bytes);
            observer.chunk(bytes)?;
        }
    })
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<()>>,
    stream: &'static str,
) -> Result<(), CommandError> {
    handle
        .join()
        .map_err(|_| CommandError::ReaderPanicked { stream })?
        .map_err(|source| CommandError::Capture { stream, source })
}

fn marker_seen(spec: &CommandSpec, stdout: &Mutex<Vec<u8>>, stderr: &Mutex<Vec<u8>>) -> bool {
    marker_seen_in_output(spec, &stdout.lock().unwrap(), &stderr.lock().unwrap())
}

fn marker_seen_in_output(spec: &CommandSpec, stdout: &[u8], stderr: &[u8]) -> bool {
    let Some(marker) = spec.completion_marker.as_deref() else {
        return false;
    };
    contains_complete_line(stdout, marker) || contains_complete_line(stderr, marker)
}

fn contains_complete_line(haystack: &[u8], marker: &[u8]) -> bool {
    if marker.is_empty() {
        return false;
    }
    haystack
        .windows(marker.len())
        .position(|value| value == marker)
        .is_some_and(|position| {
            haystack[position + marker.len()..]
                .iter()
                .any(|byte| matches!(byte, b'\n' | b'\r'))
        })
}

fn take_capture(capture: Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    core::mem::take(&mut *capture.lock().unwrap())
}

fn quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=,".contains(&byte))
    {
        value.into_owned()
    } else {
        format!("{value:?}")
    }
}

pub fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn captures_both_output_streams_and_exit_status() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "printf stdout; printf stderr >&2; exit 7"]),
            )
            .unwrap();

        assert_eq!(output.status.and_then(|status| status.code()), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        assert!(!output.timed_out);
        assert!(!output.completion_marker_hit);
    }

    #[test]
    fn display_includes_environment_overrides_and_removals() {
        let display = CommandSpec::new("cargo", ".")
            .env_remove("RUSTUP_TOOLCHAIN")
            .env("RUSTFLAGS", "-C target-cpu=atmega2560")
            .args(["check", "--target", "avr-none"])
            .display();

        assert_eq!(
            display,
            "env[-RUSTUP_TOOLCHAIN RUSTFLAGS=\"-C target-cpu=atmega2560\"] cargo check --target avr-none"
        );
    }

    #[test]
    fn terminates_a_command_at_its_deadline() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "exec sleep 2"])
                    .timeout(Duration::from_millis(25)),
            )
            .unwrap();

        assert!(output.timed_out);
        assert!(!output.success());
        assert!(output.duration < Duration::from_secs(1));
    }

    #[test]
    fn idle_timeout_ends_a_silent_command_and_keeps_its_output_in_the_logs() {
        let dir = std::env::temp_dir().join(format!("krabi-caliper-idle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "echo partial; echo warn >&2; exec sleep 10"])
                    .timeout(Duration::from_secs(20))
                    .idle_timeout(Some(Duration::from_millis(500)))
                    .logs(dir.join("stdout.log"), dir.join("stderr.log")),
            )
            .unwrap();

        assert!(output.idle_timed_out);
        assert!(output.timed_out);
        assert!(output.duration < Duration::from_secs(5));
        assert_eq!(output.stdout, b"partial\n");
        assert_eq!(std::fs::read(dir.join("stdout.log")).unwrap(), b"partial\n");
        assert_eq!(std::fs::read(dir.join("stderr.log")).unwrap(), b"warn\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn echo_splits_output_into_lines_across_chunks() {
        let (sender, receiver) = sync_channel(16);
        let mut observer = Observer::new(Some(sender), None, &Arc::new(Mutex::new(Instant::now())));
        for chunk in [&b"ab"[..], b"c\nde", b"f\n\n", b"g"] {
            observer.chunk(chunk).unwrap();
        }
        observer.finish();
        drop(observer);
        let lines: Vec<Vec<u8>> = receiver.into_iter().collect();
        assert_eq!(lines, [&b"abc\n"[..], b"def\n", b"\n", b"g\n"]);
    }

    #[test]
    fn idle_timeout_spares_a_command_that_keeps_writing() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "for i in 1 2 3 4; do echo $i; sleep 0.3; done"])
                    .timeout(Duration::from_secs(20))
                    .idle_timeout(Some(Duration::from_secs(1))),
            )
            .unwrap();

        assert!(!output.idle_timed_out);
        assert!(output.success());
        assert_eq!(output.stdout, b"1\n2\n3\n4\n");
    }

    #[test]
    fn timeout_terminates_descendant_processes() {
        let pid_file =
            std::env::temp_dir().join(format!("krabi-caliper-descendant-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > {}; wait", pid_file.display());
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", &script])
                    .timeout(Duration::from_secs(1)),
            )
            .unwrap();
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        // Group termination and child reaping are not atomic. Give init (or
        // the test runner's subreaper) a bounded opportunity to reap the
        // signalled descendant before declaring that it leaked.
        let mut still_alive = true;
        for _ in 0..100 {
            still_alive = Command::new("sh")
                .args(["-c", &format!("kill -0 {} 2>/dev/null", pid.trim())])
                .status()
                .unwrap()
                .success();
            if !still_alive {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(pid_file);

        assert!(output.timed_out);
        assert!(!still_alive, "descendant process {pid} survived timeout");
    }

    #[test]
    fn completion_marker_terminates_a_non_exiting_runner_successfully() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "printf 'EM_OUTCOME status:PASS\\n'; exec sleep 30"])
                    .completion_marker("EM_OUTCOME")
                    .timeout(Duration::from_secs(5)),
            )
            .unwrap();

        assert!(output.completion_marker_hit);
        assert!(!output.timed_out);
        assert!(output.success());
        assert!(output.stdout_lossy().contains("EM_OUTCOME"));
        assert!(output.duration < Duration::from_secs(1));
    }

    #[test]
    fn preserves_a_completion_marker_from_a_normally_exiting_command() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args(["-c", "printf 'EM_OUTCOME status:PASS\\n'"])
                    .completion_marker("EM_OUTCOME"),
            )
            .unwrap();

        assert!(output.completion_marker_hit);
        assert!(!output.timed_out);
        assert!(output.success());
    }

    #[test]
    fn interrupt_completion_allows_a_runner_to_clean_up() {
        let output = CommandRunner
            .run(
                &CommandSpec::new("sh", ".")
                    .args([
                        "-c",
                        "trap 'printf cleanup >&2; exit 0' INT; printf 'EM_OUTCOME status:PASS\\n'; while :; do :; done",
                    ])
                    .completion_marker("EM_OUTCOME")
                    .completion_action(CompletionAction::Interrupt)
                    .timeout(Duration::from_secs(5)),
            )
            .unwrap();

        assert!(output.completion_marker_hit);
        assert!(!output.timed_out);
        assert!(output.success());
        assert_eq!(output.stderr, b"cleanup");
        assert!(output.status.is_some_and(|status| status.success()));
    }

    #[test]
    fn completion_marker_requires_the_complete_output_line() {
        assert!(!contains_complete_line(b"EM_OUTCOME", b"EM_OUTCOME"));
        assert!(!contains_complete_line(
            b"EM_OUTCOME schema:1 status:PASS",
            b"EM_OUTCOME"
        ));
        assert!(contains_complete_line(
            b"EM_OUTCOME schema:1 status:PASS\n",
            b"EM_OUTCOME"
        ));
    }
}
