use std::ffi::{OsStr, OsString};
use std::format;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::string::String;
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
pub struct CommandSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
    pub env_remove: Vec<OsString>,
    pub timeout: Duration,
    pub completion_marker: Option<Vec<u8>>,
    pub completion_action: CompletionAction,
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
            completion_marker: None,
            completion_action: CompletionAction::Kill,
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

    pub fn completion_marker(mut self, marker: impl Into<Vec<u8>>) -> Self {
        self.completion_marker = Some(marker.into());
        self
    }

    pub const fn completion_action(mut self, action: CompletionAction) -> Self {
        self.completion_action = action;
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
pub struct CommandOutput {
    pub status: Option<ExitStatus>,
    pub timed_out: bool,
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
        let stdout_thread = spawn_reader(stdout, Arc::clone(&stdout_capture));
        let stderr_thread = spawn_reader(stderr, Arc::clone(&stderr_capture));

        let (status, timed_out, mut completion_marker_hit) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false, false),
                Ok(None) if marker_seen(spec, &stdout_capture, &stderr_capture) => {
                    let status = finish_after_marker(
                        child.child.as_mut().expect("managed child must exist"),
                        spec.completion_action,
                        &display,
                    )?;
                    break (Some(status), false, true);
                }
                Ok(None) if started.elapsed() >= spec.timeout => {
                    let status = child.terminate()?;
                    break (Some(status), true, false);
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
            completion_marker_hit,
            duration: started.elapsed(),
            stdout,
            stderr,
        })
    }
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
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        loop {
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                return Ok(());
            }
            capture.lock().unwrap().extend_from_slice(&chunk[..count]);
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
        format!("{:?}", value)
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
