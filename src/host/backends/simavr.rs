//! Portable simavr invocation for Cargo runners and host campaigns.

#[cfg(target_os = "windows")]
use std::borrow::ToOwned;
use std::eprintln;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::string::String;
use std::string::ToString;
use std::time::Duration;
use std::vec::Vec;

use super::{CommandError, CommandOutput, CommandRunner, CommandSpec, CompletionAction};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimavrInvocation {
    pub artifact: PathBuf,
    pub args: Vec<OsString>,
    pub completion_marker: Option<Vec<u8>>,
    pub executable: OsString,
    pub timeout: Duration,
}

impl SimavrInvocation {
    pub fn new(artifact: impl Into<PathBuf>) -> Self {
        Self {
            artifact: artifact.into(),
            args: Vec::new(),
            completion_marker: None,
            executable: OsString::from("simavr"),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn executable(mut self, executable: impl Into<OsString>) -> Self {
        self.executable = executable.into();
        self
    }

    pub fn completion_marker(mut self, marker: impl Into<Vec<u8>>) -> Self {
        self.completion_marker = Some(marker.into());
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn run(&self) -> Result<CommandOutput, SimavrError> {
        if !self.artifact.is_file() {
            return Err(SimavrError::ArtifactNotFound(self.artifact.clone()));
        }
        let cwd = std::env::current_dir().map_err(SimavrError::CurrentDirectory)?;

        #[cfg(target_os = "windows")]
        let spec = {
            let artifact = windows_to_wsl_path(&self.artifact, &cwd)?;
            wsl_spec(self, &cwd, &artifact)
        };
        #[cfg(not(target_os = "windows"))]
        let spec = posix_spec(self, &cwd);

        eprintln!("+ {}", spec.display());
        CommandRunner.run(&spec).map_err(SimavrError::Command)
    }
}

fn finish_spec(invocation: &SimavrInvocation, spec: CommandSpec) -> CommandSpec {
    if let Some(marker) = &invocation.completion_marker {
        spec.completion_marker(marker.clone())
            .completion_action(CompletionAction::Kill)
    } else {
        spec
    }
}

#[cfg_attr(all(target_os = "windows", not(test)), allow(dead_code))]
fn posix_spec(invocation: &SimavrInvocation, cwd: &Path) -> CommandSpec {
    finish_spec(
        invocation,
        CommandSpec::new(&invocation.executable, cwd)
            .args(invocation.args.iter())
            .arg(&invocation.artifact)
            .timeout(invocation.timeout),
    )
}

#[cfg_attr(not(any(test, target_os = "windows")), allow(dead_code))]
fn wsl_spec(invocation: &SimavrInvocation, cwd: &Path, artifact: &OsStr) -> CommandSpec {
    // GNU timeout inside WSL ensures the Linux simulator is terminated even if
    // killing the outer wsl.exe process would leave the distribution running.
    let seconds = invocation.timeout.as_secs().max(1).to_string();
    finish_spec(
        invocation,
        CommandSpec::new("wsl", cwd)
            .args([
                OsStr::new("-e"),
                OsStr::new("timeout"),
                OsStr::new(&seconds),
            ])
            .arg(&invocation.executable)
            .args(invocation.args.iter())
            .arg(artifact)
            .timeout(invocation.timeout + Duration::from_secs(2)),
    )
}

#[cfg(target_os = "windows")]
fn windows_to_wsl_path(artifact: &Path, cwd: &Path) -> Result<OsString, SimavrError> {
    let absolute = artifact
        .canonicalize()
        .map_err(|source| SimavrError::Canonicalize {
            path: artifact.to_path_buf(),
            source,
        })?;
    let spec = CommandSpec::new("wsl", cwd)
        .args([OsStr::new("wslpath"), OsStr::new("-u")])
        .arg(absolute.as_os_str())
        .timeout(Duration::from_secs(10));
    let output = CommandRunner.run(&spec).map_err(SimavrError::Command)?;
    if !output.success() {
        return Err(SimavrError::PathConversion(output.combined_lossy()));
    }
    let path = output.stdout_lossy().trim().to_owned();
    if path.is_empty() {
        return Err(SimavrError::PathConversion(
            "wslpath returned an empty path".to_owned(),
        ));
    }
    Ok(OsString::from(path))
}

#[derive(Debug)]
pub enum SimavrError {
    ArtifactNotFound(PathBuf),
    CurrentDirectory(std::io::Error),
    #[cfg(target_os = "windows")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    Command(CommandError),
    #[cfg(target_os = "windows")]
    PathConversion(String),
}

impl fmt::Display for SimavrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactNotFound(path) => {
                write!(formatter, "simavr artifact not found: {}", path.display())
            }
            Self::CurrentDirectory(source) => {
                write!(formatter, "cannot read current directory: {source}")
            }
            #[cfg(target_os = "windows")]
            Self::Canonicalize { path, source } => {
                write!(formatter, "cannot resolve {}: {source}", path.display())
            }
            Self::Command(source) => source.fmt(formatter),
            #[cfg(target_os = "windows")]
            Self::PathConversion(detail) => write!(formatter, "wslpath failed: {detail}"),
        }
    }
}

impl std::error::Error for SimavrError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> SimavrInvocation {
        SimavrInvocation::new("firmware.elf")
            .args(["-m", "atmega2560", "-f", "16000000"])
            .timeout(Duration::from_secs(30))
    }

    #[test]
    fn posix_command_preserves_simulator_arguments_and_artifact_order() {
        let spec = posix_spec(&invocation(), Path::new("/repo"));
        assert_eq!(spec.program, OsString::from("simavr"));
        assert_eq!(
            spec.args,
            ["-m", "atmega2560", "-f", "16000000", "firmware.elf"].map(OsString::from)
        );
        assert_eq!(spec.timeout, Duration::from_secs(30));
    }

    #[test]
    fn wsl_command_uses_inner_and_outer_timeouts() {
        let spec = wsl_spec(
            &invocation(),
            Path::new("C:/repo"),
            OsStr::new("/mnt/c/fw.elf"),
        );
        assert_eq!(spec.program, OsString::from("wsl"));
        assert_eq!(
            spec.args,
            [
                "-e",
                "timeout",
                "30",
                "simavr",
                "-m",
                "atmega2560",
                "-f",
                "16000000",
                "/mnt/c/fw.elf",
            ]
            .map(OsString::from)
        );
        assert_eq!(spec.timeout, Duration::from_secs(32));
    }

    #[test]
    fn completion_marker_is_forwarded_to_command_runner() {
        let invocation = invocation().completion_marker(b"status:PASS".to_vec());
        let spec = posix_spec(&invocation, Path::new("/repo"));
        assert_eq!(spec.completion_marker, Some(b"status:PASS".to_vec()));
        assert_eq!(spec.completion_action, CompletionAction::Kill);
    }
}
