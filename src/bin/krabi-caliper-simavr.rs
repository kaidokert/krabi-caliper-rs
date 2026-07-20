use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use krabi_caliper::host::SimavrInvocation;

/// Portable Cargo runner for simavr.
#[derive(Debug, Parser)]
#[command(about = "Run a Cargo-built AVR artifact under simavr")]
struct Cli {
    /// Maximum simulator runtime in seconds.
    #[arg(short = 't', long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// simavr executable name or path.
    #[arg(long, default_value = "simavr")]
    executable: OsString,

    /// Complete successfully after this full output-line substring is observed.
    #[arg(long)]
    completion_marker: Option<String>,

    /// simavr arguments followed by the firmware artifact appended by Cargo.
    #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
    arguments: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (arguments, artifact, artifact_args) = match split_arguments(cli.arguments) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut invocation = SimavrInvocation::new(artifact)
        .args(arguments)
        .artifact_args(artifact_args)
        .executable(cli.executable)
        .timeout(Duration::from_secs(cli.timeout));
    if let Some(marker) = cli.completion_marker {
        invocation = invocation.completion_marker(marker.into_bytes());
    }

    match invocation.run() {
        Ok(output) => {
            let _ = std::io::stdout().write_all(&output.stdout);
            let _ = std::io::stderr().write_all(&output.stderr);
            if output.completion_marker_hit {
                ExitCode::SUCCESS
            } else if output.timed_out {
                ExitCode::from(124)
            } else {
                ExitCode::from(
                    output
                        .status
                        .and_then(|status| status.code())
                        .and_then(|code| u8::try_from(code).ok())
                        .unwrap_or(1),
                )
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn split_arguments(
    arguments: Vec<OsString>,
) -> Result<(Vec<OsString>, PathBuf, Vec<OsString>), &'static str> {
    let artifact_index = arguments
        .iter()
        .position(|argument| Path::new(argument).is_file())
        .ok_or("firmware artifact argument is missing or does not exist")?;
    let mut before = arguments;
    let after = before.split_off(artifact_index + 1);
    let artifact = PathBuf::from(before.pop().expect("artifact index exists"));
    Ok((before, artifact, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_runner_argument_shape() {
        let artifact = std::env::current_exe().unwrap();
        let cli = Cli::try_parse_from([
            OsString::from("krabi-caliper-simavr"),
            OsString::from("-t"),
            OsString::from("30"),
            OsString::from("--completion-marker"),
            OsString::from("status:PASS"),
            OsString::from("-m"),
            OsString::from("atmega2560"),
            OsString::from("-f"),
            OsString::from("16000000"),
            artifact.clone().into_os_string(),
            OsString::from("--app-arg"),
        ])
        .unwrap();
        assert_eq!(cli.timeout, 30);
        assert_eq!(cli.completion_marker.as_deref(), Some("status:PASS"));
        let (simavr_args, parsed_artifact, artifact_args) = split_arguments(cli.arguments).unwrap();
        assert_eq!(parsed_artifact, artifact);
        assert_eq!(simavr_args.last().unwrap(), "16000000");
        assert_eq!(artifact_args, [OsString::from("--app-arg")]);
    }
}
