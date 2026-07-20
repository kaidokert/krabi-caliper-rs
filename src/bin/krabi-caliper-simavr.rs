use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
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
    let mut arguments = cli.arguments;
    let artifact = PathBuf::from(arguments.pop().expect("clap requires an artifact"));
    let mut invocation = SimavrInvocation::new(artifact)
        .args(arguments)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_runner_argument_shape() {
        let cli = Cli::try_parse_from([
            "krabi-caliper-simavr",
            "-t",
            "30",
            "--completion-marker",
            "status:PASS",
            "-m",
            "atmega2560",
            "-f",
            "16000000",
            "target/firmware.elf",
        ])
        .unwrap();
        assert_eq!(cli.timeout, 30);
        assert_eq!(cli.completion_marker.as_deref(), Some("status:PASS"));
        assert_eq!(cli.arguments.last().unwrap(), "target/firmware.elf");
    }
}
