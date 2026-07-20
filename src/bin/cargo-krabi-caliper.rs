use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use krabi_caliper::host::panic_audit::{
    ArtifactKind, DEFAULT_FORBIDDEN_TARGETS, PanicAuditConfig, run as run_panic_audit,
};
use krabi_caliper::host::{
    CampaignExecutor, CampaignSelection, ComparisonPolicy, JTraceCapture, JTraceCtGate, RttCapture,
    ToolkitConfig, compare_campaigns, ensure_parent, read_campaign, read_combined_inputs,
    run_timestamped_command,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PanicArtifactKind {
    Staticlib,
    Example,
}

#[derive(Debug, Parser)]
#[command(name = "cargo krabi-caliper")]
#[command(about = "Build and run embedded measurement campaigns")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build positive and negative-control artifacts and audit panic call sites.
    PanicAudit {
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        package: String,
        #[arg(long, value_enum, default_value = "staticlib")]
        artifact_kind: PanicArtifactKind,
        #[arg(long)]
        artifact_name: Option<String>,
        #[arg(long)]
        negative_artifact_name: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "release")]
        profile: String,
        #[arg(long)]
        no_default_features: bool,
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        negative_features: Vec<String>,
        #[arg(long, required = true)]
        owned_symbol: Vec<String>,
        #[arg(long)]
        forbidden_target: Vec<String>,
        #[arg(long, required = true)]
        expect_negative: Vec<String>,
        #[arg(long)]
        cargo_arg: Vec<OsString>,
        /// Override llvm-objdump or avr-objdump discovery.
        #[arg(long)]
        objdump: Option<PathBuf>,
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Validate a campaign file without building or running targets.
    ValidateConfig {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Run {
        campaign: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        quick: bool,
        #[arg(long)]
        case: Vec<String>,
    },
    Compare {
        current: PathBuf,
        baseline: PathBuf,
        #[arg(long)]
        max_flash_increase: Option<u64>,
        #[arg(long)]
        max_static_ram_increase: Option<u64>,
        #[arg(long)]
        max_stack_increase: Option<u64>,
        #[arg(long)]
        max_ticks_increase: Option<u64>,
        #[arg(long)]
        max_percent_increase: Option<f64>,
        #[arg(long)]
        json: Option<PathBuf>,
        #[arg(long)]
        markdown: Option<PathBuf>,
        #[arg(long)]
        csv: Option<PathBuf>,
    },
    /// Run a command and timestamp each target-owned measurement boundary.
    #[command(name = "timestamp-command")]
    Timestamp {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
        program: OsString,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Capture an ETM interval delimited by two exported target symbols.
    JtraceCapture {
        elf: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "STM32F407VG")]
        device: String,
        #[arg(long)]
        probe_serial: String,
        #[arg(long, default_value = "embedded_measure_trace_begin")]
        begin_symbol: String,
        #[arg(long, default_value = "embedded_measure_trace_end")]
        end_symbol: String,
        #[arg(long, default_value_t = 5_000)]
        run_millis: u64,
        #[arg(long, default_value_t = 40)]
        recent_instructions: u32,
        #[arg(long, default_value = "JLinkExe")]
        jlink_exe: PathBuf,
        #[arg(long)]
        rtt_probe_selector: Option<String>,
        #[arg(long)]
        rtt_chip: Option<String>,
        #[arg(long, default_value = "probe-rs")]
        probe_rs: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        rtt_timeout_millis: u64,
    },
    /// Require identical bounded ETM execution profiles across secret keys.
    JtraceCtGate {
        elf: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "STM32F407VG")]
        device: String,
        #[arg(long)]
        probe_serial: String,
        #[arg(long, default_value_t = 2)]
        keys: u32,
        #[arg(long, default_value_t = 2)]
        repetitions: u32,
        #[arg(long, default_value_t = 64)]
        max_dwt_spread: u32,
        /// Maximum L1 distance between repeated compact execution profiles.
        #[arg(long)]
        max_profile_delta: u64,
        #[arg(long, default_value = "JLinkExe")]
        jlink_exe: PathBuf,
        #[arg(long, default_value = "JLinkGDBServerCLExe")]
        gdb_server: PathBuf,
        #[arg(long, default_value_t = 2331)]
        port: u16,
        #[arg(long)]
        rtt_probe_selector: String,
        #[arg(long)]
        rtt_chip: String,
        #[arg(long, default_value = "probe-rs")]
        probe_rs: PathBuf,
    },
    /// Combine one campaign case with a J-Trace gate report, qualified by ELF identity.
    CombineCtEvidence {
        campaign: PathBuf,
        #[arg(long)]
        case: String,
        #[arg(long)]
        etm_report: PathBuf,
        #[arg(long)]
        etm_elf: PathBuf,
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        markdown: PathBuf,
    },
}

fn main() -> ExitCode {
    match execute(Cli::parse_from(normalized_args(std::env::args_os()))) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn normalized_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args = args.into_iter().collect::<Vec<_>>();
    if args
        .get(1)
        .is_some_and(|value| value == "krabi-caliper" || value == "embedded-measure")
    {
        args.remove(1);
    }
    args
}

fn resolve_config(config: Option<PathBuf>) -> PathBuf {
    if let Some(config) = config {
        return config;
    }

    let current = PathBuf::from("krabi-caliper.toml");
    if current.exists() {
        return current;
    }

    let legacy = PathBuf::from("embedded-measure.toml");
    if legacy.exists() {
        eprintln!(
            "warning: using legacy {legacy}; rename it to krabi-caliper.toml",
            legacy = legacy.display()
        );
        return legacy;
    }

    current
}

fn execute(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    match cli.command {
        Command::PanicAudit {
            workspace,
            package,
            artifact_kind,
            artifact_name,
            negative_artifact_name,
            target,
            profile,
            no_default_features,
            features,
            negative_features,
            owned_symbol,
            forbidden_target,
            expect_negative,
            cargo_arg,
            objdump,
            json,
        } => {
            let report = run_panic_audit(&PanicAuditConfig {
                workspace,
                package,
                artifact_kind: match artifact_kind {
                    PanicArtifactKind::Staticlib => ArtifactKind::Staticlib,
                    PanicArtifactKind::Example => ArtifactKind::Example,
                },
                artifact_name,
                negative_artifact_name,
                target,
                profile,
                no_default_features,
                positive_features: features,
                negative_features,
                owned_symbols: owned_symbol,
                forbidden_targets: if forbidden_target.is_empty() {
                    DEFAULT_FORBIDDEN_TARGETS
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect()
                } else {
                    forbidden_target
                },
                expected_negatives: expect_negative,
                extra_cargo_args: cargo_arg,
                objdump,
                json_out: json,
            })?;
            report.print_human();
            Ok(report.success())
        }
        Command::ValidateConfig { config } => {
            let path = resolve_config(config);
            let config_text = fs::read_to_string(&path)?;
            let config: ToolkitConfig = toml::from_str(&config_text)?;
            config.validate()?;
            println!("{}: PASS", path.display());
            Ok(true)
        }
        Command::Run {
            campaign,
            config,
            workspace,
            quick,
            case,
        } => {
            let config = resolve_config(config);
            let config_text = fs::read_to_string(&config)?;
            let config: ToolkitConfig = toml::from_str(&config_text)?;
            let report = CampaignExecutor::default().run(
                &config,
                &campaign,
                &workspace,
                &CampaignSelection { quick, cases: case },
            )?;
            print!("{}", report.render_markdown());
            Ok(report.success())
        }
        Command::Compare {
            current,
            baseline,
            max_flash_increase,
            max_static_ram_increase,
            max_stack_increase,
            max_ticks_increase,
            max_percent_increase,
            json,
            markdown,
            csv,
        } => {
            if max_percent_increase.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return Err("--max-percent-increase must be a finite non-negative number".into());
            }
            let current_report = read_campaign(&current)?;
            let baseline_report = read_campaign(&baseline)?;
            let report = compare_campaigns(
                &baseline,
                &baseline_report,
                &current,
                &current_report,
                ComparisonPolicy {
                    max_flash_increase,
                    max_static_ram_increase,
                    max_stack_increase,
                    max_ticks_increase,
                    max_percent_increase,
                },
            );
            let rendered_markdown = report.render_markdown();
            print!("{rendered_markdown}");
            if let Some(path) = markdown {
                ensure_parent(&path)?;
                fs::write(path, &rendered_markdown)?;
            }
            if let Some(path) = json {
                ensure_parent(&path)?;
                fs::write(path, report.render_json()?)?;
            }
            if let Some(path) = csv {
                ensure_parent(&path)?;
                fs::write(path, report.render_csv())?;
            }
            Ok(report.success())
        }
        Command::Timestamp {
            cwd,
            timeout_seconds,
            program,
            args,
        } => {
            let output = run_timestamped_command(
                &program,
                &args,
                &cwd,
                std::time::Duration::from_secs(timeout_seconds),
                std::io::stdout(),
                std::io::stderr(),
            )?;
            Ok(output.status.success())
        }
        Command::JtraceCapture {
            elf,
            output_dir,
            device,
            probe_serial,
            begin_symbol,
            end_symbol,
            run_millis,
            recent_instructions,
            jlink_exe,
            rtt_probe_selector,
            rtt_chip,
            probe_rs,
            rtt_timeout_millis,
        } => {
            let rtt = match (rtt_probe_selector, rtt_chip) {
                (Some(probe_selector), Some(chip)) => Some(RttCapture {
                    probe_rs,
                    probe_selector,
                    chip,
                    timeout_millis: rtt_timeout_millis,
                }),
                (None, None) => None,
                _ => {
                    return Err(
                        "--rtt-probe-selector and --rtt-chip must be supplied together".into(),
                    );
                }
            };
            let report = JTraceCapture {
                elf,
                output_dir,
                device,
                probe_serial,
                begin_symbol,
                end_symbol,
                run_millis,
                recent_instructions,
                jlink_exe,
                rtt,
            }
            .run()?;
            println!("J-Trace capture PASS");
            println!(
                "markers: {:#010x}..{:#010x}",
                report.begin_address, report.end_address
            );
            println!(
                "decoded recent instructions: {} ({} unique)",
                report.decoded_instruction_lines, report.unique_instruction_addresses
            );
            if let (Some(ticks), Some(hz), Some(ops)) = (
                report.ticks,
                report.frequency_hz,
                report.operations_per_second,
            ) {
                println!("DWT correlation: {ticks} cycles at {hz} Hz ({ops:.6} ops/s)");
            }
            println!("script: {}", report.script.display());
            println!("transcript: {}", report.transcript.display());
            if let Some(path) = report.rtt_transcript {
                println!("RTT transcript: {}", path.display());
            }
            println!("analysis: {}", report.analysis.display());
            Ok(true)
        }
        Command::JtraceCtGate {
            elf,
            output_dir,
            device,
            probe_serial,
            keys,
            repetitions,
            max_dwt_spread,
            max_profile_delta,
            jlink_exe,
            gdb_server,
            port,
            rtt_probe_selector,
            rtt_chip,
            probe_rs,
        } => {
            let report = JTraceCtGate {
                elf,
                output_dir,
                device,
                probe_serial,
                keys,
                repetitions,
                max_dwt_spread,
                max_profile_delta,
                jlink_exe,
                gdb_server,
                port,
                rtt: RttCapture {
                    probe_rs,
                    probe_selector: rtt_probe_selector,
                    chip: rtt_chip,
                    timeout_millis: 10_000,
                },
            }
            .run()?;
            println!("ETM constant-time gate {}", report.status);
            println!(
                "profiles: {} keys x {} repetitions, {} trace-address observations, {} active addresses",
                report.keys, report.repetitions, report.execute_sum, report.nonzero_halfwords
            );
            println!(
                "DWT checkpoint: {}..{} cycles (spread {})",
                report.dwt_min, report.dwt_max, report.dwt_spread
            );
            Ok(report.status == "PASS")
        }
        Command::CombineCtEvidence {
            campaign,
            case,
            etm_report,
            etm_elf,
            json,
            markdown,
        } => {
            let report = read_combined_inputs(&campaign, &case, &etm_report, &etm_elf)?;
            ensure_parent(&json)?;
            ensure_parent(&markdown)?;
            fs::write(&json, serde_json::to_vec_pretty(&report)?)?;
            fs::write(&markdown, report.render_markdown())?;
            print!("{}", report.render_markdown());
            Ok(matches!(
                report.verdict,
                krabi_caliper::host::CombinedCtVerdict::Pass
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cargo_external_subcommand_argument_shape() {
        let args = normalized_args(
            ["cargo-krabi-caliper", "krabi-caliper", "run", "demo"]
                .into_iter()
                .map(OsString::from),
        );

        let parsed = Cli::try_parse_from(args).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Run { campaign, .. } if campaign == "demo"
        ));
    }

    #[test]
    fn parses_panic_audit_policy_and_split_artifacts() {
        let parsed = Cli::try_parse_from([
            "cargo-krabi-caliper",
            "panic-audit",
            "--package",
            "avr_demo",
            "--artifact-kind",
            "example",
            "--artifact-name",
            "test_picojson",
            "--negative-artifact-name",
            "minimal",
            "--target",
            "avr-none",
            "--negative-features",
            "neg-controls",
            "--owned-symbol",
            "^picojson::",
            "--expect-negative",
            "panic_audit__neg__bounds",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Command::PanicAudit {
                artifact_kind: PanicArtifactKind::Example,
                artifact_name: Some(artifact),
                negative_artifact_name: Some(negative),
                target,
                ..
            } if artifact == "test_picojson" && negative == "minimal" && target == "avr-none"
        ));
    }

    #[test]
    fn parses_compare_thresholds_and_artifact_outputs() {
        let parsed = Cli::try_parse_from([
            "cargo-krabi-caliper",
            "compare",
            "current.json",
            "baseline.json",
            "--max-flash-increase",
            "16",
            "--max-percent-increase",
            "1.5",
            "--json",
            "comparison.json",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Command::Compare {
                max_flash_increase: Some(16),
                max_percent_increase: Some(value),
                ..
            } if value == 1.5
        ));
    }

    #[test]
    fn parses_timestamp_command_with_hyphenated_child_arguments() {
        let parsed = Cli::try_parse_from([
            "cargo-krabi-caliper",
            "timestamp-command",
            "qemu-system-arm",
            "--",
            "-machine",
            "lm3s6965evb",
            "-nographic",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Command::Timestamp { program, args, .. }
                if program == "qemu-system-arm" && args.len() == 3
        ));
    }

    #[test]
    fn parses_declarative_config_validation() {
        let parsed = Cli::try_parse_from([
            "cargo-krabi-caliper",
            "validate-config",
            "--config",
            "hardware.toml",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::ValidateConfig { config: Some(path) }
                if path.as_os_str() == "hardware.toml"
        ));
    }

    #[test]
    fn parses_combined_ct_evidence_inputs() {
        let parsed = Cli::try_parse_from([
            "cargo-krabi-caliper",
            "combine-ct-evidence",
            "campaign.json",
            "--case",
            "rsa512",
            "--etm-report",
            "etm.json",
            "--etm-elf",
            "etm.elf",
            "--json",
            "combined.json",
            "--markdown",
            "combined.md",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::CombineCtEvidence { case, .. } if case == "rsa512"
        ));
    }
}
