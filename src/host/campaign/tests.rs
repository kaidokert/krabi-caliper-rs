use super::*;

fn parse(input: &str) -> ToolkitConfig {
    toml::from_str(input).unwrap()
}

#[test]
fn validates_a_declarative_campaign_without_running_it() {
    let config = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"

[campaigns.smoke]
profile = "qemu"
matrix = { size = ["small", "large"] }
matrix-features = ["size-{size}"]
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    config.validate().unwrap();
}

#[test]
fn profile_inheritance_unions_requirements_and_replaces_lists() {
    let config = parse(
        r#"
[venues.lab]
capabilities = ["swd", "rtt", "etm"]

[profiles.base]
runner = "command"
target = "thumbv7em-none-eabihf"
venue = "lab"
requires = ["swd"]
args = ["base"]

[profiles.child]
extends = "base"
requires = ["etm"]
args = ["child"]

[campaigns.test]
profile = "child"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let profile = config.resolve_profile("child").unwrap();
    assert_eq!(profile.capabilities, ["etm", "swd"]);
    assert_eq!(profile.args, ["child"]);
}

#[test]
fn inheritance_cycles_and_missing_capabilities_fail_closed() {
    let cycle = parse(
        r#"
[profiles.a]
extends = "b"
[profiles.b]
extends = "a"
[campaigns.test]
profile = "a"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );
    assert!(cycle.validate().unwrap_err().to_string().contains("cycle"));

    let unavailable = parse(
        r#"
[venues.lab]
capabilities = ["swd"]
[profiles.hardware]
runner = "command"
target = "thumbv7em-none-eabihf"
venue = "lab"
requires = ["etm"]
[campaigns.test]
profile = "hardware"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );
    assert!(
        unavailable
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unavailable capabilities")
    );
}

#[test]
fn venue_bindings_expand_and_secret_evidence_is_redacted() {
    let config = parse(
        r#"
[venues.lab]
capabilities = ["swd"]
bindings = { PROBE = "serial-1", ACCESS_TOKEN = "sensitive" }
secret-bindings = ["ACCESS_TOKEN"]
controlled-environment = { probe = "${PROBE}" }

[profiles.hardware]
runner = "command"
target = "thumbv7em-none-eabihf"
venue = "lab"
requires = ["swd"]
executable = "probe-rs"
args = ["--probe", "${PROBE}", "--token", "${ACCESS_TOKEN}"]

[campaigns.test]
profile = "hardware"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let profile = config.resolve_profile("hardware").unwrap();
    assert_eq!(profile.args[1], "serial-1");
    assert_eq!(profile.resolved_bindings["PROBE"], "serial-1");
    assert_eq!(profile.resolved_bindings["ACCESS_TOKEN"], "<redacted>");
    assert!(!profile.configuration_identity.contains("sensitive"));
}

#[test]
fn secret_bindings_are_rejected_as_controlled_comparison_facts() {
    let config = parse(
        r#"
[venues.lab]
bindings = { ACCESS_TOKEN = "sensitive" }
secret-bindings = ["ACCESS_TOKEN"]
controlled-environment = { token = "${ACCESS_TOKEN}" }
[profiles.hardware]
runner = "command"
target = "thumbv7em-none-eabihf"
venue = "lab"
[campaigns.test]
profile = "hardware"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must not contain secret binding"));
    assert!(!error.contains("sensitive"));
}

#[test]
fn heuristic_secrets_cannot_enter_identity_evidence() {
    let config = parse(
        r#"
[venues.lab]
bindings = { ACCESS_TOKEN = "sensitive" }
[profiles.hardware]
runner = "command"
target = "thumbv7em-none-eabihf"
venue = "lab"
probe = "${ACCESS_TOKEN}"
[campaigns.test]
profile = "hardware"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("profile probe"));
    assert!(error.contains("ACCESS_TOKEN"));
    assert!(!error.contains("sensitive"));
}

#[test]
fn host_toolchain_bindings_validate_without_early_discovery() {
    let config = parse(
        r#"
[venues.host]
bindings = { TOOLCHAIN = "nightly-caller-pin" }
[profiles.native]
runner = "command"
target = "host"
toolchain = "${TOOLCHAIN}"
venue = "host"
[campaigns.test]
profile = "native"
cases = [{ name = "fixture", binary = "fixture" }]
"#,
    );

    let profile = config.resolve_profile("native").unwrap();
    assert_eq!(profile.target, "host");
    assert_eq!(profile.toolchain.as_deref(), Some("nightly-caller-pin"));
}

#[test]
fn validates_baselines_and_matrix_feature_placeholders() {
    let bad_baseline = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"
[campaigns.test]
profile = "qemu"
baseline-case = "missing"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );
    assert!(
        bad_baseline
            .validate()
            .unwrap_err()
            .to_string()
            .contains("is not a case")
    );

    let bad_matrix = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"
[campaigns.test]
profile = "qemu"
matrix = { size = ["small"] }
matrix-features = ["size-{siz}"]
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );
    assert!(
        bad_matrix
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown axis")
    );
}

#[test]
fn rejects_artifact_identifiers_that_can_escape_the_output_directory() {
    for input in [
        r#"
[profiles.host]
runner = "command"
target = "host"
[campaigns."../escape"]
profile = "host"
cases = [{ name = "fixture", example = "fixture" }]
"#,
        r#"
[profiles.host]
runner = "command"
target = "host"
[campaigns.test]
profile = "host"
cases = [{ name = "../../../escape", example = "fixture" }]
"#,
        r#"
[profiles.host]
runner = "command"
target = "host"
[campaigns.test]
profile = "host"
matrix = { size = ["../../escape"] }
cases = [{ name = "fixture", example = "fixture" }]
"#,
    ] {
        let error = parse(input).validate().unwrap_err().to_string();
        assert!(error.contains("must be one safe path component"), "{error}");
    }
}

#[test]
fn rejects_ambiguous_cases_and_constant_time_policy() {
    let ambiguous = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"
[campaigns.test]
profile = "qemu"
case-set = "shared"
cases = [{ name = "fixture", example = "fixture" }]
[case-sets]
shared = [{ name = "fixture", example = "fixture" }]
"#,
    );
    assert!(ambiguous.validate().is_err());

    let invalid_ct = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"
[campaigns.test]
profile = "qemu"
cases = [{ name = "fixture", example = "fixture" }]
[campaigns.test.constant-time]
minimum-samples-per-class = 1
"#,
    );
    assert!(invalid_ct.validate().is_err());
}

fn matrix_campaign() -> CampaignConfig {
    CampaignConfig {
        profile: "test".to_string(),
        constant_time: None,
        case_set: None,
        cases: vec![CaseConfig {
            name: "parser".to_string(),
            example: Some("parser".to_string()),
            binary: None,
            features: vec!["base".to_string()],
            expected_benchmark: None,
            expected_suite: None,
            timeout_seconds: None,
            delay_before_run_seconds: None,
            baseline: None,
        }],
        baseline_case: None,
        matrix: BTreeMap::from([
            ("depth".to_string(), vec!["7".to_string(), "9".to_string()]),
            (
                "mode".to_string(),
                vec!["tiny".to_string(), "small".to_string()],
            ),
        ]),
        matrix_features: vec!["depth-{depth}".to_string(), "mode-{mode}".to_string()],
        continue_on_failure: true,
        artifact_dir: None,
    }
}

#[test]
fn expands_complete_and_quick_campaign_matrices() {
    let cases = expand_cases(&matrix_campaign(), &CampaignSelection::default()).unwrap();
    assert_eq!(cases.len(), 4);
    assert_eq!(cases[0].id, "parser__depth-7__mode-tiny");
    assert_eq!(cases[3].features, ["base", "depth-9", "mode-small"]);

    let quick = expand_cases(
        &matrix_campaign(),
        &CampaignSelection {
            quick: true,
            cases: Vec::new(),
            silent: true,
        },
    )
    .unwrap();
    assert_eq!(quick.len(), 1);
    assert_eq!(quick[0].id, "parser__depth-7__mode-tiny");
}

#[test]
fn configured_commands_substitute_artifacts_and_deadlines() {
    let command = RunnerCommandConfig {
        executable: "probe-rs".to_string(),
        args: vec!["download".to_string(), "{artifact}".to_string()],
        timeout_seconds: 17,
    };
    let spec = configured_runner_command(
        &command,
        Path::new("/repo"),
        Path::new("/repo/target/firmware"),
    );

    assert_eq!(spec.program, OsString::from("probe-rs"));
    assert_eq!(
        spec.args,
        ["download", "/repo/target/firmware"].map(OsString::from)
    );
    assert_eq!(spec.timeout, Duration::from_secs(17));
}

#[test]
fn enrichment_attaches_reproducibility_evidence() {
    let case = expand_cases(&matrix_campaign(), &CampaignSelection::default())
        .unwrap()
        .remove(0);
    let environment = ReproducibilityMetadata {
        recorded_unix_seconds: 1,
        source: SourceMetadata {
            workspace: Some("/repo/fixture".to_string()),
            repository: Some("https://example.invalid/repo".to_string()),
            git_commit: Some("abc123".to_string()),
            dirty: Some(false),
        },
        build: BuildMetadata {
            toolchain: Some("test-toolchain".to_string()),
            rustc: Some("rustc test".to_string()),
            cargo: Some("cargo test".to_string()),
            target: Some("thumbv7em-none-eabihf".to_string()),
            optimization: Some("release".to_string()),
            features: case.features.clone(),
        },
        target: TargetMetadata {
            probe: Some("serial".to_string()),
            clock_frequency_hz: Some(16_000_000),
            ..TargetMetadata::default()
        },
    };
    let mut result =
        crate::host::parse("EM_SUMMARY schema:1 suite:test passed:1 failed:0\n").unwrap();

    enrich_result(&mut result, "campaign", "profile", &case, &environment);

    assert_eq!(result.identity.campaign.as_deref(), Some("campaign"));
    assert_eq!(result.identity.features, case.features);
    assert_eq!(result.source.git_commit.as_deref(), Some("abc123"));
    assert_eq!(result.target.probe.as_deref(), Some("serial"));
}

#[test]
fn unknown_case_selection_is_an_error() {
    let error = expand_cases(
        &matrix_campaign(),
        &CampaignSelection {
            quick: false,
            cases: vec!["missing".to_string()],
            silent: true,
        },
    )
    .unwrap_err();

    assert!(error.to_string().contains("produced no cases"));
}

#[cfg(unix)]
#[test]
fn executes_an_external_counter_campaign_end_to_end() {
    let workspace = std::env::temp_dir().join(format!(
        "krabi-caliper-campaign-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join("examples")).unwrap();
    std::fs::write(
        workspace.join("Cargo.toml"),
        r#"[package]
name = "external-campaign-fixture"
version = "0.0.0"
edition = "2024"
publish = false

[[example]]
name = "external-fixture"
path = "examples/external-fixture.rs"

[workspace]
"#,
    )
    .unwrap();
    std::fs::write(
        workspace.join("examples/external-fixture.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    let config: ToolkitConfig = toml::from_str(
        r#"
[profiles.external]
runner = "command"
target = "host"
executable = "sh"
require-external-measurements = true
timeout-seconds = 10
artifact-extension = ""
args = [
  "-c",
  "printf '%s\\n' 'EM_BOUNDARY schema:1 benchmark:external-fixture trial:0 phase:begin' 'EM_COUNTER schema:1 benchmark:external-fixture trial:0 phase:begin ticks:1000 width:32 unit:simulator-cycles frequency_hz:16000000 source:fixture-wrapper' 'EM_BOUNDARY schema:1 benchmark:external-fixture trial:0 phase:end status:PASS' 'EM_COUNTER schema:1 benchmark:external-fixture trial:0 phase:end ticks:1456 width:32 unit:simulator-cycles frequency_hz:16000000 source:fixture-wrapper' 'EM_OUTCOME schema:1 benchmark:external-fixture status:PASS'",
  "external-counter-wrapper",
  "{artifact}",
]

[campaigns.external]
profile = "external"
cases = [{ name = "external", example = "external-fixture", expected-benchmark = "external-fixture" }]
"#,
    )
    .unwrap();
    let output_dir = workspace.join("target/krabi-caliper/external");
    let _ = std::fs::remove_dir_all(&output_dir);

    let report = CampaignExecutor::default()
        .run(
            &config,
            "external",
            &workspace,
            &CampaignSelection::default(),
        )
        .unwrap();

    assert!(report.success());
    assert_eq!(report.cases[0].status, CaseStatus::Pass);
    assert_eq!(
        report.cases[0].result.as_ref().unwrap().benchmarks["external-fixture"].measurements[0]
            .ticks,
        456
    );
    assert!(output_dir.join("report.md").is_file());
    assert!(output_dir.join("report.csv").is_file());
    assert!(output_dir.join("results.json").is_file());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn executor_revalidates_declarative_input_before_running() {
    let config = parse(
        r#"
[profiles.qemu]
preset = "qemu-cortex-m3"
[campaigns.invalid]
profile = "qemu"
baseline-case = "missing"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let error = CampaignExecutor::default()
        .run(
            &config,
            "invalid",
            Path::new("."),
            &CampaignSelection::default(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("is not a case"));
}

#[test]
fn non_elf_artifacts_have_no_elf_footprint() {
    let path =
        std::env::temp_dir().join(format!("krabi-caliper-non-elf-test-{}", std::process::id()));
    std::fs::write(&path, b"MZ\0\0native executable").unwrap();

    assert_eq!(artifact_footprint(&path).unwrap(), None);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn simavr_preset_waits_for_a_terminal_outcome() {
    let config = parse(
        r#"
[profiles.avr]
preset = "simavr-atmega2560"
[campaigns.test]
profile = "avr"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let profile = config.resolve_profile("avr").unwrap();
    assert_eq!(profile.completion_marker.as_deref(), Some("EM_OUTCOME"));
}

#[cfg(unix)]
fn failure_workspace(name: &str, source: &str) -> PathBuf {
    let workspace =
        std::env::temp_dir().join(format!("krabi-caliper-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join("examples")).unwrap();
    std::fs::write(
        workspace.join("Cargo.toml"),
        r#"[package]
name = "campaign-failure-fixture"
version = "0.0.0"
edition = "2024"
publish = false

[[example]]
name = "fixture"
path = "examples/fixture.rs"

[workspace]
"#,
    )
    .unwrap();
    std::fs::write(workspace.join("examples/fixture.rs"), source).unwrap();
    workspace
}

#[cfg(unix)]
#[test]
fn build_failures_are_obvious_and_replace_stale_reports() {
    let workspace = failure_workspace(
        "build-failure-test",
        "compile_error!(\"deliberate build failure\");\nfn main() {}\n",
    );
    let stale_dir = workspace.join("target/krabi-caliper/failing/fixture");
    std::fs::create_dir_all(&stale_dir).unwrap();
    std::fs::write(stale_dir.join("report.md"), "# stale PASS report\n").unwrap();
    let config = parse(
        r#"
[profiles.host]
runner = "command"
target = "host"
executable = "sh"
args = ["-c", "exit 0"]

[campaigns.failing]
profile = "host"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let report = CampaignExecutor::default()
        .run(
            &config,
            "failing",
            &workspace,
            &CampaignSelection::default(),
        )
        .unwrap();

    assert_eq!(report.cases[0].status, CaseStatus::BuildFailed);
    let markdown = report.render_markdown();
    assert!(markdown.contains("## Failures"));
    assert!(markdown.contains("build command exited with status"));
    assert!(markdown.contains("cargo build"));
    assert!(markdown.contains("deliberate build failure"));
    let case_report = std::fs::read_to_string(stale_dir.join("report.md")).unwrap();
    assert!(case_report.starts_with("# Embedded measurement failure"));
    assert!(!case_report.contains("stale PASS"));
    std::fs::remove_dir_all(workspace).unwrap();
}

#[cfg(unix)]
#[test]
fn run_failures_show_the_command_reason_and_target_output() {
    let workspace = failure_workspace("run-failure-test", "fn main() {}\n");
    let config = parse(
        r#"
[profiles.host]
runner = "command"
target = "host"
executable = "sh"
args = ["-c", "printf 'first target line\\n'; printf '%07000d\\n' 0; printf 'PANIC: reporter rejected reserved field\\n'; printf 'emulator warning\\n' >&2; exit 7"]

[campaigns.failing]
profile = "host"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let report = CampaignExecutor::default()
        .run(
            &config,
            "failing",
            &workspace,
            &CampaignSelection::default(),
        )
        .unwrap();

    assert_eq!(report.cases[0].status, CaseStatus::RunFailed);
    let markdown = report.render_markdown();
    assert!(markdown.contains("runner command exited with status 7"));
    assert!(markdown.contains("sh -c"));
    assert!(markdown.contains("#### stdout"));
    assert!(markdown.contains("first target line"));
    assert!(markdown.contains("PANIC: reporter rejected reserved field"));
    assert!(markdown.contains("#### stderr"));
    assert!(markdown.contains("emulator warning"));
    assert!(report.cases[0].stdout.len() > 6_000);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[cfg(unix)]
#[test]
fn timeouts_report_the_command_and_elapsed_deadline() {
    let workspace = failure_workspace("timeout-test", "fn main() {}\n");
    let config = parse(
        r#"
[profiles.host]
runner = "command"
target = "host"
executable = "sh"
args = ["-c", "sleep 5"]
timeout-seconds = 1

[campaigns.failing]
profile = "host"
cases = [{ name = "fixture", example = "fixture" }]
"#,
    );

    let report = CampaignExecutor::default()
        .run(
            &config,
            "failing",
            &workspace,
            &CampaignSelection::default(),
        )
        .unwrap();

    assert_eq!(report.cases[0].status, CaseStatus::TimedOut);
    let markdown = report.render_markdown();
    assert!(markdown.contains("runner command timed out after"));
    assert!(markdown.contains("sh -c"));
    std::fs::remove_dir_all(workspace).unwrap();
}
