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
