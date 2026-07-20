use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::format;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{CampaignReport, CaseReport, CaseStatus, MetricPolicy, OwnedUnit};

#[derive(Clone, Copy, Debug, Default)]
pub struct ComparisonPolicy {
    pub max_flash_increase: Option<u64>,
    pub max_static_ram_increase: Option<u64>,
    pub max_stack_increase: Option<u64>,
    pub max_ticks_increase: Option<u64>,
    pub max_percent_increase: Option<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    Pass,
    Regression,
    Incompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetricKind {
    Flash,
    StaticRam,
    Stack,
    Ticks,
    Application,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricComparison {
    pub name: String,
    pub kind: MetricKind,
    pub baseline: u64,
    pub current: u64,
    pub delta: i128,
    pub percent_delta: Option<f64>,
    pub allowed_increase: Option<u64>,
    pub policy: MetricPolicy,
    pub regression: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaseComparison {
    pub id: String,
    pub baseline_status: CaseStatus,
    pub current_status: CaseStatus,
    pub status_regression: bool,
    pub metrics: Vec<MetricComparison>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    pub case: Option<String>,
    pub field: String,
    pub baseline: String,
    pub current: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonWarning {
    pub case: Option<String>,
    pub field: String,
    pub baseline: String,
    pub current: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub baseline_path: PathBuf,
    pub current_path: PathBuf,
    pub campaign: String,
    pub profile: String,
    pub status: ComparisonStatus,
    pub incompatibilities: Vec<CompatibilityIssue>,
    pub warnings: Vec<ComparisonWarning>,
    pub cases: Vec<CaseComparison>,
}

impl ComparisonReport {
    pub fn success(&self) -> bool {
        self.status == ComparisonStatus::Pass
    }

    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn render_csv(&self) -> String {
        let mut output = String::from(
            "case,metric,kind,policy,baseline,current,delta,delta_percent,allowed,status\n",
        );
        for case in &self.cases {
            for metric in &case.metrics {
                writeln!(
                    output,
                    "{},{},{},{},{},{},{},{},{},{}",
                    csv(&case.id),
                    csv(&metric.name),
                    metric_kind_name(metric.kind),
                    metric_policy_name(metric.policy),
                    metric.baseline,
                    metric.current,
                    metric.delta,
                    metric
                        .percent_delta
                        .map_or_else(String::new, |value| value.to_string()),
                    metric
                        .allowed_increase
                        .map_or_else(String::new, |value| value.to_string()),
                    if metric.regression {
                        "REGRESSION"
                    } else {
                        "PASS"
                    },
                )
                .unwrap();
            }
        }
        output
    }

    pub fn render_markdown(&self) -> String {
        let mut output = String::from("# Embedded measurement comparison\n\n");
        writeln!(output, "- Campaign: `{}`", self.campaign).unwrap();
        writeln!(output, "- Profile: `{}`", self.profile).unwrap();
        writeln!(output, "- Baseline: `{}`", self.baseline_path.display()).unwrap();
        writeln!(output, "- Current: `{}`", self.current_path.display()).unwrap();
        writeln!(output, "- Status: **{:?}**", self.status).unwrap();
        if !self.incompatibilities.is_empty() {
            output.push_str("\n## Incompatible evidence\n\n");
            output.push_str("| Case | Field | Baseline | Current |\n|---|---|---|---|\n");
            for issue in &self.incompatibilities {
                writeln!(
                    output,
                    "| {} | {} | {} | {} |",
                    issue.case.as_deref().unwrap_or("—"),
                    issue.field,
                    issue.baseline,
                    issue.current
                )
                .unwrap();
            }
        }
        if !self.warnings.is_empty() {
            output.push_str("\n## Environment warnings\n\n");
            output.push_str("| Case | Field | Baseline | Current |\n|---|---|---|---|\n");
            for warning in &self.warnings {
                writeln!(
                    output,
                    "| {} | {} | {} | {} |",
                    warning.case.as_deref().unwrap_or("—"),
                    warning.field,
                    warning.baseline,
                    warning.current
                )
                .unwrap();
            }
        }
        if !self.cases.is_empty() {
            output.push_str("\n## Metric deltas\n\n");
            output.push_str(
                "| Case | Metric | Policy | Baseline | Current | Delta | Delta % | Allowed | Status |\n",
            );
            output.push_str("|---|---|---|---:|---:|---:|---:|---:|---|\n");
            for case in &self.cases {
                for metric in &case.metrics {
                    let percent = metric
                        .percent_delta
                        .map(|value| format!("{value:.3}%"))
                        .unwrap_or_else(|| "—".to_string());
                    writeln!(
                        output,
                        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                        case.id,
                        metric.name,
                        metric_policy_name(metric.policy),
                        metric.baseline,
                        metric.current,
                        metric.delta,
                        percent,
                        metric
                            .allowed_increase
                            .map_or_else(|| "—".to_string(), |value| value.to_string()),
                        if metric.regression {
                            "REGRESSION"
                        } else {
                            "PASS"
                        }
                    )
                    .unwrap();
                }
                if case.status_regression {
                    writeln!(
                        output,
                        "| {} | gate-status | — | {:?} | {:?} | — | — | — | REGRESSION |",
                        case.id, case.baseline_status, case.current_status
                    )
                    .unwrap();
                }
            }
        }
        output
    }
}

fn csv(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn metric_policy_name(policy: MetricPolicy) -> &'static str {
    match policy {
        MetricPolicy::LowerIsBetter => "lower-is-better",
        MetricPolicy::HigherIsBetter => "higher-is-better",
        MetricPolicy::Informational => "informational",
    }
}

fn metric_kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Flash => "flash",
        MetricKind::StaticRam => "static-ram",
        MetricKind::Stack => "stack",
        MetricKind::Ticks => "ticks",
        MetricKind::Application => "application",
    }
}

pub fn compare_campaigns(
    baseline_path: impl Into<PathBuf>,
    baseline: &CampaignReport,
    current_path: impl Into<PathBuf>,
    current: &CampaignReport,
    policy: ComparisonPolicy,
) -> ComparisonReport {
    let baseline_path = baseline_path.into();
    let current_path = current_path.into();
    let mut incompatibilities = Vec::new();
    let mut warnings = Vec::new();
    compare_required(
        &mut incompatibilities,
        None,
        "campaign",
        &baseline.campaign,
        &current.campaign,
    );
    compare_required(
        &mut incompatibilities,
        None,
        "profile",
        &baseline.profile,
        &current.profile,
    );
    let baseline_cases = baseline
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let current_cases = current
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    if baseline_cases.len() != baseline.cases.len() {
        incompatibilities.push(CompatibilityIssue {
            case: None,
            field: "baseline-case-ids".to_string(),
            baseline: "unique".to_string(),
            current: "duplicates present".to_string(),
        });
    }
    if current_cases.len() != current.cases.len() {
        incompatibilities.push(CompatibilityIssue {
            case: None,
            field: "current-case-ids".to_string(),
            baseline: "unique".to_string(),
            current: "duplicates present".to_string(),
        });
    }
    let all_ids = baseline_cases
        .keys()
        .chain(current_cases.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for id in &all_ids {
        match (baseline_cases.get(id), current_cases.get(id)) {
            (Some(_), None) => incompatibilities.push(CompatibilityIssue {
                case: Some((*id).to_string()),
                field: "case".to_string(),
                baseline: "present".to_string(),
                current: "missing".to_string(),
            }),
            (None, Some(_)) => incompatibilities.push(CompatibilityIssue {
                case: Some((*id).to_string()),
                field: "case".to_string(),
                baseline: "missing".to_string(),
                current: "present".to_string(),
            }),
            (Some(baseline_case), Some(current_case)) => compare_environments(
                &mut incompatibilities,
                &mut warnings,
                baseline_case,
                current_case,
            ),
            (None, None) => unreachable!(),
        }
    }
    let cases = if incompatibilities.is_empty() {
        all_ids
            .into_iter()
            .map(|id| compare_case(baseline_cases[id], current_cases[id], policy))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let regression = cases
        .iter()
        .any(|case| case.status_regression || case.metrics.iter().any(|metric| metric.regression));
    let status = if !incompatibilities.is_empty() {
        ComparisonStatus::Incompatible
    } else if regression {
        ComparisonStatus::Regression
    } else {
        ComparisonStatus::Pass
    };
    ComparisonReport {
        baseline_path,
        current_path,
        campaign: current.campaign.clone(),
        profile: current.profile.clone(),
        status,
        incompatibilities,
        warnings,
        cases,
    }
}

fn compare_environments(
    issues: &mut Vec<CompatibilityIssue>,
    warnings: &mut Vec<ComparisonWarning>,
    baseline: &CaseReport,
    current: &CaseReport,
) {
    let case = Some(current.id.clone());
    compare_required(issues, case.clone(), "name", &baseline.name, &current.name);
    compare_required(
        issues,
        case.clone(),
        "cargo-target",
        &format!("{:?}", baseline.cargo_target),
        &format!("{:?}", current.cargo_target),
    );
    compare_required(
        issues,
        case.clone(),
        "parameters",
        &format!("{:?}", baseline.parameters),
        &format!("{:?}", current.parameters),
    );
    compare_required(
        issues,
        case.clone(),
        "features",
        &format!("{:?}", baseline.features),
        &format!("{:?}", current.features),
    );
    let b = &baseline.environment;
    let c = &current.environment;
    for (field, baseline, current) in [
        ("repository", &b.source.repository, &c.source.repository),
        ("build-target", &b.build.target, &c.build.target),
        (
            "build-profile",
            &b.build.optimization,
            &c.build.optimization,
        ),
        ("target", &b.target.target, &c.target.target),
        ("board", &b.target.board, &c.target.board),
        ("mcu", &b.target.mcu, &c.target.mcu),
        ("runner", &b.target.runner, &c.target.runner),
        ("transport", &b.target.transport, &c.target.transport),
    ] {
        compare_required_option(issues, case.clone(), field, baseline, current);
    }
    for (field, baseline, current) in [
        ("venue", &b.target.venue, &c.target.venue),
        (
            "host-usb-path",
            &b.target.host_usb_path,
            &c.target.host_usb_path,
        ),
        (
            "configuration-identity",
            &b.target.configuration_identity,
            &c.target.configuration_identity,
        ),
    ] {
        if baseline.is_some() || current.is_some() {
            compare_required_option(issues, case.clone(), field, baseline, current);
        }
    }
    compare_required(
        issues,
        case.clone(),
        "build-features",
        &b.build.features,
        &c.build.features,
    );
    compare_required(
        issues,
        case.clone(),
        "clock-frequency-hz",
        &b.target.clock_frequency_hz,
        &c.target.clock_frequency_hz,
    );
    compare_required(
        issues,
        case.clone(),
        "capabilities",
        &b.target.capabilities,
        &c.target.capabilities,
    );
    compare_required(
        issues,
        case.clone(),
        "controlled-environment",
        &b.target.controlled_environment,
        &c.target.controlled_environment,
    );
    for (label, value) in [("baseline", b.source.dirty), ("current", c.source.dirty)] {
        if value != Some(false) {
            issues.push(CompatibilityIssue {
                case: case.clone(),
                field: format!("{label}-source-dirty"),
                baseline: "false".to_string(),
                current: option_string(&value),
            });
        }
    }
    if baseline.status != CaseStatus::Pass {
        issues.push(CompatibilityIssue {
            case: case.clone(),
            field: "baseline-status".to_string(),
            baseline: format!("{:?}", baseline.status),
            current: "Pass required".to_string(),
        });
    }
    for (field, baseline, current) in [
        ("toolchain", &b.build.toolchain, &c.build.toolchain),
        ("rustc", &b.build.rustc, &c.build.rustc),
        ("cargo", &b.build.cargo, &c.build.cargo),
        (
            "runner-version",
            &b.target.runner_version,
            &c.target.runner_version,
        ),
        ("probe", &b.target.probe, &c.target.probe),
    ] {
        compare_warning(warnings, case.clone(), field, baseline, current);
    }
    let baseline_metrics = metrics(baseline).into_keys().collect::<BTreeSet<_>>();
    let current_metrics = metrics(current).into_keys().collect::<BTreeSet<_>>();
    compare_required(
        issues,
        case.clone(),
        "metric-set",
        &baseline_metrics,
        &current_metrics,
    );
    let baseline_policies = metrics(baseline)
        .into_iter()
        .map(|(name, (_, _, policy))| (name, policy))
        .collect::<BTreeMap<_, _>>();
    let current_policies = metrics(current)
        .into_iter()
        .map(|(name, (_, _, policy))| (name, policy))
        .collect::<BTreeMap<_, _>>();
    compare_required(
        issues,
        case,
        "metric-policy",
        &baseline_policies,
        &current_policies,
    );
}

fn compare_case(
    baseline: &CaseReport,
    current: &CaseReport,
    policy: ComparisonPolicy,
) -> CaseComparison {
    let baseline_metrics = metrics(baseline);
    let current_metrics = metrics(current);
    let names = baseline_metrics
        .keys()
        .chain(current_metrics.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let metrics = names
        .into_iter()
        .filter_map(|name| {
            let (kind, baseline, metric_policy) = baseline_metrics.get(&name)?;
            let (_, current, current_policy) = current_metrics.get(&name)?;
            if metric_policy != current_policy {
                return None;
            }
            let allowed = match kind {
                MetricKind::Flash => policy.max_flash_increase,
                MetricKind::StaticRam => policy.max_static_ram_increase,
                MetricKind::Stack => policy.max_stack_increase,
                MetricKind::Ticks => policy.max_ticks_increase,
                MetricKind::Application => None,
            };
            let delta = i128::from(*current) - i128::from(*baseline);
            let percent_delta = (*baseline != 0).then_some(delta as f64 * 100.0 / *baseline as f64);
            let absolute_regression = allowed.is_some_and(|limit| delta > i128::from(limit));
            let percent_regression = match (policy.max_percent_increase, percent_delta) {
                (Some(limit), Some(percent)) => percent > limit,
                (Some(_), None) if delta > 0 => {
                    allowed.is_none_or(|limit| delta > i128::from(limit))
                }
                _ => false,
            };
            let regression = match metric_policy {
                MetricPolicy::Informational => false,
                MetricPolicy::LowerIsBetter => {
                    if allowed.is_none() && policy.max_percent_increase.is_none() {
                        delta > 0
                    } else {
                        absolute_regression || percent_regression
                    }
                }
                MetricPolicy::HigherIsBetter => delta < 0,
            };
            Some(MetricComparison {
                name,
                kind: *kind,
                baseline: *baseline,
                current: *current,
                delta,
                percent_delta,
                allowed_increase: allowed,
                policy: *metric_policy,
                regression,
            })
        })
        .collect();
    CaseComparison {
        id: current.id.clone(),
        baseline_status: baseline.status,
        current_status: current.status,
        status_regression: current.status != CaseStatus::Pass,
        metrics,
    }
}

fn metrics(case: &CaseReport) -> BTreeMap<String, (MetricKind, u64, MetricPolicy)> {
    let mut metrics = BTreeMap::new();
    if let Some(footprint) = case.footprint {
        metrics.insert(
            "flash-bytes".to_string(),
            (
                MetricKind::Flash,
                footprint.flash_bytes,
                MetricPolicy::LowerIsBetter,
            ),
        );
        metrics.insert(
            "static-ram-bytes".to_string(),
            (
                MetricKind::StaticRam,
                footprint.static_ram_bytes,
                MetricPolicy::LowerIsBetter,
            ),
        );
    }
    if let Some(result) = &case.result {
        for (benchmark, result) in &result.benchmarks {
            if let Some(stack) = result.stacks.iter().map(|value| value.used as u64).max() {
                metrics.insert(
                    format!("stack:{benchmark}"),
                    (MetricKind::Stack, stack, MetricPolicy::LowerIsBetter),
                );
            }
            for (sample, measurement) in result.measurements.iter().enumerate() {
                let counter = measurement
                    .fields
                    .get("counter")
                    .map(String::as_str)
                    .unwrap_or("primary");
                metrics.insert(
                    format!(
                        "ticks:{benchmark}:{counter}:{}:sample:{sample}",
                        unit_name(measurement.unit),
                    ),
                    (
                        MetricKind::Ticks,
                        measurement.ticks,
                        MetricPolicy::LowerIsBetter,
                    ),
                );
            }
            for (sample, metric) in result.metrics.iter().enumerate() {
                metrics.insert(
                    format!(
                        "metric:{benchmark}:{}:{}:sample:{sample}",
                        metric.name,
                        metric.unit.as_deref().unwrap_or("none"),
                    ),
                    (MetricKind::Application, metric.value, metric.policy),
                );
            }
        }
    }
    metrics
}

fn compare_required<T: core::fmt::Debug + PartialEq>(
    issues: &mut Vec<CompatibilityIssue>,
    case: Option<String>,
    field: &str,
    baseline: &T,
    current: &T,
) {
    if baseline != current {
        issues.push(CompatibilityIssue {
            case,
            field: field.to_string(),
            baseline: format!("{baseline:?}"),
            current: format!("{current:?}"),
        });
    }
}

fn compare_required_option<T: core::fmt::Debug + PartialEq>(
    issues: &mut Vec<CompatibilityIssue>,
    case: Option<String>,
    field: &str,
    baseline: &Option<T>,
    current: &Option<T>,
) {
    if baseline.is_none() || current.is_none() || baseline != current {
        issues.push(CompatibilityIssue {
            case,
            field: field.to_string(),
            baseline: format!("{baseline:?}"),
            current: format!("{current:?}"),
        });
    }
}

fn compare_warning<T: core::fmt::Debug + PartialEq>(
    warnings: &mut Vec<ComparisonWarning>,
    case: Option<String>,
    field: &str,
    baseline: &T,
    current: &T,
) {
    if baseline != current {
        warnings.push(ComparisonWarning {
            case,
            field: field.to_string(),
            baseline: format!("{baseline:?}"),
            current: format!("{current:?}"),
        });
    }
}

fn option_string<T: core::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

fn unit_name(unit: OwnedUnit) -> &'static str {
    match unit {
        OwnedUnit::CoreCycles => "core-cycles",
        OwnedUnit::TimerTicks => "timer-ticks",
        OwnedUnit::Instructions => "instructions",
        OwnedUnit::SimulatorCycles => "simulator-cycles",
    }
}

pub fn read_campaign(path: &Path) -> Result<CampaignReport, Box<dyn std::error::Error>> {
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{
        BenchmarkResult, BuildMetadata, CargoTarget, ElfFootprint, MeasurementEvent, MetricEvent,
        ReproducibilityMetadata, RunResult, SourceMetadata, StackEvent, TargetMetadata,
    };
    use std::vec;

    fn campaign() -> CampaignReport {
        let mut result = RunResult::default();
        result.benchmarks.insert(
            "bench".to_string(),
            BenchmarkResult {
                measurements: vec![MeasurementEvent {
                    schema: 1,
                    benchmark: "bench".to_string(),
                    ticks: 1_000,
                    unit: OwnedUnit::CoreCycles,
                    frequency_hz: Some(16_000_000),
                    wrapped: false,
                    fields: BTreeMap::from([("counter".to_string(), "dwt".to_string())]),
                }],
                stacks: vec![StackEvent {
                    schema: 1,
                    benchmark: "bench".to_string(),
                    used: 512,
                    available: 4096,
                    painted: 3584,
                    safe_zone: 128,
                    overflowed: false,
                    fields: BTreeMap::new(),
                }],
                metrics: Vec::new(),
            },
        );
        CampaignReport {
            campaign: "campaign".to_string(),
            profile: "profile".to_string(),
            cases: vec![CaseReport {
                id: "case".to_string(),
                name: "case".to_string(),
                cargo_target: CargoTarget::Example("fixture".to_string()),
                environment: ReproducibilityMetadata {
                    recorded_unix_seconds: 1,
                    source: SourceMetadata {
                        workspace: Some("/repo".to_string()),
                        repository: Some("https://example.invalid/repo".to_string()),
                        git_commit: Some("abc".to_string()),
                        dirty: Some(false),
                    },
                    build: BuildMetadata {
                        toolchain: Some("stable".to_string()),
                        rustc: Some("rustc 1".to_string()),
                        cargo: Some("cargo 1".to_string()),
                        target: Some("thumbv7em-none-eabihf".to_string()),
                        optimization: Some("release".to_string()),
                        features: vec!["fixture".to_string()],
                    },
                    target: TargetMetadata {
                        target: Some("thumbv7em-none-eabihf".to_string()),
                        board: Some("board".to_string()),
                        mcu: Some("mcu".to_string()),
                        runner: Some("probe-rs".to_string()),
                        runner_version: Some("probe-rs 1".to_string()),
                        transport: Some("rtt".to_string()),
                        probe: Some("serial".to_string()),
                        clock_frequency_hz: Some(16_000_000),
                        ..TargetMetadata::default()
                    },
                },
                features: vec!["fixture".to_string()],
                parameters: BTreeMap::new(),
                artifact: Some(PathBuf::from("firmware")),
                footprint: Some(ElfFootprint {
                    flash_bytes: 10_000,
                    static_ram_bytes: 2_000,
                    ..ElfFootprint::default()
                }),
                baseline: None,
                build_command: "cargo build".to_string(),
                prepare_commands: Vec::new(),
                delay_before_run_seconds: None,
                run_command: Some("probe-rs run".to_string()),
                build_duration_ms: 1,
                run_duration_ms: Some(1),
                status: CaseStatus::Pass,
                error: None,
                result: Some(result),
            }],
        }
    }

    fn compare(baseline: &CampaignReport, current: &CampaignReport) -> ComparisonReport {
        compare_campaigns(
            "baseline.json",
            baseline,
            "current.json",
            current,
            ComparisonPolicy::default(),
        )
    }

    #[test]
    fn identical_campaigns_pass_and_round_trip() {
        let campaign = campaign();
        let decoded: CampaignReport =
            serde_json::from_str(&serde_json::to_string(&campaign).unwrap()).unwrap();
        let report = compare(&campaign, &decoded);

        assert_eq!(report.status, ComparisonStatus::Pass);
        assert_eq!(report.cases[0].metrics.len(), 4);
        assert!(report.render_markdown().contains("**Pass**"));
        let csv = report.render_csv();
        assert!(csv.starts_with("case,metric,kind,policy,"));
        assert!(csv.contains("flash-bytes,flash,lower-is-better"));
        let campaign_csv = campaign.render_csv();
        assert!(campaign_csv.starts_with("campaign,profile,case,status,"));
        assert!(campaign_csv.contains("flash-bytes,10000,bytes,lower-is-better"));
    }

    #[test]
    fn metric_growth_is_a_regression_unless_allowed() {
        let baseline = campaign();
        let mut current = baseline.clone();
        current.cases[0].footprint.as_mut().unwrap().flash_bytes += 8;

        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Regression
        );
        let report = compare_campaigns(
            "baseline.json",
            &baseline,
            "current.json",
            &current,
            ComparisonPolicy {
                max_flash_increase: Some(8),
                ..ComparisonPolicy::default()
            },
        );
        assert_eq!(report.status, ComparisonStatus::Pass);

        let report = compare_campaigns(
            "baseline.json",
            &baseline,
            "current.json",
            &current,
            ComparisonPolicy {
                max_percent_increase: Some(0.1),
                ..ComparisonPolicy::default()
            },
        );
        assert_eq!(report.status, ComparisonStatus::Pass);
    }

    #[test]
    fn application_metrics_share_baseline_comparison() {
        let mut baseline = campaign();
        baseline.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics
            .push(MetricEvent {
                schema: 1,
                benchmark: "bench".to_string(),
                name: "bytes".to_string(),
                value: 512,
                unit: Some("bytes".to_string()),
                policy: MetricPolicy::LowerIsBetter,
                fields: BTreeMap::new(),
            });
        baseline.cases[0].result.as_mut().unwrap().metrics =
            baseline.cases[0].result.as_ref().unwrap().benchmarks["bench"]
                .metrics
                .clone();
        let mut current = baseline.clone();
        current.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics[0]
            .value = 513;

        let report = compare(&baseline, &current);
        let metric = report.cases[0]
            .metrics
            .iter()
            .find(|value| value.name == "metric:bench:bytes:bytes:sample:0")
            .unwrap();
        assert_eq!(metric.kind, MetricKind::Application);
        assert!(metric.regression);
    }

    #[test]
    fn application_metric_policy_controls_gating_and_must_match() {
        let mut baseline = campaign();
        let metric = MetricEvent {
            schema: 1,
            benchmark: "bench".to_string(),
            name: "throughput".to_string(),
            value: 100,
            unit: Some("items-per-second".to_string()),
            policy: MetricPolicy::HigherIsBetter,
            fields: BTreeMap::new(),
        };
        baseline.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics
            .push(metric.clone());
        baseline.cases[0]
            .result
            .as_mut()
            .unwrap()
            .metrics
            .push(metric);

        let mut faster = baseline.clone();
        faster.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics[0]
            .value = 101;
        faster.cases[0].result.as_mut().unwrap().metrics[0].value = 101;
        assert_eq!(compare(&baseline, &faster).status, ComparisonStatus::Pass);

        let mut slower = baseline.clone();
        slower.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics[0]
            .value = 99;
        slower.cases[0].result.as_mut().unwrap().metrics[0].value = 99;
        assert_eq!(
            compare(&baseline, &slower).status,
            ComparisonStatus::Regression
        );

        let mut changed_policy = baseline.clone();
        changed_policy.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .metrics[0]
            .policy = MetricPolicy::Informational;
        changed_policy.cases[0].result.as_mut().unwrap().metrics[0].policy =
            MetricPolicy::Informational;
        assert_eq!(
            compare(&baseline, &changed_policy).status,
            ComparisonStatus::Incompatible
        );
    }

    #[test]
    fn repeated_measurements_and_metrics_keep_sample_identity() {
        let mut baseline = campaign();
        let benchmark = baseline.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap();
        benchmark
            .measurements
            .push(benchmark.measurements[0].clone());
        let metric = MetricEvent {
            schema: 1,
            benchmark: "bench".to_string(),
            name: "bytes".to_string(),
            value: 10,
            unit: Some("bytes".to_string()),
            policy: MetricPolicy::LowerIsBetter,
            fields: BTreeMap::new(),
        };
        benchmark.metrics.extend([metric.clone(), metric]);

        let mut current = baseline.clone();
        let benchmark = current.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap();
        benchmark.measurements[0].ticks += 1;
        benchmark.metrics[0].value += 1;

        let report = compare(&baseline, &current);
        assert_eq!(report.status, ComparisonStatus::Regression);
        assert!(
            report.cases[0]
                .metrics
                .iter()
                .any(|metric| metric.name.ends_with("sample:0") && metric.regression)
        );

        current.cases[0]
            .result
            .as_mut()
            .unwrap()
            .benchmarks
            .get_mut("bench")
            .unwrap()
            .measurements
            .pop();
        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Incompatible
        );
    }

    #[test]
    fn zero_baseline_growth_requires_an_absolute_allowance() {
        let mut baseline = campaign();
        baseline.cases[0].footprint.as_mut().unwrap().flash_bytes = 0;
        let mut current = baseline.clone();
        current.cases[0].footprint.as_mut().unwrap().flash_bytes = 1;

        let percent_only = ComparisonPolicy {
            max_percent_increase: Some(100.0),
            ..ComparisonPolicy::default()
        };
        assert_eq!(
            compare_campaigns("baseline", &baseline, "current", &current, percent_only).status,
            ComparisonStatus::Regression
        );

        let with_absolute_allowance = ComparisonPolicy {
            max_flash_increase: Some(1),
            max_percent_increase: Some(100.0),
            ..ComparisonPolicy::default()
        };
        assert_eq!(
            compare_campaigns(
                "baseline",
                &baseline,
                "current",
                &current,
                with_absolute_allowance,
            )
            .status,
            ComparisonStatus::Pass
        );
    }

    #[test]
    fn rejects_environment_and_case_set_mismatches() {
        let baseline = campaign();
        let mut current = baseline.clone();
        current.cases[0].environment.target.mcu = Some("other".to_string());
        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Incompatible
        );

        let mut current = baseline.clone();
        current.cases.push(current.cases[0].clone());
        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Incompatible
        );

        let mut current = baseline.clone();
        current.cases.push(current.cases[0].clone());
        current.cases[1].id = "extra".to_string();
        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Incompatible
        );
    }

    #[test]
    fn missing_required_environment_evidence_is_incompatible() {
        let mut baseline = campaign();
        baseline.cases[0].environment.target.mcu = None;
        let current = baseline.clone();

        let report = compare(&baseline, &current);
        assert_eq!(report.status, ComparisonStatus::Incompatible);
        assert!(
            report
                .incompatibilities
                .iter()
                .any(|issue| issue.field == "mcu")
        );
    }

    #[test]
    fn rejects_dirty_evidence_but_only_warns_on_tool_versions() {
        let baseline = campaign();
        let mut current = baseline.clone();
        current.cases[0].environment.source.dirty = Some(true);
        assert_eq!(
            compare(&baseline, &current).status,
            ComparisonStatus::Incompatible
        );

        let mut current = baseline.clone();
        current.cases[0].environment.build.rustc = Some("rustc 2".to_string());
        let report = compare(&baseline, &current);
        assert_eq!(report.status, ComparisonStatus::Pass);
        assert_eq!(report.warnings[0].field, "rustc");
    }

    #[test]
    fn rejects_different_controlled_configuration_identities() {
        let mut baseline = campaign();
        baseline.cases[0].environment.target.configuration_identity =
            Some("kernel=stock;probe-rs=0.30".to_string());
        let mut current = baseline.clone();
        current.cases[0].environment.target.configuration_identity =
            Some("kernel=preempt-rt;probe-rs=0.30".to_string());

        let report = compare(&baseline, &current);
        assert_eq!(report.status, ComparisonStatus::Incompatible);
        assert!(
            report
                .incompatibilities
                .iter()
                .any(|issue| issue.field == "configuration-identity")
        );
    }

    #[test]
    fn a_current_gate_failure_is_a_regression() {
        let baseline = campaign();
        let mut current = baseline.clone();
        current.cases[0].status = CaseStatus::WorkloadFail;

        let report = compare(&baseline, &current);
        assert_eq!(report.status, ComparisonStatus::Regression);
        assert!(
            report.render_markdown().contains(
                "| case | gate-status | — | Pass | WorkloadFail | — | — | — | REGRESSION |"
            )
        );
    }
}
