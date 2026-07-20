#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedCase {
    pub id: String,
    pub name: String,
    pub cargo_target: CargoTarget,
    pub features: Vec<String>,
    pub parameters: BTreeMap<String, String>,
    pub expected_benchmark: Option<String>,
    pub expected_suite: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub delay_before_run_seconds: Option<u64>,
    pub baseline: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "kebab-case")]
pub enum CargoTarget {
    Example(String),
    Binary(String),
}

impl CargoTarget {
    fn name(&self) -> &str {
        match self {
            Self::Example(value) | Self::Binary(value) => value,
        }
    }

    fn cargo_flag(&self) -> &'static str {
        match self {
            Self::Example(_) => "--example",
            Self::Binary(_) => "--bin",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatus {
    Pass,
    WorkloadFail,
    MeasurementError,
    BuildFailed,
    RunFailed,
    TimedOut,
    ProtocolError,
    MissingTerminalRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseReport {
    pub id: String,
    pub name: String,
    pub cargo_target: CargoTarget,
    pub environment: ReproducibilityMetadata,
    pub features: Vec<String>,
    pub parameters: BTreeMap<String, String>,
    pub artifact: Option<PathBuf>,
    pub footprint: Option<ElfFootprint>,
    pub baseline: Option<String>,
    pub build_command: String,
    #[serde(default)]
    pub prepare_commands: Vec<String>,
    #[serde(default)]
    pub delay_before_run_seconds: Option<u64>,
    pub run_command: Option<String>,
    pub build_duration_ms: u128,
    pub run_duration_ms: Option<u128>,
    pub status: CaseStatus,
    pub error: Option<String>,
    pub result: Option<RunResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReproducibilityMetadata {
    pub recorded_unix_seconds: u64,
    pub source: SourceMetadata,
    pub build: BuildMetadata,
    pub target: TargetMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CampaignReport {
    pub campaign: String,
    pub profile: String,
    pub cases: Vec<CaseReport>,
}

impl CampaignReport {
    pub fn success(&self) -> bool {
        self.cases
            .iter()
            .all(|case| case.status == CaseStatus::Pass)
    }

    pub fn render_markdown(&self) -> String {
        let mut output = String::from("# Embedded measurement campaign\n\n");
        output.push_str(&format!("- Campaign: `{}`\n", self.campaign));
        output.push_str(&format!("- Profile: `{}`\n", self.profile));
        output.push_str(&format!(
            "- Status: **{}**\n\n",
            if self.success() { "PASS" } else { "FAIL" }
        ));
        if let Some(environment) = self.cases.first().map(|case| &case.environment) {
            output.push_str(&format!(
                "- Source commit: `{}`\n- Source dirty: `{}`\n- Build target: `{}`\n- Build profile: `{}`\n- Runner: `{}`\n\n",
                environment.source.git_commit.as_deref().unwrap_or("unknown"),
                environment
                    .source
                    .dirty
                    .map_or("unknown", |value| if value { "yes" } else { "no" }),
                environment.build.target.as_deref().unwrap_or("unknown"),
                environment
                    .build
                    .optimization
                    .as_deref()
                    .unwrap_or("unknown"),
                environment.target.runner.as_deref().unwrap_or("unknown"),
            ));
            if let Some(venue) = &environment.target.venue {
                output.push_str(&format!("- Venue: `{venue}`\n"));
            }
            if let Some(identity) = &environment.target.configuration_identity {
                output.push_str(&format!("- Configuration identity: `{identity}`\n\n"));
            }
        }
        output.push_str(
            "| Case | Parameters | Status | Flash | Δ Flash | Static RAM | Stack | Δ Stack | Measurements | Metrics | Δ Ticks |\n",
        );
        output.push_str("|---|---|---|---:|---:|---:|---:|---:|---|---|---:|\n");
        for case in &self.cases {
            let parameters = case
                .parameters
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ");
            let (stack, measurements, metrics) = case.result.as_ref().map_or_else(
                || ("—".to_string(), "—".to_string(), "—".to_string()),
                |result| {
                    let stack = result
                        .benchmarks
                        .values()
                        .flat_map(|value| &value.stacks)
                        .map(|value| value.used)
                        .max()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "—".to_string());
                    let measurements = result
                        .benchmarks
                        .values()
                        .flat_map(|value| &value.measurements)
                        .map(|value| format!("{} {}", value.ticks, unit_name(value.unit)))
                        .collect::<Vec<_>>()
                        .join("<br>");
                    let metrics = result
                        .metrics
                        .iter()
                        .map(|value| {
                            format!(
                                "{}={}{} ({})",
                                value.name,
                                value.value,
                                value
                                    .unit
                                    .as_deref()
                                    .map(|unit| format!(" {unit}"))
                                    .unwrap_or_default(),
                                metric_policy(value.policy),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("<br>");
                    (
                        stack,
                        measurements,
                        if metrics.is_empty() {
                            "—".to_string()
                        } else {
                            metrics
                        },
                    )
                },
            );
            let baseline = case
                .baseline
                .as_ref()
                .and_then(|id| self.cases.iter().find(|candidate| &candidate.id == id));
            output.push_str(&format!(
                "| {} | {} | {:?} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                case.id,
                parameters,
                case.status,
                case.footprint
                    .map_or_else(|| "—".to_string(), |value| value.flash_bytes.to_string()),
                delta(
                    case.footprint.map(|value| value.flash_bytes),
                    baseline.and_then(|value| value.footprint.map(|value| value.flash_bytes))
                ),
                case.footprint.map_or_else(
                    || "—".to_string(),
                    |value| value.static_ram_bytes.to_string()
                ),
                stack,
                delta(case_stack(case), baseline.and_then(case_stack)),
                measurements,
                metrics,
                delta(primary_ticks(case), baseline.and_then(primary_ticks)),
            ));
        }
        if self.cases.iter().any(|case| {
            case.result
                .as_ref()
                .is_some_and(|result| !result.welch_analyses.is_empty())
        }) {
            output.push_str("\n## Welch t-test evidence\n\n");
            output.push_str("| Case | Fixture | Class | nA/nB | t | df | Threshold | Verdict |\n");
            output.push_str("|---|---|---|---:|---:|---:|---:|---|\n");
            for case in &self.cases {
                if let Some(result) = &case.result {
                    for analysis in &result.welch_analyses {
                        output.push_str(&format!(
                            "| {} | {} | {} | {}/{} | {} | {} | {:.2} | {:?} |\n",
                            case.id,
                            analysis.fixture,
                            analysis.class,
                            analysis.a_samples,
                            analysis.b_samples,
                            analysis
                                .t_statistic
                                .map_or_else(|| "—".to_string(), |value| format!("{value:.3}")),
                            analysis
                                .degrees_of_freedom
                                .map_or_else(|| "—".to_string(), |value| format!("{value:.1}")),
                            analysis.threshold,
                            analysis.verdict,
                        ));
                    }
                }
            }
        }
        output
    }

    /// Long-form CSV: one row per footprint, stack, counter, or application metric.
    pub fn render_csv(&self) -> String {
        let mut output =
            String::from("campaign,profile,case,status,benchmark,kind,name,value,unit,policy\n");
        for case in &self.cases {
            let mut row =
                |benchmark: &str, kind: &str, name: &str, value: u64, unit: &str, policy: &str| {
                    output.push_str(&format!(
                        "{},{},{},{:?},{},{},{},{},{},{}\n",
                        csv_field(&self.campaign),
                        csv_field(&self.profile),
                        csv_field(&case.id),
                        case.status,
                        csv_field(benchmark),
                        kind,
                        csv_field(name),
                        value,
                        csv_field(unit),
                        policy,
                    ));
                };
            if let Some(footprint) = case.footprint {
                row(
                    "",
                    "footprint",
                    "flash-bytes",
                    footprint.flash_bytes,
                    "bytes",
                    "lower-is-better",
                );
                row(
                    "",
                    "footprint",
                    "static-ram-bytes",
                    footprint.static_ram_bytes,
                    "bytes",
                    "lower-is-better",
                );
            }
            if let Some(result) = &case.result {
                for (benchmark, result) in &result.benchmarks {
                    for stack in &result.stacks {
                        row(
                            benchmark,
                            "stack",
                            "high-water",
                            stack.used as u64,
                            "bytes",
                            "lower-is-better",
                        );
                    }
                    for measurement in &result.measurements {
                        row(
                            benchmark,
                            "measurement",
                            measurement
                                .fields
                                .get("counter")
                                .map(String::as_str)
                                .unwrap_or("primary"),
                            measurement.ticks,
                            unit_name(measurement.unit),
                            "lower-is-better",
                        );
                    }
                    for metric in &result.metrics {
                        row(
                            benchmark,
                            "application",
                            &metric.name,
                            metric.value,
                            metric.unit.as_deref().unwrap_or(""),
                            metric_policy(metric.policy),
                        );
                    }
                }
            }
        }
        output
    }
}

fn metric_policy(policy: MetricPolicy) -> &'static str {
    match policy {
        MetricPolicy::LowerIsBetter => "lower-is-better",
        MetricPolicy::HigherIsBetter => "higher-is-better",
        MetricPolicy::Informational => "informational",
    }
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn case_stack(case: &CaseReport) -> Option<u64> {
    case.result
        .as_ref()?
        .benchmarks
        .values()
        .flat_map(|value| &value.stacks)
        .map(|value| value.used as u64)
        .max()
}

fn primary_ticks(case: &CaseReport) -> Option<u64> {
    let measurements = case
        .result
        .as_ref()?
        .benchmarks
        .values()
        .flat_map(|value| &value.measurements)
        .collect::<Vec<_>>();
    ["dwt", "mcycle", "systick"]
        .into_iter()
        .find_map(|counter| {
            measurements
                .iter()
                .find(|value| {
                    value
                        .fields
                        .get("counter")
                        .is_some_and(|value| value == counter)
                })
                .map(|value| value.ticks)
        })
        .or_else(|| measurements.first().map(|value| value.ticks))
}

fn delta(value: Option<u64>, baseline: Option<u64>) -> String {
    match (value, baseline) {
        (Some(value), Some(baseline)) => i128::from(value)
            .checked_sub(i128::from(baseline))
            .unwrap()
            .to_string(),
        _ => "—".to_string(),
    }
}

#[derive(Debug)]
pub enum CampaignError {
    MissingCampaign(String),
    MissingProfile(String),
    InvalidConfig(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Command(CommandError),
    Json(serde_json::Error),
}

impl fmt::Display for CampaignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCampaign(value) => write!(formatter, "unknown campaign {value:?}"),
            Self::MissingProfile(value) => write!(formatter, "unknown runner profile {value:?}"),
            Self::InvalidConfig(value) => formatter.write_str(value),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Command(source) => source.fmt(formatter),
            Self::Json(source) => source.fmt(formatter),
        }
    }
}

impl Error for CampaignError {}

impl From<CommandError> for CampaignError {
    fn from(value: CommandError) -> Self {
        Self::Command(value)
    }
}
