use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::format;
use std::string::{String, ToString};

use super::model::*;

#[derive(Debug)]
pub struct RenderError(serde_json::Error);

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "failed to render report: {}", self.0)
    }
}

impl Error for RenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

pub fn render_json(result: &RunResult) -> Result<String, RenderError> {
    serde_json::to_string_pretty(result).map_err(RenderError)
}

pub fn render_markdown(result: &RunResult) -> String {
    let mut output = String::new();
    writeln!(output, "# Embedded measurement report\n").unwrap();
    writeln!(output, "- Status: **{}**", status_name(result.status)).unwrap();
    writeln!(output, "- Protocol schema: `{}`", result.protocol_schema).unwrap();
    if let Some(target) = &result.target.target {
        writeln!(output, "- Target: `{}`", escape(target)).unwrap();
    }
    if let Some(board) = &result.target.board {
        writeln!(output, "- Board: `{}`", escape(board)).unwrap();
    }
    if let Some(mcu) = &result.target.mcu {
        writeln!(output, "- MCU: `{}`", escape(mcu)).unwrap();
    }
    if let Some(runner) = &result.target.runner {
        writeln!(output, "- Runner: `{}`", escape(runner)).unwrap();
    }
    if let Some(transport) = &result.target.transport {
        writeln!(output, "- Transport: `{}`", escape(transport)).unwrap();
    }
    if let Some(frequency) = result.target.clock_frequency_hz {
        writeln!(output, "- Clock frequency: `{frequency}` Hz").unwrap();
    }
    if let Some(campaign) = &result.identity.campaign {
        writeln!(output, "- Campaign: `{}`", escape(campaign)).unwrap();
    }
    if let Some(case) = &result.identity.case {
        writeln!(output, "- Case: `{}`", escape(case)).unwrap();
    }
    if let Some(profile) = &result.identity.profile {
        writeln!(output, "- Profile: `{}`", escape(profile)).unwrap();
    }
    if let Some(commit) = &result.source.git_commit {
        writeln!(output, "- Git commit: `{}`", escape(commit)).unwrap();
    }
    if let Some(dirty) = result.source.dirty {
        writeln!(output, "- Source dirty: `{}`", yes_no(dirty)).unwrap();
    }
    if let Some(rustc) = &result.build.rustc {
        writeln!(output, "- Rust compiler: `{}`", escape(rustc)).unwrap();
    }
    if result.ignored_lines != 0 {
        writeln!(
            output,
            "- Ignored non-protocol lines: {}",
            result.ignored_lines
        )
        .unwrap();
    }

    if result
        .benchmarks
        .values()
        .any(|benchmark| !benchmark.measurements.is_empty())
    {
        output.push_str("\n## Measurements\n\n");
        output
            .push_str("| Benchmark | Counter | Ticks | Unit | Frequency | Duration | Wrapped |\n");
        output.push_str("|---|---|---:|---|---:|---:|---:|\n");
        for (name, benchmark) in &result.benchmarks {
            for measurement in &benchmark.measurements {
                let counter = measurement
                    .fields
                    .get("counter")
                    .map(String::as_str)
                    .unwrap_or("—");
                let frequency = measurement
                    .frequency_hz
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let duration = measurement
                    .nanoseconds()
                    .map(format_duration)
                    .unwrap_or_else(|| "—".to_string());
                writeln!(
                    output,
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    escape(name),
                    escape(counter),
                    measurement.ticks,
                    unit_name(measurement.unit),
                    frequency,
                    duration,
                    yes_no(measurement.wrapped),
                )
                .unwrap();
            }
        }
    }

    if !result.metrics.is_empty() {
        output.push_str("\n## Application metrics\n\n");
        output.push_str("| Benchmark | Metric | Value | Unit | Policy |\n");
        output.push_str("|---|---|---:|---|---|\n");
        for metric in &result.metrics {
            writeln!(
                output,
                "| {} | {} | {} | {} | {} |",
                escape(&metric.benchmark),
                escape(&metric.name),
                metric.value,
                metric
                    .unit
                    .as_deref()
                    .map(escape)
                    .unwrap_or_else(|| "—".to_string()),
                metric_policy_name(metric.policy),
            )
            .unwrap();
        }
    }

    if !result.external_errors.is_empty() {
        output.push_str("\n## External measurement errors\n\n");
        for error in &result.external_errors {
            writeln!(output, "- {}", escape(error)).unwrap();
        }
    }

    if result
        .benchmarks
        .values()
        .any(|benchmark| !benchmark.stacks.is_empty())
    {
        output.push_str("\n## Stack high-water marks\n\n");
        output.push_str("| Benchmark | Used | Available | Painted | Safe zone | Overflowed |\n");
        output.push_str("|---|---:|---:|---:|---:|---:|\n");
        for (name, benchmark) in &result.benchmarks {
            for stack in &benchmark.stacks {
                writeln!(
                    output,
                    "| {} | {} | {} | {} | {} | {} |",
                    escape(name),
                    stack.used,
                    stack.available,
                    stack.painted,
                    stack.safe_zone,
                    yes_no(stack.overflowed),
                )
                .unwrap();
            }
        }
    }

    if !result.results.is_empty() {
        output.push_str("\n## Results\n\n");
        output.push_str(
            "| Fixture | Class | Policy | A range | B range | Spread | Overlap | Output | Status |\n",
        );
        output.push_str("|---|---|---|---:|---:|---:|---:|---:|---|\n");
        for value in &result.results {
            writeln!(
                output,
                "| {} | {} | {} | {}–{} | {}–{} | {} | {} | {} | {} |",
                escape(&value.fixture),
                escape(&value.class),
                value
                    .policy
                    .as_deref()
                    .map(escape)
                    .unwrap_or_else(|| "—".to_string()),
                value.a_min,
                value.a_max,
                value.b_min,
                value.b_max,
                value.spread,
                yes_no(value.overlap),
                if value.output_ok { "valid" } else { "invalid" },
                value.status.map(event_status_name).unwrap_or("INFO"),
            )
            .unwrap();
        }
    }

    if !result.outcomes.is_empty() {
        output.push_str("\n## Workload outcomes\n\n");
        output.push_str("| Benchmark | Status |\n");
        output.push_str("|---|---|\n");
        for value in &result.outcomes {
            writeln!(
                output,
                "| {} | {} |",
                escape(&value.benchmark),
                event_status_name(value.status),
            )
            .unwrap();
        }
    }

    if !result.diagnostics.is_empty() {
        output.push_str("\n## Diagnostics\n\n");
        output.push_str("| Fixture | Class | A range | B range | Spread | Wrapped |\n");
        output.push_str("|---|---|---:|---:|---:|---:|\n");
        for value in &result.diagnostics {
            writeln!(
                output,
                "| {} | {} | {}–{} | {}–{} | {} | {} |",
                escape(&value.fixture),
                escape(&value.class),
                value.a_min,
                value.a_max,
                value.b_min,
                value.b_max,
                value.spread,
                yes_no(value.wrapped),
            )
            .unwrap();
        }
    }

    if !result.samples.is_empty() {
        output.push_str("\n## Raw samples\n\n");
        output.push_str("| Fixture | Side | Index | Ticks | Wrapped |\n");
        output.push_str("|---|---:|---:|---:|---:|\n");
        for (fixture, samples) in &result.samples {
            for sample in samples {
                writeln!(
                    output,
                    "| {} | {} | {} | {} | {} |",
                    escape(fixture),
                    sample.side,
                    sample.index,
                    sample.ticks,
                    yes_no(sample.wrapped),
                )
                .unwrap();
            }
        }
    }

    output
}

fn metric_policy_name(policy: MetricPolicy) -> &'static str {
    match policy {
        MetricPolicy::LowerIsBetter => "lower is better",
        MetricPolicy::HigherIsBetter => "higher is better",
        MetricPolicy::Informational => "informational",
    }
}

fn escape(value: &str) -> String {
    value.replace('|', "\\|").replace('`', "\\`")
}

fn status_name(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Pass => "PASS",
        RunStatus::Fail => "FAIL",
        RunStatus::Informational => "INFORMATIONAL",
        RunStatus::MeasurementError => "MEASUREMENT ERROR",
    }
}

fn event_status_name(status: EventStatus) -> &'static str {
    match status {
        EventStatus::Pass => "PASS",
        EventStatus::Fail => "FAIL",
    }
}

fn unit_name(unit: OwnedUnit) -> &'static str {
    match unit {
        OwnedUnit::CoreCycles => "core cycles",
        OwnedUnit::TimerTicks => "timer ticks",
        OwnedUnit::Instructions => "instructions",
        OwnedUnit::SimulatorCycles => "simulator cycles",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_duration(nanoseconds: u64) -> String {
    if nanoseconds >= 1_000_000_000 {
        format!("{:.6} s", nanoseconds as f64 / 1_000_000_000.0)
    } else if nanoseconds >= 1_000_000 {
        format!("{:.3} ms", nanoseconds as f64 / 1_000_000.0)
    } else if nanoseconds >= 1_000 {
        format!("{:.3} µs", nanoseconds as f64 / 1_000.0)
    } else {
        format!("{nanoseconds} ns")
    }
}
