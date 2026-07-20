use std::collections::BTreeMap;
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::report::EventTag;
use serde::{Deserialize, Serialize};

pub type OwnedFields = BTreeMap<String, String>;
pub use crate::Unit as OwnedUnit;
pub use crate::report::{BoundaryPhase as OwnedBoundaryPhase, MetricPolicy};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub campaign: Option<String>,
    pub case: Option<String>,
    pub parameters: OwnedFields,
    pub features: Vec<String>,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetMetadata {
    pub target: Option<String>,
    pub board: Option<String>,
    pub mcu: Option<String>,
    pub runner: Option<String>,
    pub runner_version: Option<String>,
    pub transport: Option<String>,
    pub probe: Option<String>,
    pub clock_frequency_hz: Option<u64>,
    pub host_usb_path: Option<String>,
    pub venue: Option<String>,
    pub capabilities: Vec<String>,
    pub resolved_bindings: OwnedFields,
    pub controlled_environment: OwnedFields,
    pub configuration_identity: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildMetadata {
    pub toolchain: Option<String>,
    pub rustc: Option<String>,
    pub cargo: Option<String>,
    pub target: Option<String>,
    pub optimization: Option<String>,
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceMetadata {
    pub workspace: Option<String>,
    pub repository: Option<String>,
    pub git_commit: Option<String>,
    pub dirty: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Pass,
    Fail,
    Informational,
    MeasurementError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginEvent {
    pub schema: u16,
    pub suite: String,
    pub target: String,
    pub board: Option<String>,
    pub unit: OwnedUnit,
    pub frequency_hz: Option<u64>,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SampleEvent {
    pub schema: u16,
    pub fixture: String,
    pub side: char,
    pub index: usize,
    pub ticks: u64,
    pub wrapped: bool,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonEvent {
    pub schema: u16,
    pub fixture: String,
    pub class: String,
    pub policy: Option<String>,
    pub a_min: u64,
    pub a_max: u64,
    pub b_min: u64,
    pub b_max: u64,
    pub spread: u64,
    pub overlap: bool,
    pub wrapped: bool,
    pub output_ok: bool,
    pub status: Option<EventStatus>,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SummaryEvent {
    pub schema: u16,
    pub suite: String,
    pub passed: u32,
    pub failed: u32,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StackEvent {
    pub schema: u16,
    pub benchmark: String,
    pub used: usize,
    pub available: usize,
    pub painted: usize,
    pub safe_zone: usize,
    pub overflowed: bool,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MeasurementEvent {
    pub schema: u16,
    pub benchmark: String,
    pub ticks: u64,
    pub unit: OwnedUnit,
    pub frequency_hz: Option<u64>,
    pub wrapped: bool,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutcomeEvent {
    pub schema: u16,
    pub benchmark: String,
    pub status: EventStatus,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundaryEvent {
    pub schema: u16,
    pub benchmark: String,
    pub trial: u32,
    pub phase: OwnedBoundaryPhase,
    pub status: Option<EventStatus>,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CounterSnapshotEvent {
    pub schema: u16,
    pub benchmark: String,
    pub trial: u32,
    pub phase: OwnedBoundaryPhase,
    pub ticks: u64,
    pub width_bits: u8,
    pub unit: OwnedUnit,
    pub frequency_hz: Option<u64>,
    pub fields: OwnedFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetricEvent {
    pub schema: u16,
    pub benchmark: String,
    pub name: String,
    pub value: u64,
    pub unit: Option<String>,
    #[serde(default)]
    pub policy: MetricPolicy,
    pub fields: OwnedFields,
}

impl MeasurementEvent {
    pub fn nanoseconds(&self) -> Option<u64> {
        let frequency = self.frequency_hz?;
        if frequency == 0 {
            return None;
        }
        let value = self.ticks as u128 * 1_000_000_000 / frequency as u128;
        u64::try_from(value).ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OwnedEvent {
    Begin(BeginEvent),
    Sample(SampleEvent),
    Result(ComparisonEvent),
    Diagnostic(ComparisonEvent),
    Summary(SummaryEvent),
    Stack(StackEvent),
    Measurement(MeasurementEvent),
    Outcome(OutcomeEvent),
    Boundary(BoundaryEvent),
    Counter(CounterSnapshotEvent),
    Metric(MetricEvent),
}

impl OwnedEvent {
    pub const fn tag(&self) -> EventTag {
        match self {
            Self::Begin(_) => EventTag::Begin,
            Self::Sample(_) => EventTag::Sample,
            Self::Result(_) => EventTag::Result,
            Self::Diagnostic(_) => EventTag::Diagnostic,
            Self::Summary(_) => EventTag::Summary,
            Self::Stack(_) => EventTag::Stack,
            Self::Measurement(_) => EventTag::Measurement,
            Self::Outcome(_) => EventTag::Outcome,
            Self::Boundary(_) => EventTag::Boundary,
            Self::Counter(_) => EventTag::Counter,
            Self::Metric(_) => EventTag::Metric,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub measurements: Vec<MeasurementEvent>,
    pub stacks: Vec<StackEvent>,
    #[serde(default)]
    pub metrics: Vec<MetricEvent>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunResult {
    pub protocol_schema: u16,
    pub identity: RunIdentity,
    pub target: TargetMetadata,
    pub build: BuildMetadata,
    #[serde(default)]
    pub source: SourceMetadata,
    pub benchmarks: BTreeMap<String, BenchmarkResult>,
    pub samples: BTreeMap<String, Vec<SampleEvent>>,
    pub results: Vec<ComparisonEvent>,
    pub diagnostics: Vec<ComparisonEvent>,
    pub outcomes: Vec<OutcomeEvent>,
    pub summaries: Vec<SummaryEvent>,
    pub starts: Vec<BeginEvent>,
    #[serde(default)]
    pub boundaries: Vec<BoundaryEvent>,
    #[serde(default)]
    pub counter_snapshots: Vec<CounterSnapshotEvent>,
    #[serde(default)]
    pub metrics: Vec<MetricEvent>,
    #[serde(default)]
    pub external_errors: Vec<String>,
    pub events: Vec<OwnedEvent>,
    #[serde(default)]
    pub welch_analyses: Vec<super::WelchAnalysis>,
    pub status: RunStatus,
    pub ignored_lines: usize,
}

impl Default for RunResult {
    fn default() -> Self {
        Self {
            protocol_schema: 1,
            identity: RunIdentity::default(),
            target: TargetMetadata::default(),
            build: BuildMetadata::default(),
            source: SourceMetadata::default(),
            benchmarks: BTreeMap::new(),
            samples: BTreeMap::new(),
            results: Vec::new(),
            diagnostics: Vec::new(),
            outcomes: Vec::new(),
            summaries: Vec::new(),
            starts: Vec::new(),
            boundaries: Vec::new(),
            counter_snapshots: Vec::new(),
            metrics: Vec::new(),
            external_errors: Vec::new(),
            events: Vec::new(),
            welch_analyses: Vec::new(),
            status: RunStatus::Informational,
            ignored_lines: 0,
        }
    }
}

impl RunResult {
    pub fn push(&mut self, event: OwnedEvent) {
        match &event {
            OwnedEvent::Begin(value) => {
                if self.target.target.is_none() {
                    self.target.target = Some(value.target.clone());
                }
                if self.target.board.is_none() {
                    self.target.board = value.board.clone();
                }
                self.starts.push(value.clone());
            }
            OwnedEvent::Sample(value) => self
                .samples
                .entry(value.fixture.clone())
                .or_default()
                .push(value.clone()),
            OwnedEvent::Result(value) => self.results.push(value.clone()),
            OwnedEvent::Diagnostic(value) => self.diagnostics.push(value.clone()),
            OwnedEvent::Summary(value) => self.summaries.push(value.clone()),
            OwnedEvent::Stack(value) => self
                .benchmarks
                .entry(value.benchmark.clone())
                .or_default()
                .stacks
                .push(value.clone()),
            OwnedEvent::Measurement(value) => self
                .benchmarks
                .entry(value.benchmark.clone())
                .or_default()
                .measurements
                .push(value.clone()),
            OwnedEvent::Outcome(value) => self.outcomes.push(value.clone()),
            OwnedEvent::Boundary(value) => self.boundaries.push(value.clone()),
            OwnedEvent::Counter(value) => self.counter_snapshots.push(value.clone()),
            OwnedEvent::Metric(value) => {
                self.benchmarks
                    .entry(value.benchmark.clone())
                    .or_default()
                    .metrics
                    .push(value.clone());
                self.metrics.push(value.clone());
            }
        }
        self.events.push(event);
        self.recompute_status();
    }

    pub fn recompute_status(&mut self) {
        let measurement_error = self.events.iter().any(|event| match event {
            OwnedEvent::Sample(value) => value.wrapped,
            OwnedEvent::Result(value) | OwnedEvent::Diagnostic(value) => value.wrapped,
            OwnedEvent::Stack(value) => value.overflowed,
            OwnedEvent::Measurement(value) => value.wrapped,
            OwnedEvent::Outcome(_) => false,
            OwnedEvent::Begin(_)
            | OwnedEvent::Summary(_)
            | OwnedEvent::Boundary(_)
            | OwnedEvent::Counter(_)
            | OwnedEvent::Metric(_) => false,
        }) || self.benchmarks.values().any(|benchmark| {
            benchmark.measurements.iter().any(|value| value.wrapped)
                || benchmark.stacks.iter().any(|value| value.overflowed)
        });
        let failed = self
            .results
            .iter()
            .any(|value| value.status == Some(EventStatus::Fail) || !value.output_ok)
            || self.summaries.iter().any(|value| value.failed != 0);
        let failed = failed
            || self
                .outcomes
                .iter()
                .any(|value| value.status == EventStatus::Fail)
            || self
                .boundaries
                .iter()
                .any(|value| value.status == Some(EventStatus::Fail));
        self.status = if measurement_error || !self.external_errors.is_empty() {
            RunStatus::MeasurementError
        } else if failed {
            RunStatus::Fail
        } else if self.events.is_empty()
            || (self.results.is_empty() && self.summaries.is_empty() && self.outcomes.is_empty())
        {
            RunStatus::Informational
        } else {
            RunStatus::Pass
        };
    }

    /// Correlates target boundaries and externally supplied counter snapshots.
    ///
    /// A command wrapper or simulator integration emits `EM_COUNTER` records
    /// for the same benchmark, trial, and phase as target `EM_BOUNDARY`
    /// records. Correlated intervals enter the ordinary measurement model.
    pub fn correlate_external(&mut self, required: bool) {
        self.external_errors.clear();
        let has_counter_snapshots = !self.counter_snapshots.is_empty();
        for benchmark in self.benchmarks.values_mut() {
            benchmark.measurements.retain(|measurement| {
                measurement.fields.get("measurement").map(String::as_str) != Some("external")
            });
        }

        let mut boundaries = BTreeMap::new();
        for boundary in &self.boundaries {
            let key = (boundary.benchmark.clone(), boundary.trial, boundary.phase);
            if boundaries.insert(key, boundary).is_some() {
                self.external_errors.push(format!(
                    "duplicate boundary for {} trial {} {:?}",
                    boundary.benchmark, boundary.trial, boundary.phase
                ));
            }
        }
        let mut counters = BTreeMap::new();
        for snapshot in &self.counter_snapshots {
            let key = (snapshot.benchmark.clone(), snapshot.trial, snapshot.phase);
            if counters.insert(key, snapshot).is_some() {
                self.external_errors.push(format!(
                    "duplicate counter snapshot for {} trial {} {:?}",
                    snapshot.benchmark, snapshot.trial, snapshot.phase
                ));
            }
        }

        for boundary in self
            .boundaries
            .iter()
            .filter(|value| value.phase == OwnedBoundaryPhase::Begin)
        {
            let end_key = (
                boundary.benchmark.clone(),
                boundary.trial,
                OwnedBoundaryPhase::End,
            );
            let Some(end_boundary) = boundaries.get(&end_key) else {
                self.external_errors.push(format!(
                    "missing end boundary for {} trial {}",
                    boundary.benchmark, boundary.trial
                ));
                continue;
            };
            if boundary.status.is_some() || end_boundary.status.is_none() {
                self.external_errors.push(format!(
                    "invalid boundary status placement for {} trial {}",
                    boundary.benchmark, boundary.trial
                ));
                continue;
            }
            let begin_key = (
                boundary.benchmark.clone(),
                boundary.trial,
                OwnedBoundaryPhase::Begin,
            );
            let (Some(begin), Some(end)) = (counters.get(&begin_key), counters.get(&end_key))
            else {
                if required || has_counter_snapshots {
                    self.external_errors.push(format!(
                        "missing external counter pair for {} trial {}",
                        boundary.benchmark, boundary.trial
                    ));
                }
                continue;
            };
            if begin.unit != end.unit
                || begin.frequency_hz != end.frequency_hz
                || begin.width_bits != end.width_bits
                || !(1..=64).contains(&begin.width_bits)
            {
                self.external_errors.push(format!(
                    "incompatible external counter pair for {} trial {}",
                    boundary.benchmark, boundary.trial
                ));
                continue;
            }
            let mut fields = end.fields.clone();
            fields.insert("measurement".to_string(), "external".to_string());
            fields.insert("trial".to_string(), boundary.trial.to_string());
            fields.insert("counter-width".to_string(), end.width_bits.to_string());
            if end.width_bits < 64 {
                let modulus = 1_u64 << end.width_bits;
                if begin.ticks >= modulus || end.ticks >= modulus {
                    self.external_errors.push(format!(
                        "external counter value exceeds {}-bit width for {} trial {}",
                        end.width_bits, boundary.benchmark, boundary.trial
                    ));
                    continue;
                }
            }
            let wrapped = end.ticks < begin.ticks;
            let ticks = if wrapped && end.width_bits < 64 {
                let modulus = 1_u64 << end.width_bits;
                modulus - begin.ticks + end.ticks
            } else {
                end.ticks.wrapping_sub(begin.ticks)
            };
            self.benchmarks
                .entry(boundary.benchmark.clone())
                .or_default()
                .measurements
                .push(MeasurementEvent {
                    schema: boundary.schema,
                    benchmark: boundary.benchmark.clone(),
                    ticks,
                    unit: end.unit,
                    frequency_hz: end.frequency_hz,
                    wrapped,
                    fields,
                });
        }
        for snapshot in &self.counter_snapshots {
            let key = (snapshot.benchmark.clone(), snapshot.trial, snapshot.phase);
            if !boundaries.contains_key(&key) {
                self.external_errors.push(format!(
                    "counter snapshot has no matching boundary for {} trial {} {:?}",
                    snapshot.benchmark, snapshot.trial, snapshot.phase
                ));
            }
        }
        if required && self.boundaries.is_empty() {
            self.external_errors
                .push("external measurement required but no boundaries were emitted".to_string());
        }
        self.recompute_status();
    }
}
