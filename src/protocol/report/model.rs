/// Stable event taxonomy shared by target encoders and host decoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventTag {
    Begin,
    Sample,
    Result,
    Diagnostic,
    Summary,
    Stack,
    Measurement,
    Outcome,
    Boundary,
    Counter,
    Metric,
}

impl EventTag {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Begin => "EM_BEGIN",
            Self::Sample => "EM_SAMPLE",
            Self::Result => "EM_RESULT",
            Self::Diagnostic => "EM_DIAGNOSTIC",
            Self::Summary => "EM_SUMMARY",
            Self::Stack => "EM_STACK",
            Self::Measurement => "EM_MEASUREMENT",
            Self::Outcome => "EM_OUTCOME",
            Self::Boundary => "EM_BOUNDARY",
            Self::Counter => "EM_COUNTER",
            Self::Metric => "EM_METRIC",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Self> {
        Some(match value {
            "EM_BEGIN" => Self::Begin,
            "EM_SAMPLE" => Self::Sample,
            "EM_RESULT" => Self::Result,
            "EM_DIAGNOSTIC" => Self::Diagnostic,
            "EM_SUMMARY" => Self::Summary,
            "EM_STACK" => Self::Stack,
            "EM_MEASUREMENT" => Self::Measurement,
            "EM_OUTCOME" => Self::Outcome,
            "EM_BOUNDARY" => Self::Boundary,
            "EM_COUNTER" => Self::Counter,
            "EM_METRIC" => Self::Metric,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldValue<'a> {
    Token(&'a str),
    U64(u64),
    Bool(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field<'a> {
    pub key: &'a str,
    pub value: FieldValue<'a>,
}

impl<'a> Field<'a> {
    pub const fn token(key: &'a str, value: &'a str) -> Self {
        Self {
            key,
            value: FieldValue::Token(value),
        }
    }

    pub const fn u64(key: &'a str, value: u64) -> Self {
        Self {
            key,
            value: FieldValue::U64(value),
        }
    }

    pub const fn bool(key: &'a str, value: bool) -> Self {
        Self {
            key,
            value: FieldValue::Bool(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunStart<'a> {
    pub suite: &'a str,
    pub target: &'a str,
    pub board: Option<&'a str>,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleRecord<'a> {
    pub fixture: &'a str,
    pub side: char,
    pub index: usize,
    pub ticks: u64,
    pub wrapped: bool,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonRecord<'a> {
    pub fixture: &'a str,
    pub class: &'a str,
    pub policy: Option<&'a str>,
    pub a_min: u64,
    pub a_max: u64,
    pub b_min: u64,
    pub b_max: u64,
    pub spread: u64,
    pub overlap: bool,
    pub wrapped: bool,
    pub output_ok: bool,
    pub passed: Option<bool>,
    pub fields: &'a [Field<'a>],
}

#[cfg(feature = "paired")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedResult<'a, const N: usize> {
    pub fixture: &'a str,
    pub class: &'a str,
    pub policy: &'a str,
    pub run: &'a PairedRun<N>,
    pub passed: bool,
    pub fields: &'a [Field<'a>],
}

#[cfg(feature = "paired")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedDiagnostic<'a, const N: usize> {
    pub fixture: &'a str,
    pub class: &'a str,
    pub run: &'a PairedRun<N>,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSummary<'a> {
    pub suite: &'a str,
    pub passed: u32,
    pub failed: u32,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementRecord<'a> {
    pub benchmark: &'a str,
    pub measurement: crate::Measurement,
    /// Optional architecture or peripheral counter name (for example `dwt`).
    pub counter: Option<&'a str>,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeRecord<'a> {
    pub benchmark: &'a str,
    pub passed: bool,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
pub enum BoundaryPhase {
    Begin,
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryRecord<'a> {
    pub benchmark: &'a str,
    pub trial: u32,
    pub phase: BoundaryPhase,
    pub passed: Option<bool>,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterSnapshotRecord<'a> {
    pub benchmark: &'a str,
    pub trial: u32,
    pub phase: BoundaryPhase,
    pub ticks: u64,
    pub width_bits: u8,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub fields: &'a [Field<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
pub enum MetricPolicy {
    LowerIsBetter,
    HigherIsBetter,
    Informational,
}

impl Default for MetricPolicy {
    fn default() -> Self {
        Self::Informational
    }
}

impl MetricPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowerIsBetter => "lower-is-better",
            Self::HigherIsBetter => "higher-is-better",
            Self::Informational => "informational",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricRecord<'a> {
    pub benchmark: &'a str,
    pub name: &'a str,
    pub value: u64,
    pub unit: Option<&'a str>,
    pub policy: MetricPolicy,
    pub fields: &'a [Field<'a>],
}

/// Borrowed target-side event model. Text is one encoding of these events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    Begin(&'a RunStart<'a>),
    Sample(&'a SampleRecord<'a>),
    Result(&'a ComparisonRecord<'a>),
    Diagnostic(&'a ComparisonRecord<'a>),
    Summary(&'a RunSummary<'a>),
    Measurement {
        record: &'a MeasurementRecord<'a>,
        trial: Option<u32>,
    },
    Outcome(&'a OutcomeRecord<'a>),
    Boundary(&'a BoundaryRecord<'a>),
    Counter(&'a CounterSnapshotRecord<'a>),
    Metric(&'a MetricRecord<'a>),
}
impl Event<'_> {
    pub const fn tag(&self) -> EventTag {
        match self {
            Self::Begin(_) => EventTag::Begin,
            Self::Sample(_) => EventTag::Sample,
            Self::Result(_) => EventTag::Result,
            Self::Diagnostic(_) => EventTag::Diagnostic,
            Self::Summary(_) => EventTag::Summary,
            Self::Measurement { .. } => EventTag::Measurement,
            Self::Outcome(_) => EventTag::Outcome,
            Self::Boundary(_) => EventTag::Boundary,
            Self::Counter(_) => EventTag::Counter,
            Self::Metric(_) => EventTag::Metric,
        }
    }
}

pub trait Reporter {
    type Error;

    /// Emits one typed event through this reporter's selected encoding.
    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error> {
        match event {
            Event::Begin(record) => self.run_start(record),
            Event::Sample(record) => self.sample(record),
            Event::Result(record) => self.result(record),
            Event::Diagnostic(record) => self.diagnostic(record),
            Event::Summary(record) => self.run_summary(record),
            Event::Measurement {
                record,
                trial: None,
            } => self.measurement(record),
            Event::Measurement {
                record,
                trial: Some(trial),
            } => self.indexed_measurement(record, trial),
            Event::Outcome(record) => self.outcome(record),
            Event::Boundary(record) => self.boundary(record),
            Event::Counter(record) => self.counter_snapshot(record),
            Event::Metric(record) => self.metric(record),
        }
    }

    fn run_start(&mut self, record: &RunStart<'_>) -> Result<(), Self::Error>;

    fn sample(&mut self, record: &SampleRecord<'_>) -> Result<(), Self::Error>;

    fn result(&mut self, record: &ComparisonRecord<'_>) -> Result<(), Self::Error>;

    fn diagnostic(&mut self, record: &ComparisonRecord<'_>) -> Result<(), Self::Error>;

    #[cfg(feature = "paired")]
    fn paired_result<const N: usize>(
        &mut self,
        record: &PairedResult<'_, N>,
    ) -> Result<(), Self::Error>
    where
        Self: Sized;

    #[cfg(feature = "paired")]
    fn paired_diagnostic<const N: usize>(
        &mut self,
        record: &PairedDiagnostic<'_, N>,
    ) -> Result<(), Self::Error>
    where
        Self: Sized;

    fn run_summary(&mut self, record: &RunSummary<'_>) -> Result<(), Self::Error>;

    fn measurement(&mut self, record: &MeasurementRecord<'_>) -> Result<(), Self::Error>;

    fn indexed_measurement(
        &mut self,
        record: &MeasurementRecord<'_>,
        trial: u32,
    ) -> Result<(), Self::Error>;

    fn outcome(&mut self, record: &OutcomeRecord<'_>) -> Result<(), Self::Error>;

    fn boundary(&mut self, record: &BoundaryRecord<'_>) -> Result<(), Self::Error>;

    fn counter_snapshot(&mut self, record: &CounterSnapshotRecord<'_>) -> Result<(), Self::Error>;

    fn metric(&mut self, record: &MetricRecord<'_>) -> Result<(), Self::Error>;
}
