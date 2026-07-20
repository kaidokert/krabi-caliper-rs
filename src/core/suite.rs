//! High-level paired measurement campaigns.

use core::hint::black_box;

use crate::Unit;
pub use crate::core::benchmark::MeasurementPlatform;
use crate::paired::{
    Comparison, ComparisonPolicy, DisjointRanges, MaxSpread, PairedRunner, RunError, Side,
};
use crate::report::{
    Event, Field, PairedDiagnostic, PairedReporter, PairedResult, RunStart, RunSummary,
};
#[cfg(feature = "stack")]
use crate::report::{StackRecord, StackReporter};
#[cfg(feature = "stack")]
use crate::stack::StackMeasurement;

#[cfg(feature = "stack")]
pub trait SuiteReporter: PairedReporter + StackReporter {}

#[cfg(feature = "stack")]
impl<R: PairedReporter + StackReporter> SuiteReporter for R {}

#[cfg(not(feature = "stack"))]
pub trait SuiteReporter: PairedReporter {}

#[cfg(not(feature = "stack"))]
impl<R: PairedReporter> SuiteReporter for R {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedSuiteConfig<'a> {
    pub suite: &'a str,
    pub target: &'a str,
    pub board: Option<&'a str>,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub warmup_blocks: usize,
    pub batches: usize,
    pub positive_max_spread: u64,
    pub positive_require_overlap: bool,
    pub fields: PairedSuiteFields<'a>,
}

/// Fields scoped to each record type, avoiding redundant transport traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PairedSuiteFields<'a> {
    pub run: &'a [Field<'a>],
    pub fixture: &'a [Field<'a>],
    pub summary: &'a [Field<'a>],
}

#[derive(Debug, Eq, PartialEq)]
pub enum SuiteError<E> {
    Reporter(E),
    Runner(RunError),
    IncompatibleMeasurements,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SuiteTotals {
    pub passed: u32,
    pub failed: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureSpec<'a> {
    pub name: &'a str,
    pub class: &'a str,
    pub policy: &'a str,
}

/// Owns the common lifecycle of a paired measurement campaign.
pub struct PairedSuite<'a, P, R, const N: usize> {
    platform: &'a mut P,
    reporter: &'a mut R,
    config: PairedSuiteConfig<'a>,
    max_sample_ticks: Option<u64>,
    totals: SuiteTotals,
}

impl<'a, P, R, const N: usize> PairedSuite<'a, P, R, N>
where
    P: MeasurementPlatform,
    R: SuiteReporter,
{
    pub fn start(
        platform: &'a mut P,
        reporter: &'a mut R,
        config: PairedSuiteConfig<'a>,
    ) -> Result<Self, SuiteError<R::Error>> {
        reporter
            .event(Event::Begin(&RunStart {
                suite: config.suite,
                target: config.target,
                board: config.board,
                unit: config.unit,
                frequency_hz: config.frequency_hz,
                fields: config.fields.run,
            }))
            .map_err(SuiteError::Reporter)?;
        Ok(Self {
            platform,
            reporter,
            config,
            max_sample_ticks: None,
            totals: SuiteTotals::default(),
        })
    }

    /// Rejects recorded samples at or above a target-specific safe interval.
    pub const fn max_sample_ticks(mut self, exclusive_limit: u64) -> Self {
        self.max_sample_ticks = Some(exclusive_limit);
        self
    }

    pub fn positive<I: ?Sized>(
        &mut self,
        fixture: &str,
        input_a: &I,
        input_b: &I,
        operation: impl FnMut(&I) -> bool,
    ) -> Result<bool, SuiteError<R::Error>> {
        self.fixture(
            FixtureSpec {
                name: fixture,
                class: "positive",
                policy: "max-spread",
            },
            input_a,
            input_b,
            MaxSpread {
                ticks: self.config.positive_max_spread,
                require_overlap: self.config.positive_require_overlap,
            },
            operation,
        )
    }

    /// Runs a positive fixture while preparing each selected input outside the
    /// measured region.
    ///
    /// This is useful when both sides must occupy the same local storage, or
    /// when setup such as key construction is intentionally excluded from the
    /// operation boundary.
    pub fn positive_prepared<I: ?Sized, S>(
        &mut self,
        fixture: &str,
        input_a: &I,
        input_b: &I,
        prepare: impl FnMut(&I) -> S,
        operation: impl FnMut(&S) -> bool,
    ) -> Result<bool, SuiteError<R::Error>> {
        self.fixture_prepared(
            FixtureSpec {
                name: fixture,
                class: "positive",
                policy: "max-spread",
            },
            input_a,
            input_b,
            MaxSpread {
                ticks: self.config.positive_max_spread,
                require_overlap: self.config.positive_require_overlap,
            },
            prepare,
            operation,
        )
    }

    pub fn negative<I: ?Sized>(
        &mut self,
        fixture: &str,
        input_a: &I,
        input_b: &I,
        operation: impl FnMut(&I) -> bool,
    ) -> Result<bool, SuiteError<R::Error>> {
        self.fixture(
            FixtureSpec {
                name: fixture,
                class: "negative",
                policy: "disjoint-ranges",
            },
            input_a,
            input_b,
            DisjointRanges,
            operation,
        )
    }

    pub fn fixture<I: ?Sized>(
        &mut self,
        spec: FixtureSpec<'_>,
        input_a: &I,
        input_b: &I,
        policy: impl ComparisonPolicy,
        mut operation: impl FnMut(&I) -> bool,
    ) -> Result<bool, SuiteError<R::Error>> {
        let run = self.run_pair(input_a, input_b, &mut operation)?;
        self.record_fixture(spec, run, policy)
    }

    /// Runs a custom fixture with per-side preparation outside the measured
    /// operation boundary.
    pub fn fixture_prepared<I: ?Sized, S>(
        &mut self,
        spec: FixtureSpec<'_>,
        input_a: &I,
        input_b: &I,
        policy: impl ComparisonPolicy,
        mut prepare: impl FnMut(&I) -> S,
        mut operation: impl FnMut(&S) -> bool,
    ) -> Result<bool, SuiteError<R::Error>> {
        let run = PairedRunner::<N>::new()
            .warmup_blocks(self.config.warmup_blocks)
            .run(|side| {
                let input = match side {
                    Side::A => input_a,
                    Side::B => input_b,
                };
                let prepared = prepare(black_box(input));
                let (measurement, outputs_ok) = self
                    .platform
                    .measure(self.config.batches, || operation(black_box(&prepared)));
                let within_limit = self
                    .max_sample_ticks
                    .is_none_or(|limit| measurement.ticks < limit);
                (measurement, outputs_ok && within_limit)
            })
            .map_err(SuiteError::Runner)?;
        self.record_fixture(spec, run, policy)
    }

    fn record_fixture(
        &mut self,
        spec: FixtureSpec<'_>,
        run: crate::paired::PairedRun<N>,
        policy: impl ComparisonPolicy,
    ) -> Result<bool, SuiteError<R::Error>> {
        let passed = run
            .evaluate(policy)
            .map_err(|_| SuiteError::IncompatibleMeasurements)?;
        self.reporter
            .paired_result(&PairedResult {
                fixture: spec.name,
                class: spec.class,
                policy: spec.policy,
                run: &run,
                passed,
                fields: self.config.fields.fixture,
            })
            .map_err(SuiteError::Reporter)?;
        if passed {
            self.totals.passed += 1;
        } else {
            self.totals.failed += 1;
        }
        Ok(passed)
    }

    /// Records paired evidence without applying policy or changing totals.
    pub fn diagnostic<I: ?Sized>(
        &mut self,
        fixture: &str,
        class: &str,
        input_a: &I,
        input_b: &I,
        mut operation: impl FnMut(&I) -> bool,
    ) -> Result<Comparison, SuiteError<R::Error>> {
        let run = self.run_pair(input_a, input_b, &mut operation)?;
        let comparison = run
            .comparison()
            .map_err(|_| SuiteError::IncompatibleMeasurements)?;
        self.reporter
            .paired_diagnostic(&PairedDiagnostic {
                fixture,
                class,
                run: &run,
                fields: self.config.fields.fixture,
            })
            .map_err(SuiteError::Reporter)?;
        Ok(comparison)
    }

    fn run_pair<I: ?Sized>(
        &mut self,
        input_a: &I,
        input_b: &I,
        operation: &mut impl FnMut(&I) -> bool,
    ) -> Result<crate::paired::PairedRun<N>, SuiteError<R::Error>> {
        PairedRunner::<N>::new()
            .warmup_blocks(self.config.warmup_blocks)
            .run(|side| {
                let input = match side {
                    Side::A => input_a,
                    Side::B => input_b,
                };
                let (measurement, outputs_ok) = self
                    .platform
                    .measure(self.config.batches, || operation(black_box(input)));
                let within_limit = self
                    .max_sample_ticks
                    .is_none_or(|limit| measurement.ticks < limit);
                (measurement, outputs_ok && within_limit)
            })
            .map_err(SuiteError::Runner)
    }

    pub fn finish(self) -> Result<SuiteTotals, SuiteError<R::Error>> {
        self.reporter
            .event(Event::Summary(&RunSummary {
                suite: self.config.suite,
                passed: self.totals.passed,
                failed: self.totals.failed,
                fields: self.config.fields.summary,
            }))
            .map_err(SuiteError::Reporter)?;
        Ok(self.totals)
    }

    /// Reports stack evidence through the same transport as the campaign.
    #[cfg(feature = "stack")]
    pub fn stack_measurement(
        &mut self,
        measurement: StackMeasurement,
        fields: &[Field<'_>],
    ) -> Result<(), SuiteError<R::Error>> {
        self.reporter
            .stack_measurement(&StackRecord {
                benchmark: self.config.suite,
                measurement,
                fields,
            })
            .map_err(SuiteError::Reporter)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::cell::Cell;
    use std::string::String;

    use super::*;
    use crate::Measurement;
    use crate::report::{Compatibility, TextReporter};

    struct FakePlatform {
        ticks: u64,
        calls: usize,
    }

    impl MeasurementPlatform for FakePlatform {
        fn measure(
            &mut self,
            batches: usize,
            mut operation: impl FnMut() -> bool,
        ) -> (Measurement, bool) {
            let mut outputs_ok = true;
            for _ in 0..batches {
                outputs_ok &= operation();
            }
            self.calls += 1;
            self.ticks += 1;
            (Measurement::new(self.ticks, Unit::CoreCycles), outputs_ok)
        }
    }

    #[test]
    fn suite_owns_campaign_lifecycle_and_totals() {
        let mut platform = FakePlatform {
            ticks: 99,
            calls: 0,
        };
        let mut reporter = TextReporter::new(String::new()).compatibility(Compatibility::CtV0);
        let run_fields = [Field::token("scope", "run")];
        let fixture_fields = [Field::token("scope", "fixture")];
        let summary_fields = [Field::token("scope", "summary")];
        let mut suite = PairedSuite::<_, _, 2>::start(
            &mut platform,
            &mut reporter,
            PairedSuiteConfig {
                suite: "test-suite",
                target: "host",
                board: None,
                unit: Unit::CoreCycles,
                frequency_hz: None,
                warmup_blocks: 1,
                batches: 2,
                positive_max_spread: 20,
                positive_require_overlap: false,
                fields: PairedSuiteFields {
                    run: &run_fields,
                    fixture: &fixture_fields,
                    summary: &summary_fields,
                },
            },
        )
        .unwrap();

        assert!(suite.positive("equal", &0, &1, |_| true).unwrap());
        assert!(!suite.negative("variable", &0, &1, |_| true).unwrap());
        let diagnostic = suite
            .diagnostic("observe", "address-only", &0, &1, |_| true)
            .unwrap();
        assert_eq!(diagnostic.combined_spread, 3);
        #[cfg(feature = "stack")]
        suite
            .stack_measurement(
                StackMeasurement {
                    high_water_bytes: 512,
                    available_bytes: 4096,
                    painted_bytes: 3072,
                    safe_zone_bytes: 256,
                    overflowed: false,
                },
                &fixture_fields,
            )
            .unwrap();
        assert_eq!(
            suite.finish().unwrap(),
            SuiteTotals {
                passed: 1,
                failed: 1
            }
        );
        assert_eq!(platform.calls, 24);

        let output = reporter.into_inner();
        assert!(output.contains("EM_BEGIN schema:1 suite:test-suite"));
        assert!(output.contains("frequency_hz:none scope:run\n"));
        assert!(output.contains("EM_RESULT schema:1 fixture:equal class:positive"));
        assert!(output.contains("EM_RESULT schema:1 fixture:variable class:negative"));
        assert!(output.contains("EM_DIAGNOSTIC schema:1 fixture:observe class:address-only"));
        assert!(output.contains("CT_DIAGNOSTIC fixture:observe class:address-only"));
        assert!(output.contains("EM_SUMMARY schema:1 suite:test-suite passed:1 failed:1"));
        #[cfg(feature = "stack")]
        assert!(output.contains("EM_STACK schema:1 benchmark:test-suite used:512"));
        for line in output.lines() {
            if line.starts_with("EM_SAMPLE")
                || line.starts_with("EM_RESULT")
                || line.starts_with("EM_DIAGNOSTIC")
            {
                assert!(line.ends_with("scope:fixture"));
            }
            if line.starts_with("EM_SUMMARY") {
                assert!(line.ends_with("scope:summary"));
            }
        }
    }

    #[test]
    fn sample_limit_invalidates_fixture_output() {
        let mut platform = FakePlatform {
            ticks: 99,
            calls: 0,
        };
        let mut reporter = TextReporter::new(String::new());
        let mut suite = PairedSuite::<_, _, 2>::start(
            &mut platform,
            &mut reporter,
            PairedSuiteConfig {
                suite: "bounded-suite",
                target: "host",
                board: None,
                unit: Unit::CoreCycles,
                frequency_hz: None,
                warmup_blocks: 0,
                batches: 1,
                positive_max_spread: 10,
                positive_require_overlap: false,
                fields: PairedSuiteFields::default(),
            },
        )
        .unwrap()
        .max_sample_ticks(102);

        assert!(!suite.positive("bounded", &0, &1, |_| true).unwrap());
        assert_eq!(suite.finish().unwrap().failed, 1);
    }

    #[test]
    fn prepared_inputs_are_built_outside_the_measured_region() {
        struct BoundaryPlatform<'a> {
            measuring: &'a Cell<bool>,
        }

        impl MeasurementPlatform for BoundaryPlatform<'_> {
            fn measure(
                &mut self,
                batches: usize,
                mut operation: impl FnMut() -> bool,
            ) -> (Measurement, bool) {
                self.measuring.set(true);
                let mut outputs_ok = true;
                for _ in 0..batches {
                    outputs_ok &= operation();
                }
                self.measuring.set(false);
                (Measurement::new(100, Unit::CoreCycles), outputs_ok)
            }
        }

        let measuring = Cell::new(false);
        let mut platform = BoundaryPlatform {
            measuring: &measuring,
        };
        let mut reporter = TextReporter::new(String::new());
        let mut suite = PairedSuite::<_, _, 2>::start(
            &mut platform,
            &mut reporter,
            PairedSuiteConfig {
                suite: "prepared-suite",
                target: "host",
                board: None,
                unit: Unit::CoreCycles,
                frequency_hz: None,
                warmup_blocks: 1,
                batches: 2,
                positive_max_spread: 0,
                positive_require_overlap: true,
                fields: PairedSuiteFields::default(),
            },
        )
        .unwrap();

        assert!(
            suite
                .positive_prepared(
                    "prepared",
                    &1_u32,
                    &2_u32,
                    |input| {
                        assert!(!measuring.get());
                        *input
                    },
                    |prepared| {
                        assert!(measuring.get());
                        *prepared != 0
                    },
                )
                .unwrap()
        );
        assert_eq!(suite.finish().unwrap().passed, 1);
    }

    #[test]
    fn counter_wrap_cannot_produce_a_passing_verdict() {
        struct WrappedPlatform;
        impl MeasurementPlatform for WrappedPlatform {
            fn measure(
                &mut self,
                _batches: usize,
                mut operation: impl FnMut() -> bool,
            ) -> (Measurement, bool) {
                (
                    Measurement::new(100, Unit::CoreCycles).with_wrapped(true),
                    operation(),
                )
            }
        }

        let mut platform = WrappedPlatform;
        let mut reporter = TextReporter::new(String::new());
        let mut suite = PairedSuite::<_, _, 2>::start(
            &mut platform,
            &mut reporter,
            PairedSuiteConfig {
                suite: "wrapped-suite",
                target: "host",
                board: None,
                unit: Unit::CoreCycles,
                frequency_hz: None,
                warmup_blocks: 0,
                batches: 1,
                positive_max_spread: 0,
                positive_require_overlap: true,
                fields: PairedSuiteFields::default(),
            },
        )
        .unwrap()
        .max_sample_ticks(101);

        assert_eq!(
            suite.positive("wrapped", &0, &1, |_| true),
            Err(SuiteError::IncompatibleMeasurements)
        );
        assert_eq!(suite.finish().unwrap(), SuiteTotals::default());
    }
}
