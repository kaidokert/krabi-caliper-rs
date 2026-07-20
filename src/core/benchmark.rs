//! General repeated benchmark semantics independent of architecture and transport.

use core::hint::black_box;

use crate::report::{
    BoundaryPhase, BoundaryRecord, Event, Field, MeasurementRecord, MetricRecord, OutcomeRecord,
    Reporter,
};
#[cfg(feature = "stack")]
use crate::report::{StackRecord, StackReporter};
#[cfg(feature = "stack")]
use crate::stack::{DescendingStack, StackConfig, StackError, StackMeasurement, StackProbe};
use crate::{Counter, Measurement, SampleSet};

/// Reporter capabilities required by [`Benchmark`].
#[cfg(feature = "stack")]
pub trait BenchmarkReporter: Reporter + StackReporter {}

#[cfg(feature = "stack")]
impl<R: Reporter + StackReporter> BenchmarkReporter for R {}

/// Reporter capabilities required by [`Benchmark`].
#[cfg(not(feature = "stack"))]
pub trait BenchmarkReporter: Reporter {}

#[cfg(not(feature = "stack"))]
impl<R: Reporter> BenchmarkReporter for R {}

/// Target-specific mechanics for measuring a batched operation.
pub trait MeasurementPlatform {
    fn measure(&mut self, batches: usize, operation: impl FnMut() -> bool) -> (Measurement, bool);
}

/// Best-effort platform for application-owned counters.
///
/// Architecture adapters that can mask interrupts or apply barriers should
/// implement [`MeasurementPlatform`] directly instead.
pub struct CounterPlatform<C> {
    counter: C,
}

impl<C> CounterPlatform<C> {
    pub const fn new(counter: C) -> Self {
        Self { counter }
    }

    pub fn into_inner(self) -> C {
        self.counter
    }
}

impl<C: Counter> MeasurementPlatform for CounterPlatform<C> {
    fn measure(
        &mut self,
        batches: usize,
        mut operation: impl FnMut() -> bool,
    ) -> (Measurement, bool) {
        let start = self.counter.now();
        let mut outputs_ok = true;
        for _ in 0..batches {
            outputs_ok &= black_box(operation());
        }
        (self.counter.elapsed(start), outputs_ok)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkConfig<'a> {
    pub benchmark: &'a str,
    pub warmups: usize,
    pub batches: usize,
    pub fields: &'a [Field<'a>],
}

impl<'a> BenchmarkConfig<'a> {
    pub const fn new(benchmark: &'a str) -> Self {
        Self {
            benchmark,
            warmups: 1,
            batches: 1,
            fields: &[],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkResult<const N: usize> {
    pub samples: SampleSet<N>,
    #[cfg(feature = "stack")]
    pub stack: Option<StackMeasurement>,
    pub passed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalBenchmarkResult {
    pub passed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkError<E> {
    Reporter(E),
    SampleCapacity,
    #[cfg(feature = "stack")]
    Stack(StackError),
}

/// A fixed-capacity repeated benchmark.
pub struct Benchmark<'a, const N: usize> {
    config: BenchmarkConfig<'a>,
    max_sample_ticks: Option<u64>,
}

impl<'a, const N: usize> Benchmark<'a, N> {
    pub const fn new(benchmark: &'a str) -> Self {
        Self {
            config: BenchmarkConfig::new(benchmark),
            max_sample_ticks: None,
        }
    }

    pub const fn warmups(mut self, warmups: usize) -> Self {
        self.config.warmups = warmups;
        self
    }

    pub const fn batches(mut self, batches: usize) -> Self {
        self.config.batches = batches;
        self
    }

    pub const fn fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.config.fields = fields;
        self
    }

    pub const fn max_sample_ticks(mut self, exclusive_limit: u64) -> Self {
        self.max_sample_ticks = Some(exclusive_limit);
        self
    }

    pub fn run<P: MeasurementPlatform, R: BenchmarkReporter>(
        &self,
        platform: &mut P,
        reporter: &mut R,
        operation: impl FnMut() -> bool,
    ) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
        self.run_inner(platform, reporter, operation, None)
    }

    /// Emits target-owned begin/end boundaries for an external counter source.
    ///
    /// A simulator or command wrapper records matching `EM_COUNTER` snapshots;
    /// the host correlates them into ordinary measurements.
    pub fn run_external<R: Reporter>(
        &self,
        reporter: &mut R,
        mut operation: impl FnMut() -> bool,
    ) -> Result<ExternalBenchmarkResult, BenchmarkError<R::Error>> {
        for _ in 0..self.config.warmups {
            let _ = run_batches(self.config.batches, &mut operation);
        }
        let mut passed = true;
        for trial in 0..N {
            reporter
                .event(Event::Boundary(&BoundaryRecord {
                    benchmark: self.config.benchmark,
                    trial: trial as u32,
                    phase: BoundaryPhase::Begin,
                    passed: None,
                    fields: self.config.fields,
                }))
                .map_err(BenchmarkError::Reporter)?;
            let trial_passed = run_batches(self.config.batches, &mut operation);
            passed &= trial_passed;
            reporter
                .event(Event::Boundary(&BoundaryRecord {
                    benchmark: self.config.benchmark,
                    trial: trial as u32,
                    phase: BoundaryPhase::End,
                    passed: Some(trial_passed),
                    fields: self.config.fields,
                }))
                .map_err(BenchmarkError::Reporter)?;
        }
        reporter
            .event(Event::Outcome(&OutcomeRecord {
                benchmark: self.config.benchmark,
                passed,
                fields: self.config.fields,
            }))
            .map_err(BenchmarkError::Reporter)?;
        Ok(ExternalBenchmarkResult { passed })
    }

    pub fn report_metric<R: Reporter>(
        &self,
        reporter: &mut R,
        name: &str,
        value: u64,
        unit: Option<&str>,
    ) -> Result<(), BenchmarkError<R::Error>> {
        self.report_metric_with_policy(
            reporter,
            name,
            value,
            unit,
            crate::report::MetricPolicy::Informational,
        )
    }

    pub fn report_metric_with_policy<R: Reporter>(
        &self,
        reporter: &mut R,
        name: &str,
        value: u64,
        unit: Option<&str>,
        policy: crate::report::MetricPolicy,
    ) -> Result<(), BenchmarkError<R::Error>> {
        reporter
            .event(Event::Metric(&MetricRecord {
                benchmark: self.config.benchmark,
                name,
                value,
                unit,
                policy,
                fields: self.config.fields,
            }))
            .map_err(BenchmarkError::Reporter)
    }

    #[cfg(feature = "stack")]
    /// # Safety
    ///
    /// No interrupt, task, scheduler, or other execution context may access
    /// the supplied stack while it is being painted or scanned.
    pub unsafe fn run_with_stack<P: MeasurementPlatform, R: BenchmarkReporter>(
        &self,
        platform: &mut P,
        reporter: &mut R,
        stack: &impl DescendingStack,
        stack_config: StackConfig,
        operation: impl FnMut() -> bool,
    ) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
        // SAFETY: upheld by this method's caller.
        let probe =
            unsafe { StackProbe::paint(stack, stack_config) }.map_err(BenchmarkError::Stack)?;
        self.run_inner(platform, reporter, operation, Some(&probe))
    }

    fn run_inner<P: MeasurementPlatform, R: BenchmarkReporter>(
        &self,
        platform: &mut P,
        reporter: &mut R,
        mut operation: impl FnMut() -> bool,
        #[cfg(feature = "stack")] stack_probe: Option<&StackProbe>,
        #[cfg(not(feature = "stack"))] _stack_probe: Option<&()>,
    ) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
        for _ in 0..self.config.warmups {
            let (_, _) = platform.measure(self.config.batches, &mut operation);
        }

        let mut samples = SampleSet::new();
        let mut passed = true;
        for _ in 0..N {
            let (measurement, output_ok) = platform.measure(self.config.batches, &mut operation);
            passed &= output_ok
                && self
                    .max_sample_ticks
                    .is_none_or(|limit| measurement.ticks < limit);
            samples
                .push(measurement)
                .map_err(|_| BenchmarkError::SampleCapacity)?;
        }

        #[cfg(feature = "stack")]
        // SAFETY: a probe can enter this method only through
        // `run_with_stack`, whose caller owns the exclusion contract.
        let stack = stack_probe.map(|probe| unsafe { probe.measure() });
        #[cfg(feature = "stack")]
        if let Some(measurement) = stack {
            passed &= !measurement.overflowed;
        }

        // Keep transport formatting and I/O outside the stack and cycle
        // evidence. All fixed-capacity measurements are retained above, so
        // reporting can happen after the workload boundary closes.
        for (trial, measurement) in samples.iter().copied().enumerate() {
            reporter
                .event(Event::Measurement {
                    record: &MeasurementRecord {
                        benchmark: self.config.benchmark,
                        measurement,
                        counter: None,
                        fields: self.config.fields,
                    },
                    trial: Some(trial as u32),
                })
                .map_err(BenchmarkError::Reporter)?;
        }
        #[cfg(feature = "stack")]
        if let Some(measurement) = stack {
            reporter
                .stack_measurement(&StackRecord {
                    benchmark: self.config.benchmark,
                    measurement,
                    fields: self.config.fields,
                })
                .map_err(BenchmarkError::Reporter)?;
        }
        reporter
            .event(Event::Outcome(&OutcomeRecord {
                benchmark: self.config.benchmark,
                passed,
                fields: self.config.fields,
            }))
            .map_err(BenchmarkError::Reporter)?;

        Ok(BenchmarkResult {
            samples,
            #[cfg(feature = "stack")]
            stack,
            passed,
        })
    }
}

fn run_batches(batches: usize, operation: &mut impl FnMut() -> bool) -> bool {
    let mut passed = true;
    for _ in 0..batches {
        passed &= black_box(operation());
    }
    passed
}

#[cfg(test)]
mod tests {
    extern crate std;

    #[cfg(feature = "stack")]
    use core::ptr::NonNull;
    use std::string::String;

    use super::*;
    use crate::Unit;
    use crate::report::TextReporter;

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
            let mut passed = true;
            for _ in 0..batches {
                passed &= operation();
            }
            self.calls += 1;
            self.ticks += 10;
            (Measurement::new(self.ticks, Unit::CoreCycles), passed)
        }
    }

    #[test]
    fn repeated_benchmark_reports_indexed_samples_and_one_outcome() {
        let mut platform = FakePlatform { ticks: 0, calls: 0 };
        let mut reporter = TextReporter::new(String::new());
        let result = Benchmark::<3>::new("parser")
            .warmups(2)
            .batches(4)
            .run(&mut platform, &mut reporter, || true)
            .unwrap();

        assert_eq!(platform.calls, 5);
        assert_eq!(result.samples.summary().unwrap().min, 30);
        assert_eq!(result.samples.summary().unwrap().max, 50);
        assert!(result.passed);
        let output = reporter.into_inner();
        assert!(output.contains("benchmark:parser ticks:30"));
        assert!(output.contains("trial:0"));
        assert!(output.contains("trial:2"));
        assert_eq!(output.matches("EM_MEASUREMENT").count(), 3);
        assert_eq!(output.matches("EM_OUTCOME").count(), 1);
    }

    #[cfg(feature = "stack")]
    #[test]
    fn completed_benchmark_reports_multiple_application_owned_counters() {
        let common = [Field::token("architecture", "riscv32")];
        let mut reporter = TextReporter::new(String::new());

        crate::report_completed!(
            &mut reporter,
            benchmark: "parser",
            passed: true,
            fields: &common,
            stack: StackMeasurement {
                high_water_bytes: 32,
                available_bytes: 128,
                painted_bytes: 96,
                safe_zone_bytes: 16,
                overflowed: false,
            },
            measurements: [
                ("mcycle", Measurement::new(120, Unit::CoreCycles)),
                ("minstret", Measurement::new(80, Unit::Instructions)),
            ]
        )
        .unwrap();

        let output = reporter.into_inner();
        assert_eq!(output.matches("EM_MEASUREMENT").count(), 2);
        assert!(output.contains("counter:mcycle"));
        assert!(output.contains("unit:instructions"));
        assert!(output.contains("counter:minstret"));
        assert!(
            output
                .contains("EM_OUTCOME schema:1 benchmark:parser status:PASS architecture:riscv32")
        );
    }

    #[test]
    fn external_benchmark_emits_balanced_boundaries_and_metrics() {
        let mut reporter = TextReporter::new(String::new());
        let benchmark = Benchmark::<2>::new("external-parser").warmups(1).batches(2);
        let mut calls = 0;
        let result = benchmark
            .run_external(&mut reporter, || {
                calls += 1;
                true
            })
            .unwrap();
        benchmark
            .report_metric(&mut reporter, "input-bytes", 512, Some("bytes"))
            .unwrap();

        assert!(result.passed);
        assert_eq!(calls, 6);
        let output = reporter.into_inner();
        assert_eq!(output.matches("EM_BOUNDARY").count(), 4);
        assert!(output.contains("trial:0 phase:begin"));
        assert!(output.contains("trial:1 phase:end status:PASS"));
        assert!(
            output.contains(
                "EM_METRIC schema:1 benchmark:external-parser name:input-bytes value:512"
            )
        );
    }

    #[cfg(not(feature = "stack"))]
    #[test]
    fn completed_benchmark_does_not_require_stack_support() {
        let mut reporter = TextReporter::new(String::new());
        crate::report_completed!(
            &mut reporter,
            benchmark: "parser",
            passed: true,
            fields: &[],
            measurements: [("timer", Measurement::new(12, Unit::TimerTicks))]
        )
        .unwrap();

        let output = reporter.into_inner();
        assert!(output.contains("EM_MEASUREMENT"));
        assert!(output.contains("EM_OUTCOME schema:1 benchmark:parser status:PASS"));
    }

    #[cfg(feature = "stack")]
    struct FakeStack {
        memory: [u8; 128],
        sp_offset: usize,
    }

    #[cfg(feature = "stack")]
    unsafe impl DescendingStack for FakeStack {
        fn bottom(&self) -> NonNull<u8> {
            NonNull::from(&self.memory[0]).cast()
        }

        fn top(&self) -> NonNull<u8> {
            NonNull::new(self.memory.as_ptr().wrapping_add(self.memory.len()) as *mut u8).unwrap()
        }

        fn current_stack_pointer(&self) -> NonNull<u8> {
            NonNull::new(self.memory.as_ptr().wrapping_add(self.sp_offset) as *mut u8).unwrap()
        }
    }

    #[cfg(feature = "stack")]
    #[test]
    fn stack_measurement_is_part_of_the_benchmark_outcome() {
        let stack = FakeStack {
            memory: [0; 128],
            sp_offset: 112,
        };
        let mut platform = FakePlatform { ticks: 0, calls: 0 };
        let mut reporter = TextReporter::new(String::new());
        // SAFETY: the test owns the stack allocation and has no concurrent
        // execution contexts.
        let result = unsafe {
            Benchmark::<2>::new("stacked-parser")
                .warmups(0)
                .run_with_stack(
                    &mut platform,
                    &mut reporter,
                    &stack,
                    StackConfig::new(16),
                    || true,
                )
        }
        .unwrap();

        assert!(result.passed);
        assert_eq!(result.stack.unwrap().high_water_bytes, 32);
        let output = reporter.into_inner();
        assert!(output.contains("EM_STACK schema:1 benchmark:stacked-parser used:32"));
        assert!(output.contains("EM_OUTCOME schema:1 benchmark:stacked-parser status:PASS"));
    }
}
