#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Architecture-neutral measurement values and fixed-capacity samples.
//!
//! Hardware counter ownership and configuration remain with the application.
//! [`ReadCounter`] adapts an application-owned monotonically increasing reader
//! without imposing a HAL, PAC, runtime, or board framework.

#[cfg(feature = "host")]
extern crate std;

pub mod backends;
pub mod core;
#[cfg(feature = "host")]
pub mod host;
pub mod protocol;

pub use core::benchmark::{
    Benchmark, BenchmarkConfig, BenchmarkError, BenchmarkReporter, BenchmarkResult,
    CounterPlatform, ExternalBenchmarkResult, MeasurementPlatform,
};
pub use core::counter::{Counter, Measurement, Nanoseconds, Rate, ReadCounter, Unit};
#[cfg(feature = "deterministic-rng")]
pub use core::deterministic;
pub use core::footprint::FootprintError;
#[cfg(feature = "paired")]
pub use core::paired;
pub use core::sample::{SampleSet, Summary, SummaryError};
#[cfg(feature = "stack")]
pub use core::stack;
#[cfg(feature = "paired")]
pub use core::suite;
pub use protocol::report;

/// Reports application-owned measurements and one outcome.
///
/// This expands to direct reporter calls so footprint-sensitive firmware does
/// not retain a generic measurement loop. The `stack:` form additionally
/// reports stack evidence and requires the `stack` feature.
#[macro_export]
macro_rules! report_completed {
    (
        $reporter:expr,
        benchmark: $benchmark:expr,
        passed: $passed:expr,
        fields: $fields:expr,
        measurements: [
            $(
                $(#[$measurement_meta:meta])*
                ($counter:expr, $measurement:expr)
            ),* $(,)?
        ]
    ) => {{
        use $crate::report::Reporter as _;
        let result: Result<(), _> = Ok(());
        $(
            $(#[$measurement_meta])*
            let result = result.and_then(|()| {
                $reporter.measurement(&$crate::report::MeasurementRecord {
                    benchmark: $benchmark,
                    measurement: $measurement,
                    counter: Some($counter),
                    fields: $fields,
                })
            });
        )*
        result.and_then(|()| {
            $reporter.outcome(&$crate::report::OutcomeRecord {
                benchmark: $benchmark,
                passed: $passed,
                fields: $fields,
            })
        })
    }};
    (
        $reporter:expr,
        benchmark: $benchmark:expr,
        passed: $passed:expr,
        fields: $fields:expr,
        stack: $stack:expr,
        measurements: [
            $(
                $(#[$measurement_meta:meta])*
                ($counter:expr, $measurement:expr)
            ),* $(,)?
        ]
    ) => {{
        use $crate::report::{Reporter as _, StackReporter as _};
        let result: Result<(), _> = Ok(());
        $(
            $(#[$measurement_meta])*
            let result = result.and_then(|()| {
                $reporter.measurement(&$crate::report::MeasurementRecord {
                    benchmark: $benchmark,
                    measurement: $measurement,
                    counter: Some($counter),
                    fields: $fields,
                })
            });
        )*
        result
            .and_then(|()| {
                $reporter.stack_measurement(&$crate::report::StackRecord {
                    benchmark: $benchmark,
                    measurement: $stack,
                    fields: $fields,
                })
            })
            .and_then(|()| {
                $reporter.outcome(&$crate::report::OutcomeRecord {
                    benchmark: $benchmark,
                    passed: $passed,
                    fields: $fields,
                })
            })
    }};
}

#[cfg(feature = "avr")]
pub use backends::avr;

#[cfg(feature = "cortex-m")]
pub use backends::cortex_m;

#[cfg(all(
    feature = "risc-v",
    any(target_arch = "riscv32", target_arch = "riscv64")
))]
pub use backends::risc_v;
