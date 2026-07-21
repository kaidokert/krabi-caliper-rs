#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(target_arch = "avr", feature(asm_experimental_arch))]

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

#[doc(hidden)]
#[cfg(feature = "ctgrind")]
pub mod __ctgrind_private {
    pub use inventory;
    pub use paste::paste;
}

/// Registers a CT-grind fixture using the shared inventory and naming policy.
#[cfg(feature = "ctgrind")]
#[macro_export]
macro_rules! ctgrind_fixture {
    ($name:ident, $body:block) => {
        $crate::__ctgrind_private::paste! {
            #[allow(non_snake_case)]
            fn [<run_ $name>]() $body
            $crate::__ctgrind_private::inventory::submit! {
                $crate::host::ctgrind::CtgrindFixture {
                    name: stringify!($name),
                    run: [<run_ $name>],
                }
            }
        }
    };
}

/// Places a typed ctgrind registration beside an already-defined exported
/// fixture without colliding with its Rust value-namespace name.
#[cfg(feature = "ctgrind")]
#[macro_export]
macro_rules! ctgrind_local {
    ($name:ident, $registration:item) => {
        $crate::__ctgrind_private::paste! {
            #[allow(non_snake_case)]
            mod [<ctgrind_registration_ $name>] {
                $registration
            }
        }
    };
}

/// Registers detector controls for secret-dependent branching, equality, and
/// indexed memory access. Every CT-grind binary should include these controls.
#[cfg(feature = "ctgrind")]
#[macro_export]
macro_rules! ctgrind_standard_controls {
    () => {
        $crate::ctgrind_fixture!(nct_fix__neg__caliper_branch, {
            let secret = core::hint::black_box([0u8; 32]);
            $crate::host::ctgrind::taint(&secret);
            let mut observed = 0u8;
            if secret[0] & 1 == 0 {
                unsafe { core::ptr::write_volatile(&mut observed, 1) };
            }
            core::hint::black_box(observed);
        });
        $crate::ctgrind_fixture!(nct_fix__neg__caliper_equality, {
            let secret = core::hint::black_box([0u8; 32]);
            $crate::host::ctgrind::taint(&secret);
            let mut observed = 0u8;
            if secret[0] == 42 {
                unsafe { core::ptr::write_volatile(&mut observed, 1) };
            }
            core::hint::black_box(observed);
        });
        $crate::ctgrind_fixture!(nct_fix__neg__caliper_index, {
            let secret = core::hint::black_box([0u8; 32]);
            let table = core::hint::black_box([0u8; 256]);
            $crate::host::ctgrind::taint(&secret);
            core::hint::black_box(table[secret[0] as usize]);
        });
    };
}

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

/// Installs the SysTick exception required by the Cortex-M footprint counter.
#[cfg(feature = "cortex-m")]
#[macro_export]
macro_rules! cortex_m_systick_overflow_handler {
    () => {
        #[cortex_m_rt::exception]
        fn SysTick() {
            $crate::cortex_m::systick_overflow();
        }
    };
}

/// Installs the Timer/Counter1 overflow ISR required by the ATmega2560 counter.
#[cfg(feature = "avr-atmega2560")]
#[macro_export]
macro_rules! atmega2560_timer1_overflow_handler {
    () => {
        #[avr_device::interrupt(atmega2560)]
        fn TIMER1_OVF() {
            $crate::avr::timer1_overflow();
        }
    };
}

/// Selects RTT on a caller-defined hardware feature and semihosting otherwise.
#[macro_export]
macro_rules! cortex_m_reporter {
    ($hardware_feature:literal) => {{
        #[cfg(feature = $hardware_feature)]
        {
            $crate::protocol::rtt::init_blocking()
        }
        #[cfg(not(feature = $hardware_feature))]
        {
            $crate::protocol::semihosting::init().expect("failed to open semihosting stdout")
        }
    }};
}

/// Exits a semihosted fixture and leaves hardware firmware running for RTT.
#[macro_export]
macro_rules! finish_cortex_m_report {
    ($passed:expr, $hardware_feature:literal) => {{
        #[cfg(not(feature = $hardware_feature))]
        if $passed {
            $crate::protocol::semihosting::exit_success();
        } else {
            $crate::protocol::semihosting::exit_failure();
        }
        #[cfg(feature = $hardware_feature)]
        let _ = $passed;
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
