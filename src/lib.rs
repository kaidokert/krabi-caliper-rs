#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Architecture-neutral measurement values and fixed-capacity samples.
//!
//! Hardware counter ownership and configuration remain with the application.
//! [`ReadCounter`] adapts an application-owned monotonically increasing reader
//! without imposing a HAL, PAC, runtime, or board framework.

pub mod backends;
pub mod core;
pub mod protocol;

pub use core::counter::{Counter, Measurement, Nanoseconds, Rate, ReadCounter, Unit};
#[cfg(feature = "paired")]
pub use core::paired;
pub use core::sample::{SampleSet, Summary, SummaryError};
#[cfg(feature = "stack")]
pub use core::stack;
pub use protocol::report;

#[cfg(feature = "cortex-m")]
pub use backends::cortex_m;

#[cfg(all(
    feature = "risc-v",
    any(target_arch = "riscv32", target_arch = "riscv64")
))]
pub use backends::risc_v;
