#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Architecture-neutral measurement values and fixed-capacity samples.
//!
//! Hardware counter ownership and configuration remain with the application.
//! [`ReadCounter`] adapts an application-owned monotonically increasing reader
//! without imposing a HAL, PAC, runtime, or board framework.

pub mod core;

pub use core::counter::{Counter, Measurement, Nanoseconds, Rate, ReadCounter, Unit};
pub use core::sample::{SampleSet, Summary, SummaryError};
