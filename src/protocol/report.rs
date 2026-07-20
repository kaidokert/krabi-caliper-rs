//! Versioned, line-oriented measurement reporting.

use core::fmt::{self, Write};

use crate::Unit;
#[cfg(feature = "paired")]
use crate::paired::PairedRun;
#[cfg(feature = "stack")]
use crate::stack::StackMeasurement;

pub const SCHEMA_VERSION: u16 = 1;

include!("report/model.rs");
include!("report/encoding.rs");
include!("report/tests.rs");
