//! Versioned, line-oriented measurement reporting.

use core::fmt::{self, Write};

use crate::Unit;

pub const SCHEMA_VERSION: u16 = 1;

include!("report/model.rs");
include!("report/encoding.rs");
include!("report/tests.rs");
