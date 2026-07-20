//! Host execution backends, isolated from campaign policy and reporting.

mod command;
mod gdb_remote;
mod jtrace;
mod jtrace_gate;
mod simavr;
mod timestamp;

pub use command::*;
pub use gdb_remote::*;
pub use jtrace::*;
pub use jtrace_gate::*;
pub use simavr::*;
pub use timestamp::*;
