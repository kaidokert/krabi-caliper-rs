//! Cortex-M semihosting transport for QEMU and debugger-hosted firmware.

use core::fmt;

use cortex_m_semihosting::{debug, hio};

use crate::report::TextReporter;

pub type SemihostingWriter = hio::HostStream;
pub type SemihostingReporter = TextReporter<SemihostingWriter>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitError;

pub fn init() -> Result<SemihostingReporter, InitError> {
    hio::hstdout()
        .map(TextReporter::new)
        .map_err(|()| InitError)
}

pub fn print(arguments: fmt::Arguments<'_>) {
    cortex_m_semihosting::hprint!("{}", arguments);
}

pub fn exit_success() -> ! {
    debug::exit(debug::EXIT_SUCCESS);
    loop {
        core::hint::spin_loop();
    }
}

pub fn exit_failure() -> ! {
    debug::exit(debug::EXIT_FAILURE);
    loop {
        core::hint::spin_loop();
    }
}
