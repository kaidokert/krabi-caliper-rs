//! RTT transport for the stable text reporting protocol.

use core::fmt;

use rtt_target::{ChannelMode, rprint, rtt_init, set_print_channel};

use crate::report::{Compatibility, TextReporter};

pub type RttReporter = TextReporter<RttWriter>;

#[derive(Clone, Copy, Debug, Default)]
pub struct RttWriter;

impl fmt::Write for RttWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        rprint!("{}", value);
        Ok(())
    }
}

/// Initializes a non-blocking reporter that may drop data when the host stalls.
pub fn init() -> RttReporter {
    init_with_mode(ChannelMode::NoBlockSkip)
}

/// Initializes a lossless reporting channel for debugger-attached campaigns.
///
/// This blocks if the host stops draining RTT and should not be used for
/// unattended firmware. It is appropriate for machine evidence, where a
/// dropped fragment would corrupt the record stream.
pub fn init_blocking() -> RttReporter {
    init_with_mode(ChannelMode::BlockIfFull)
}

pub fn init_ct_compatible() -> RttReporter {
    init_blocking().compatibility(Compatibility::CtV0)
}

pub fn print(arguments: fmt::Arguments<'_>) {
    rprint!("{}", arguments);
}

fn init_with_mode(mode: ChannelMode) -> RttReporter {
    let mut channels = rtt_init! {
        up: {
            0: {
                size: 4096,
                mode: ChannelMode::NoBlockSkip,
                name: "Terminal"
            }
        }
    };
    channels.up.0.set_mode(mode);
    set_print_channel(channels.up.0);
    TextReporter::new(RttWriter)
}
