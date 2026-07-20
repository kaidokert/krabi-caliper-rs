//! RTT transport for the stable text reporting protocol.
//!
//! Use [`reporter`] when the application already owns an RTT control block.
//! The [`init`] family is an optional convenience for firmware that delegates
//! control-block and print-channel ownership to this module.

use core::fmt;

use rtt_target::{ChannelMode, UpChannel, rprint, rtt_init, set_print_channel};

use crate::report::{Compatibility, TextReporter};

pub type RttReporter = TextReporter<RttWriter>;
pub type ChannelReporter = TextReporter<UpChannel>;

/// Wraps an application-owned RTT up-channel without creating a control block
/// or changing the process-wide print channel.
pub const fn reporter(channel: UpChannel) -> ChannelReporter {
    TextReporter::new(channel)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RttWriter;

impl fmt::Write for RttWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        rprint!("{}", value);
        Ok(())
    }
}

/// Creates and installs RTT channel 0 as a non-blocking global print channel.
///
/// Use [`reporter`] instead if the application has already initialized RTT.
/// This mode may drop data when the host stalls.
pub fn init() -> RttReporter {
    init_with_mode(ChannelMode::NoBlockSkip)
}

/// Creates and installs RTT channel 0 as a lossless global print channel.
///
/// This blocks if the host stops draining RTT and should not be used for
/// unattended firmware. It is appropriate for machine evidence, where a
/// dropped fragment would corrupt the record stream. Use [`reporter`] instead
/// if the application has already initialized RTT.
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
