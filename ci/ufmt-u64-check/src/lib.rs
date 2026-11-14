//! Instantiates the ufmt encoder for one measurement, so the object file shows which helpers the
//! encoder calls. See `Cargo.toml`.
#![no_std]

use core::convert::Infallible;

unsafe extern "C" {
    fn emit(bytes: *const u8, length: usize);
}

struct Sink;

impl ufmt::uWrite for Sink {
    type Error = Infallible;

    fn write_str(&mut self, text: &str) -> Result<(), Infallible> {
        // SAFETY: `emit` is resolved at link time by whoever links this object; this crate only
        // compiles it to an object file.
        unsafe { emit(text.as_ptr(), text.len()) };
        Ok(())
    }
}

/// Reports one measurement and one metric with caller-supplied `u64` values.
#[cfg(not(feature = "control"))]
#[unsafe(no_mangle)]
pub extern "C" fn report_wide(ticks: u64, frequency: u64, bytes: u64) -> bool {
    use krabi_caliper::report::{
        Field, MeasurementRecord, MetricPolicy, MetricRecord, Reporter, UfmtReporter,
    };
    use krabi_caliper::{Measurement, Unit};

    let fields = [Field::u64("bytes", bytes)];
    let record = MeasurementRecord {
        benchmark: "check",
        measurement: Measurement::new(ticks, Unit::CoreCycles).with_frequency(frequency),
        counter: Some("counter"),
        fields: &fields,
    };
    let metric = MetricRecord {
        benchmark: "check",
        name: "bytes",
        value: bytes,
        unit: None,
        policy: MetricPolicy::Informational,
        fields: &[],
    };
    let mut reporter = UfmtReporter::new(Sink);
    reporter.indexed_measurement(&record, 0).is_ok() && reporter.metric(&metric).is_ok()
}

/// Positive control: ufmt's own `u64` formatting.
#[cfg(feature = "control")]
#[unsafe(no_mangle)]
pub extern "C" fn report_wide(ticks: u64, _frequency: u64, _bytes: u64) -> bool {
    ufmt::uwrite!(Sink, "{}", ticks).is_ok()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
