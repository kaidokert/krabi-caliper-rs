//! Instantiates the ufmt encoder for every event that carries a `u64`, so the object file shows
//! which helpers the encoder calls. See `Cargo.toml`.
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

/// Reports every event that carries a `u64`, with caller-supplied values.
#[cfg(not(feature = "control"))]
#[unsafe(no_mangle)]
pub extern "C" fn report_wide(ticks: u64, frequency: u64, bytes: u64) -> bool {
    use krabi_caliper::report::{
        BoundaryPhase, ComparisonRecord, CounterSnapshotRecord, Field, MeasurementRecord,
        MetricPolicy, MetricRecord, Reporter, RunStart, SampleRecord, UfmtReporter,
    };
    use krabi_caliper::{Measurement, Unit};

    let fields = [Field::u64("bytes", bytes)];
    let comparison = ComparisonRecord {
        fixture: "check",
        class: "check",
        policy: None,
        a_min: ticks,
        a_max: frequency,
        b_min: bytes,
        b_max: ticks,
        spread: frequency,
        overlap: false,
        wrapped: false,
        output_ok: true,
        passed: None,
        fields: &fields,
    };
    let mut reporter = UfmtReporter::new(Sink);
    reporter
        .run_start(&RunStart {
            suite: "check",
            target: "check",
            board: None,
            unit: Unit::CoreCycles,
            frequency_hz: Some(frequency),
            fields: &fields,
        })
        .is_ok()
        && reporter
            .sample(&SampleRecord {
                fixture: "check",
                side: 'A',
                index: 0,
                ticks,
                wrapped: false,
                fields: &fields,
            })
            .is_ok()
        && reporter.result(&comparison).is_ok()
        && reporter.diagnostic(&comparison).is_ok()
        && reporter
            .indexed_measurement(
                &MeasurementRecord {
                    benchmark: "check",
                    measurement: Measurement::new(ticks, Unit::CoreCycles)
                        .with_frequency(frequency),
                    counter: Some("counter"),
                    fields: &fields,
                },
                0,
            )
            .is_ok()
        && reporter
            .counter_snapshot(&CounterSnapshotRecord {
                benchmark: "check",
                trial: 0,
                phase: BoundaryPhase::Begin,
                ticks,
                width_bits: 32,
                unit: Unit::CoreCycles,
                frequency_hz: Some(frequency),
                fields: &fields,
            })
            .is_ok()
        && reporter
            .metric(&MetricRecord {
                benchmark: "check",
                name: "bytes",
                value: bytes,
                unit: None,
                policy: MetricPolicy::Informational,
                fields: &fields,
            })
            .is_ok()
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
