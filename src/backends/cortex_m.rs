//! Cortex-M measurement adapters.

#[cfg(all(feature = "cortex-m-dwt", krabi_caliper_armv6m))]
compile_error!(
    "the `cortex-m-dwt` feature requires a DWT-capable core and is unavailable on ARMv6-M"
);

#[cfg(all(feature = "cortex-m-dwt", not(krabi_caliper_armv6m)))]
mod dwt {
    use core::hint::black_box;

    use cortex_m::peripheral::{DCB, DWT};

    use crate::MeasurementPlatform;
    use crate::{Counter, Measurement, Unit};

    fn measurement_between(start: u32, end: u32, frequency_hz: Option<u64>) -> Measurement {
        let mut measurement = Measurement::new(end.wrapping_sub(start) as u64, Unit::CoreCycles)
            .with_wrapped(end < start);
        measurement.frequency_hz = frequency_hz;
        measurement
    }

    /// The Cortex-M DWT 32-bit core-cycle counter.
    ///
    /// The application retains ownership of the peripheral handles and core
    /// clock configuration. No other code may read, reset, or reconfigure
    /// CYCCNT while this adapter is active. Measurements are valid only when
    /// the interval remains below one complete 32-bit counter period.
    pub struct DwtCycleCounter<'dwt> {
        dwt: &'dwt mut DWT,
        frequency_hz: Option<u64>,
    }

    impl<'dwt> DwtCycleCounter<'dwt> {
        /// Enables trace and CYCCNT, resets the counter, and returns its adapter.
        pub fn enable(
            dcb: &mut DCB,
            dwt: &'dwt mut DWT,
            frequency_hz: Option<u64>,
        ) -> Option<Self> {
            if !DWT::has_cycle_counter() {
                return None;
            }
            dcb.enable_trace();
            DWT::unlock();
            dwt.set_cycle_count(0);
            dwt.enable_cycle_counter();
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            if !DWT::cycle_counter_enabled() {
                return None;
            }
            Some(Self { dwt, frequency_hz })
        }

        /// Resets CYCCNT immediately before a guarded measurement interval.
        ///
        /// Resetting avoids rejecting a short operation merely because it
        /// crossed the counter's arbitrary global wrap boundary.
        fn reset(&mut self) {
            self.dwt.set_cycle_count(0);
        }
    }

    impl Counter for DwtCycleCounter<'_> {
        type Instant = u32;

        #[inline(always)]
        fn now(&mut self) -> Self::Instant {
            DWT::cycle_count()
        }

        #[inline(always)]
        fn elapsed(&mut self, start: Self::Instant) -> Measurement {
            let end = DWT::cycle_count();
            measurement_between(start, end, self.frequency_hz)
        }
    }

    /// Measures one or more calls inside a critical section with DWT barriers.
    ///
    /// This resets CYCCNT before every interval and therefore requires
    /// exclusive use of that counter. The application must provide the
    /// `critical-section` implementation appropriate for its processor,
    /// runtime, and scheduler. The measured interval must remain below one
    /// complete 32-bit CYCCNT period.
    #[inline(always)]
    pub fn measure_in_critical_section(
        counter: &mut DwtCycleCounter<'_>,
        batches: usize,
        mut operation: impl FnMut() -> bool,
    ) -> (Measurement, bool) {
        critical_section::with(|_| {
            counter.reset();
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let start = counter.now();
            let mut outputs_ok = true;
            for _ in 0..batches {
                outputs_ok &= black_box(operation());
            }
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            (counter.elapsed(start), outputs_ok)
        })
    }

    /// DWT-backed benchmark platform with interrupt exclusion and barriers.
    ///
    /// The measured operation runs with interrupts disabled. It must not wait
    /// for interrupt-driven I/O, timers, executors, or background work.
    pub struct DwtMeasurementPlatform<'dwt> {
        counter: DwtCycleCounter<'dwt>,
    }

    impl<'dwt> DwtMeasurementPlatform<'dwt> {
        pub fn enable(
            dcb: &mut DCB,
            dwt: &'dwt mut DWT,
            frequency_hz: Option<u64>,
        ) -> Option<Self> {
            DwtCycleCounter::enable(dcb, dwt, frequency_hz).map(|counter| Self { counter })
        }
    }

    impl MeasurementPlatform for DwtMeasurementPlatform<'_> {
        #[inline(always)]
        fn measure(
            &mut self,
            batches: usize,
            operation: impl FnMut() -> bool,
        ) -> (Measurement, bool) {
            measure_in_critical_section(&mut self.counter, batches, operation)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn elapsed_measurement_retains_frequency_and_wrap_evidence() {
            assert_eq!(
                measurement_between(10, 35, Some(168_000_000)),
                Measurement::new(25, Unit::CoreCycles).with_frequency(168_000_000)
            );
            assert_eq!(
                measurement_between(u32::MAX - 5, 3, None),
                Measurement::new(9, Unit::CoreCycles).with_wrapped(true)
            );
        }
    }
}

#[cfg(all(feature = "cortex-m-dwt", not(krabi_caliper_armv6m)))]
pub use dwt::{DwtCycleCounter, DwtMeasurementPlatform, measure_in_critical_section};

#[cfg(all(feature = "stack", target_arch = "arm"))]
mod footprint {
    use core::sync::atomic::{AtomicU32, Ordering};

    use cortex_m::peripheral::{SYST, syst::SystClkSource};

    use crate::report::{Field, MeasurementRecord, OutcomeRecord, StackRecord, StackReporter};
    use crate::stack::{StackMeasurement, paint_cortex_m_runtime};
    use crate::{Counter, FootprintError, Measurement, Unit};

    const SYSTICK_RELOAD: u32 = 0x00ff_ffff;
    static SYSTICK_WRAPS: AtomicU32 = AtomicU32::new(0);

    fn extend_systick(wraps: u32, current: u32) -> u64 {
        wraps as u64 * (SYSTICK_RELOAD as u64 + 1) + (SYSTICK_RELOAD as u64 - current as u64)
    }

    /// Records one SysTick overflow for the footprint cycle counter.
    pub fn systick_overflow() {
        let wraps = SYSTICK_WRAPS.load(Ordering::Relaxed);
        SYSTICK_WRAPS.store(wraps.wrapping_add(1), Ordering::Relaxed);
    }

    pub struct SysTickCycleCounter {
        start: u64,
        frequency_hz: Option<u64>,
    }

    impl SysTickCycleCounter {
        pub fn start(syst: &mut SYST, frequency_hz: Option<u64>) -> Self {
            SYSTICK_WRAPS.store(0, Ordering::SeqCst);
            syst.set_clock_source(SystClkSource::Core);
            syst.set_reload(SYSTICK_RELOAD);
            syst.clear_current();
            syst.enable_interrupt();
            syst.enable_counter();
            cortex_m::asm::dsb();
            while SYST::get_current() == 0 {
                cortex_m::asm::nop();
            }
            Self {
                start: Self::read_cycles(),
                frequency_hz,
            }
        }

        fn read_cycles() -> u64 {
            loop {
                let wraps_before = SYSTICK_WRAPS.load(Ordering::SeqCst);
                let current = SYST::get_current();
                let wraps_after = SYSTICK_WRAPS.load(Ordering::SeqCst);
                if wraps_before == wraps_after {
                    return extend_systick(wraps_before, current);
                }
            }
        }

        fn elapsed_since_start(&mut self) -> Measurement {
            self.elapsed(self.start)
        }
    }

    impl Counter for SysTickCycleCounter {
        type Instant = u64;

        fn now(&mut self) -> Self::Instant {
            Self::read_cycles()
        }

        fn elapsed(&mut self, start: Self::Instant) -> Measurement {
            let mut measurement =
                Measurement::new(Self::read_cycles().wrapping_sub(start), Unit::CoreCycles);
            measurement.frequency_hz = self.frequency_hz;
            measurement
        }
    }

    /// Client-owned policy for one Cortex-M footprint operation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FootprintConfig<'a> {
        pub benchmark: &'a str,
        pub fields: &'a [Field<'a>],
        pub enable_dwt: bool,
        pub frequency_hz: Option<u64>,
    }

    impl<'a> FootprintConfig<'a> {
        pub const fn new(benchmark: &'a str, fields: &'a [Field<'a>]) -> Self {
            Self {
                benchmark,
                fields,
                enable_dwt: false,
                frequency_hz: None,
            }
        }

        pub const fn enable_dwt(mut self, enable: bool) -> Self {
            self.enable_dwt = enable;
            self
        }

        pub const fn frequency_hz(mut self, frequency_hz: u64) -> Self {
            self.frequency_hz = Some(frequency_hz);
            self
        }
    }

    /// Paints the runtime stack, measures one operation, and emits canonical events.
    ///
    /// # Safety
    /// The `cortex-m-rt` linker stack must be exclusively owned while the probe is active.
    pub unsafe fn run_footprint<const SAFE_ZONE_BYTES: usize, R: StackReporter>(
        reporter: impl FnOnce() -> R,
        config: FootprintConfig<'_>,
        operation: fn() -> bool,
    ) -> Result<bool, FootprintError<R::Error>> {
        let stack_probe = unsafe { paint_cortex_m_runtime::<SAFE_ZONE_BYTES>() }
            .map_err(FootprintError::Stack)?;
        let mut peripherals =
            cortex_m::Peripherals::take().ok_or(FootprintError::CounterUnavailable)?;
        let mut systick = SysTickCycleCounter::start(&mut peripherals.SYST, config.frequency_hz);

        #[cfg(all(feature = "cortex-m-dwt", not(krabi_caliper_armv6m)))]
        let mut dwt = if config.enable_dwt {
            super::DwtCycleCounter::enable(
                &mut peripherals.DCB,
                &mut peripherals.DWT,
                config.frequency_hz,
            )
        } else {
            None
        };
        #[cfg(any(not(feature = "cortex-m-dwt"), krabi_caliper_armv6m))]
        if config.enable_dwt {
            return Err(FootprintError::CounterUnavailable);
        }

        #[cfg(all(feature = "cortex-m-dwt", not(krabi_caliper_armv6m)))]
        let dwt_start = dwt.as_mut().map(Counter::now);
        let passed = operation();
        #[cfg(all(feature = "cortex-m-dwt", not(krabi_caliper_armv6m)))]
        let dwt_measurement = dwt
            .as_mut()
            .zip(dwt_start)
            .map(|(counter, start)| counter.elapsed(start));
        #[cfg(any(not(feature = "cortex-m-dwt"), krabi_caliper_armv6m))]
        let dwt_measurement = None;
        let systick_measurement = systick.elapsed_since_start();
        let stack = unsafe { stack_probe.measure() };
        let mut reporter = reporter();

        report_footprint(
            &mut reporter,
            config,
            passed,
            stack,
            systick_measurement,
            dwt_measurement,
        )?;
        Ok(passed)
    }

    fn report_footprint<R: StackReporter>(
        reporter: &mut R,
        config: FootprintConfig<'_>,
        passed: bool,
        stack: StackMeasurement,
        systick: Measurement,
        dwt: Option<Measurement>,
    ) -> Result<(), FootprintError<R::Error>> {
        reporter
            .measurement(&MeasurementRecord {
                benchmark: config.benchmark,
                measurement: systick,
                counter: Some("systick"),
                fields: config.fields,
            })
            .map_err(FootprintError::Reporter)?;
        if let Some(measurement) = dwt {
            reporter
                .measurement(&MeasurementRecord {
                    benchmark: config.benchmark,
                    measurement,
                    counter: Some("dwt"),
                    fields: config.fields,
                })
                .map_err(FootprintError::Reporter)?;
        }
        reporter
            .stack_measurement(&StackRecord {
                benchmark: config.benchmark,
                measurement: stack,
                fields: config.fields,
            })
            .map_err(FootprintError::Reporter)?;
        reporter
            .outcome(&OutcomeRecord {
                benchmark: config.benchmark,
                passed,
                fields: config.fields,
            })
            .map_err(FootprintError::Reporter)
    }
}

#[cfg(all(feature = "stack", target_arch = "arm"))]
pub use footprint::{FootprintConfig, SysTickCycleCounter, run_footprint, systick_overflow};

/// Debugger-safe terminal loop for hardware measurement firmware.
#[cfg(target_arch = "arm")]
pub fn park() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}
