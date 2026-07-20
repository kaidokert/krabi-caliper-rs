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

/// Debugger-safe terminal loop for hardware measurement firmware.
#[cfg(target_arch = "arm")]
pub fn park() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}
