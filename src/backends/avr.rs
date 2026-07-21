//! AVR timer counter adapters.

#[cfg(any(test, all(feature = "avr-atmega2560", target_arch = "avr")))]
use crate::{Measurement, Unit};

/// Extends a 16-bit timer snapshot with a software overflow count.
///
/// `overflow_pending` handles the interval after the peripheral wraps but
/// before its ISR increments `wraps`. The three inputs must be sampled in one
/// interrupt-free critical section. Sampling the counter before the pending
/// flag is intentional: a pending flag paired with a high counter value means
/// the overflow happened after the counter read and must not yet be folded in.
pub const fn extend_timer16(wraps: u32, counter: u16, overflow_pending: bool) -> u64 {
    let pending_wrap = overflow_pending && counter < 0x8000;
    (wraps.wrapping_add(pending_wrap as u32) as u64) << 16 | counter as u64
}

#[cfg(any(test, all(feature = "avr-atmega2560", target_arch = "avr")))]
fn timer_measurement(ticks: u64, frequency_hz: Option<u64>, wrapped: bool) -> Measurement {
    let mut measurement = Measurement::new(ticks, Unit::TimerTicks).with_wrapped(wrapped);
    measurement.frequency_hz = frequency_hz;
    measurement
}

#[cfg(all(feature = "avr-atmega2560", target_arch = "avr"))]
mod atmega2560 {
    use core::cell::Cell;

    use avr_device::atmega2560::{CPU, TC1};
    use avr_device::interrupt::Mutex;

    use super::{extend_timer16, timer_measurement};
    #[cfg(feature = "stack")]
    use crate::FootprintError;
    #[cfg(feature = "stack")]
    use crate::report::{Field, MeasurementRecord, OutcomeRecord, StackRecord, StackReporter};
    #[cfg(feature = "stack")]
    use crate::stack::{DescendingStack, StackConfig};
    #[cfg(feature = "stack")]
    use crate::stack::{StackMeasurement, paint_avr_runtime};
    #[cfg(feature = "stack")]
    use crate::{Benchmark, BenchmarkError, BenchmarkReporter, BenchmarkResult, CounterPlatform};
    use crate::{Counter, Measurement};

    static TIMER1_WRAPS: Mutex<Cell<u32>> = Mutex::new(Cell::new(0));

    /// Records one Timer/Counter1 overflow.
    ///
    /// The application must call this from its `TIMER1_OVF` interrupt handler.
    #[inline(always)]
    pub fn timer1_overflow() {
        avr_device::interrupt::free(|cs| {
            let wraps = TIMER1_WRAPS.borrow(cs);
            wraps.set(wraps.get().wrapping_add(1));
        });
    }

    fn read_timer1(timer: &TC1) -> u64 {
        avr_device::interrupt::free(|cs| {
            extend_timer16(
                TIMER1_WRAPS.borrow(cs).get(),
                timer.tcnt1.read().bits(),
                timer.tifr1.read().tov1().bit_is_set(),
            )
        })
    }

    /// Wrap-extended ATmega2560 Timer/Counter1 using the `/1024` prescaler.
    ///
    /// The application owns the CPU clock and supplies the resulting timer
    /// tick frequency. It must install an overflow ISR that calls
    /// [`timer1_overflow`] and enable global interrupts before relying on
    /// software wrap extension. This adapter never changes global interrupt
    /// state.
    pub struct Timer1Counter<'timer> {
        timer: &'timer mut TC1,
        frequency_hz: Option<u64>,
        start_total: u64,
    }

    impl<'timer> Timer1Counter<'timer> {
        /// Stops and configures Timer1, clears stale overflow state, enables
        /// its overflow interrupt, then starts it with the `/1024` prescaler.
        pub fn start_prescale_1024(timer: &'timer mut TC1, frequency_hz: Option<u64>) -> Self {
            timer.tccr1b.write(|writer| writer.cs1().no_clock());
            timer.tccr1a.reset();
            avr_device::interrupt::free(|cs| TIMER1_WRAPS.borrow(cs).set(0));
            timer.tifr1.write(|writer| writer.tov1().set_bit());
            timer.timsk1.write(|writer| writer.toie1().set_bit());
            timer.tccr1b.write(|writer| writer.cs1().prescale_1024());
            let start_total = read_timer1(timer);
            Self {
                timer,
                frequency_hz,
                start_total,
            }
        }

        pub fn elapsed_ticks_since_start(&self) -> u64 {
            read_timer1(self.timer).wrapping_sub(self.start_total)
        }
    }

    impl Counter for Timer1Counter<'_> {
        type Instant = u64;

        #[inline(always)]
        fn now(&mut self) -> Self::Instant {
            read_timer1(self.timer)
        }

        #[inline(always)]
        fn elapsed(&mut self, start: Self::Instant) -> Measurement {
            let end = read_timer1(self.timer);
            timer_measurement(end.wrapping_sub(start), self.frequency_hz, end < start)
        }
    }

    /// Client-owned policy for one ATmega2560 footprint operation.
    #[cfg(feature = "stack")]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FootprintConfig<'a> {
        pub benchmark: &'a str,
        pub fields: &'a [Field<'a>],
        pub sentinel: u8,
        pub frequency_hz: Option<u64>,
    }

    #[cfg(feature = "stack")]
    impl<'a> FootprintConfig<'a> {
        pub const fn new(benchmark: &'a str, fields: &'a [Field<'a>]) -> Self {
            Self {
                benchmark,
                fields,
                sentinel: crate::stack::DEFAULT_SENTINEL,
                frequency_hz: Some(15_625),
            }
        }

        pub const fn sentinel(mut self, sentinel: u8) -> Self {
            self.sentinel = sentinel;
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
    /// The avr-libc `_end..RAMEND` stack region must be exclusively owned while active.
    #[cfg(feature = "stack")]
    pub unsafe fn run_footprint<const SAFE_ZONE_BYTES: usize, R: StackReporter>(
        timer: &mut TC1,
        reporter: &mut R,
        config: FootprintConfig<'_>,
        operation: fn() -> bool,
    ) -> Result<bool, FootprintError<R::Error>> {
        let stack_probe = unsafe { paint_avr_runtime::<SAFE_ZONE_BYTES>(0x2200, config.sentinel) }
            .map_err(FootprintError::Stack)?;
        let counter = Timer1Counter::start_prescale_1024(timer, config.frequency_hz);
        let passed = operation();
        let timer1 = timer_measurement(
            counter.elapsed_ticks_since_start(),
            config.frequency_hz,
            false,
        );
        let stack = unsafe { stack_probe.measure() };

        report_footprint(reporter, config, passed, stack, timer1)?;
        Ok(passed)
    }

    #[cfg(feature = "stack")]
    fn report_footprint<R: StackReporter>(
        reporter: &mut R,
        config: FootprintConfig<'_>,
        passed: bool,
        stack: StackMeasurement,
        timer1: Measurement,
    ) -> Result<(), FootprintError<R::Error>> {
        reporter
            .measurement(&MeasurementRecord {
                benchmark: config.benchmark,
                measurement: timer1,
                counter: Some("timer1"),
                fields: config.fields,
            })
            .map_err(FootprintError::Reporter)?;
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

    /// Runs a repeated Timer1 benchmark with a caller-owned stack allocation.
    ///
    /// # Safety
    /// The caller must uphold [`Benchmark::run_with_stack`]'s exclusive stack
    /// access contract for the supplied allocation.
    #[cfg(feature = "stack")]
    pub unsafe fn run_benchmark<const N: usize, R: BenchmarkReporter>(
        timer: &mut TC1,
        frequency_hz: Option<u64>,
        reporter: &mut R,
        benchmark: &Benchmark<'_, N>,
        stack: &impl DescendingStack,
        stack_config: StackConfig,
        operation: impl FnMut() -> bool,
    ) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
        let counter = Timer1Counter::start_prescale_1024(timer, frequency_hz);
        let mut platform = CounterPlatform::new(counter);
        unsafe { benchmark.run_with_stack(&mut platform, reporter, stack, stack_config, operation) }
    }

    /// Terminates a simavr fixture after reporting without burning host CPU.
    pub fn park_simavr(cpu: &CPU) -> ! {
        avr_device::interrupt::disable();
        cpu.smcr.write(|writer| writer.se().set_bit());
        loop {
            avr_device::asm::sleep();
        }
    }
}

#[cfg(all(feature = "avr-atmega2560", target_arch = "avr", feature = "stack"))]
pub use atmega2560::run_benchmark as run_atmega2560_benchmark;
#[cfg(all(feature = "avr-atmega2560", target_arch = "avr", feature = "stack"))]
pub use atmega2560::{FootprintConfig, run_footprint as run_atmega2560_footprint};
#[cfg(all(feature = "avr-atmega2560", target_arch = "avr"))]
pub use atmega2560::{Timer1Counter as Atmega2560Timer1Counter, park_simavr, timer1_overflow};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_in_only_an_overflow_that_precedes_the_counter_read() {
        assert_eq!(extend_timer16(4, 7, true), (5 << 16) + 7);
        assert_eq!(extend_timer16(5, 7, false), (5 << 16) + 7);
        assert_eq!(extend_timer16(4, 0xf000, true), (4 << 16) + 0xf000);
    }

    #[test]
    fn qualifies_timer_measurements_without_assuming_a_board_clock() {
        assert_eq!(
            timer_measurement(25, Some(15_625), false),
            Measurement::new(25, Unit::TimerTicks).with_frequency(15_625)
        );
        assert_eq!(
            timer_measurement(9, None, true),
            Measurement::new(9, Unit::TimerTicks).with_wrapped(true)
        );
    }
}
