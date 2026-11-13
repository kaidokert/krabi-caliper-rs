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

/// Internal clock source for 16-bit Timer/Counter1 (and the identical Timer3/4/5): the CPU clock
/// divided by a prescaler.
///
/// A smaller divisor gives finer ticks but wraps sooner. Software wrap extension needs the
/// overflow ISR to run within 0x8000 ticks of each wrap: about 2.1 s at `/1024` on a 16 MHz part,
/// but only 32,768 CPU cycles at `/1`. Interrupts disabled for longer than that, or a long ISR
/// elsewhere (AVR ISRs don't nest), make a measurement silently short by 65,536 ticks per late
/// wrap. Choose the largest divisor that still resolves the operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Timer1Prescale {
    /// The CPU clock itself: one tick per CPU cycle.
    Div1,
    /// The CPU clock divided by 8.
    Div8,
    /// The CPU clock divided by 64.
    Div64,
    /// The CPU clock divided by 256.
    Div256,
    /// The CPU clock divided by 1024.
    Div1024,
}

impl Timer1Prescale {
    /// The clock divisor.
    pub const fn divisor(self) -> u32 {
        match self {
            Self::Div1 => 1,
            Self::Div8 => 8,
            Self::Div64 => 64,
            Self::Div256 => 256,
            Self::Div1024 => 1024,
        }
    }

    /// The exact timer tick frequency for a CPU clock.
    ///
    /// `None` if the clock is unknown, or if the divisor does not divide it exactly (20 MHz / 1024
    /// is 19,531.25 Hz), since measurement metadata would otherwise carry a rounded frequency.
    pub const fn tick_frequency_hz(self, cpu_hz: Option<u64>) -> Option<u64> {
        let divisor = self.divisor() as u64;
        match cpu_hz {
            Some(hz) if hz != 0 && hz % divisor == 0 => Some(hz / divisor),
            _ => None,
        }
    }
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

    use super::{Timer1Prescale, extend_timer16, timer_measurement};
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

    /// Wrap-extended ATmega2560 Timer/Counter1 at a caller-chosen prescaler.
    ///
    /// The application owns the CPU clock and supplies the resulting timer
    /// tick frequency. It must install an overflow ISR that calls
    /// [`timer1_overflow`] and enable global interrupts before relying on
    /// software wrap extension, and that ISR must run within 0x8000 ticks of
    /// each wrap (see [`Timer1Prescale`]). This adapter never changes global
    /// interrupt state.
    pub struct Timer1Counter<'timer> {
        timer: &'timer mut TC1,
        frequency_hz: Option<u64>,
        start_total: u64,
    }

    impl<'timer> Timer1Counter<'timer> {
        /// Stops and configures Timer1, clears stale overflow state, enables
        /// its overflow interrupt, then starts it with the `/1024` prescaler.
        pub fn start_prescale_1024(timer: &'timer mut TC1, frequency_hz: Option<u64>) -> Self {
            Self::start(timer, Timer1Prescale::Div1024, frequency_hz)
        }

        /// Stops and configures Timer1 at `prescale`, deriving the tick
        /// frequency from the CPU clock with [`Timer1Prescale::tick_frequency_hz`].
        pub fn start_with_cpu_clock(
            timer: &'timer mut TC1,
            prescale: Timer1Prescale,
            cpu_hz: Option<u64>,
        ) -> Self {
            Self::start(timer, prescale, prescale.tick_frequency_hz(cpu_hz))
        }

        /// Stops and configures Timer1, zeroes it, clears stale overflow
        /// state, enables its overflow interrupt, then starts it with
        /// `prescale`.
        ///
        /// `frequency_hz` labels every measurement, so it must be the tick
        /// frequency at `prescale`: `prescale.tick_frequency_hz(cpu_hz)`, or
        /// `None` if unknown. Prefer [`start_with_cpu_clock`](Self::start_with_cpu_clock),
        /// which derives it.
        pub fn start(
            timer: &'timer mut TC1,
            prescale: Timer1Prescale,
            frequency_hz: Option<u64>,
        ) -> Self {
            timer.tccr1b.write(|writer| writer.cs1().no_clock());
            timer.tccr1a.reset();
            // A stale count near 0xffff would wrap almost at once, which at `/1` leaves the
            // overflow ISR almost no margin.
            timer.tcnt1.write(|writer| writer.bits(0));
            avr_device::interrupt::free(|cs| TIMER1_WRAPS.borrow(cs).set(0));
            timer.tifr1.write(|writer| writer.tov1().set_bit());
            timer.timsk1.write(|writer| writer.toie1().set_bit());
            timer.tccr1b.write(|writer| match prescale {
                Timer1Prescale::Div1 => writer.cs1().direct(),
                Timer1Prescale::Div8 => writer.cs1().prescale_8(),
                Timer1Prescale::Div64 => writer.cs1().prescale_64(),
                Timer1Prescale::Div256 => writer.cs1().prescale_256(),
                Timer1Prescale::Div1024 => writer.cs1().prescale_1024(),
            });
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
        let passed = passed && !stack.overflowed;

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
        unsafe {
            run_benchmark_with_prescale(
                timer,
                Timer1Prescale::Div1024,
                frequency_hz,
                reporter,
                benchmark,
                stack,
                stack_config,
                operation,
            )
        }
    }

    /// [`run_benchmark`] with a caller-chosen Timer1 prescaler.
    ///
    /// # Safety
    /// The caller must uphold [`Benchmark::run_with_stack`]'s exclusive stack
    /// access contract for the supplied allocation.
    #[cfg(feature = "stack")]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn run_benchmark_with_prescale<const N: usize, R: BenchmarkReporter>(
        timer: &mut TC1,
        prescale: Timer1Prescale,
        frequency_hz: Option<u64>,
        reporter: &mut R,
        benchmark: &Benchmark<'_, N>,
        stack: &impl DescendingStack,
        stack_config: StackConfig,
        operation: impl FnMut() -> bool,
    ) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
        let counter = Timer1Counter::start(timer, prescale, frequency_hz);
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
pub use atmega2560::run_benchmark_with_prescale as run_atmega2560_benchmark_with_prescale;
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
    fn prescalers_divide_the_cpu_clock() {
        let cases = [
            (Timer1Prescale::Div1, 1, 16_000_000),
            (Timer1Prescale::Div8, 8, 2_000_000),
            (Timer1Prescale::Div64, 64, 250_000),
            (Timer1Prescale::Div256, 256, 62_500),
            (Timer1Prescale::Div1024, 1024, 15_625),
        ];
        for (prescale, divisor, hz) in cases {
            assert_eq!(prescale.divisor(), divisor);
            assert_eq!(prescale.tick_frequency_hz(Some(16_000_000)), Some(hz));
            assert_eq!(prescale.tick_frequency_hz(None), None);
            assert_eq!(prescale.tick_frequency_hz(Some(0)), None);
        }
        // A clock the divisor doesn't divide exactly has no exact tick frequency.
        assert_eq!(
            Timer1Prescale::Div1024.tick_frequency_hz(Some(20_000_000)),
            None
        );
        assert_eq!(
            Timer1Prescale::Div8.tick_frequency_hz(Some(20_000_000)),
            Some(2_500_000)
        );
        assert_eq!(Timer1Prescale::Div256.tick_frequency_hz(Some(100)), None);
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
