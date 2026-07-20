/// The quantity represented by a counter tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Unit {
    CoreCycles,
    TimerTicks,
    Instructions,
    SimulatorCycles,
}

/// One elapsed measurement, retaining clock qualification and wrap state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measurement {
    pub ticks: u64,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub wrapped: bool,
}

impl Measurement {
    pub const fn new(ticks: u64, unit: Unit) -> Self {
        Self {
            ticks,
            unit,
            frequency_hz: None,
            wrapped: false,
        }
    }

    pub const fn with_frequency(mut self, frequency_hz: u64) -> Self {
        self.frequency_hz = Some(frequency_hz);
        self
    }

    pub const fn with_wrapped(mut self, wrapped: bool) -> Self {
        self.wrapped = wrapped;
        self
    }

    /// Returns a rational operations-per-second rate without requiring floats.
    pub const fn operations_per_second(self) -> Option<Rate> {
        match (self.frequency_hz, self.ticks) {
            (Some(frequency_hz), ticks) if ticks != 0 => Some(Rate {
                numerator: frequency_hz,
                denominator: ticks,
            }),
            _ => None,
        }
    }

    /// Returns elapsed nanoseconds, rounded down, when the frequency is known.
    pub const fn nanoseconds(self) -> Option<u64> {
        match self.frequency_hz {
            Some(0) | None => None,
            Some(frequency_hz) => {
                let value = (self.ticks as u128) * 1_000_000_000u128 / frequency_hz as u128;
                if value > u64::MAX as u128 {
                    None
                } else {
                    Some(value as u64)
                }
            }
        }
    }
}

/// An exact rational rate suitable for `no_std` target code and host formatting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rate {
    pub numerator: u64,
    pub denominator: u64,
}

/// A monotonically advancing measurement source.
pub trait Counter {
    type Instant: Copy;

    fn now(&mut self) -> Self::Instant;
    fn elapsed(&mut self, start: Self::Instant) -> Measurement;
}

/// Adapts an application-owned counter register or extended timer to the
/// portable [`Counter`] interface.
///
/// The reader should return a monotonically increasing, already-extended
/// `u64` value. This keeps PAC ownership, timer configuration, and overflow
/// interrupt ownership in the application while sharing measurement and
/// reporting semantics.
pub struct ReadCounter<F> {
    read: F,
    unit: Unit,
    frequency_hz: Option<u64>,
}

impl<F> ReadCounter<F> {
    pub const fn new(read: F, unit: Unit, frequency_hz: Option<u64>) -> Self {
        Self {
            read,
            unit,
            frequency_hz,
        }
    }
}

impl<F: FnMut() -> u64> Counter for ReadCounter<F> {
    type Instant = u64;

    fn now(&mut self) -> Self::Instant {
        (self.read)()
    }

    fn elapsed(&mut self, start: Self::Instant) -> Measurement {
        let end = (self.read)();
        let mut measurement =
            Measurement::new(end.wrapping_sub(start), self.unit).with_wrapped(end < start);
        measurement.frequency_hz = self.frequency_hz;
        measurement
    }
}

#[cfg(test)]
mod read_counter_tests {
    use super::*;

    #[test]
    fn qualifies_application_owned_timer() {
        let mut values = [10_u64, 35].into_iter();
        let mut counter =
            ReadCounter::new(|| values.next().unwrap(), Unit::TimerTicks, Some(15_625));
        let start = counter.now();
        assert_eq!(
            counter.elapsed(start),
            Measurement::new(25, Unit::TimerTicks).with_frequency(15_625)
        );
    }

    #[test]
    fn derives_exact_rate_and_elapsed_nanoseconds() {
        let measurement = Measurement::new(84_000, Unit::CoreCycles).with_frequency(168_000_000);

        assert_eq!(
            measurement.operations_per_second(),
            Some(Rate {
                numerator: 168_000_000,
                denominator: 84_000,
            })
        );
        assert_eq!(measurement.nanoseconds(), Some(500_000));
        assert_eq!(
            Measurement::new(0, Unit::CoreCycles)
                .with_frequency(168_000_000)
                .operations_per_second(),
            None
        );
    }

    #[test]
    fn retains_wrapping_subtraction_as_evidence() {
        let mut values = [u64::MAX - 2, 4].into_iter();
        let mut counter = ReadCounter::new(|| values.next().unwrap(), Unit::TimerTicks, None);
        let start = counter.now();

        assert_eq!(
            counter.elapsed(start),
            Measurement::new(7, Unit::TimerTicks).with_wrapped(true)
        );
    }
}
