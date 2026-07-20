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
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
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
            (Some(frequency_hz), ticks) if frequency_hz != 0 && ticks != 0 => Some(Rate {
                numerator: frequency_hz,
                denominator: ticks,
            }),
            _ => None,
        }
    }

    /// Returns elapsed nanoseconds, rounded down.
    pub const fn nanoseconds(self) -> Nanoseconds {
        match self.frequency_hz {
            None => Nanoseconds::MissingFrequency,
            Some(0) => Nanoseconds::ZeroFrequency,
            Some(frequency_hz) => {
                let value = (self.ticks as u128) * 1_000_000_000u128 / frequency_hz as u128;
                if value > u64::MAX as u128 {
                    Nanoseconds::Overflow
                } else {
                    Nanoseconds::Value(value as u64)
                }
            }
        }
    }
}

/// Result of converting a measurement to integer nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Nanoseconds {
    MissingFrequency,
    ZeroFrequency,
    Overflow,
    Value(u64),
}

/// An exact rational rate suitable for `no_std` target code and host formatting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
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
pub struct ReadCounter<F, T = u64> {
    read: F,
    unit: Unit,
    frequency_hz: Option<u64>,
    value: core::marker::PhantomData<T>,
}

impl<F, T> ReadCounter<F, T> {
    pub const fn new(read: F, unit: Unit, frequency_hz: Option<u64>) -> Self {
        Self {
            read,
            unit,
            frequency_hz,
            value: core::marker::PhantomData,
        }
    }
}

macro_rules! impl_read_counter {
    ($value:ty) => {
        impl<F: FnMut() -> $value> Counter for ReadCounter<F, $value> {
            type Instant = $value;

            fn now(&mut self) -> Self::Instant {
                (self.read)()
            }

            fn elapsed(&mut self, start: Self::Instant) -> Measurement {
                let end = (self.read)();
                let mut measurement = Measurement::new(end.wrapping_sub(start) as u64, self.unit)
                    .with_wrapped(end < start);
                measurement.frequency_hz = self.frequency_hz;
                measurement
            }
        }
    };
}

impl_read_counter!(u16);
impl_read_counter!(u32);
impl_read_counter!(u64);

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
        assert_eq!(measurement.nanoseconds(), Nanoseconds::Value(500_000));
        assert_eq!(
            Measurement::new(0, Unit::CoreCycles)
                .with_frequency(168_000_000)
                .operations_per_second(),
            None
        );
        assert_eq!(
            Measurement::new(1, Unit::CoreCycles)
                .with_frequency(0)
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

    #[test]
    fn reads_native_width_hardware_counters() {
        let mut values = [u16::MAX - 1, 3].into_iter();
        let mut counter = ReadCounter::<_, u16>::new(
            || values.next().unwrap(),
            Unit::TimerTicks,
            Some(1_000_000),
        );
        let start = counter.now();
        assert_eq!(
            counter.elapsed(start),
            Measurement::new(5, Unit::TimerTicks)
                .with_frequency(1_000_000)
                .with_wrapped(true)
        );

        let mut values = [u32::MAX - 2, 4].into_iter();
        let mut counter = ReadCounter::<_, u32>::new(
            || values.next().unwrap(),
            Unit::CoreCycles,
            Some(168_000_000),
        );
        let start = counter.now();
        assert_eq!(counter.elapsed(start).ticks, 7);
    }

    #[test]
    fn distinguishes_nanosecond_conversion_failures() {
        assert_eq!(
            Measurement::new(1, Unit::TimerTicks).nanoseconds(),
            Nanoseconds::MissingFrequency
        );
        assert_eq!(
            Measurement::new(1, Unit::TimerTicks)
                .with_frequency(0)
                .nanoseconds(),
            Nanoseconds::ZeroFrequency
        );
        assert_eq!(
            Measurement::new(u64::MAX, Unit::TimerTicks)
                .with_frequency(1)
                .nanoseconds(),
            Nanoseconds::Overflow
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn serde_round_trips_public_counter_values() {
        let measurement = Measurement::new(84_000, Unit::CoreCycles)
            .with_frequency(168_000_000)
            .with_wrapped(true);
        let encoded = serde_json::to_string(&measurement).unwrap();
        assert_eq!(
            serde_json::from_str::<Measurement>(&encoded).unwrap(),
            measurement
        );

        let rate = measurement.operations_per_second().unwrap();
        let encoded = serde_json::to_string(&rate).unwrap();
        assert_eq!(serde_json::from_str::<Rate>(&encoded).unwrap(), rate);

        let duration = measurement.nanoseconds();
        let encoded = serde_json::to_string(&duration).unwrap();
        assert_eq!(
            serde_json::from_str::<Nanoseconds>(&encoded).unwrap(),
            duration
        );
    }
}
