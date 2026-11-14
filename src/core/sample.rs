use crate::{Measurement, Unit};

/// Fixed-capacity measurements from one counter, collected without allocation.
///
/// Every sample in a set shares the unit and frequency of the first one; [`push`](Self::push)
/// rejects a sample that does not. So the set stores, per sample, only its tick count and whether
/// it wrapped: `9 * N` bytes plus a few words, rather than a whole [`Measurement`] each.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleSet<const N: usize> {
    ticks: [u64; N],
    wrapped: [bool; N],
    len: usize,
    /// The first sample's unit and frequency; meaningless while the set is empty.
    unit: Unit,
    frequency_hz: Option<u64>,
}

/// Why [`SampleSet::push`] rejected a measurement. Each variant hands the measurement back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PushError {
    /// The set already holds `N` samples.
    Full(Measurement),
    /// The measurement's unit differs from the set's.
    UnitMismatch(Measurement),
    /// The measurement's frequency differs from the set's.
    FrequencyMismatch(Measurement),
}

impl PushError {
    /// The rejected measurement.
    pub const fn measurement(self) -> Measurement {
        match self {
            Self::Full(measurement)
            | Self::UnitMismatch(measurement)
            | Self::FrequencyMismatch(measurement) => measurement,
        }
    }
}

impl<const N: usize> SampleSet<N> {
    pub const fn new() -> Self {
        Self {
            ticks: [0; N],
            wrapped: [false; N],
            len: 0,
            unit: Unit::CoreCycles,
            frequency_hz: None,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends a measurement. The first sample sets the unit and frequency; a later one must
    /// match them. On error the set is unchanged.
    pub fn push(&mut self, measurement: Measurement) -> Result<(), PushError> {
        if self.len > 0 {
            if measurement.unit != self.unit {
                return Err(PushError::UnitMismatch(measurement));
            }
            if measurement.frequency_hz != self.frequency_hz {
                return Err(PushError::FrequencyMismatch(measurement));
            }
        }
        let (Some(ticks), Some(wrapped)) =
            (self.ticks.get_mut(self.len), self.wrapped.get_mut(self.len))
        else {
            return Err(PushError::Full(measurement));
        };
        *ticks = measurement.ticks;
        *wrapped = measurement.wrapped;
        if self.len == 0 {
            self.unit = measurement.unit;
            self.frequency_hz = measurement.frequency_hz;
        }
        self.len += 1;
        Ok(())
    }

    /// The samples, in the order they were pushed.
    pub fn iter(&self) -> impl Iterator<Item = Measurement> + '_ {
        self.ticks
            .iter()
            .zip(&self.wrapped)
            .take(self.len)
            .map(|(&ticks, &wrapped)| Measurement {
                ticks,
                unit: self.unit,
                frequency_hz: self.frequency_hz,
                wrapped,
            })
    }

    /// The tick counts, in the order they were pushed.
    pub fn ticks(&self) -> &[u64] {
        self.ticks.get(..self.len).unwrap_or(&[])
    }

    /// The set's unit and frequency with `wrapped` set if any sample wrapped, or `Empty`.
    fn qualification(&self) -> Result<Measurement, SummaryError> {
        if self.len == 0 {
            return Err(SummaryError::Empty);
        }
        Ok(Measurement {
            ticks: 0,
            unit: self.unit,
            frequency_hz: self.frequency_hz,
            wrapped: self.wrapped.iter().take(self.len).any(|&wrapped| wrapped),
        })
    }

    pub fn summary(&self) -> Result<Summary, SummaryError> {
        let qualification = self.qualification()?;
        let mut min = u64::MAX;
        let mut max = 0;
        let mut total = 0_u128;
        for &value in self.ticks() {
            min = min.min(value);
            max = max.max(value);
            total += u128::from(value);
        }

        Ok(Summary {
            count: self.len,
            min,
            max,
            // `len` is non-zero here, and the mean of u64 values fits in a u64.
            mean: (total / self.len as u128) as u64,
            unit: qualification.unit,
            frequency_hz: qualification.frequency_hz,
            wrapped: qualification.wrapped,
        })
    }

    /// Returns the `index`-th smallest tick count, counting from zero, as a measurement.
    ///
    /// The set must be non-empty. The result carries the set's unit and frequency, and `wrapped`
    /// is set if any sample in the set wrapped, as for [`summary`](Self::summary): a selected
    /// value is only as trustworthy as the set it was selected from.
    ///
    /// The selection counts in place instead of sorting: no copy of the set, no allocator and
    /// no panic path, in O(len²) comparisons. That suits the small fixed capacities a target
    /// collects; for large sets on a host, sort the ticks instead.
    pub fn order_statistic(&self, index: usize) -> Result<Measurement, SummaryError> {
        let mut result = self.qualification()?;
        if index >= self.len {
            return Err(SummaryError::IndexOutOfRange);
        }
        let ticks = self.ticks();
        // The answer is the candidate with fewer than `index + 1` smaller samples and at least
        // `index + 1` samples no larger than it.
        for &candidate in ticks {
            let mut smaller = 0;
            let mut not_larger = 0;
            for &sample in ticks {
                smaller += usize::from(sample < candidate);
                not_larger += usize::from(sample <= candidate);
            }
            if smaller <= index && index < not_larger {
                result.ticks = candidate;
                return Ok(result);
            }
        }
        Err(SummaryError::IndexOutOfRange)
    }

    /// Returns the upper median: the measurement at sorted index `len / 2`.
    ///
    /// For an odd count this is the median. For an even count it is the larger of the two
    /// middle measurements, so the result is always an observed value rather than an average.
    /// Note that [`percentile(1, 2)`](Self::percentile) is the lower of the two for an even
    /// count, by the nearest-rank definition.
    pub fn median(&self) -> Result<Measurement, SummaryError> {
        self.order_statistic(self.len / 2)
    }

    /// Returns the nearest-rank percentile `numerator / denominator` (for example `95 / 100`).
    ///
    /// The result is the measurement at rank `ceil(numerator * len / denominator)`, counting
    /// from one, with rank 0 taken as rank 1. So `0 / 1` is the minimum and `1 / 1` the maximum.
    /// Nothing is interpolated: the result is always an observed value. A zero denominator or a
    /// fraction above one returns [`SummaryError::InvalidQuantile`]. The rank takes one 64-bit
    /// multiply and divide.
    pub fn percentile(
        &self,
        numerator: u32,
        denominator: u32,
    ) -> Result<Measurement, SummaryError> {
        if denominator == 0 || numerator > denominator {
            return Err(SummaryError::InvalidQuantile);
        }
        let scaled = u64::from(numerator)
            .checked_mul(self.len as u64)
            .ok_or(SummaryError::IndexOutOfRange)?;
        let rank = scaled.div_ceil(u64::from(denominator)).max(1);
        let index = usize::try_from(rank - 1).map_err(|_| SummaryError::IndexOutOfRange)?;
        self.order_statistic(index)
    }
}

impl<const N: usize> Default for SampleSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "host")]
impl<const N: usize> serde::Serialize for SampleSet<N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut sequence = serializer.serialize_seq(Some(self.len))?;
        for sample in self.iter() {
            sequence.serialize_element(&sample)?;
        }
        sequence.end()
    }
}

#[cfg(feature = "host")]
impl<'de, const N: usize> serde::Deserialize<'de> for SampleSet<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SampleSetVisitor<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for SampleSetVisitor<N> {
            type Value = SampleSet<N>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(formatter, "at most {N} measurement samples")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut samples = SampleSet::new();
                while let Some(sample) = sequence.next_element()? {
                    samples.push(sample).map_err(|_| {
                        serde::de::Error::invalid_length(N + 1, &SampleSetVisitor::<N>)
                    })?;
                }
                Ok(samples)
            }
        }

        deserializer.deserialize_seq(SampleSetVisitor::<N>)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct Summary {
    pub count: usize,
    pub min: u64,
    pub max: u64,
    /// Arithmetic mean of sample ticks, rounded down to an integer.
    pub mean: u64,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub wrapped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum SummaryError {
    Empty,
    UnitMismatch,
    FrequencyMismatch,
    /// An order statistic was requested beyond the last sample.
    IndexOutOfRange,
    /// A percentile fraction had a zero denominator or exceeded one.
    InvalidQuantile,
}

impl Summary {
    pub const fn spread(self) -> u64 {
        self.max - self.min
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_fixed_capacity_samples() {
        let mut samples = SampleSet::<3>::new();
        for ticks in [12, 18, 15] {
            samples
                .push(Measurement::new(ticks, Unit::CoreCycles).with_frequency(48_000_000))
                .unwrap();
        }

        assert_eq!(
            samples.summary(),
            Ok(Summary {
                count: 3,
                min: 12,
                max: 18,
                mean: 15,
                unit: Unit::CoreCycles,
                frequency_hz: Some(48_000_000),
                wrapped: false,
            })
        );
        assert_eq!(samples.summary().unwrap().spread(), 6);
    }

    #[test]
    fn rejects_full_and_incompatibly_qualified_samples_at_push() {
        let mut full = SampleSet::<1>::new();
        full.push(Measurement::new(1, Unit::CoreCycles)).unwrap();
        let before = full;
        let extra = Measurement::new(2, Unit::CoreCycles);
        assert_eq!(full.push(extra), Err(PushError::Full(extra)));
        assert_eq!(full, before);

        let mut set = SampleSet::<3>::new();
        set.push(Measurement::new(1, Unit::CoreCycles).with_frequency(1))
            .unwrap();
        let before = set;
        let timer = Measurement::new(2, Unit::TimerTicks).with_frequency(1);
        assert_eq!(set.push(timer), Err(PushError::UnitMismatch(timer)));
        let clock = Measurement::new(2, Unit::CoreCycles).with_frequency(2);
        assert_eq!(set.push(clock), Err(PushError::FrequencyMismatch(clock)));
        let unknown = Measurement::new(2, Unit::CoreCycles);
        assert_eq!(
            set.push(unknown),
            Err(PushError::FrequencyMismatch(unknown))
        );
        assert_eq!(set, before);
        assert_eq!(PushError::UnitMismatch(timer).measurement(), timer);
        assert_eq!(SampleSet::<1>::new().summary(), Err(SummaryError::Empty));
    }

    #[test]
    fn iterates_samples_in_push_order_with_their_wrap_flags() {
        let mut samples = SampleSet::<4>::new();
        let pushed = [
            Measurement::new(9, Unit::TimerTicks).with_frequency(15_625),
            Measurement::new(3, Unit::TimerTicks)
                .with_frequency(15_625)
                .with_wrapped(true),
            Measurement::new(u64::MAX, Unit::TimerTicks).with_frequency(15_625),
        ];
        for sample in pushed {
            samples.push(sample).unwrap();
        }
        assert!(samples.iter().eq(pushed));
        assert_eq!(samples.ticks(), &[9, 3, u64::MAX]);
        let mut none = SampleSet::<0>::new();
        assert_eq!(none.iter().count(), 0);
        let sample = Measurement::new(1, Unit::CoreCycles);
        assert_eq!(none.push(sample), Err(PushError::Full(sample)));
    }

    #[test]
    fn stores_ticks_and_wrap_flags_rather_than_whole_measurements() {
        // Per sample, a u64 and a bool; the rest is one shared qualification and the length.
        let shared = core::mem::size_of::<Measurement>() + 2 * core::mem::size_of::<usize>();
        assert!(core::mem::size_of::<SampleSet<31>>() <= 31 * 9 + shared);
    }

    fn cycles<const N: usize>(ticks: &[u64]) -> SampleSet<N> {
        let mut samples = SampleSet::<N>::new();
        for &value in ticks {
            samples
                .push(Measurement::new(value, Unit::CoreCycles))
                .unwrap();
        }
        samples
    }

    #[test]
    fn order_statistics_select_observed_values_without_reordering_the_set() {
        let samples = cycles::<9>(&[40, 12, 33, 12, 90, 7, 51, 33, 18]);
        let before = samples;
        let sorted = [7, 12, 12, 18, 33, 33, 40, 51, 90];
        for (index, &want) in sorted.iter().enumerate() {
            assert_eq!(samples.order_statistic(index).unwrap().ticks, want);
        }
        assert_eq!(
            samples.order_statistic(9),
            Err(SummaryError::IndexOutOfRange)
        );
        assert_eq!(samples.median().unwrap().ticks, 33);
        assert_eq!(samples, before);

        // Even count: the upper of the two middle values, never their average.
        assert_eq!(cycles::<4>(&[4, 1, 3, 2]).median().unwrap().ticks, 3);
        assert_eq!(cycles::<1>(&[5]).median().unwrap().ticks, 5);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let samples = cycles::<10>(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        for (numerator, denominator, want) in [
            (0, 1, 10),
            (1, 100, 10),
            (1, 10, 10),
            (11, 100, 20),
            (1, 2, 50),
            (90, 100, 90),
            (95, 100, 100),
            (1, 1, 100),
        ] {
            assert_eq!(
                samples.percentile(numerator, denominator).unwrap().ticks,
                want,
                "{numerator}/{denominator}"
            );
        }
        assert_eq!(samples.percentile(1, 0), Err(SummaryError::InvalidQuantile));
        assert_eq!(samples.percentile(2, 1), Err(SummaryError::InvalidQuantile));
        let wide = u32::MAX;
        assert_eq!(samples.percentile(wide, wide).unwrap().ticks, 100);
    }

    #[test]
    fn order_statistics_of_an_empty_set_are_errors() {
        let empty = SampleSet::<3>::new();
        assert_eq!(empty.median(), Err(SummaryError::Empty));
        assert_eq!(empty.percentile(1, 2), Err(SummaryError::Empty));
        assert_eq!(empty.order_statistic(0), Err(SummaryError::Empty));
    }

    #[test]
    fn order_statistics_carry_the_set_qualification() {
        let mut samples = SampleSet::<3>::new();
        for (ticks, wrapped) in [(30, false), (10, true), (20, false)] {
            let mut sample = Measurement::new(ticks, Unit::TimerTicks).with_frequency(15_625);
            sample.wrapped = wrapped;
            samples.push(sample).unwrap();
        }
        // The median sample itself did not wrap, but the set did, as `summary` reports.
        let median = samples.median().unwrap();
        assert_eq!(median.ticks, 20);
        assert_eq!(median.unit, Unit::TimerTicks);
        assert_eq!(median.frequency_hz, Some(15_625));
        assert!(median.wrapped);
        assert_eq!(median.wrapped, samples.summary().unwrap().wrapped);
    }

    #[test]
    fn median_and_half_percentile_differ_for_even_counts() {
        let samples = cycles::<4>(&[1, 2, 3, 4]);
        assert_eq!(samples.median().unwrap().ticks, 3);
        assert_eq!(samples.percentile(1, 2).unwrap().ticks, 2);
        let single = cycles::<1>(&[7]);
        for (numerator, denominator) in [(0, 1), (1, 2), (99, 100), (1, 1)] {
            assert_eq!(single.percentile(numerator, denominator).unwrap().ticks, 7);
        }
        // All equal: every rank is that value.
        let flat = cycles::<5>(&[4, 4, 4, 4, 4]);
        for index in 0..5 {
            assert_eq!(flat.order_statistic(index).unwrap().ticks, 4);
        }
    }

    #[cfg(feature = "host")]
    #[test]
    fn serde_round_trips_initialized_samples_for_any_capacity() {
        let mut samples = SampleSet::<37>::new();
        samples
            .push(Measurement::new(12, Unit::CoreCycles).with_frequency(48_000_000))
            .unwrap();
        samples
            .push(Measurement::new(18, Unit::CoreCycles).with_frequency(48_000_000))
            .unwrap();

        let encoded = serde_json::to_string(&samples).unwrap();
        assert!(!encoded.contains("null"));
        let decoded: SampleSet<37> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, samples);
        assert!(serde_json::from_str::<SampleSet<1>>(&encoded).is_err());

        let summary = samples.summary().unwrap();
        let encoded = serde_json::to_string(&summary).unwrap();
        assert_eq!(serde_json::from_str::<Summary>(&encoded).unwrap(), summary);
    }
}
