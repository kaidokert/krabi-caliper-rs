use crate::{Measurement, Unit};

/// Fixed-capacity raw measurements collected without allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleSet<const N: usize> {
    samples: [Option<Measurement>; N],
    len: usize,
}

impl<const N: usize> SampleSet<N> {
    pub const fn new() -> Self {
        Self {
            samples: [None; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, measurement: Measurement) -> Result<(), Measurement> {
        if self.len == N {
            return Err(measurement);
        }
        self.samples[self.len] = Some(measurement);
        self.len += 1;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Measurement> {
        self.samples[..self.len].iter().map(|sample| {
            sample
                .as_ref()
                .expect("entries below SampleSet::len are initialized")
        })
    }

    pub fn summary(&self) -> Result<Summary, SummaryError> {
        let first = *self.iter().next().ok_or(SummaryError::Empty)?;
        let mut min = first.ticks;
        let mut max = first.ticks;
        let mut total = first.ticks as u128;
        let mut wrapped = first.wrapped;

        for sample in self.iter().skip(1) {
            if sample.unit != first.unit {
                return Err(SummaryError::UnitMismatch);
            }
            if sample.frequency_hz != first.frequency_hz {
                return Err(SummaryError::FrequencyMismatch);
            }
            min = min.min(sample.ticks);
            max = max.max(sample.ticks);
            total += sample.ticks as u128;
            wrapped |= sample.wrapped;
        }

        Ok(Summary {
            count: self.len,
            min,
            max,
            mean: (total / self.len as u128) as u64,
            unit: first.unit,
            frequency_hz: first.frequency_hz,
            wrapped,
        })
    }

    /// Returns the measurement with the `index`-th smallest tick count, counting from zero.
    ///
    /// The samples must be non-empty and share a unit and frequency, as for
    /// [`summary`](Self::summary). Ties between equal tick counts may return any of the equal
    /// measurements; they differ at most in `wrapped`. The selection sorts a copy of the samples
    /// on the stack, so it needs no allocator and leaves the set unchanged.
    pub fn order_statistic(&self, index: usize) -> Result<Measurement, SummaryError> {
        self.summary()?;
        let mut sorted = self.samples;
        let initialized = sorted
            .get_mut(..self.len)
            .ok_or(SummaryError::IndexOutOfRange)?;
        initialized.sort_unstable_by_key(|sample| sample.map(|sample| sample.ticks));
        initialized
            .get(index)
            .copied()
            .flatten()
            .ok_or(SummaryError::IndexOutOfRange)
    }

    /// Returns the upper median: the measurement at sorted index `len / 2`.
    ///
    /// For an odd count this is the median. For an even count it is the larger of the two
    /// middle measurements, so the result is always an observed value rather than an average.
    pub fn median(&self) -> Result<Measurement, SummaryError> {
        self.order_statistic(self.len / 2)
    }

    /// Returns the nearest-rank percentile `numerator / denominator` (for example `95 / 100`).
    ///
    /// The result is the measurement at rank `ceil(numerator * len / denominator)`, counting
    /// from one, with rank 0 taken as rank 1. So `0 / 1` is the minimum and `1 / 1` the maximum.
    /// Nothing is interpolated: the result is always an observed value. A zero denominator or a
    /// fraction above one returns [`SummaryError::InvalidQuantile`].
    pub fn percentile(
        &self,
        numerator: u32,
        denominator: u32,
    ) -> Result<Measurement, SummaryError> {
        if denominator == 0 || numerator > denominator {
            return Err(SummaryError::InvalidQuantile);
        }
        let scaled = u64::from(numerator) * self.len as u64;
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
            sequence.serialize_element(sample)?;
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
    fn rejects_full_and_incompatibly_qualified_sample_sets() {
        let mut full = SampleSet::<1>::new();
        full.push(Measurement::new(1, Unit::CoreCycles)).unwrap();
        assert_eq!(
            full.push(Measurement::new(2, Unit::CoreCycles)),
            Err(Measurement::new(2, Unit::CoreCycles))
        );

        let mut incompatible = SampleSet::<2>::new();
        incompatible
            .push(Measurement::new(1, Unit::CoreCycles))
            .unwrap();
        incompatible
            .push(Measurement::new(2, Unit::TimerTicks))
            .unwrap();
        assert_eq!(incompatible.summary(), Err(SummaryError::UnitMismatch));

        let mut incompatible = SampleSet::<2>::new();
        incompatible
            .push(Measurement::new(1, Unit::CoreCycles).with_frequency(1))
            .unwrap();
        incompatible
            .push(Measurement::new(2, Unit::CoreCycles).with_frequency(2))
            .unwrap();
        assert_eq!(incompatible.summary(), Err(SummaryError::FrequencyMismatch));
        assert_eq!(SampleSet::<1>::new().summary(), Err(SummaryError::Empty));
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
    fn order_statistics_keep_summary_checks() {
        assert_eq!(SampleSet::<3>::new().median(), Err(SummaryError::Empty));
        let mut mixed = SampleSet::<2>::new();
        mixed.push(Measurement::new(1, Unit::CoreCycles)).unwrap();
        mixed.push(Measurement::new(2, Unit::TimerTicks)).unwrap();
        assert_eq!(mixed.median(), Err(SummaryError::UnitMismatch));
        assert_eq!(mixed.percentile(1, 2), Err(SummaryError::UnitMismatch));
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
