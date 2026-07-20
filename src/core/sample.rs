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
