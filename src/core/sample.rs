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

    pub fn summary(&self) -> Option<Summary> {
        let first = *self.iter().next()?;
        let mut min = first.ticks;
        let mut max = first.ticks;
        let mut total = first.ticks as u128;
        let mut wrapped = first.wrapped;

        for sample in self.iter().skip(1) {
            if sample.unit != first.unit || sample.frequency_hz != first.frequency_hz {
                return None;
            }
            min = min.min(sample.ticks);
            max = max.max(sample.ticks);
            total += sample.ticks as u128;
            wrapped |= sample.wrapped;
        }

        Some(Summary {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub count: usize,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub unit: Unit,
    pub frequency_hz: Option<u64>,
    pub wrapped: bool,
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
            Some(Summary {
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
        assert_eq!(incompatible.summary(), None);
    }
}
