use crate::{Measurement, SampleSet, Summary, SummaryError};

/// Input class selected for one paired measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub enum Side {
    A,
    B,
}

/// One balanced block that cancels first-order ordering drift.
pub const ABBA: [Side; 4] = [Side::A, Side::B, Side::B, Side::A];
/// The complementary balanced block.
pub const BAAB: [Side; 4] = [Side::B, Side::A, Side::A, Side::B];
/// Two complementary blocks, useful for inspecting expected acquisition order.
pub const BALANCED_8: [Side; 8] = [
    Side::A,
    Side::B,
    Side::B,
    Side::A,
    Side::B,
    Side::A,
    Side::A,
    Side::B,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum RunError {
    OddSampleCapacity,
    BlockCountOverflow,
    CapacityExceeded,
}

/// Raw paired evidence plus application-output validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct PairedRun<const N: usize> {
    pub samples: PairedSamples<N>,
    pub outputs_ok: bool,
}

/// Portable balanced-order runner. Measurement mechanics stay in the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedRunner<const N: usize> {
    warmup_blocks: usize,
}

impl<const N: usize> PairedRunner<N> {
    pub const fn new() -> Self {
        Self { warmup_blocks: 1 }
    }

    pub const fn warmup_blocks(mut self, blocks: usize) -> Self {
        self.warmup_blocks = blocks;
        self
    }

    pub fn run(
        self,
        mut measure: impl FnMut(Side) -> (Measurement, bool),
    ) -> Result<PairedRun<N>, RunError> {
        if N % 2 != 0 {
            return Err(RunError::OddSampleCapacity);
        }

        let mut samples = PairedSamples::new();
        let mut outputs_ok = true;
        let mut block = 0;
        let total_blocks = self
            .warmup_blocks
            .checked_add(N / 2)
            .ok_or(RunError::BlockCountOverflow)?;
        while block < total_blocks {
            let order = if block % 2 == 0 { ABBA } else { BAAB };
            for side in order {
                let (measurement, ok) = measure(side);
                if block >= self.warmup_blocks {
                    outputs_ok &= ok;
                    samples
                        .push(side, measurement)
                        .map_err(|_| RunError::CapacityExceeded)?;
                }
            }
            block += 1;
        }
        Ok(PairedRun {
            samples,
            outputs_ok,
        })
    }
}

impl<const N: usize> Default for PairedRunner<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct Comparison {
    pub a: Summary,
    pub b: Summary,
    pub combined_spread: u64,
    pub ranges_overlap: bool,
    pub wrapped: bool,
}

impl<const N: usize> PairedRun<N> {
    pub fn comparison(&self) -> Result<Comparison, SummaryError> {
        let (a, b) = self.samples.summaries()?;
        Ok(Comparison {
            a,
            b,
            combined_spread: a.min.min(b.min).abs_diff(a.max.max(b.max)),
            ranges_overlap: a.min <= b.max && b.min <= a.max,
            wrapped: a.wrapped || b.wrapped,
        })
    }

    pub fn evaluate(&self, policy: impl ComparisonPolicy) -> Result<bool, SummaryError> {
        let comparison = self.comparison()?;
        Ok(self.outputs_ok && policy.accepts(&comparison))
    }
}

pub trait ComparisonPolicy {
    fn accepts(&self, comparison: &Comparison) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct MaxSpread {
    pub ticks: u64,
    pub require_overlap: bool,
}

impl ComparisonPolicy for MaxSpread {
    fn accepts(&self, comparison: &Comparison) -> bool {
        comparison.combined_spread <= self.ticks
            && (!self.require_overlap || comparison.ranges_overlap)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct DisjointRanges;

impl ComparisonPolicy for DisjointRanges {
    fn accepts(&self, comparison: &Comparison) -> bool {
        !comparison.ranges_overlap
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct PairedSamples<const N: usize> {
    pub a: SampleSet<N>,
    pub b: SampleSet<N>,
}

impl<const N: usize> PairedSamples<N> {
    pub const fn new() -> Self {
        Self {
            a: SampleSet::new(),
            b: SampleSet::new(),
        }
    }

    pub fn push(&mut self, side: Side, measurement: Measurement) -> Result<(), Measurement> {
        match side {
            Side::A => self.a.push(measurement),
            Side::B => self.b.push(measurement),
        }
    }

    pub fn summaries(&self) -> Result<(Summary, Summary), SummaryError> {
        let a = self.a.summary()?;
        let b = self.b.summary()?;
        if a.unit != b.unit {
            return Err(SummaryError::UnitMismatch);
        }
        if a.frequency_hz != b.frequency_hz {
            return Err(SummaryError::FrequencyMismatch);
        }
        Ok((a, b))
    }

    pub fn combined_spread(&self) -> Result<u64, SummaryError> {
        let (a, b) = self.summaries()?;
        Ok(a.min.min(b.min).abs_diff(a.max.max(b.max)))
    }

    pub fn ranges_overlap(&self) -> Result<bool, SummaryError> {
        let (a, b) = self.summaries()?;
        Ok(a.min <= b.max && b.min <= a.max)
    }
}

impl<const N: usize> Default for PairedSamples<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unit;

    fn cycles(ticks: u64) -> Measurement {
        Measurement::new(ticks, Unit::CoreCycles).with_frequency(168_000_000)
    }

    #[test]
    fn paired_summary_preserves_raw_ranges() {
        let mut samples = PairedSamples::<2>::new();
        samples.push(Side::A, cycles(100)).unwrap();
        samples.push(Side::B, cycles(102)).unwrap();
        samples.push(Side::B, cycles(104)).unwrap();
        samples.push(Side::A, cycles(103)).unwrap();

        assert_eq!(samples.combined_spread(), Ok(4));
        assert_eq!(samples.ranges_overlap(), Ok(true));
    }

    #[test]
    fn mismatched_units_are_not_compared() {
        let mut samples = PairedSamples::<1>::new();
        samples.push(Side::A, cycles(100)).unwrap();
        samples
            .push(Side::B, Measurement::new(100, Unit::TimerTicks))
            .unwrap();
        assert_eq!(samples.summaries(), Err(SummaryError::UnitMismatch));
    }

    #[test]
    fn runner_records_balanced_abba_blocks() {
        let mut order = [Side::A; 8];
        let mut index = 0;
        let run = PairedRunner::<4>::new()
            .warmup_blocks(0)
            .run(|side| {
                order[index] = side;
                index += 1;
                (cycles(index as u64), true)
            })
            .unwrap();
        assert_eq!(order, BALANCED_8);
        assert_eq!(run.samples.a.len(), 4);
        assert_eq!(run.samples.b.len(), 4);
    }

    #[test]
    fn warmups_and_samples_share_one_alternating_block_sequence() {
        let mut order = [Side::A; 12];
        let mut index = 0;
        let run = PairedRunner::<2>::new()
            .warmup_blocks(2)
            .run(|side| {
                order[index] = side;
                index += 1;
                (cycles(index as u64), true)
            })
            .unwrap();
        assert_eq!(&order[..4], &ABBA);
        assert_eq!(&order[4..8], &BAAB);
        assert_eq!(&order[8..], &ABBA);
        assert_eq!(run.samples.a.len(), 2);
        assert_eq!(run.samples.b.len(), 2);
    }

    #[test]
    fn policies_separate_positive_and_negative_controls() {
        let mut positive = PairedRun {
            samples: PairedSamples::<2>::new(),
            outputs_ok: true,
        };
        positive.samples.push(Side::A, cycles(100)).unwrap();
        positive.samples.push(Side::A, cycles(103)).unwrap();
        positive.samples.push(Side::B, cycles(102)).unwrap();
        positive.samples.push(Side::B, cycles(104)).unwrap();
        assert_eq!(
            positive.evaluate(MaxSpread {
                ticks: 4,
                require_overlap: true,
            }),
            Ok(true)
        );

        let mut negative = PairedRun {
            samples: PairedSamples::<2>::new(),
            outputs_ok: true,
        };
        negative.samples.push(Side::A, cycles(100)).unwrap();
        negative.samples.push(Side::A, cycles(101)).unwrap();
        negative.samples.push(Side::B, cycles(200)).unwrap();
        negative.samples.push(Side::B, cycles(201)).unwrap();
        assert_eq!(negative.evaluate(DisjointRanges), Ok(true));
    }

    #[test]
    fn rejects_odd_capacities_and_propagates_output_failures() {
        assert_eq!(
            PairedRunner::<3>::new().run(|_| (cycles(1), true)),
            Err(RunError::OddSampleCapacity)
        );
        assert_eq!(
            PairedRunner::<2>::new()
                .warmup_blocks(usize::MAX)
                .run(|_| (cycles(1), true)),
            Err(RunError::BlockCountOverflow)
        );

        let run = PairedRunner::<2>::new()
            .warmup_blocks(0)
            .run(|side| (cycles(1), side == Side::A))
            .unwrap();
        assert_eq!(
            run.evaluate(MaxSpread {
                ticks: 0,
                require_overlap: true
            }),
            Ok(false)
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn serde_round_trips_paired_evidence() {
        let mut run = PairedRun {
            samples: PairedSamples::<2>::new(),
            outputs_ok: true,
        };
        run.samples.push(Side::A, cycles(100)).unwrap();
        run.samples.push(Side::A, cycles(101)).unwrap();
        run.samples.push(Side::B, cycles(102)).unwrap();
        run.samples.push(Side::B, cycles(103)).unwrap();

        let encoded = serde_json::to_string(&run).unwrap();
        assert_eq!(serde_json::from_str::<PairedRun<2>>(&encoded).unwrap(), run);
    }
}
