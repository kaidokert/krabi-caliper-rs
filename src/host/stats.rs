//! Statistical analysis of class-labelled paired timing samples.

use std::string::String;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{ComparisonEvent, RunResult, SampleEvent};

pub const DEFAULT_WELCH_THRESHOLD: f64 = 4.5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WelchVerdict {
    InsufficientSamples,
    BelowThreshold,
    ExceedsThreshold,
    DeterministicDifference,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WelchAnalysis {
    pub fixture: String,
    pub class: String,
    pub a_samples: usize,
    pub b_samples: usize,
    pub mean_a: Option<f64>,
    pub mean_b: Option<f64>,
    pub variance_a: Option<f64>,
    pub variance_b: Option<f64>,
    pub t_statistic: Option<f64>,
    pub degrees_of_freedom: Option<f64>,
    pub threshold: f64,
    pub verdict: WelchVerdict,
}

impl WelchAnalysis {
    pub fn exceeds_threshold(&self) -> bool {
        matches!(
            self.verdict,
            WelchVerdict::ExceedsThreshold | WelchVerdict::DeterministicDifference
        )
    }
}

pub fn analyze_welch(result: &RunResult, threshold: f64) -> Vec<WelchAnalysis> {
    let threshold = if threshold.is_finite() && threshold >= 0.0 {
        threshold
    } else {
        DEFAULT_WELCH_THRESHOLD
    };
    result
        .results
        .iter()
        .chain(&result.diagnostics)
        .filter_map(|comparison| {
            result
                .samples
                .get(&comparison.fixture)
                .map(|samples| analyze_fixture(comparison, samples, threshold))
        })
        .collect()
}

fn analyze_fixture(
    comparison: &ComparisonEvent,
    samples: &[SampleEvent],
    threshold: f64,
) -> WelchAnalysis {
    let a = samples
        .iter()
        .filter(|sample| sample.side == 'A' && !sample.wrapped)
        .map(|sample| sample.ticks as f64)
        .collect::<Vec<_>>();
    let b = samples
        .iter()
        .filter(|sample| sample.side == 'B' && !sample.wrapped)
        .map(|sample| sample.ticks as f64)
        .collect::<Vec<_>>();
    let mut analysis = WelchAnalysis {
        fixture: comparison.fixture.clone(),
        class: comparison.class.clone(),
        a_samples: a.len(),
        b_samples: b.len(),
        mean_a: mean(&a),
        mean_b: mean(&b),
        variance_a: sample_variance(&a),
        variance_b: sample_variance(&b),
        t_statistic: None,
        degrees_of_freedom: None,
        threshold,
        verdict: WelchVerdict::InsufficientSamples,
    };
    let (Some(mean_a), Some(mean_b), Some(var_a), Some(var_b)) = (
        analysis.mean_a,
        analysis.mean_b,
        analysis.variance_a,
        analysis.variance_b,
    ) else {
        return analysis;
    };
    let a_term = var_a / a.len() as f64;
    let b_term = var_b / b.len() as f64;
    let standard_error_squared = a_term + b_term;
    if standard_error_squared == 0.0 {
        analysis.verdict = if mean_a == mean_b {
            WelchVerdict::BelowThreshold
        } else {
            WelchVerdict::DeterministicDifference
        };
        return analysis;
    }
    let t = (mean_a - mean_b) / standard_error_squared.sqrt();
    let denominator =
        a_term * a_term / (a.len() - 1) as f64 + b_term * b_term / (b.len() - 1) as f64;
    analysis.t_statistic = Some(t);
    analysis.degrees_of_freedom = (denominator > 0.0)
        .then_some(standard_error_squared * standard_error_squared / denominator);
    analysis.verdict = if t.abs() > threshold {
        WelchVerdict::ExceedsThreshold
    } else {
        WelchVerdict::BelowThreshold
    };
    analysis
}

fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn sample_variance(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = mean(values)?;
    Some(
        values
            .iter()
            .map(|value| {
                let delta = value - mean;
                delta * delta
            })
            .sum::<f64>()
            / (values.len() - 1) as f64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{EventStatus, OwnedFields};

    fn result(a: &[u64], b: &[u64]) -> RunResult {
        let mut result = RunResult::default();
        result.results.push(ComparisonEvent {
            schema: 1,
            fixture: "fixture".into(),
            class: "positive".into(),
            policy: Some("max-spread".into()),
            a_min: *a.iter().min().unwrap(),
            a_max: *a.iter().max().unwrap(),
            b_min: *b.iter().min().unwrap(),
            b_max: *b.iter().max().unwrap(),
            spread: 0,
            overlap: true,
            wrapped: false,
            output_ok: true,
            status: Some(EventStatus::Pass),
            fields: OwnedFields::new(),
        });
        result.samples.insert(
            "fixture".into(),
            a.iter()
                .enumerate()
                .map(|(index, ticks)| ('A', index, ticks))
                .chain(
                    b.iter()
                        .enumerate()
                        .map(|(index, ticks)| ('B', index, ticks)),
                )
                .map(|(side, index, ticks)| SampleEvent {
                    schema: 1,
                    fixture: "fixture".into(),
                    side,
                    index,
                    ticks: *ticks,
                    wrapped: false,
                    fields: OwnedFields::new(),
                })
                .collect(),
        );
        result
    }

    #[test]
    fn equal_distributions_have_zero_t_statistic() {
        let analysis = analyze_welch(&result(&[99, 100, 101, 100], &[99, 100, 101, 100]), 4.5);
        assert_eq!(analysis[0].t_statistic, Some(0.0));
        assert_eq!(analysis[0].verdict, WelchVerdict::BelowThreshold);
    }

    #[test]
    fn separated_distributions_exceed_threshold() {
        let analysis = analyze_welch(&result(&[99, 100, 101, 100], &[199, 200, 201, 200]), 4.5);
        assert!(analysis[0].t_statistic.unwrap().abs() > 4.5);
        assert_eq!(analysis[0].verdict, WelchVerdict::ExceedsThreshold);
    }

    #[test]
    fn zero_variance_separation_is_deterministic_evidence() {
        let analysis = analyze_welch(&result(&[100, 100], &[101, 101]), 4.5);
        assert_eq!(analysis[0].t_statistic, None);
        assert_eq!(analysis[0].verdict, WelchVerdict::DeterministicDifference);
    }

    #[test]
    fn preserves_multiple_classes_for_one_fixture() {
        let mut result = result(&[99, 100], &[100, 101]);
        let mut diagnostic = result.results[0].clone();
        diagnostic.class = "diagnostic".into();
        diagnostic.status = None;
        result.diagnostics.push(diagnostic);

        let analyses = analyze_welch(&result, 4.5);
        assert_eq!(analyses.len(), 2);
        assert_eq!(analyses[0].class, "positive");
        assert_eq!(analyses[1].class, "diagnostic");
    }
}
