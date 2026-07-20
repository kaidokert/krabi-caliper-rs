#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt::Write as _;
    use std::string::String;

    use super::*;
    use crate::{Measurement, Unit};

    const FIELDS: &[Field<'_>] = &[
        Field::token("case", "small"),
        Field::u64("bytes", 64),
        Field::bool("cached", true),
    ];

    #[test]
    fn emits_the_complete_base_event_vocabulary() {
        let mut reporter = TextReporter::new(String::new());
        reporter
            .event(Event::Begin(&RunStart {
                suite: "fixture",
                target: "thumbv7em-none-eabihf",
                board: Some("board"),
                unit: Unit::CoreCycles,
                frequency_hz: Some(168_000_000),
                fields: FIELDS,
            }))
            .unwrap();
        reporter
            .event(Event::Sample(&SampleRecord {
                fixture: "timing",
                side: 'A',
                index: 0,
                ticks: 42,
                wrapped: false,
                fields: &[],
            }))
            .unwrap();
        reporter
            .event(Event::Result(&ComparisonRecord {
                fixture: "timing",
                class: "positive",
                policy: Some("max-spread"),
                a_min: 40,
                a_max: 42,
                b_min: 41,
                b_max: 43,
                spread: 3,
                overlap: true,
                wrapped: false,
                output_ok: true,
                passed: Some(true),
                fields: &[],
            }))
            .unwrap();
        reporter
            .event(Event::Summary(&RunSummary {
                suite: "fixture",
                passed: 1,
                failed: 0,
                fields: &[],
            }))
            .unwrap();
        let measurement = Measurement::new(84, Unit::CoreCycles).with_frequency(168_000_000);
        reporter
            .event(Event::Measurement {
                record: &MeasurementRecord {
                    benchmark: "verify",
                    measurement,
                    counter: Some("dwt"),
                    fields: &[],
                },
                trial: Some(2),
            })
            .unwrap();
        reporter
            .event(Event::Outcome(&OutcomeRecord {
                benchmark: "verify",
                passed: true,
                fields: &[],
            }))
            .unwrap();
        reporter
            .event(Event::Boundary(&BoundaryRecord {
                benchmark: "verify",
                trial: 2,
                phase: BoundaryPhase::End,
                passed: Some(true),
                fields: &[],
            }))
            .unwrap();
        reporter
            .event(Event::Counter(&CounterSnapshotRecord {
                benchmark: "verify",
                trial: 2,
                phase: BoundaryPhase::End,
                ticks: 84,
                width_bits: 32,
                unit: Unit::CoreCycles,
                frequency_hz: Some(168_000_000),
                fields: &[],
            }))
            .unwrap();
        reporter
            .event(Event::Metric(&MetricRecord {
                benchmark: "verify",
                name: "input-bytes",
                value: 64,
                unit: Some("bytes"),
                policy: MetricPolicy::Informational,
                fields: &[],
            }))
            .unwrap();

        let output = reporter.into_inner();
        for record in [
            "EM_BEGIN",
            "EM_SAMPLE",
            "EM_RESULT",
            "EM_SUMMARY",
            "EM_MEASUREMENT",
            "EM_OUTCOME",
            "EM_BOUNDARY",
            "EM_COUNTER",
            "EM_METRIC",
        ] {
            assert!(output.lines().any(|line| line.starts_with(record)));
        }
        assert!(output.contains(" trial:2 counter:dwt"));
        assert!(output.contains(" case:small bytes:64 cached:1"));
    }

    #[test]
    fn compatibility_output_and_diagnostics_share_the_writer() {
        let mut reporter = TextReporter::new(String::new()).compatibility(Compatibility::CtV0);
        writeln!(reporter, "diagnostic before records").unwrap();
        reporter
            .run_start(&RunStart {
                suite: "ct",
                target: "cortex-m4",
                board: None,
                unit: Unit::CoreCycles,
                frequency_hz: None,
                fields: &[],
            })
            .unwrap();
        reporter
            .run_summary(&RunSummary {
                suite: "ct",
                passed: 1,
                failed: 0,
                fields: &[],
            })
            .unwrap();

        let output = reporter.into_inner();
        assert!(output.starts_with("diagnostic before records\nEM_BEGIN"));
        assert!(output.contains("CT_BEGIN suite:ct"));
        assert!(output.contains("CT_SUMMARY passed:1 failed:0"));
    }

    #[test]
    fn rejects_ambiguous_tokens_and_protocol_field_overrides() {
        let mut reporter = TextReporter::new(String::new());
        assert!(
            reporter
                .outcome(&OutcomeRecord {
                    benchmark: "contains whitespace",
                    passed: true,
                    fields: &[],
                })
                .is_err()
        );
        assert!(
            reporter
                .outcome(&OutcomeRecord {
                    benchmark: "valid",
                    passed: true,
                    fields: &[Field::u64("status", 1)],
                })
                .is_err()
        );
    }

    #[test]
    fn event_tags_round_trip_wire_names() {
        for tag in [
            EventTag::Begin,
            EventTag::Sample,
            EventTag::Result,
            EventTag::Diagnostic,
            EventTag::Summary,
            EventTag::Stack,
            EventTag::Measurement,
            EventTag::Outcome,
            EventTag::Boundary,
            EventTag::Counter,
            EventTag::Metric,
        ] {
            assert_eq!(EventTag::from_wire_name(tag.wire_name()), Some(tag));
        }
        assert_eq!(EventTag::from_wire_name("EM_UNKNOWN"), None);
    }
}
