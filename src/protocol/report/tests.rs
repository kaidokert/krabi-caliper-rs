#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt::Write as _;
    use std::string::String;

    use super::*;
    use crate::{Measurement, Unit};
    #[cfg(feature = "paired")]
    use crate::paired::{MaxSpread, PairedRun, PairedSamples, Side};

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
        for field in [
            Field::token("target", "custom"),
            Field::token("board", "custom"),
            Field::u64("width", 32),
        ] {
            assert!(
                reporter
                    .outcome(&OutcomeRecord {
                        benchmark: "valid",
                        passed: true,
                        fields: &[field],
                    })
                    .is_err()
            );
        }
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

    #[cfg(feature = "paired")]
    #[test]
    fn paired_records_emit_raw_evidence_and_comparison() {
        let mut run = PairedRun {
            samples: PairedSamples::<2>::new(),
            outputs_ok: true,
        };
        run.samples.push(Side::A, cycles(100)).unwrap();
        run.samples.push(Side::A, cycles(103)).unwrap();
        run.samples.push(Side::B, cycles(102)).unwrap();
        run.samples.push(Side::B, cycles(104)).unwrap();
        let passed = run
            .evaluate(MaxSpread {
                ticks: 4,
                require_overlap: true,
            })
            .unwrap();

        let mut reporter = TextReporter::new(String::new()).compatibility(Compatibility::CtV0);
        reporter
            .paired_result(&PairedResult {
                fixture: "ct-eq",
                class: "positive",
                policy: "max-spread-overlap",
                run: &run,
                passed,
                fields: &[Field::token("carrier", "u32x8")],
            })
            .unwrap();

        let output = reporter.into_inner();
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("EM_SAMPLE"))
                .count(),
            4
        );
        assert!(output.contains("EM_SAMPLE schema:1 fixture:ct-eq side:A index:0 ticks:100"));
        assert!(output.contains("EM_RESULT schema:1 fixture:ct-eq class:positive"));
        assert!(output.contains("spread:4 overlap:1 wrapped:0 output_ok:1 status:PASS"));
        assert!(output.contains("CT_RESULT fixture:ct-eq class:positive"));
    }

    #[cfg(feature = "paired")]
    #[test]
    fn paired_reporter_rejects_incompatible_evidence() {
        let mut run = PairedRun {
            samples: PairedSamples::<1>::new(),
            outputs_ok: true,
        };
        run.samples
            .push(Side::A, Measurement::new(1, Unit::CoreCycles))
            .unwrap();
        run.samples
            .push(Side::B, Measurement::new(1, Unit::TimerTicks))
            .unwrap();

        assert!(
            TextReporter::new(String::new())
                .paired_diagnostic(&PairedDiagnostic {
                    fixture: "mismatch",
                    class: "control",
                    run: &run,
                    fields: &[],
                })
                .is_err()
        );
    }

    #[cfg(feature = "paired")]
    fn cycles(ticks: u64) -> Measurement {
        Measurement::new(ticks, Unit::CoreCycles).with_frequency(168_000_000)
    }

    #[cfg(feature = "stack")]
    #[test]
    fn emits_stack_evidence_and_compatibility_record() {
        let mut reporter = TextReporter::new(String::new()).compatibility(Compatibility::CtV0);
        reporter
            .stack_measurement(&StackRecord {
                benchmark: "verify",
                measurement: crate::stack::StackMeasurement {
                    high_water_bytes: 2048,
                    available_bytes: 8192,
                    painted_bytes: 7168,
                    safe_zone_bytes: 256,
                    overflowed: false,
                },
                fields: &[Field::token("source", "cortex-m4")],
            })
            .unwrap();

        let output = reporter.into_inner();
        assert!(output.contains(
            "EM_STACK schema:1 benchmark:verify used:2048 available:8192 painted:7168 safe_zone:256 overflowed:0 source:cortex-m4"
        ));
        assert!(output.contains(
            "CT_STACK suite:verify bytes:2048 available:8192 painted:7168 safe_zone:256 overflowed:0 source:cortex-m4"
        ));
    }
}
