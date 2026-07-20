use super::*;

const COMPLETE_RUN: &str = concat!(
    "diagnostic before protocol\n",
    "EM_BEGIN schema:1 suite:ct target:thumbv7em board:f407 unit:core-cycles frequency_hz:168000000\n",
    "EM_SAMPLE schema:1 fixture:verify side:A index:0 ticks:100 wrapped:0\n",
    "EM_SAMPLE schema:1 fixture:verify side:B index:0 ticks:101 wrapped:0\n",
    "EM_RESULT schema:1 fixture:verify class:positive policy:max-spread a_min:100 a_max:100 b_min:101 b_max:101 spread:1 overlap:0 wrapped:0 output_ok:1 status:PASS\n",
    "EM_MEASUREMENT schema:1 benchmark:verify ticks:100 unit:core-cycles frequency_hz:168000000 wrapped:0 counter:dwt\n",
    "EM_OUTCOME schema:1 benchmark:verify status:PASS\n",
    "EM_SUMMARY schema:1 suite:ct passed:1 failed:0\n",
);

#[test]
fn parses_aggregates_and_renders_complete_evidence() {
    let result = parse(COMPLETE_RUN).unwrap();

    assert_eq!(result.status, RunStatus::Pass);
    assert_eq!(result.target.target.as_deref(), Some("thumbv7em"));
    assert_eq!(result.target.board.as_deref(), Some("f407"));
    assert_eq!(result.target.clock_frequency_hz, Some(168_000_000));
    assert_eq!(result.ignored_lines, 1);
    assert_eq!(result.samples["verify"].len(), 2);
    assert_eq!(result.results.len(), 1);
    assert_eq!(result.benchmarks["verify"].measurements.len(), 1);

    let json = render_json(&result).unwrap();
    let decoded: RunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, result);

    let markdown = render_markdown(&result);
    assert!(markdown.contains("Status: **PASS**"));
    assert!(markdown.contains("Target: `thumbv7em`"));
    assert!(markdown.contains("| verify |"));
}

#[test]
fn incremental_parser_retains_ignored_line_evidence() {
    let mut parser = ProtocolParser::new();
    assert!(parser.push_line("debug output").unwrap().is_none());
    assert!(
        parser
            .push_line("EM_SUMMARY schema:1 suite:ct passed:0 failed:1")
            .unwrap()
            .is_some()
    );

    let result = parser.finish();
    assert_eq!(result.ignored_lines, 1);
    assert_eq!(result.status, RunStatus::Fail);
}

#[test]
fn rejects_ambiguous_duplicate_fields() {
    let error =
        parse("EM_OUTCOME schema:1 benchmark:first benchmark:second status:PASS\n").unwrap_err();

    assert_eq!(error.record.as_deref(), Some("EM_OUTCOME"));
    assert_eq!(error.field.as_deref(), Some("benchmark"));
    assert!(error.message.contains("duplicate"));
}

#[test]
fn correlates_wrapped_full_width_counters_without_shifting_by_64() {
    let mut result = parse(concat!(
        "EM_BOUNDARY schema:1 benchmark:external trial:0 phase:begin\n",
        "EM_COUNTER schema:1 benchmark:external trial:0 phase:begin ticks:18446744073709551614 width:64 unit:core-cycles frequency_hz:none\n",
        "EM_BOUNDARY schema:1 benchmark:external trial:0 phase:end status:PASS\n",
        "EM_COUNTER schema:1 benchmark:external trial:0 phase:end ticks:2 width:64 unit:core-cycles frequency_hz:none\n",
    ))
    .unwrap();

    result.correlate_external(true);
    assert!(result.external_errors.is_empty());
    let measurement = &result.benchmarks["external"].measurements[0];
    assert_eq!(measurement.ticks, 4);
    assert!(measurement.wrapped);
}
