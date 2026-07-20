use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::string::{String, ToString};

use super::model::*;
use crate::report::{EventTag, SCHEMA_VERSION};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub record: Option<String>,
    pub field: Option<String>,
    pub message: String,
}

impl ParseError {
    fn new(
        line: usize,
        record: Option<&str>,
        field: Option<&str>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            line,
            record: record.map(ToString::to_string),
            field: field.map(ToString::to_string),
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "protocol parse error on line {}", self.line)?;
        if let Some(record) = &self.record {
            write!(formatter, " in {record}")?;
        }
        if let Some(field) = &self.field {
            write!(formatter, " field {field}")?;
        }
        write!(formatter, ": {}", self.message)
    }
}

impl Error for ParseError {}

#[derive(Clone, Debug, Default)]
pub struct ProtocolParser {
    result: RunResult,
    line: usize,
}

impl ProtocolParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_line(&mut self, line: &str) -> Result<Option<&OwnedEvent>, ParseError> {
        self.line += 1;
        match parse_line(self.line, line)? {
            Some(event) => {
                self.result.push(event);
                Ok(self.result.events.last())
            }
            None => {
                self.result.ignored_lines += 1;
                Ok(None)
            }
        }
    }

    pub fn finish(mut self) -> RunResult {
        self.result.recompute_status();
        self.result.welch_analyses =
            super::analyze_welch(&self.result, super::DEFAULT_WELCH_THRESHOLD);
        self.result
    }
}

pub fn parse(input: &str) -> Result<RunResult, ParseError> {
    let mut parser = ProtocolParser::new();
    for line in input.lines() {
        parser.push_line(line)?;
    }
    Ok(parser.finish())
}

fn parse_line(line_number: usize, input: &str) -> Result<Option<OwnedEvent>, ParseError> {
    let had_ansi = input.as_bytes().contains(&0x1b);
    let clean = strip_ansi(input);
    let Some(offset) = clean.find("EM_") else {
        return Ok(None);
    };
    let mut payload = clean[offset..].trim();
    if had_ansi {
        payload = payload.strip_suffix('.').unwrap_or(payload);
    }
    let mut words = payload.split_ascii_whitespace();
    let record = words
        .next()
        .ok_or_else(|| ParseError::new(line_number, None, None, "missing record identifier"))?;
    let mut fields = BTreeMap::new();
    for word in words {
        let (key, value) = word.split_once(':').ok_or_else(|| {
            ParseError::new(
                line_number,
                Some(record),
                None,
                format_args!("field token {word:?} has no ':' separator").to_string(),
            )
        })?;
        if key.is_empty() || value.is_empty() {
            return Err(ParseError::new(
                line_number,
                Some(record),
                Some(key),
                "field key and value must be non-empty",
            ));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(ParseError::new(
                line_number,
                Some(record),
                Some(key),
                "duplicate field",
            ));
        }
    }
    let schema = take_parse::<u16>(&mut fields, "schema", line_number, record)?;
    if schema != SCHEMA_VERSION {
        return Err(ParseError::new(
            line_number,
            Some(record),
            Some("schema"),
            format_args!("unsupported schema {schema}; expected {SCHEMA_VERSION}").to_string(),
        ));
    }

    let tag = EventTag::from_wire_name(record).ok_or_else(|| {
        ParseError::new(line_number, Some(record), None, "unknown EM record type")
    })?;
    let event = match tag {
        EventTag::Begin => OwnedEvent::Begin(BeginEvent {
            schema,
            suite: take(&mut fields, "suite", line_number, record)?,
            target: take(&mut fields, "target", line_number, record)?,
            board: take_optional(&mut fields, "board", line_number, record)?,
            unit: take_unit(&mut fields, "unit", line_number, record)?,
            frequency_hz: take_optional_u64(&mut fields, "frequency_hz", line_number, record)?,
            fields,
        }),
        EventTag::Sample => {
            let side = take(&mut fields, "side", line_number, record)?;
            let mut chars = side.chars();
            let side = match (chars.next(), chars.next()) {
                (Some(value @ ('A' | 'B')), None) => value,
                _ => {
                    return Err(ParseError::new(
                        line_number,
                        Some(record),
                        Some("side"),
                        "expected A or B",
                    ));
                }
            };
            OwnedEvent::Sample(SampleEvent {
                schema,
                fixture: take(&mut fields, "fixture", line_number, record)?,
                side,
                index: take_parse(&mut fields, "index", line_number, record)?,
                ticks: take_parse(&mut fields, "ticks", line_number, record)?,
                wrapped: take_bool(&mut fields, "wrapped", line_number, record)?,
                fields,
            })
        }
        EventTag::Result => OwnedEvent::Result(parse_comparison(
            schema,
            &mut fields,
            line_number,
            record,
            true,
        )?),
        EventTag::Diagnostic => OwnedEvent::Diagnostic(parse_comparison(
            schema,
            &mut fields,
            line_number,
            record,
            false,
        )?),
        EventTag::Summary => OwnedEvent::Summary(SummaryEvent {
            schema,
            suite: take(&mut fields, "suite", line_number, record)?,
            passed: take_parse(&mut fields, "passed", line_number, record)?,
            failed: take_parse(&mut fields, "failed", line_number, record)?,
            fields,
        }),
        EventTag::Stack => OwnedEvent::Stack(StackEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            used: take_parse(&mut fields, "used", line_number, record)?,
            available: take_parse(&mut fields, "available", line_number, record)?,
            painted: take_parse(&mut fields, "painted", line_number, record)?,
            safe_zone: take_parse(&mut fields, "safe_zone", line_number, record)?,
            overflowed: take_bool(&mut fields, "overflowed", line_number, record)?,
            fields,
        }),
        EventTag::Measurement => OwnedEvent::Measurement(MeasurementEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            ticks: take_parse(&mut fields, "ticks", line_number, record)?,
            unit: take_unit(&mut fields, "unit", line_number, record)?,
            frequency_hz: take_optional_u64(&mut fields, "frequency_hz", line_number, record)?,
            wrapped: take_bool(&mut fields, "wrapped", line_number, record)?,
            fields,
        }),
        EventTag::Outcome => OwnedEvent::Outcome(OutcomeEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            status: take_status(&mut fields, "status", line_number, record)?,
            fields,
        }),
        EventTag::Boundary => OwnedEvent::Boundary(BoundaryEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            trial: take_parse(&mut fields, "trial", line_number, record)?,
            phase: take_phase(&mut fields, "phase", line_number, record)?,
            status: take_optional_status(&mut fields, "status", line_number, record)?,
            fields,
        }),
        EventTag::Counter => OwnedEvent::Counter(CounterSnapshotEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            trial: take_parse(&mut fields, "trial", line_number, record)?,
            phase: take_phase(&mut fields, "phase", line_number, record)?,
            ticks: take_parse(&mut fields, "ticks", line_number, record)?,
            width_bits: take_parse(&mut fields, "width", line_number, record)?,
            unit: take_unit(&mut fields, "unit", line_number, record)?,
            frequency_hz: take_optional_u64(&mut fields, "frequency_hz", line_number, record)?,
            fields,
        }),
        EventTag::Metric => OwnedEvent::Metric(MetricEvent {
            schema,
            benchmark: take(&mut fields, "benchmark", line_number, record)?,
            name: take(&mut fields, "name", line_number, record)?,
            value: take_parse(&mut fields, "value", line_number, record)?,
            unit: take_optional(&mut fields, "unit", line_number, record)?,
            policy: take_metric_policy(&mut fields, line_number, record)?,
            fields,
        }),
    };
    Ok(Some(event))
}

fn take_metric_policy(
    fields: &mut OwnedFields,
    line: usize,
    record: &str,
) -> Result<MetricPolicy, ParseError> {
    match fields.remove("policy").as_deref() {
        Some("lower-is-better") => Ok(MetricPolicy::LowerIsBetter),
        Some("higher-is-better") => Ok(MetricPolicy::HigherIsBetter),
        Some("informational") | None => Ok(MetricPolicy::Informational),
        Some(_) => Err(ParseError::new(
            line,
            Some(record),
            Some("policy"),
            "expected lower-is-better, higher-is-better, or informational",
        )),
    }
}

fn take_phase(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<OwnedBoundaryPhase, ParseError> {
    match take(fields, key, line, record)?.as_str() {
        "begin" => Ok(OwnedBoundaryPhase::Begin),
        "end" => Ok(OwnedBoundaryPhase::End),
        value => Err(ParseError::new(
            line,
            Some(record),
            Some(key),
            format_args!("expected begin or end, got {value:?}").to_string(),
        )),
    }
}

fn take_optional_status(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<Option<EventStatus>, ParseError> {
    fields
        .remove(key)
        .map(|value| match value.as_str() {
            "PASS" => Ok(EventStatus::Pass),
            "FAIL" => Ok(EventStatus::Fail),
            _ => Err(ParseError::new(
                line,
                Some(record),
                Some(key),
                "expected PASS or FAIL",
            )),
        })
        .transpose()
}

fn parse_comparison(
    schema: u16,
    fields: &mut OwnedFields,
    line: usize,
    record: &str,
    has_policy: bool,
) -> Result<ComparisonEvent, ParseError> {
    Ok(ComparisonEvent {
        schema,
        fixture: take(fields, "fixture", line, record)?,
        class: take(fields, "class", line, record)?,
        policy: if has_policy {
            Some(take(fields, "policy", line, record)?)
        } else {
            None
        },
        a_min: take_parse(fields, "a_min", line, record)?,
        a_max: take_parse(fields, "a_max", line, record)?,
        b_min: take_parse(fields, "b_min", line, record)?,
        b_max: take_parse(fields, "b_max", line, record)?,
        spread: take_parse(fields, "spread", line, record)?,
        overlap: take_bool(fields, "overlap", line, record)?,
        wrapped: take_bool(fields, "wrapped", line, record)?,
        output_ok: take_bool(fields, "output_ok", line, record)?,
        status: if has_policy {
            Some(match take(fields, "status", line, record)?.as_str() {
                "PASS" => EventStatus::Pass,
                "FAIL" => EventStatus::Fail,
                value => {
                    return Err(ParseError::new(
                        line,
                        Some(record),
                        Some("status"),
                        format_args!("expected PASS or FAIL, got {value:?}").to_string(),
                    ));
                }
            })
        } else {
            None
        },
        fields: core::mem::take(fields),
    })
}

fn take(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<String, ParseError> {
    fields
        .remove(key)
        .ok_or_else(|| ParseError::new(line, Some(record), Some(key), "missing required field"))
}

fn take_parse<T: core::str::FromStr>(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<T, ParseError> {
    let value = take(fields, key, line, record)?;
    value.parse().map_err(|_| {
        ParseError::new(
            line,
            Some(record),
            Some(key),
            format_args!("invalid numeric value {value:?}").to_string(),
        )
    })
}

fn take_bool(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<bool, ParseError> {
    match take(fields, key, line, record)?.as_str() {
        "0" => Ok(false),
        "1" => Ok(true),
        value => Err(ParseError::new(
            line,
            Some(record),
            Some(key),
            format_args!("expected 0 or 1, got {value:?}").to_string(),
        )),
    }
}

fn take_unit(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<OwnedUnit, ParseError> {
    match take(fields, key, line, record)?.as_str() {
        "core-cycles" => Ok(OwnedUnit::CoreCycles),
        "timer-ticks" => Ok(OwnedUnit::TimerTicks),
        "instructions" => Ok(OwnedUnit::Instructions),
        "simulator-cycles" => Ok(OwnedUnit::SimulatorCycles),
        value => Err(ParseError::new(
            line,
            Some(record),
            Some(key),
            format_args!("unknown unit {value:?}").to_string(),
        )),
    }
}

fn take_status(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<EventStatus, ParseError> {
    match take(fields, key, line, record)?.as_str() {
        "PASS" => Ok(EventStatus::Pass),
        "FAIL" => Ok(EventStatus::Fail),
        value => Err(ParseError::new(
            line,
            Some(record),
            Some(key),
            format_args!("expected PASS or FAIL, got {value:?}").to_string(),
        )),
    }
}

fn take_optional(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<Option<String>, ParseError> {
    match take(fields, key, line, record)?.as_str() {
        "none" => Ok(None),
        value => Ok(Some(value.to_string())),
    }
}

fn take_optional_u64(
    fields: &mut OwnedFields,
    key: &str,
    line: usize,
    record: &str,
) -> Result<Option<u64>, ParseError> {
    let value = take(fields, key, line, record)?;
    if value == "none" {
        Ok(None)
    } else {
        value.parse().map(Some).map_err(|_| {
            ParseError::new(
                line,
                Some(record),
                Some(key),
                format_args!("invalid optional integer {value:?}").to_string(),
            )
        })
    }
}

fn strip_ansi(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            if chars.next() == Some('[') {
                for suffix in chars.by_ref() {
                    if suffix.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            output.push(character);
        }
    }
    output
}
