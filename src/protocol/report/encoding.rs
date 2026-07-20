#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Compatibility {
    #[default]
    None,
    CtV0,
}

/// A reporter for the stable `EM_*` line protocol.
pub struct TextReporter<W> {
    writer: W,
    compatibility: Compatibility,
}

impl<W> TextReporter<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            compatibility: Compatibility::None,
        }
    }

    pub const fn compatibility(mut self, compatibility: Compatibility) -> Self {
        self.compatibility = compatibility;
        self
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for TextReporter<W> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.writer.write_str(value)
    }
}

impl<W: Write> Reporter for TextReporter<W> {
    type Error = fmt::Error;

    #[inline(never)]
    fn run_start(&mut self, record: &RunStart<'_>) -> fmt::Result {
        validate_token(record.suite)?;
        validate_token(record.target)?;
        if let Some(board) = record.board {
            validate_token(board)?;
        }
        validate_fields(record.fields)?;

        write!(
            self.writer,
            "EM_BEGIN schema:{} suite:{} target:{} board:{} unit:{} frequency_hz:",
            SCHEMA_VERSION,
            record.suite,
            record.target,
            record.board.unwrap_or("none"),
            unit_name(record.unit),
        )?;
        write_optional_u64(&mut self.writer, record.frequency_hz)?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)?;

        if self.compatibility == Compatibility::CtV0 {
            write!(self.writer, "CT_BEGIN suite:{}", record.suite)?;
            write_fields(&mut self.writer, record.fields)?;
            writeln!(self.writer)?;
        }
        Ok(())
    }

    fn sample(&mut self, record: &SampleRecord<'_>) -> fmt::Result {
        validate_token(record.fixture)?;
        validate_fields(record.fields)?;
        if !matches!(record.side, 'A' | 'B') {
            return Err(fmt::Error);
        }
        write!(
            self.writer,
            "{} schema:{} fixture:{} side:{} index:{} ticks:{} wrapped:{}",
            EventTag::Sample.wire_name(),
            SCHEMA_VERSION,
            record.fixture,
            record.side,
            record.index,
            record.ticks,
            record.wrapped as u8,
        )?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)
    }

    fn result(&mut self, record: &ComparisonRecord<'_>) -> fmt::Result {
        write_comparison_fmt(&mut self.writer, EventTag::Result, record)
    }

    fn diagnostic(&mut self, record: &ComparisonRecord<'_>) -> fmt::Result {
        write_comparison_fmt(&mut self.writer, EventTag::Diagnostic, record)
    }

    #[inline(never)]
    fn run_summary(&mut self, record: &RunSummary<'_>) -> fmt::Result {
        validate_token(record.suite)?;
        validate_fields(record.fields)?;
        write!(
            self.writer,
            "EM_SUMMARY schema:{} suite:{} passed:{} failed:{}",
            SCHEMA_VERSION, record.suite, record.passed, record.failed,
        )?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)?;

        if self.compatibility == Compatibility::CtV0 {
            write!(
                self.writer,
                "CT_SUMMARY passed:{} failed:{}",
                record.passed, record.failed,
            )?;
            write_fields(&mut self.writer, record.fields)?;
            writeln!(self.writer)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn measurement(&mut self, record: &MeasurementRecord<'_>) -> fmt::Result {
        write_measurement_fmt(&mut self.writer, record, None)
    }

    #[inline(never)]
    fn indexed_measurement(&mut self, record: &MeasurementRecord<'_>, trial: u32) -> fmt::Result {
        write_measurement_fmt(&mut self.writer, record, Some(trial))
    }

    #[inline(never)]
    fn outcome(&mut self, record: &OutcomeRecord<'_>) -> fmt::Result {
        validate_token(record.benchmark)?;
        validate_fields(record.fields)?;
        write!(
            self.writer,
            "EM_OUTCOME schema:{} benchmark:{} status:{}",
            SCHEMA_VERSION,
            record.benchmark,
            if record.passed { "PASS" } else { "FAIL" },
        )?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)
    }

    #[inline(never)]
    fn boundary(&mut self, record: &BoundaryRecord<'_>) -> fmt::Result {
        validate_token(record.benchmark)?;
        validate_fields(record.fields)?;
        write!(
            self.writer,
            "EM_BOUNDARY schema:{} benchmark:{} trial:{} phase:{}",
            SCHEMA_VERSION,
            record.benchmark,
            record.trial,
            phase_name(record.phase),
        )?;
        if let Some(passed) = record.passed {
            write!(
                self.writer,
                " status:{}",
                if passed { "PASS" } else { "FAIL" }
            )?;
        }
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)
    }

    #[inline(never)]
    fn counter_snapshot(&mut self, record: &CounterSnapshotRecord<'_>) -> fmt::Result {
        validate_token(record.benchmark)?;
        validate_fields(record.fields)?;
        write!(
            self.writer,
            "EM_COUNTER schema:{} benchmark:{} trial:{} phase:{} ticks:{} width:{} unit:{} frequency_hz:",
            SCHEMA_VERSION,
            record.benchmark,
            record.trial,
            phase_name(record.phase),
            record.ticks,
            record.width_bits,
            unit_name(record.unit),
        )?;
        write_optional_u64(&mut self.writer, record.frequency_hz)?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)
    }

    #[inline(never)]
    fn metric(&mut self, record: &MetricRecord<'_>) -> fmt::Result {
        validate_token(record.benchmark)?;
        validate_token(record.name)?;
        if let Some(unit) = record.unit {
            validate_token(unit)?;
        }
        validate_fields(record.fields)?;
        write!(
            self.writer,
            "EM_METRIC schema:{} benchmark:{} name:{} value:{} unit:{} policy:{}",
            SCHEMA_VERSION,
            record.benchmark,
            record.name,
            record.value,
            record.unit.unwrap_or("none"),
            record.policy.as_str(),
        )?;
        write_fields(&mut self.writer, record.fields)?;
        writeln!(self.writer)
    }
}

fn unit_name(unit: Unit) -> &'static str {
    match unit {
        Unit::CoreCycles => "core-cycles",
        Unit::TimerTicks => "timer-ticks",
        Unit::Instructions => "instructions",
        Unit::SimulatorCycles => "simulator-cycles",
    }
}

const fn phase_name(phase: BoundaryPhase) -> &'static str {
    match phase {
        BoundaryPhase::Begin => "begin",
        BoundaryPhase::End => "end",
    }
}

fn write_optional_u64(writer: &mut impl Write, value: Option<u64>) -> fmt::Result {
    match value {
        Some(value) => write!(writer, "{value}"),
        None => writer.write_str("none"),
    }
}

fn write_measurement_fmt(
    writer: &mut impl Write,
    record: &MeasurementRecord<'_>,
    trial: Option<u32>,
) -> fmt::Result {
    validate_token(record.benchmark)?;
    if let Some(counter) = record.counter {
        validate_token(counter)?;
    }
    validate_fields(record.fields)?;
    write!(
        writer,
        "EM_MEASUREMENT schema:{} benchmark:{} ticks:{} unit:{} frequency_hz:",
        SCHEMA_VERSION,
        record.benchmark,
        record.measurement.ticks,
        unit_name(record.measurement.unit),
    )?;
    write_optional_u64(writer, record.measurement.frequency_hz)?;
    write!(writer, " wrapped:{}", record.measurement.wrapped as u8)?;
    if let Some(trial) = trial {
        write!(writer, " trial:{trial}")?;
    }
    if let Some(counter) = record.counter {
        write!(writer, " counter:{counter}")?;
    }
    write_fields(writer, record.fields)?;
    writeln!(writer)
}

fn write_comparison_fmt(
    writer: &mut impl Write,
    tag: EventTag,
    record: &ComparisonRecord<'_>,
) -> fmt::Result {
    validate_token(record.fixture)?;
    validate_token(record.class)?;
    if let Some(policy) = record.policy {
        validate_token(policy)?;
    }
    validate_fields(record.fields)?;
    write!(
        writer,
        "{} schema:{} fixture:{} class:{}",
        tag.wire_name(),
        SCHEMA_VERSION,
        record.fixture,
        record.class,
    )?;
    if let Some(policy) = record.policy {
        write!(writer, " policy:{policy}")?;
    }
    write!(
        writer,
        " a_min:{} a_max:{} b_min:{} b_max:{} spread:{} overlap:{} wrapped:{} output_ok:{}",
        record.a_min,
        record.a_max,
        record.b_min,
        record.b_max,
        record.spread,
        record.overlap as u8,
        record.wrapped as u8,
        record.output_ok as u8,
    )?;
    if let Some(passed) = record.passed {
        write!(writer, " status:{}", if passed { "PASS" } else { "FAIL" })?;
    }
    write_fields(writer, record.fields)?;
    writeln!(writer)
}

fn write_fields(writer: &mut impl Write, fields: &[Field<'_>]) -> fmt::Result {
    for field in fields {
        write!(writer, " {}:", field.key)?;
        match field.value {
            FieldValue::Token(value) => writer.write_str(value)?,
            FieldValue::U64(value) => write!(writer, "{value}")?,
            FieldValue::Bool(value) => writer.write_str(if value { "1" } else { "0" })?,
        }
    }
    Ok(())
}

fn validate_fields(fields: &[Field<'_>]) -> fmt::Result {
    for field in fields {
        validate_token(field.key)?;
        if is_reserved_field(field.key) {
            return Err(fmt::Error);
        }
        if let FieldValue::Token(value) = field.value {
            validate_token(value)?;
        }
    }
    Ok(())
}

fn is_reserved_field(key: &str) -> bool {
    matches!(
        key,
        "schema"
            | "benchmark"
            | "suite"
            | "target"
            | "board"
            | "fixture"
            | "class"
            | "policy"
            | "passed"
            | "failed"
            | "ticks"
            | "counter"
            | "unit"
            | "frequency_hz"
            | "wrapped"
            | "status"
            | "trial"
            | "phase"
            | "width"
            | "name"
            | "value"
            | "used"
            | "available"
            | "painted"
            | "safe_zone"
            | "overflowed"
            | "side"
            | "index"
            | "a_min"
            | "a_max"
            | "b_min"
            | "b_max"
            | "spread"
            | "overlap"
            | "output_ok"
    )
}

fn validate_token(token: &str) -> fmt::Result {
    if !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(fmt::Error)
    }
}
