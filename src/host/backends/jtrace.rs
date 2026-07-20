use std::eprintln;
use std::ffi::OsString;
use std::fmt;
use std::format;
use std::fs;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::time::Duration;
use std::vec::Vec;

use super::{CommandRunner, CommandSpec};
use crate::host::read_elf_symbol;

const DWT_COMP0: u32 = 0xE000_1020;
const DWT_MASK0: u32 = 0xE000_1024;
const DWT_FUNCTION0: u32 = 0xE000_1028;
const DWT_COMP1: u32 = 0xE000_1030;
const DWT_MASK1: u32 = 0xE000_1034;
const DWT_FUNCTION1: u32 = 0xE000_1038;
const ETM_CR: u32 = 0xE004_1000;
const ETM_TECR1: u32 = 0xE004_1024;
const ETM_TESSEICR: u32 = 0xE004_11F0;

#[derive(Clone, Debug)]
pub struct JTraceCapture {
    pub elf: PathBuf,
    pub output_dir: PathBuf,
    pub device: String,
    pub probe_serial: String,
    pub begin_symbol: String,
    pub end_symbol: String,
    pub run_millis: u64,
    pub recent_instructions: u32,
    pub jlink_exe: PathBuf,
    pub rtt: Option<RttCapture>,
}

#[derive(Clone, Debug)]
pub struct RttCapture {
    pub probe_rs: PathBuf,
    pub probe_selector: String,
    pub chip: String,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug)]
pub struct JTraceReport {
    pub begin_address: u64,
    pub end_address: u64,
    pub script: PathBuf,
    pub transcript: PathBuf,
    pub decoded_instruction_lines: usize,
    pub unique_instruction_addresses: usize,
    pub trace_reported_instructions: u64,
    pub ticks: Option<u64>,
    pub frequency_hz: Option<u64>,
    pub operations_per_second: Option<f64>,
    pub rtt_transcript: Option<PathBuf>,
    pub analysis: PathBuf,
}

#[derive(Debug)]
pub struct JTraceError(String);

impl fmt::Display for JTraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JTraceError {}

impl JTraceCapture {
    pub fn run(&self) -> Result<JTraceReport, JTraceError> {
        fs::create_dir_all(&self.output_dir).map_err(error)?;
        // ELF function symbols on Arm may encode Thumb state in bit zero. DWT
        // PC comparators require the aligned instruction address.
        let begin = required_symbol(&self.elf, &self.begin_symbol)? & !1;
        let end = required_symbol(&self.elf, &self.end_symbol)? & !1;
        if begin > u32::MAX as u64 || end > u32::MAX as u64 {
            return Err(JTraceError(
                "ETM marker address exceeds 32-bit address space".into(),
            ));
        }
        let script = self.output_dir.join("jtrace-command.jlink");
        let transcript = self.output_dir.join("jtrace-transcript.txt");
        // Commander infers the input format from the extension. Cargo's final
        // executable is commonly extensionless, so stage an exact `.elf` copy.
        let staged_elf = self.output_dir.join("firmware.elf");
        fs::copy(&self.elf, &staged_elf).map_err(error)?;
        let elf = commander_path(&staged_elf)?;
        let body = format!(
            "device {}\nsi SWD\nspeed 4000\nconnect\nr\nloadfile \"{}\"\nr\n\
             STraceStart\nw4 {ETM_CR:#010x} 0x00000c10\nsleep 10\n\
             w4 {DWT_COMP0:#010x} {begin:#010x}\nw4 {DWT_MASK0:#010x} 0\nw4 {DWT_FUNCTION0:#010x} 8\n\
             w4 {DWT_COMP1:#010x} {end:#010x}\nw4 {DWT_MASK1:#010x} 0\nw4 {DWT_FUNCTION1:#010x} 8\n\
             w4 {ETM_TESSEICR:#010x} 0x00020001\nw4 {ETM_TECR1:#010x} 0x02000000\n\
             w4 {ETM_CR:#010x} 0x00000810\nsleep 10\ng\nsleep {}\nh\n\
             STraceStop\nSTraceRead {}\nexit\n",
            self.device, elf, self.run_millis, self.recent_instructions,
        );
        fs::write(&script, body).map_err(error)?;
        let spec = CommandSpec::new(&self.jlink_exe, &self.output_dir)
            .args([
                OsString::from("-USB"),
                OsString::from(&self.probe_serial),
                OsString::from("-CommanderScript"),
                OsString::from(script.as_os_str()),
            ])
            .timeout(Duration::from_millis(self.run_millis + 30_000));
        eprintln!("running: {}", spec.display());
        let output = CommandRunner.run(&spec).map_err(error)?;
        let text = output.combined_lossy();
        fs::write(&transcript, &text).map_err(error)?;
        if !output.success() {
            return Err(JTraceError(format!(
                "J-Link command failed; see {}",
                transcript.display()
            )));
        }
        let lower = text.to_ascii_lowercase();
        if lower.contains("trace buffer overflow")
            || lower.contains("trace data overflow")
            || lower.contains("unknown / unsupported format")
        {
            return Err(JTraceError(format!(
                "J-Trace overflow; see {}",
                transcript.display()
            )));
        }
        let addresses = decoded_addresses(&text);
        let decoded_instruction_lines = addresses.len();
        let mut unique = addresses.clone();
        unique.sort_unstable();
        unique.dedup();
        let trace_reported_instructions = trace_instruction_count(&text).unwrap_or(0);
        if decoded_instruction_lines == 0 || trace_reported_instructions == 0 {
            return Err(JTraceError(format!(
                "J-Trace transcript contains no decoded instructions; see {}",
                transcript.display()
            )));
        }
        if addresses.first().copied() != Some(end) {
            return Err(JTraceError(format!(
                "most recent decoded instruction is not the ETM end marker {end:#010x}; capture may be incomplete; see {}",
                transcript.display()
            )));
        }
        let (rtt_transcript, ticks, frequency_hz) = if let Some(rtt) = &self.rtt {
            let path = self.output_dir.join("rtt-transcript.txt");
            let rtt_output = capture_rtt(rtt, &self.elf, &self.output_dir)?;
            fs::write(&path, &rtt_output).map_err(error)?;
            let (ticks, frequency_hz) = parse_etm_trial(&rtt_output).ok_or_else(|| {
                JTraceError(format!(
                    "RTT output has no valid ETM_TRIAL record; see {}",
                    path.display()
                ))
            })?;
            (Some(path), Some(ticks), Some(frequency_hz))
        } else {
            (None, None, None)
        };
        let operations_per_second = ticks
            .zip(frequency_hz)
            .map(|(ticks, hz)| hz as f64 / ticks as f64);
        let analysis = self.output_dir.join("jtrace-analysis.md");
        fs::write(
            &analysis,
            render_analysis(
                &self.elf,
                begin,
                end,
                trace_reported_instructions,
                decoded_instruction_lines,
                unique.len(),
                ticks,
                frequency_hz,
                operations_per_second,
            ),
        )
        .map_err(error)?;
        Ok(JTraceReport {
            begin_address: begin,
            end_address: end,
            script,
            transcript,
            decoded_instruction_lines,
            unique_instruction_addresses: unique.len(),
            trace_reported_instructions,
            ticks,
            frequency_hz,
            operations_per_second,
            rtt_transcript,
            analysis,
        })
    }
}

fn decoded_addresses(text: &str) -> Vec<u64> {
    text.lines()
        .filter_map(|line| {
            let (address, _) = line.split_once(':')?;
            (address.len() == 8 && address.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| u64::from_str_radix(address, 16).ok())
                .flatten()
        })
        .collect()
}

fn trace_instruction_count(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        line.strip_suffix(" instructions (most recently executed first):")?
            .trim()
            .parse()
            .ok()
    })
}

pub(crate) fn capture_rtt(rtt: &RttCapture, elf: &Path, cwd: &Path) -> Result<String, JTraceError> {
    let spec = CommandSpec::new(&rtt.probe_rs, cwd)
        .args([
            OsString::from("attach"),
            OsString::from("--chip"),
            OsString::from(&rtt.chip),
            OsString::from("--protocol"),
            OsString::from("swd"),
            OsString::from("--probe"),
            OsString::from(&rtt.probe_selector),
            OsString::from("--non-interactive"),
            OsString::from("--disable-progressbars"),
            OsString::from("--no-location"),
            OsString::from(elf.as_os_str()),
        ])
        .completion_marker(b"ETM_TRIAL ".to_vec())
        .timeout(Duration::from_millis(rtt.timeout_millis));
    eprintln!("running: {}", spec.display());
    let output = CommandRunner.run(&spec).map_err(error)?;
    if !output.success() {
        return Err(JTraceError(format!(
            "RTT capture command failed: {}",
            spec.display()
        )));
    }
    Ok(output.combined_lossy())
}

pub(crate) fn parse_etm_trial(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|line| line.starts_with("ETM_TRIAL "))?;
    let field = |name: &str| {
        line.split_ascii_whitespace()
            .find_map(|item| item.strip_prefix(name))?
            .parse::<u64>()
            .ok()
    };
    let ticks = field("ticks:")?;
    let frequency_hz = field("frequency_hz:")?;
    (field("output_ok:")? == 1 && ticks != 0 && frequency_hz != 0).then_some((ticks, frequency_hz))
}

#[allow(clippy::too_many_arguments)]
fn render_analysis(
    elf: &Path,
    begin: u64,
    end: u64,
    trace_count: u64,
    decoded_count: usize,
    unique_count: usize,
    ticks: Option<u64>,
    frequency_hz: Option<u64>,
    operations_per_second: Option<f64>,
) -> String {
    let timing = match (ticks, frequency_hz, operations_per_second) {
        (Some(ticks), Some(hz), Some(ops)) => format!(
            "- DWT cycles: `{ticks}`\n- Qualified core clock: `{hz}` Hz\n- Throughput: `{ops:.6}` operations/second\n- Duration: `{:.6}` seconds\n",
            ticks as f64 / hz as f64
        ),
        _ => "- DWT correlation: not requested\n".to_string(),
    };
    format!(
        "# J-Trace capture analysis\n\n- ELF: `{}`\n- ETM interval: `{begin:#010x}` through `{end:#010x}`\n- Trace status: bounded capture completed without reported overflow\n- Recent instructions reported by J-Trace: `{trace_count}`\n- Decoded instruction records retained: `{decoded_count}`\n- Unique retained instruction addresses: `{unique_count}`\n{timing}",
        elf.display()
    )
}

fn required_symbol(path: &Path, name: &str) -> Result<u64, JTraceError> {
    read_elf_symbol(path, name)
        .map_err(error)?
        .ok_or_else(|| JTraceError(format!("ELF {} has no symbol {name}", path.display())))
}

fn commander_path(path: &Path) -> Result<String, JTraceError> {
    let value = path
        .canonicalize()
        .map_err(error)?
        .to_string_lossy()
        .into_owned();
    if value.contains(['\n', '\r', '"']) {
        return Err(JTraceError(
            "ELF path cannot be represented in a J-Link script".into(),
        ));
    }
    Ok(value)
}

fn error(error: impl fmt::Display) -> JTraceError {
    JTraceError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commander_instruction_summary_and_addresses() {
        let text = "64 instructions (most recently executed first):\n\
                    08002A08:   80 B5              PUSH      {R7,LR}\n\
                    08000ECC:   80 47              BLX       R0\n";
        assert_eq!(trace_instruction_count(text), Some(64));
        assert_eq!(decoded_addresses(text), [0x0800_2a08, 0x0800_0ecc]);
        assert_eq!(
            trace_instruction_count("10 instructions (most recently executed first):\n"),
            Some(10)
        );
    }

    #[test]
    fn parses_target_timing_record() {
        let text = "ETM_TRIAL fixture:sign ticks:142430551 frequency_hz:168000000 output_ok:1\n";
        assert_eq!(parse_etm_trial(text), Some((142_430_551, 168_000_000)));
        assert_eq!(
            parse_etm_trial("ETM_TRIAL ticks:1 frequency_hz:2 output_ok:0\n"),
            None
        );
        assert_eq!(
            parse_etm_trial("ETM_TRIAL ticks:0 frequency_hz:2 output_ok:1\n"),
            None
        );
        assert_eq!(
            parse_etm_trial("ETM_TRIAL ticks:1 frequency_hz:0 output_ok:1\n"),
            None
        );
    }
}
