use std::eprintln;
use std::ffi::OsString;
use std::fmt;
use std::format;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::string::{String, ToString};
use std::thread;
use std::time::Duration;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{
    CommandRunner, CommandSpec, GdbRemote, InstructionStats, ManagedChild, RttCapture, capture_rtt,
    parse_etm_trial,
};
use crate::host::{read_elf_code_range, read_elf_symbol, read_elf_text_symbols};

const DWT_COMP_START: u64 = 0xE000_1040;
const DWT_MASK_START: u64 = 0xE000_1044;
const DWT_FUNCTION_START: u64 = 0xE000_1048;
const DWT_COMP_STOP: u64 = 0xE000_1050;
const DWT_MASK_STOP: u64 = 0xE000_1054;
const DWT_FUNCTION_STOP: u64 = 0xE000_1058;
const ETM_CR: u64 = 0xE004_1000;
const ETM_TECR1: u64 = 0xE004_1024;
const ETM_TESSEICR: u64 = 0xE004_11F0;

#[derive(Clone, Debug)]
pub struct JTraceCtGate {
    pub elf: PathBuf,
    pub output_dir: PathBuf,
    pub device: String,
    pub probe_serial: String,
    pub keys: u32,
    pub repetitions: u32,
    pub max_dwt_spread: u32,
    pub max_profile_delta: u64,
    pub jlink_exe: PathBuf,
    pub gdb_server: PathBuf,
    pub port: u16,
    pub rtt: RttCapture,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JTraceCtGateReport {
    pub status: String,
    pub begin_address: u32,
    pub end_address: u32,
    pub code_start: u32,
    pub code_end: u32,
    pub keys: u32,
    pub repetitions: u32,
    pub dwt_min: u32,
    pub dwt_max: u32,
    pub dwt_spread: u32,
    pub dwt_rtt_checkpoint_ticks: u32,
    pub dwt_rtt_checkpoint_match: bool,
    pub all_trials_valid: bool,
    pub matched_rng_words: u32,
    pub execute_sum: u64,
    pub nonzero_halfwords: usize,
    pub profiles_equal: bool,
    pub within_key_profiles_equal: bool,
    pub cross_key_profiles_equal: bool,
    pub max_profile_delta_allowed: u64,
    pub max_within_key_profile_delta: u64,
    pub max_cross_key_profile_delta: u64,
    pub trials: Vec<TraceTrialSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceTrialSummary {
    pub key: u32,
    pub repetition: u32,
    pub dwt_ticks: u32,
    pub observed_key: u32,
    pub output_ok: bool,
    pub rng_words: u32,
    pub fetch_sum: u64,
    pub execute_sum: u64,
    pub skip_sum: u64,
    pub nonzero_halfwords: usize,
}

#[derive(Debug)]
pub struct JTraceCtGateError(String);

impl fmt::Display for JTraceCtGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for JTraceCtGateError {}

impl JTraceCtGate {
    pub fn run(&self) -> Result<JTraceCtGateReport, JTraceCtGateError> {
        if self.keys < 2 || self.repetitions == 0 {
            return Err(JTraceCtGateError(
                "ETM CT gate requires at least two keys and one repetition".into(),
            ));
        }
        self.prepare_output_dir()?;
        let begin = symbol_u32(&self.elf, "embedded_measure_trace_begin")? & !1;
        let end = symbol_u32(&self.elf, "embedded_measure_trace_end")? & !1;
        let key_selector = symbol_u32(&self.elf, "embedded_measure_etm_key_index")?;
        let dwt_ticks = symbol_u32(&self.elf, "embedded_measure_etm_dwt_ticks")?;
        let observed_key = symbol_u32(&self.elf, "embedded_measure_etm_observed_key")?;
        let output_ok = symbol_u32(&self.elf, "embedded_measure_etm_output_ok")?;
        let rng_words = symbol_u32(&self.elf, "embedded_measure_etm_rng_words")?;
        let (code_start, code_end) = read_elf_code_range(&self.elf)
            .map_err(error)?
            .ok_or_else(|| JTraceCtGateError("ELF has no executable code range".into()))?;
        let code_start = u32::try_from(code_start).map_err(error)? & !1;
        let code_end = u32::try_from((code_end + 1) & !1).map_err(error)?;
        let halfwords = (code_end - code_start) / 2;

        self.flash_exact_elf()?;
        let mut key_baselines: Vec<Option<InstructionStats>> =
            (0..self.keys).map(|_| None).collect();
        let mut within_key_profiles_equal = true;
        let mut cross_key_profiles_equal = true;
        let mut max_within_key_profile_delta = 0;
        let mut max_cross_key_profile_delta = 0;
        let mut summaries = Vec::new();
        let mut ticks = Vec::new();
        let mut dwt_rtt_checkpoint_ticks = None;
        let mut matched_rng_words = None;
        for key in 0..self.keys {
            for repetition in 0..self.repetitions {
                let (stats, trial_ticks, trial_observed_key, trial_output_ok, trial_rng_words) =
                    self.capture_trial(
                        key,
                        repetition,
                        begin,
                        end,
                        key_selector,
                        dwt_ticks,
                        observed_key,
                        output_ok,
                        rng_words,
                        code_start,
                        halfwords,
                    )?;
                if trial_observed_key != key {
                    return Err(JTraceCtGateError(format!(
                        "trial key mismatch: requested={key} observed={trial_observed_key} repetition={repetition}"
                    )));
                }
                if trial_output_ok != 1 {
                    return Err(JTraceCtGateError(format!(
                        "trial output invalid: key={key} repetition={repetition} output_ok={trial_output_ok}"
                    )));
                }
                match matched_rng_words {
                    Some(expected) if expected != trial_rng_words => {
                        return Err(JTraceCtGateError(format!(
                            "trial RNG stream mismatch: expected={expected} observed={trial_rng_words} key={key} repetition={repetition}"
                        )));
                    }
                    None => matched_rng_words = Some(trial_rng_words),
                    _ => {}
                }
                if key == 0 && repetition == 0 {
                    let rtt_output =
                        capture_rtt(&self.rtt, &self.elf, &self.output_dir).map_err(error)?;
                    fs::write(self.output_dir.join("dwt-checkpoint-rtt.txt"), &rtt_output)
                        .map_err(error)?;
                    let (rtt_ticks, _) = parse_etm_trial(&rtt_output).ok_or_else(|| {
                        JTraceCtGateError("RTT checkpoint has no ETM_TRIAL record".into())
                    })?;
                    let rtt_ticks = u32::try_from(rtt_ticks).map_err(error)?;
                    if rtt_ticks != trial_ticks {
                        return Err(JTraceCtGateError(format!(
                            "DWT checkpoint mismatch: memory={trial_ticks} RTT={rtt_ticks}"
                        )));
                    }
                    dwt_rtt_checkpoint_ticks = Some(rtt_ticks);
                }
                self.write_profile(&stats, key, repetition)?;
                if let Some(expected) = &key_baselines[key as usize] {
                    let delta = profile_distance(expected, &stats);
                    max_within_key_profile_delta = max_within_key_profile_delta.max(delta);
                    if delta > self.max_profile_delta {
                        within_key_profiles_equal = false;
                        self.write_profile_diff(expected, &stats, key, repetition, "within-key")?;
                    }
                } else {
                    key_baselines[key as usize] = Some(stats.clone());
                }
                if key != 0 {
                    let expected = key_baselines[0].as_ref().unwrap();
                    let delta = profile_distance(expected, &stats);
                    max_cross_key_profile_delta = max_cross_key_profile_delta.max(delta);
                    if delta > self.max_profile_delta {
                        cross_key_profiles_equal = false;
                        self.write_profile_diff(expected, &stats, key, repetition, "cross-key")?;
                    }
                }
                let nonzero_halfwords = stats.execute.iter().filter(|count| **count != 0).count();
                summaries.push(TraceTrialSummary {
                    key,
                    repetition,
                    dwt_ticks: trial_ticks,
                    observed_key: trial_observed_key,
                    output_ok: true,
                    rng_words: trial_rng_words,
                    fetch_sum: stats.fetch_sum,
                    execute_sum: stats.execute_sum,
                    skip_sum: stats.skip_sum,
                    nonzero_halfwords,
                });
                ticks.push(trial_ticks);
            }
        }
        let baseline = key_baselines[0]
            .as_ref()
            .expect("validated non-empty trial matrix");
        let dwt_min = *ticks.iter().min().unwrap();
        let dwt_max = *ticks.iter().max().unwrap();
        let dwt_spread = dwt_max.wrapping_sub(dwt_min);
        let profiles_equal = within_key_profiles_equal && cross_key_profiles_equal;
        let passed = profiles_equal && dwt_spread <= self.max_dwt_spread;
        let report = JTraceCtGateReport {
            status: if passed { "PASS" } else { "FAIL" }.to_string(),
            begin_address: begin,
            end_address: end,
            code_start,
            code_end,
            keys: self.keys,
            repetitions: self.repetitions,
            dwt_min,
            dwt_max,
            dwt_spread,
            dwt_rtt_checkpoint_ticks: dwt_rtt_checkpoint_ticks
                .expect("first trial always establishes RTT checkpoint"),
            dwt_rtt_checkpoint_match: true,
            all_trials_valid: true,
            matched_rng_words: matched_rng_words.expect("validated non-empty trial matrix"),
            execute_sum: baseline.execute_sum,
            nonzero_halfwords: baseline.execute.iter().filter(|count| **count != 0).count(),
            profiles_equal,
            within_key_profiles_equal,
            cross_key_profiles_equal,
            max_profile_delta_allowed: self.max_profile_delta,
            max_within_key_profile_delta,
            max_cross_key_profile_delta,
            trials: summaries,
        };
        fs::write(
            self.output_dir.join("gate-report.json"),
            serde_json::to_vec_pretty(&report).map_err(error)?,
        )
        .map_err(error)?;
        fs::write(
            self.output_dir.join("gate-report.md"),
            render_markdown(&report),
        )
        .map_err(error)?;
        Ok(report)
    }

    fn prepare_output_dir(&self) -> Result<(), JTraceCtGateError> {
        fs::create_dir_all(&self.output_dir).map_err(error)?;
        for entry in fs::read_dir(&self.output_dir).map_err(error)? {
            let entry = entry.map_err(error)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let generated = matches!(
                name.as_ref(),
                "firmware.elf"
                    | "flash.jlink"
                    | "flash-transcript.txt"
                    | "dwt-checkpoint-rtt.txt"
                    | "gate-report.json"
                    | "gate-report.md"
            ) || name.starts_with("profile-key-")
                || name.starts_with("profile-diff-")
                || name.starts_with("gdb-server-key-");
            if generated && entry.file_type().map_err(error)?.is_file() {
                fs::remove_file(entry.path()).map_err(error)?;
            }
        }
        Ok(())
    }

    fn flash_exact_elf(&self) -> Result<(), JTraceCtGateError> {
        let staged = self.output_dir.join("firmware.elf");
        fs::copy(&self.elf, &staged).map_err(error)?;
        let script = self.output_dir.join("flash.jlink");
        let staged = staged.canonicalize().map_err(error)?;
        fs::write(
            &script,
            format!(
                "device {}\nsi SWD\nspeed 4000\nconnect\nr\nloadfile \"{}\"\nr\nexit\n",
                self.device,
                staged.display()
            ),
        )
        .map_err(error)?;
        let spec = CommandSpec::new(&self.jlink_exe, &self.output_dir)
            .args([
                OsString::from("-USB"),
                OsString::from(&self.probe_serial),
                OsString::from("-CommanderScript"),
                OsString::from(script.as_os_str()),
            ])
            .timeout(Duration::from_secs(60));
        eprintln!("running: {}", spec.display());
        let output = CommandRunner.run(&spec).map_err(error)?;
        fs::write(
            self.output_dir.join("flash-transcript.txt"),
            output.combined_lossy(),
        )
        .map_err(error)?;
        if !output.success()
            || output
                .combined_lossy()
                .contains("unknown / unsupported format")
        {
            return Err(JTraceCtGateError("J-Link ELF load failed".into()));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_trial(
        &self,
        key: u32,
        repetition: u32,
        begin: u32,
        end: u32,
        key_selector: u32,
        dwt_ticks: u32,
        observed_key: u32,
        output_ok: u32,
        rng_words: u32,
        code_start: u32,
        halfwords: u32,
    ) -> Result<(InstructionStats, u32, u32, u32, u32), JTraceCtGateError> {
        let transcript_path = self
            .output_dir
            .join(format!("gdb-server-key-{key}-trial-{repetition}.txt"));
        let transcript = File::create(&transcript_path).map_err(error)?;
        let stderr = transcript.try_clone().map_err(error)?;
        let args = [
            "-select".to_string(),
            format!("USB={}", self.probe_serial),
            "-device".into(),
            self.device.clone(),
            "-if".into(),
            "SWD".into(),
            "-speed".into(),
            "4000".into(),
            "-port".into(),
            self.port.to_string(),
            "-swoport".into(),
            (self.port + 1).to_string(),
            "-telnetport".into(),
            (self.port + 2).to_string(),
            "-noir".into(),
            "-nogui".into(),
        ];
        let spec = CommandSpec::new(&self.gdb_server, &self.output_dir).args(&args);
        eprintln!("running: {}", spec.display());
        let mut child = CommandRunner
            .spawn(&spec, Stdio::from(transcript), Stdio::from(stderr))
            .map_err(error)?;
        let result = (|| {
            let mut remote = connect_with_retry(self.port, &mut child)?;
            remote.monitor("reset").map_err(error)?;
            remote.write_u32(key_selector as u64, key).map_err(error)?;
            remote.start_streaming_trace().map_err(error)?;
            thread::sleep(Duration::from_millis(20));
            configure_filtered_etm(&mut remote, begin, end)?;
            let halt = remote.continue_until_halt().map_err(error)?;
            if !halt.starts_with(b"T05") && !halt.starts_with(b"S05") {
                return Err(JTraceCtGateError(format!(
                    "target did not halt at terminal BKPT: {}",
                    String::from_utf8_lossy(&halt)
                )));
            }
            let etm_status = remote.read_u32(0xE004_1010).map_err(error)?;
            let etm_enable = remote.read_u32(ETM_TECR1).map_err(error)?;
            let etm_start_stop = remote.read_u32(ETM_TESSEICR).map_err(error)?;
            let start_match = remote.read_u32(DWT_FUNCTION_START).map_err(error)?;
            let stop_match = remote.read_u32(DWT_FUNCTION_STOP).map_err(error)?;
            remote.stop_streaming_trace().map_err(error)?;
            let recent = remote.recent_instructions(4).map_err(error)?;
            if recent.is_empty()
                || etm_status & (1 << 2) != 0
                || start_match & (1 << 24) == 0
                || stop_match & (1 << 24) == 0
            {
                return Err(JTraceCtGateError(format!(
                    "bounded ETM markers were not both observed: recent={recent:?}; ETMSR={etm_status:#010x} ETMTECR1={etm_enable:#010x} ETMTESSEICR={etm_start_stop:#010x} start_function={start_match:#010x} stop_function={stop_match:#010x}"
                )));
            }
            let stats = remote
                .instruction_stats(code_start, halfwords)
                .map_err(error)?;
            let ticks = remote.read_u32(dwt_ticks as u64).map_err(error)?;
            let observed_key = remote.read_u32(observed_key as u64).map_err(error)?;
            let output_ok = remote.read_u32(output_ok as u64).map_err(error)?;
            let rng_words = remote.read_u32(rng_words as u64).map_err(error)?;
            Ok((stats, ticks, observed_key, output_ok, rng_words))
        })();
        let _ = child.terminate();
        result
    }

    fn write_profile(
        &self,
        stats: &InstructionStats,
        key: u32,
        repetition: u32,
    ) -> Result<(), JTraceCtGateError> {
        let rows = profile_rows(stats);
        fs::write(
            self.output_dir
                .join(format!("profile-key-{key}-trial-{repetition}.json")),
            serde_json::to_vec_pretty(&rows).map_err(error)?,
        )
        .map_err(error)
    }

    fn write_profile_diff(
        &self,
        expected: &InstructionStats,
        actual: &InstructionStats,
        key: u32,
        repetition: u32,
        class: &str,
    ) -> Result<(), JTraceCtGateError> {
        let symbols = read_elf_text_symbols(&self.elf).map_err(error)?;
        let mut output =
            format!("profile mismatch: class={class} key={key} repetition={repetition}\n");
        for index in 0..expected.execute.len() {
            let before = (
                expected.fetch[index],
                expected.execute[index],
                expected.skip[index],
            );
            let after = (
                actual.fetch[index],
                actual.execute[index],
                actual.skip[index],
            );
            if before != after {
                let address = expected.address + index as u32 * 2;
                output.push_str(&format!(
                    "{address:#010x} {}: expected={before:?} actual={after:?}\n",
                    symbolize(address, &symbols),
                ));
            }
        }
        fs::write(
            self.output_dir.join(format!(
                "profile-diff-{class}-key-{key}-trial-{repetition}.txt"
            )),
            output,
        )
        .map_err(error)
    }
}

fn symbolize(address: u32, symbols: &[(u64, String)]) -> String {
    let address = u64::from(address);
    match symbols.partition_point(|(symbol_address, _)| *symbol_address <= address) {
        0 => "<unknown>".into(),
        index => {
            let (symbol_address, name) = &symbols[index - 1];
            format!("{name}+{:#x}", address - symbol_address)
        }
    }
}

fn configure_filtered_etm(
    remote: &mut GdbRemote,
    begin: u32,
    end: u32,
) -> Result<(), JTraceCtGateError> {
    for (address, value) in [
        (ETM_CR, 0x0000_0c10),
        (DWT_COMP_START, begin),
        (DWT_MASK_START, 0),
        (DWT_FUNCTION_START, 8),
        (DWT_COMP_STOP, end),
        (DWT_MASK_STOP, 0),
        (DWT_FUNCTION_STOP, 8),
        (ETM_TESSEICR, 0x0008_0004),
        (ETM_TECR1, 0x0200_0000),
        (ETM_CR, 0x0000_0810),
    ] {
        remote.write_u32(address, value).map_err(error)?;
        if address == ETM_CR && value == 0x0000_0c10 {
            thread::sleep(Duration::from_millis(20));
        }
        let readback = remote.read_u32(address).map_err(error)?;
        let mask = if address == DWT_FUNCTION_START || address == DWT_FUNCTION_STOP {
            0x0f
        } else {
            u32::MAX
        };
        if readback & mask != value & mask {
            return Err(JTraceCtGateError(format!(
                "ETM register {address:#010x} read back {readback:#010x}, expected {value:#010x}"
            )));
        }
    }
    Ok(())
}

fn connect_with_retry(port: u16, child: &mut ManagedChild) -> Result<GdbRemote, JTraceCtGateError> {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().map_err(error)? {
            return Err(JTraceCtGateError(format!(
                "J-Link GDB Server exited early: {status}"
            )));
        }
        if let Ok(remote) = GdbRemote::connect(("127.0.0.1", port), Duration::from_secs(30)) {
            return Ok(remote);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(JTraceCtGateError(
        "timed out connecting to J-Link GDB Server".into(),
    ))
}

fn symbol_u32(path: &Path, name: &str) -> Result<u32, JTraceCtGateError> {
    let address = read_elf_symbol(path, name)
        .map_err(error)?
        .ok_or_else(|| JTraceCtGateError(format!("ELF has no symbol {name}")))?;
    u32::try_from(address).map_err(error)
}

#[derive(Serialize)]
struct ProfileRow {
    address: u32,
    fetch: u64,
    execute: u64,
    skip: u64,
}

fn profile_rows(stats: &InstructionStats) -> Vec<ProfileRow> {
    (0..stats.execute.len())
        .filter(|index| {
            stats.fetch[*index] != 0 || stats.execute[*index] != 0 || stats.skip[*index] != 0
        })
        .map(|index| ProfileRow {
            address: stats.address + index as u32 * 2,
            fetch: stats.fetch[index],
            execute: stats.execute[index],
            skip: stats.skip[index],
        })
        .collect()
}

fn profile_distance(expected: &InstructionStats, actual: &InstructionStats) -> u64 {
    expected
        .execute
        .iter()
        .zip(&actual.execute)
        .map(|(expected, actual)| expected.abs_diff(*actual))
        .sum()
}

fn render_markdown(report: &JTraceCtGateReport) -> String {
    format!(
        "# ETM constant-time gate\n\n- Status: **{}**\n- Keys: `{}`\n- Repetitions per key: `{}`\n- Trial key/output validation: `{}`\n- Matched deterministic RNG words: `{}`\n- Profile-distance allowance: `{}` execution counts\n- Maximum within-key profile distance: `{}`\n- Maximum cross-key profile distance: `{}`\n- Within-key ETM profiles stable: `{}`\n- Cross-key ETM profiles equivalent: `{}`\n- Executed trace-address observations: `{}`\n- Active halfword addresses: `{}`\n- DWT self-measure checkpoint range: `{}–{}` cycles\n- DWT checkpoint spread: `{}` cycles\n- DWT memory/RTT checkpoint: `{}` cycles (match: `{}`)\n",
        report.status,
        report.keys,
        report.repetitions,
        report.all_trials_valid,
        report.matched_rng_words,
        report.max_profile_delta_allowed,
        report.max_within_key_profile_delta,
        report.max_cross_key_profile_delta,
        report.within_key_profiles_equal,
        report.cross_key_profiles_equal,
        report.execute_sum,
        report.nonzero_halfwords,
        report.dwt_min,
        report.dwt_max,
        report.dwt_spread,
        report.dwt_rtt_checkpoint_ticks,
        report.dwt_rtt_checkpoint_match,
    )
}

fn error(error: impl fmt::Display) -> JTraceCtGateError {
    JTraceCtGateError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn stats(execute: &[u64]) -> InstructionStats {
        InstructionStats {
            address: 0x0800_0000,
            fetch: execute.to_vec(),
            execute: execute.to_vec(),
            skip: vec![0; execute.len()],
            fetch_sum: execute.iter().sum(),
            execute_sum: execute.iter().sum(),
            skip_sum: 0,
        }
    }

    #[test]
    fn profile_distance_sums_absolute_execute_count_differences() {
        assert_eq!(profile_distance(&stats(&[10, 2, 7]), &stats(&[8, 5, 7])), 5);
    }

    #[test]
    fn symbolization_uses_the_nearest_preceding_text_symbol() {
        let symbols = vec![(0x0800_0010, "first".into()), (0x0800_0020, "next".into())];
        assert_eq!(symbolize(0x0800_0016, &symbols), "first+0x6");
        assert_eq!(symbolize(0x0800_0020, &symbols), "next+0x0");
        assert_eq!(symbolize(0x0800_000e, &symbols), "<unknown>");
    }
}
