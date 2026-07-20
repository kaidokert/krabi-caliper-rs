//! Relocation-aware, negative-control-backed panic-path auditing.

use std::eprintln;
use std::ffi::OsString;
use std::fmt;
use std::format;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::println;
use std::process::{Command, Stdio};
use std::string::{String, ToString};
use std::vec::Vec;

use cargo_metadata::Message;
use regex::Regex;
use serde::Serialize;

use super::ct_asm::{extract_target, split_blocks};

pub const DEFAULT_FORBIDDEN_TARGETS: &[&str] = &[
    r"(?:^|::)(?:panic_fmt|panic_bounds_check|panic_nounwind|assert_failed|unwrap_failed|expect_failed)(?:::h[0-9a-f]+)?$",
    r"(?:slice_(?:start|end)_index(?:_len)?|slice_index(?:_len)?|len_mismatch)_fail",
    r"core::panicking::",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Staticlib,
    Example,
}

#[derive(Debug, Clone)]
pub struct PanicAuditConfig {
    pub workspace: PathBuf,
    pub package: String,
    pub artifact_kind: ArtifactKind,
    pub artifact_name: Option<String>,
    pub negative_artifact_name: Option<String>,
    pub target: String,
    pub profile: String,
    pub no_default_features: bool,
    pub positive_features: Vec<String>,
    pub negative_features: Vec<String>,
    pub owned_symbols: Vec<String>,
    pub forbidden_targets: Vec<String>,
    pub expected_negatives: Vec<String>,
    pub extra_cargo_args: Vec<OsString>,
    pub json_out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct PanicCallSite {
    pub caller: String,
    pub callee: String,
    pub offset: u64,
    pub instruction: String,
}

#[derive(Debug, Serialize)]
pub struct PanicAuditPass {
    pub artifact: PathBuf,
    pub owned_symbols_seen: usize,
    pub panic_call_sites: Vec<PanicCallSite>,
}

#[derive(Debug, Serialize)]
pub struct PanicAuditReport {
    pub target: String,
    pub positive: PanicAuditPass,
    pub negative: PanicAuditPass,
    pub expected_negatives: Vec<String>,
    pub missing_negatives: Vec<String>,
    pub status: &'static str,
}

impl PanicAuditReport {
    pub fn success(&self) -> bool {
        self.status == "PASS"
    }

    pub fn print_human(&self) {
        println!("==== Panic audit for {} ====", self.target);
        println!(
            "  positive: {} owned symbols, {} panic call sites",
            self.positive.owned_symbols_seen,
            self.positive.panic_call_sites.len()
        );
        for site in &self.positive.panic_call_sites {
            println!("    FAIL: {} -> {}", site.caller, site.callee);
        }
        println!(
            "  negative: {} owned symbols, {} panic call sites",
            self.negative.owned_symbols_seen,
            self.negative.panic_call_sites.len()
        );
        if self.missing_negatives.is_empty() {
            println!(
                "  negative controls: all {} tripped",
                self.expected_negatives.len()
            );
        } else {
            println!(
                "  negative controls missing: {}",
                self.missing_negatives.join(", ")
            );
        }
        println!("  status: {}", self.status);
    }
}

#[derive(Debug)]
pub struct PanicAuditError(String);

impl fmt::Display for PanicAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PanicAuditError {}

pub fn run(config: &PanicAuditConfig) -> Result<PanicAuditReport, PanicAuditError> {
    validate(config)?;
    let owned = compile(&config.owned_symbols, "owned-symbol")?;
    let forbidden = compile(&config.forbidden_targets, "forbidden-target")?;
    let expected = compile(&config.expected_negatives, "expect-negative")?;

    let positive_artifact = build(
        config,
        &config.positive_features,
        config.artifact_name.as_deref(),
    )?;
    let positive = analyze(config, positive_artifact, &owned, &forbidden)?;

    let mut negative_features = config.positive_features.clone();
    for feature in &config.negative_features {
        if !negative_features.contains(feature) {
            negative_features.push(feature.clone());
        }
    }
    let negative_artifact = build(
        config,
        &negative_features,
        config
            .negative_artifact_name
            .as_deref()
            .or(config.artifact_name.as_deref()),
    )?;
    let negative = analyze(config, negative_artifact, &owned, &forbidden)?;

    let missing_negatives = config
        .expected_negatives
        .iter()
        .zip(expected.iter())
        .filter(|(_, pattern)| {
            !negative
                .panic_call_sites
                .iter()
                .any(|site| pattern.is_match(&site.caller))
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let success = positive.panic_call_sites.is_empty()
        && positive.owned_symbols_seen > 0
        && negative.owned_symbols_seen > 0
        && missing_negatives.is_empty();
    let report = PanicAuditReport {
        target: config.target.clone(),
        positive,
        negative,
        expected_negatives: config.expected_negatives.clone(),
        missing_negatives,
        status: if success { "PASS" } else { "FAIL" },
    };
    if let Some(path) = &config.json_out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(error)?;
        }
        fs::write(path, serde_json::to_vec_pretty(&report).map_err(error)?).map_err(error)?;
    }
    Ok(report)
}

fn validate(config: &PanicAuditConfig) -> Result<(), PanicAuditError> {
    if config.owned_symbols.is_empty() {
        return Err(PanicAuditError(
            "at least one --owned-symbol is required".into(),
        ));
    }
    if config.negative_features.is_empty() {
        return Err(PanicAuditError(
            "--negative-features must not be empty".into(),
        ));
    }
    if config.expected_negatives.is_empty() {
        return Err(PanicAuditError(
            "at least one --expect-negative is required".into(),
        ));
    }
    if config.artifact_kind == ArtifactKind::Example && config.artifact_name.is_none() {
        return Err(PanicAuditError(
            "example audits require --artifact-name".into(),
        ));
    }
    Ok(())
}

fn compile(values: &[String], label: &str) -> Result<Vec<Regex>, PanicAuditError> {
    values
        .iter()
        .map(|value| {
            Regex::new(value)
                .map_err(|e| PanicAuditError(format!("bad --{label} regex {value:?}: {e}")))
        })
        .collect()
}

fn build(
    config: &PanicAuditConfig,
    features: &[String],
    artifact_name: Option<&str>,
) -> Result<PathBuf, PanicAuditError> {
    let mut command = Command::new("cargo");
    command
        .current_dir(&config.workspace)
        .arg("build")
        .arg("--message-format=json-render-diagnostics")
        .arg("--profile")
        .arg(&config.profile)
        .arg("--target")
        .arg(&config.target)
        .arg("-p")
        .arg(&config.package);
    if config.no_default_features {
        command.arg("--no-default-features");
    }
    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }
    if config.artifact_kind == ArtifactKind::Example {
        command.arg("--example").arg(artifact_name.unwrap());
    }
    command.args(&config.extra_cargo_args);
    eprintln!("[panic-audit] {:?}", command);
    let output = command.stdout(Stdio::piped()).output().map_err(error)?;
    if !output.status.success() {
        return Err(PanicAuditError(format!(
            "cargo build failed with {}:\n{}{}",
            output.status,
            render_cargo_diagnostics(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    artifact_from_messages(config, artifact_name, &output.stdout)
}

fn render_cargo_diagnostics(stdout: &[u8]) -> String {
    Message::parse_stream(Cursor::new(stdout))
        .filter_map(Result::ok)
        .filter_map(|message| match message {
            Message::CompilerMessage(message) => message.message.rendered,
            Message::TextLine(line) => Some(format!("{line}\n")),
            _ => None,
        })
        .collect()
}

fn artifact_from_messages(
    config: &PanicAuditConfig,
    artifact_name: Option<&str>,
    stdout: &[u8],
) -> Result<PathBuf, PanicAuditError> {
    let mut matches = Message::parse_stream(Cursor::new(stdout))
        .filter_map(Result::ok)
        .filter_map(|message| match message {
            Message::CompilerArtifact(artifact)
                if artifact.target.name
                    == artifact_name.unwrap_or(&config.package).replace('-', "_") =>
            {
                Some(artifact)
            }
            _ => None,
        })
        .filter_map(|artifact| match config.artifact_kind {
            ArtifactKind::Example => artifact.executable.map(|path| path.into_std_path_buf()),
            ArtifactKind::Staticlib => artifact
                .filenames
                .into_iter()
                .map(|path| path.into_std_path_buf())
                .find(|path| path.extension().is_some_and(|ext| ext == "a")),
        })
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [artifact] => Ok(artifact.clone()),
        [] => Err(PanicAuditError(
            "Cargo did not report the requested audit artifact".into(),
        )),
        _ => Err(PanicAuditError(format!(
            "Cargo reported multiple audit artifacts: {matches:?}"
        ))),
    }
}

fn analyze(
    config: &PanicAuditConfig,
    artifact: PathBuf,
    owned: &[Regex],
    forbidden: &[Regex],
) -> Result<PanicAuditPass, PanicAuditError> {
    let (mut command, disassembler) = disassembler(config)?;
    let output = command.arg(&artifact).output().map_err(error)?;
    if !output.status.success() {
        return Err(PanicAuditError(format!(
            "{disassembler} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let blocks = split_blocks(&String::from_utf8_lossy(&output.stdout));
    let owned_blocks = blocks
        .iter()
        .filter(|block| owned.iter().any(|pattern| pattern.is_match(&block.symbol)))
        .collect::<Vec<_>>();
    if owned_blocks.is_empty() {
        return Err(PanicAuditError(
            "owned-symbol scope is empty; refusing a vacuous pass".into(),
        ));
    }
    let mut panic_call_sites = Vec::new();
    for block in &owned_blocks {
        for instruction in &block.insns {
            let target = instruction
                .call_target
                .clone()
                .or_else(|| extract_target(&instruction.full_line));
            let Some(target) = target else { continue };
            if forbidden.iter().any(|pattern| pattern.is_match(&target)) {
                panic_call_sites.push(PanicCallSite {
                    caller: block.symbol.clone(),
                    callee: target,
                    offset: instruction.offset,
                    instruction: instruction.full_line.clone(),
                });
            }
        }
    }
    Ok(PanicAuditPass {
        artifact,
        owned_symbols_seen: owned_blocks.len(),
        panic_call_sites,
    })
}

fn disassembler(config: &PanicAuditConfig) -> Result<(Command, &'static str), PanicAuditError> {
    if config.target.starts_with("avr-") || config.target == "avr-none" {
        // LLVM's AVR decoder currently prints ordinary CALL instructions as
        // `<unknown>`, losing the linked target labels needed for attribution.
        // GNU avr-objdump decodes the final ELF and retains those labels.
        let mut command = Command::new("avr-objdump");
        command.args(["--disassemble", "--demangle", "--no-show-raw-insn"]);
        return Ok((command, "avr-objdump"));
    }

    let mut command = Command::new(llvm_objdump()?);
    command.args([
        "--disassemble",
        "--reloc",
        "--demangle",
        "--no-show-raw-insn",
    ]);
    Ok((command, "llvm-objdump"))
}

fn llvm_objdump() -> Result<PathBuf, PanicAuditError> {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(error)?;
    let version = Command::new("rustc").arg("-vV").output().map_err(error)?;
    let version_text = String::from_utf8_lossy(&version.stdout);
    let host = version_text
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| PanicAuditError("rustc -vV did not report a host triple".into()))?;
    let path = Path::new(String::from_utf8_lossy(&sysroot.stdout).trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(format!("llvm-objdump{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        Ok(path)
    } else {
        Err(PanicAuditError(format!(
            "llvm-objdump not found at {}; install llvm-tools-preview",
            path.display()
        )))
    }
}

fn error(error: impl fmt::Display) -> PanicAuditError {
    PanicAuditError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn base_config() -> PanicAuditConfig {
        PanicAuditConfig {
            workspace: ".".into(),
            package: "fixture".into(),
            artifact_kind: ArtifactKind::Staticlib,
            artifact_name: None,
            negative_artifact_name: None,
            target: "thumbv7m-none-eabi".into(),
            profile: "release".into(),
            no_default_features: false,
            positive_features: vec![],
            negative_features: vec!["neg-controls".into()],
            owned_symbols: vec!["panic_audit__".into()],
            forbidden_targets: DEFAULT_FORBIDDEN_TARGETS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            expected_negatives: vec!["panic_audit__neg__bounds".into()],
            extra_cargo_args: vec![],
            json_out: None,
        }
    }

    #[test]
    fn rejects_empty_scope_and_missing_negative_policy() {
        let mut config = base_config();
        config.owned_symbols.clear();
        assert!(validate(&config).is_err());
        config.owned_symbols.push("owned".into());
        config.expected_negatives.clear();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn default_forbidden_targets_cover_required_panic_classes() {
        let patterns = compile(
            &DEFAULT_FORBIDDEN_TARGETS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "forbidden",
        )
        .unwrap();
        for symbol in [
            "core::panicking::panic_fmt",
            "core::panicking::panic_bounds_check",
            "core::slice::index::slice_end_index_len_fail",
            "core::option::unwrap_failed",
            "core::result::expect_failed",
        ] {
            assert!(
                patterns.iter().any(|pattern| pattern.is_match(symbol)),
                "{symbol}"
            );
        }
    }
}
