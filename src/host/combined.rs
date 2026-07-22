//! Combined DWT campaign and J-Trace ETM evidence.

use std::format;
use std::fs;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};

use serde::{Deserialize, Serialize};

use super::{CampaignReport, CaseStatus, JTraceCtGateReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CombinedCtVerdict {
    Pass,
    Fail,
    IncomparableArtifacts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CombinedCtEvidence {
    pub case: String,
    pub dwt_campaign: CampaignReport,
    pub etm: JTraceCtGateReport,
    pub dwt_elf: PathBuf,
    pub etm_elf: PathBuf,
    pub same_elf: bool,
    pub verdict: CombinedCtVerdict,
}

impl CombinedCtEvidence {
    pub fn from_reports(
        campaign: CampaignReport,
        case: &str,
        etm: JTraceCtGateReport,
        etm_elf: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let case_report = campaign
            .cases
            .iter()
            .find(|candidate| candidate.id == case)
            .ok_or_else(|| format!("campaign has no case {case:?}"))?;
        let mut dwt_elf = case_report
            .artifact
            .clone()
            .ok_or_else(|| format!("campaign case {case:?} has no retained ELF"))?;
        if dwt_elf.is_relative() {
            let workspace = case_report
                .environment
                .source
                .workspace
                .as_ref()
                .ok_or_else(|| {
                    "relative campaign artifact has no recorded workspace".to_string()
                })?;
            dwt_elf = Path::new(workspace).join(dwt_elf);
        }
        let etm_elf = etm_elf.into();
        let dwt_len = fs::metadata(&dwt_elf)
            .map_err(|error| format!("{}: {error}", dwt_elf.display()))?
            .len();
        let etm_len = fs::metadata(&etm_elf)
            .map_err(|error| format!("{}: {error}", etm_elf.display()))?
            .len();
        let same_elf = dwt_len == etm_len
            && fs::read(&dwt_elf).map_err(|error| format!("{}: {error}", dwt_elf.display()))?
                == fs::read(&etm_elf).map_err(|error| format!("{}: {error}", etm_elf.display()))?;
        let has_dwt_ct_evidence = case_report
            .result
            .as_ref()
            .is_some_and(|result| !result.welch_analyses.is_empty());
        let verdict = if !same_elf {
            CombinedCtVerdict::IncomparableArtifacts
        } else if has_dwt_ct_evidence
            && case_report.status == CaseStatus::Pass
            && etm.status == "PASS"
        {
            CombinedCtVerdict::Pass
        } else {
            CombinedCtVerdict::Fail
        };
        Ok(Self {
            case: case.to_string(),
            dwt_campaign: campaign,
            etm,
            dwt_elf,
            etm_elf,
            same_elf,
            verdict,
        })
    }

    pub fn render_markdown(&self) -> String {
        let case = self
            .dwt_campaign
            .cases
            .iter()
            .find(|candidate| candidate.id == self.case)
            .expect("constructor validates case identity");
        let mut output = String::from("# Combined DWT and ETM constant-time evidence\n\n");
        output.push_str(&format!("- Case: `{}`\n", self.case));
        output.push_str(&format!("- Combined verdict: **{:?}**\n", self.verdict));
        output.push_str(&format!("- Identical ELF: `{}`\n", self.same_elf));
        output.push_str(&format!("- DWT campaign verdict: `{:?}`\n", case.status));
        output.push_str(&format!(
            "- ETM strict-invariance verdict: `{}`\n\n",
            self.etm.status
        ));
        if !self.same_elf {
            output.push_str(
                "> The DWT and ETM inputs are different ELF files. Their findings are retained side by side, but they do not support one combined security verdict.\n\n",
            );
        }
        output.push_str("## DWT statistical evidence\n\n");
        if let Some(result) = &case.result {
            output.push_str("| Fixture | Class | nA/nB | t | Verdict |\n");
            output.push_str("|---|---|---:|---:|---|\n");
            for analysis in &result.welch_analyses {
                output.push_str(&format!(
                    "| {} | {} | {}/{} | {} | {:?} |\n",
                    analysis.fixture,
                    analysis.class,
                    analysis.a_samples,
                    analysis.b_samples,
                    analysis
                        .t_statistic
                        .map_or_else(|| "—".to_string(), |value| format!("{value:.3}")),
                    analysis.verdict,
                ));
            }
        }
        output.push_str("\n## ETM execution-profile evidence\n\n");
        output.push_str(&format!(
            "- Keys/repetitions: `{}/{}`\n- DWT spread: `{}` cycles\n- Maximum within-key profile distance: `{}`\n- Maximum cross-key profile distance: `{}`\n- Profiles invariant: `{}`\n",
            self.etm.keys,
            self.etm.repetitions,
            self.etm.dwt_spread,
            self.etm.max_within_key_profile_delta,
            self.etm.max_cross_key_profile_delta,
            self.etm.profiles_equal,
        ));
        output
    }
}

pub fn read_combined_inputs(
    campaign: &Path,
    case: &str,
    etm_report: &Path,
    etm_elf: &Path,
) -> Result<CombinedCtEvidence, String> {
    let campaign =
        serde_json::from_reader(fs::File::open(campaign).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let etm =
        serde_json::from_reader(fs::File::open(etm_report).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    CombinedCtEvidence::from_reports(campaign, case, etm, etm_elf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{
        BuildMetadata, CargoTarget, CaseReport, ReproducibilityMetadata, SourceMetadata,
        TargetMetadata, WelchAnalysis, WelchVerdict,
    };
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    fn campaign(elf: PathBuf) -> CampaignReport {
        CampaignReport {
            campaign: "ct".to_string(),
            profile: "hardware".to_string(),
            cases: vec![CaseReport {
                id: "fixture".to_string(),
                name: "fixture".to_string(),
                cargo_target: CargoTarget::Binary("fixture".to_string()),
                environment: ReproducibilityMetadata {
                    recorded_unix_seconds: 0,
                    source: SourceMetadata::default(),
                    build: BuildMetadata::default(),
                    target: TargetMetadata::default(),
                },
                features: Vec::new(),
                parameters: BTreeMap::new(),
                artifact: Some(elf),
                footprint: None,
                baseline: None,
                build_command: String::new(),
                prepare_commands: Vec::new(),
                delay_before_run_seconds: None,
                run_command: None,
                build_duration_ms: 0,
                run_duration_ms: None,
                status: CaseStatus::Pass,
                error: None,
                diagnostic: None,
                result: Some(crate::host::RunResult {
                    welch_analyses: vec![WelchAnalysis {
                        fixture: "fixture".to_string(),
                        class: "protected".to_string(),
                        a_samples: 100,
                        b_samples: 100,
                        mean_a: Some(10.0),
                        mean_b: Some(10.0),
                        variance_a: Some(1.0),
                        variance_b: Some(1.0),
                        t_statistic: Some(0.0),
                        degrees_of_freedom: Some(198.0),
                        threshold: 4.5,
                        verdict: WelchVerdict::BelowThreshold,
                    }],
                    ..crate::host::RunResult::default()
                }),
            }],
        }
    }

    fn etm() -> JTraceCtGateReport {
        JTraceCtGateReport {
            status: "PASS".to_string(),
            begin_address: 0,
            end_address: 0,
            code_start: 0,
            code_end: 0,
            keys: 2,
            repetitions: 2,
            dwt_min: 10,
            dwt_max: 10,
            dwt_spread: 0,
            dwt_rtt_checkpoint_ticks: 10,
            dwt_rtt_checkpoint_match: true,
            all_trials_valid: true,
            matched_rng_words: 40,
            execute_sum: 1,
            nonzero_halfwords: 1,
            profiles_equal: true,
            within_key_profiles_equal: true,
            cross_key_profiles_equal: true,
            max_profile_delta_allowed: 0,
            max_within_key_profile_delta: 0,
            max_cross_key_profile_delta: 0,
            trials: Vec::new(),
        }
    }

    #[test]
    fn combined_verdict_requires_byte_identical_elfs() {
        let root =
            std::env::temp_dir().join(format!("krabi-caliper-combined-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let dwt = root.join("dwt.elf");
        let etm_path = root.join("etm.elf");
        fs::write(&dwt, b"same").unwrap();
        fs::write(&etm_path, b"same").unwrap();
        let report =
            CombinedCtEvidence::from_reports(campaign(dwt.clone()), "fixture", etm(), &etm_path)
                .unwrap();
        assert_eq!(report.verdict, CombinedCtVerdict::Pass);

        fs::write(&etm_path, b"different").unwrap();
        let report =
            CombinedCtEvidence::from_reports(campaign(dwt), "fixture", etm(), &etm_path).unwrap();
        assert_eq!(report.verdict, CombinedCtVerdict::IncomparableArtifacts);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn combined_pass_requires_dwt_constant_time_evidence() {
        let root =
            std::env::temp_dir().join(format!("krabi-caliper-no-dwt-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let elf = root.join("firmware.elf");
        fs::write(&elf, b"same").unwrap();
        let mut campaign = campaign(elf.clone());
        campaign.cases[0]
            .result
            .as_mut()
            .unwrap()
            .welch_analyses
            .clear();

        let report = CombinedCtEvidence::from_reports(campaign, "fixture", etm(), &elf).unwrap();
        assert_eq!(report.verdict, CombinedCtVerdict::Fail);
        fs::remove_dir_all(root).unwrap();
    }
}
