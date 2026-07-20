//! Declarative, fail-closed campaign configuration.
//!
//! This module describes workloads and runner requirements. It does not own
//! repository layout, runner registration, USB topology, or hardware locks.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::format;
use std::path::PathBuf;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use super::CompletionAction;

include!("campaign/config.rs");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CampaignConfig {
    pub profile: String,
    #[serde(default)]
    pub constant_time: Option<ConstantTimeConfig>,
    #[serde(default)]
    pub case_set: Option<String>,
    #[serde(default)]
    pub cases: Vec<CaseConfig>,
    #[serde(default)]
    pub baseline_case: Option<String>,
    #[serde(default)]
    pub matrix: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub matrix_features: Vec<String>,
    #[serde(default = "continue_on_failure")]
    pub continue_on_failure: bool,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CaseConfig {
    pub name: String,
    #[serde(default)]
    pub example: Option<String>,
    #[serde(default)]
    pub binary: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub expected_benchmark: Option<String>,
    #[serde(default)]
    pub expected_suite: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub delay_before_run_seconds: Option<u64>,
    #[serde(default)]
    pub baseline: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "kebab-case")]
pub enum CargoTarget {
    Example(String),
    Binary(String),
}

#[derive(Debug)]
pub enum CampaignConfigError {
    MissingProfile(String),
    InvalidConfig(String),
}

impl fmt::Display for CampaignConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile(value) => write!(formatter, "unknown runner profile {value:?}"),
            Self::InvalidConfig(value) => formatter.write_str(value),
        }
    }
}

impl Error for CampaignConfigError {}

type CampaignError = CampaignConfigError;

const fn continue_on_failure() -> bool {
    true
}

#[cfg(test)]
mod tests;
