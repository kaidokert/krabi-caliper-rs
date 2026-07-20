//! Declarative, fail-closed campaign configuration.
//!
//! This module describes workloads and runner requirements. It does not own
//! repository layout, runner registration, USB topology, or hardware locks.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::format;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;
use std::string::{String, ToString};
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use cargo_metadata::Message;
use serde::{Deserialize, Serialize};

use super::{
    BuildMetadata, CommandError, CommandOutput, CommandRunner, CommandSpec, CompletionAction,
    ElfFootprint, MetricPolicy, RunResult, RunStatus, SourceMetadata, TargetMetadata, parse,
    read_elf_footprint, render_json, render_markdown,
};

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

const fn continue_on_failure() -> bool {
    true
}

include!("campaign/model.rs");
include!("campaign/executor.rs");

#[cfg(test)]
mod tests;
