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
use std::io::{Cursor, Read};
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
#[non_exhaustive]
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
    /// How often a case that ends in a transient status is run again.
    #[serde(default)]
    pub retry: RetryPolicy,
}

/// Re-runs a case whose status is in `on`, up to `attempts` runs in total.
///
/// The default, one attempt, never retries. `on` defaults to `run-failed` and `timed-out`: the
/// statuses a flaky emulator, probe or host process produces. A workload or measurement failure
/// is a result, so retrying it would hide a real failure; list it explicitly only if the fixture
/// itself is known to be nondeterministic. The final attempt's report is kept and records every
/// status it retried past.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct RetryPolicy {
    #[serde(default = "one_attempt")]
    pub attempts: u32,
    #[serde(default = "transient_statuses")]
    pub on: Vec<CaseStatus>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: one_attempt(),
            on: transient_statuses(),
        }
    }
}

impl RetryPolicy {
    /// A policy of `attempts` runs in total, retrying the statuses in `on`.
    pub fn new(attempts: u32, on: Vec<CaseStatus>) -> Self {
        Self { attempts, on }
    }

    /// Whether a report from attempt `attempt` (counting from one) should be run again.
    pub fn retries(&self, attempt: u32, status: CaseStatus) -> bool {
        attempt < self.attempts && self.on.contains(&status)
    }
}

const fn one_attempt() -> u32 {
    1
}

fn transient_statuses() -> Vec<CaseStatus> {
    vec![CaseStatus::RunFailed, CaseStatus::TimedOut]
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
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
include!("campaign/prepared.rs");
include!("campaign/executor.rs");

#[cfg(test)]
mod tests;
