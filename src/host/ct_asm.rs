//! Shared parsing, scanning, reachability and reports for CT assembly gates.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::env;
use std::eprintln;
use std::format;
use std::fs;
use std::path::{Path, PathBuf};
use std::println;
use std::process::{Command, ExitCode};
use std::string::{String, ToString};
use std::sync::LazyLock;
use std::vec::Vec;

use regex::Regex;
use serde::Serialize;

static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^>]+)>:\s*$").unwrap());
static INSN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:([0-9a-fA-F]+):)?\s+(\S+)(?:\s+(.*))?$").unwrap());
static RELOC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s+(?:[0-9a-fA-F]+:)?\s*(?:[A-Z][A-Z0-9_]*_RELOC_[A-Z0-9_]+|R_[A-Z0-9_]+)\s+(\S+)\s*$",
    )
    .unwrap()
});
static TARGET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<([^>]+)>(?:\s+@\s+imm[^<]*)?\s*$").unwrap());

include!("ct_asm/analysis.rs");
include!("ct_asm/driver.rs");
include!("ct_asm/tests.rs");
