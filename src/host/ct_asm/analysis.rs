#[derive(Debug)]
pub struct FunctionBlock {
    pub symbol: String,
    pub insns: Vec<Insn>,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub offset: u64,
    pub mnemonic: String,
    pub full_line: String,
    pub call_target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub symbol: String,
    pub offset: u64,
    pub mnemonic: String,
    pub line: String,
    pub context: Vec<String>,
}

pub struct Patterns {
    forbidden: Vec<Regex>,
    allowed: Vec<Regex>,
    pub call: Vec<Regex>,
    pub allowed_helpers: Vec<Regex>,
}

impl Patterns {
    pub fn new(
        forbidden: &[&str],
        allowed: &[&str],
        call: &[&str],
        allowed_helpers: &[&str],
        extra_allowed_helpers: &[&str],
    ) -> Result<Self, String> {
        let compile = |items: &[&str], label: &str| {
            items
                .iter()
                .map(|pattern| {
                    Regex::new(pattern)
                        .map_err(|error| format!("bad {label} regex {pattern:?}: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            forbidden: compile(forbidden, "forbidden")?,
            allowed: compile(allowed, "allowed")?,
            call: compile(call, "call")?,
            allowed_helpers: allowed_helpers
                .iter()
                .chain(extra_allowed_helpers)
                .map(|pattern| {
                    Regex::new(pattern)
                        .map_err(|error| format!("bad helper regex {pattern:?}: {error}"))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

pub fn split_blocks(text: &str) -> Vec<FunctionBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<FunctionBlock> = None;
    let mut implicit_index = 0;
    for line in text.lines() {
        if line.is_empty()
            || line.starts_with("Disassembly")
            || line.starts_with(';')
            || line.contains(":\tfile format ")
        {
            continue;
        }
        if let Some(c) = HEADER_RE.captures(line) {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            current = Some(FunctionBlock {
                symbol: c[1].to_string(),
                insns: Vec::new(),
            });
            implicit_index = 0;
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue;
        };
        if let Some(c) = RELOC_RE.captures(line) {
            if let Some(last) = block.insns.last_mut() {
                if last.call_target.is_none() {
                    last.call_target = Some(normalize_target(&c[1]));
                }
            }
            continue;
        }
        if let Some(c) = INSN_RE.captures(line) {
            let offset = c
                .get(1)
                .and_then(|m| u64::from_str_radix(m.as_str(), 16).ok())
                .unwrap_or(implicit_index);
            implicit_index += 1;
            let mnemonic = c[2].to_ascii_lowercase();
            if mnemonic == "..." {
                continue;
            }
            block.insns.push(Insn {
                offset,
                mnemonic,
                full_line: line.trim_end().to_string(),
                call_target: None,
            });
        }
    }
    if let Some(b) = current {
        blocks.push(b);
    }
    blocks
}

/// Scan a function for forbidden mnemonics. Thumb IT is an allowed
/// predication instruction, but never hides a branch inside its window.
pub fn scan_block(
    block: &FunctionBlock,
    patterns: &Patterns,
    thumb_it_blocks: bool,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut recent = VecDeque::with_capacity(3);
    for insn in &block.insns {
        recent.push_back(insn.full_line.clone());
        if recent.len() > 3 {
            recent.pop_front();
        }
        let mnemonic = insn.mnemonic.as_str();
        if thumb_it_blocks && mnemonic.starts_with("it") && mnemonic.len() <= 5 {
            continue;
        }
        if patterns.allowed.iter().any(|p| p.is_match(mnemonic)) {
            continue;
        }
        if patterns.forbidden.iter().any(|p| p.is_match(mnemonic)) {
            out.push(Violation {
                symbol: block.symbol.clone(),
                offset: insn.offset,
                mnemonic: insn.mnemonic.clone(),
                line: insn.full_line.clone(),
                context: recent.iter().cloned().collect(),
            });
        }
    }
    out
}

pub fn compute_reachable_symbols(blocks: &[FunctionBlock], calls: &[Regex]) -> HashSet<String> {
    let by_symbol: HashMap<&str, &FunctionBlock> =
        blocks.iter().map(|b| (b.symbol.as_str(), b)).collect();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<String> = blocks
        .iter()
        .filter(|b| is_positive_fixture(&b.symbol))
        .map(|b| b.symbol.clone())
        .collect();
    while let Some(symbol) = queue.pop_front() {
        if visited.contains(&symbol) {
            continue;
        }
        if let Some(block) = by_symbol.get(symbol.as_str()) {
            for insn in &block.insns {
                if !calls.iter().any(|p| p.is_match(&insn.mnemonic)) {
                    continue;
                }
                let target = insn
                    .call_target
                    .clone()
                    .or_else(|| extract_target(&insn.full_line));
                if let Some(target) = target {
                    if !visited.contains(&target) {
                        queue.push_back(target);
                    }
                }
            }
        }
        visited.insert(symbol);
    }
    visited
}

pub(crate) fn extract_target(line: &str) -> Option<String> {
    TARGET_RE
        .captures(line.trim_end())
        .map(|c| normalize_target(&c[1]))
}

fn normalize_target(raw: &str) -> String {
    let end = raw
        .find(|c: char| matches!(c, '+' | '-' | '@') || c.is_whitespace())
        .unwrap_or(raw.len());
    raw[..end].to_string()
}

pub fn is_allowed_helper(symbol: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|p| p.is_match(symbol))
}
pub fn is_negative_control(symbol: &str) -> bool {
    symbol.starts_with("nct_fix__neg__") || symbol.starts_with("_nct_fix__neg__")
}
pub fn is_positive_fixture(symbol: &str) -> bool {
    symbol.starts_with("ct_fix__") || symbol.starts_with("_ct_fix__")
}

#[derive(Debug, Serialize)]
pub struct ViolationOut {
    pub symbol: String,
    pub offset: String,
    pub insn: String,
    pub context: Vec<String>,
}
impl From<Violation> for ViolationOut {
    fn from(v: Violation) -> Self {
        Self {
            symbol: v.symbol,
            offset: format!("0x{:x}", v.offset),
            insn: v.line.trim().to_string(),
            context: v.context,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WholeSurfaceReport {
    pub target: String,
    pub fixtures_checked: usize,
    pub negative_controls_checked: usize,
    pub helpers_scanned: usize,
    pub helpers_allowlisted: usize,
    pub ct_violations: Vec<ViolationOut>,
    pub helper_violations: Vec<ViolationOut>,
    pub negative_controls_failed_to_trip: Vec<String>,
}
impl WholeSurfaceReport {
    pub fn exit_code(&self) -> i32 {
        (!self.ct_violations.is_empty()
            || !self.helper_violations.is_empty()
            || !self.negative_controls_failed_to_trip.is_empty()) as i32
    }
    pub fn print_human(&self) {
        println!("==== CT-verify report for {} ====", self.target);
        println!(
            "  ct_fix__*       fixtures checked: {}",
            self.fixtures_checked
        );
        println!(
            "  nct_fix__neg__* controls checked: {}",
            self.negative_controls_checked
        );
        println!(
            "  helpers scanned (reachable):      {} ({} allowlisted)",
            self.helpers_scanned, self.helpers_allowlisted
        );
        print_violations("fixture", &self.ct_violations);
        print_violations("helper", &self.helper_violations);
        if self.negative_controls_failed_to_trip.is_empty() {
            println!("  Negative controls tripped:        all ✓");
        } else {
            println!(
                "  Negative controls FAILED to trip: {}  ✗",
                self.negative_controls_failed_to_trip.len()
            );
            for s in &self.negative_controls_failed_to_trip {
                println!("    {s} (expected ≥1 forbidden mnemonic, found 0)");
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LadderReport {
    pub target: String,
    pub ladder_symbols_matched: usize,
    pub ladder_symbols_expected: usize,
    pub ladder_branches_seen: usize,
    pub ladder_branches_allowed: usize,
    pub positive_fixtures_checked: usize,
    pub negative_controls_checked: usize,
    pub negative_controls_tripped: usize,
    pub negative_controls_failed_to_trip: Vec<String>,
    pub ladder_violations: Vec<ViolationOut>,
}

/// One client-owned symbol calibration for an exact structural assembly gate.
///
/// The selector is a regular expression matched against disassembled function
/// symbols. A passing check requires exactly one matching symbol and exactly
/// `expected_branches` forbidden conditional-branch instructions in it.
#[derive(Debug, Clone, Copy)]
pub struct SymbolCalibration {
    pub display_name: &'static str,
    pub selector: &'static str,
    pub expected_branches: usize,
}

#[derive(Debug, Serialize)]
pub struct SymbolCalibrationResult {
    pub display_name: String,
    pub selector: String,
    pub symbols_matched: usize,
    pub expected_branches: usize,
    pub branches_seen: usize,
    pub matched_symbols: Vec<String>,
    pub branch_evidence: Vec<ViolationOut>,
}

impl SymbolCalibrationResult {
    fn passes(&self) -> bool {
        self.symbols_matched == 1 && self.branches_seen == self.expected_branches
    }
}

#[derive(Debug, Serialize)]
pub struct CalibratedSymbolsReport {
    pub target: String,
    pub checks: Vec<SymbolCalibrationResult>,
}

impl CalibratedSymbolsReport {
    pub fn exit_code(&self) -> i32 {
        self.checks.iter().any(|check| !check.passes()) as i32
    }

    pub fn print_human(&self) {
        println!("==== CT calibrated-symbol report for {} ====", self.target);
        for check in &self.checks {
            if check.passes() {
                println!(
                    "  OK: {} — {} conditional branch(es) matches calibration",
                    check.display_name, check.branches_seen
                );
                continue;
            }
            if check.symbols_matched != 1 {
                eprintln!(
                    "  FAIL: {} — selector {:?} matched {} symbols (expected exactly 1)",
                    check.display_name, check.selector, check.symbols_matched
                );
                for symbol in &check.matched_symbols {
                    eprintln!("    {symbol}");
                }
            } else {
                eprintln!(
                    "  FAIL: {} — expected {} conditional branch(es), found {}",
                    check.display_name, check.expected_branches, check.branches_seen
                );
                for branch in &check.branch_evidence {
                    eprintln!("    [{}] {} {}", branch.offset, branch.symbol, branch.insn);
                    for line in &branch.context {
                        eprintln!("        | {}", line.trim());
                    }
                }
            }
        }
    }
}
impl LadderReport {
    pub fn exit_code(&self) -> i32 {
        (self.ladder_symbols_matched != self.ladder_symbols_expected
            || self.positive_fixtures_checked == 0
            || self.negative_controls_checked == 0
            || !self.negative_controls_failed_to_trip.is_empty()
            || !self.ladder_violations.is_empty()) as i32
    }
    pub fn print_human(&self) {
        println!("==== CT ladder report for {} ====", self.target);
        println!(
            "  ladder symbols:      {} (expected {})",
            self.ladder_symbols_matched, self.ladder_symbols_expected
        );
        println!(
            "  branches seen:       {} (allowed per symbol: {})",
            self.ladder_branches_seen, self.ladder_branches_allowed
        );
        println!(
            "  negative controls:   {} of {} tripped",
            self.negative_controls_tripped, self.negative_controls_checked
        );
        for control in &self.negative_controls_failed_to_trip {
            eprintln!("  FAIL: negative control {control} did not trip");
        }
        print_violations("ladder", &self.ladder_violations);
    }
}

fn print_violations(label: &str, values: &[ViolationOut]) {
    if values.is_empty() {
        println!("  Ct violations ({label}):          0  ✓");
    } else {
        println!("  Ct violations ({label}):          {}  ✗", values.len());
        for v in values {
            println!("    [{}] {} {}", v.offset, v.symbol, v.insn);
            for line in &v.context {
                println!("        | {}", line.trim());
            }
        }
    }
}

pub fn negative_failures(seen: &BTreeSet<String>, tripped: &BTreeSet<String>) -> Vec<String> {
    seen.difference(tripped).cloned().collect()
}
