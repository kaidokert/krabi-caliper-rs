// Counted-loop recognition for the whole-surface gate.
//
// A loop over a public bound compiles to a conditional branch that the
// mnemonic scan cannot tell apart from a secret-dependent one. Whole-symbol
// helper allowlists cover those loops only while the helper stays out of
// line; once the optimizer inlines it (routinely at `opt-level = "s"`), the
// loop lands in a scanned symbol. This recogniser accepts a conditional
// branch only when it is the latch or an exit of a loop and every register
// deciding it is either
//
// - an induction register: written inside the loop body only by a constant
//   step (add/sub of an immediate, or load/store base writeback), and
//   actually stepped at least once; or
// - loop-invariant: never written inside the body.
//
// At least one deciding register must be an induction register.
//
// What this does NOT establish: that the counter's initial value or the
// invariant bound is public. `for _ in 0..secret` passes. Those are the
// value-dependent cases the taint and timing layers exist for; this layer
// only stops public-shape loops from drowning out real findings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopIsa {
    Thumb,
    RiscV,
    AArch64,
    X86_64,
    Avr,
}

impl LoopIsa {
    pub fn for_triple(triple: &str) -> Option<Self> {
        if triple.starts_with("thumb") {
            Some(Self::Thumb)
        } else if triple.starts_with("riscv") {
            Some(Self::RiscV)
        } else if triple.starts_with("aarch64") {
            Some(Self::AArch64)
        } else if triple.starts_with("x86_64") {
            Some(Self::X86_64)
        } else if triple.starts_with("avr") {
            Some(Self::Avr)
        } else {
            None
        }
    }
}

/// What a flag-setting (or compare-and-branch) instruction decides on.
struct Decision {
    /// Registers whose values decide the branch.
    regs: Vec<String>,
}

/// Effect of one instruction on one register.
#[derive(Debug, PartialEq, Eq)]
enum Effect {
    Untouched,
    /// Constant step: `add r, r, #k`, base writeback, `inc`, ...
    Step,
    /// Any other write, including call clobbers and undecodable instructions.
    Clobber,
}

static THUMB_REG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(r\d{1,2}|sb|sl|fp|ip|sp|lr|pc)$").unwrap());
static RISCV_REG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(zero|ra|sp|gp|tp|fp|t[0-6]|s\d{1,2}|a[0-7]|x\d{1,2})$").unwrap()
});
static AARCH64_REG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([wx](\d{1,2}|zr)|sp|wsp)$").unwrap());
static X86_REG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^%([a-z0-9]+)$").unwrap());
static AVR_REG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^r(\d{1,2})$").unwrap());
static HEX_IMM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\.[+-]?\d+|(?:0x)?[0-9a-fA-F]+)$").unwrap());

/// Is `block.insns[index]` a conditional branch closing or leaving a counted
/// loop?
pub fn is_counted_loop_branch(block: &FunctionBlock, index: usize, isa: LoopIsa) -> bool {
    let insns = &block.insns;
    let branch = &insns[index];
    let Some(target) = in_function_target(block, branch, isa) else {
        return false;
    };
    let (head, tail) = if target <= branch.offset {
        (target, branch.offset)
    } else {
        // A forward branch counts only as an exit from an enclosing loop:
        // the innermost back edge that spans it and that it jumps past.
        let Some(edge) = insns
            .iter()
            .filter(|i| i.offset > branch.offset && target > i.offset)
            .filter_map(|i| {
                is_branch(isa, &i.mnemonic)
                    .then(|| in_function_target(block, i, isa))
                    .flatten()
                    .filter(|h| *h <= branch.offset)
                    .map(|h| (h, i.offset))
            })
            .min_by_key(|(h, j)| j - h)
        else {
            return false;
        };
        edge
    };
    let body: Vec<&Insn> = insns
        .iter()
        .filter(|i| i.offset >= head && i.offset <= tail)
        .collect();
    let Some(position) = body.iter().position(|i| i.offset == branch.offset) else {
        return false;
    };
    let predicated = it_predicated(isa, insns);
    let Some(decision) = decision(isa, &body[..position], branch, &predicated) else {
        return false;
    };
    if decision.regs.is_empty() {
        return false;
    }
    // With no other branch in the body, every iteration runs it top to bottom,
    // so a counter may move between registers through copies (scratch borrow
    // and restore, AVR pointer round-trips through X/Y/Z). Otherwise only
    // constant steps keep a register a counter.
    let straight_line = body
        .iter()
        .all(|i| i.offset == branch.offset || i.offset == tail || !is_branch(isa, &i.mnemonic));
    let Some(at_branch) = counters_at_branch(isa, &body, &decision.regs, branch.offset, &predicated, straight_line)
    else {
        return false;
    };
    decision.regs.iter().all(|r| at_branch.contains_key(r))
        && decision.regs.iter().any(|r| at_branch[r])
}

/// Registers holding a counter value (loop-entry value of some counter plus
/// constant steps) where the branch reads them, each with whether it was
/// stepped on the way. A register counts only if it again holds a counter value
/// at the back edge, so the set is the greatest fixpoint of one body pass.
/// Loaded data never enters it.
fn counters_at_branch(
    isa: LoopIsa,
    body: &[&Insn],
    decision: &[String],
    branch_offset: u64,
    predicated: &HashSet<u64>,
    straight_line: bool,
) -> Option<HashMap<String, bool>> {
    let mut universe: HashSet<String> = decision.iter().cloned().collect();
    for insn in body {
        universe.extend(operands(isa, insn).iter().filter_map(|o| reg(isa, o)));
        for (d, s) in copy_pairs(isa, insn) {
            universe.insert(d);
            universe.insert(s);
        }
    }
    if isa == LoopIsa::Avr {
        // Pointer and pair operands name registers implicitly.
        universe.extend((0..32).map(|n| std::format!("r{n}")));
    }
    let mut entry = universe.clone();
    loop {
        // Live counter registers and whether each was stepped this pass.
        let mut live: HashMap<String, bool> = entry.iter().map(|r| (r.clone(), false)).collect();
        let mut at_branch = None;
        for insn in body {
            if insn.offset == branch_offset {
                at_branch = Some(live.clone());
            }
            let pairs = if straight_line { copy_pairs(isa, insn) } else { std::vec![] };
            let mut next = live.clone();
            for r in &universe {
                if let Some((_, s)) = pairs.iter().find(|(d, _)| d == r) {
                    match live.get(s) {
                        Some(&stepped) => next.insert(r.clone(), stepped),
                        None => next.remove(r),
                    };
                    continue;
                }
                match effect(isa, insn, r) {
                    Effect::Untouched => {}
                    // A predicated step is conditional, so not a constant one.
                    Effect::Step if predicated.contains(&insn.offset) => {
                        next.remove(r);
                    }
                    Effect::Step => {
                        if let Some(stepped) = next.get_mut(r) {
                            *stepped = true;
                        }
                    }
                    Effect::Clobber => {
                        next.remove(r);
                    }
                }
            }
            live = next;
        }
        let narrowed: HashSet<String> = entry.iter().filter(|r| live.contains_key(*r)).cloned().collect();
        if narrowed.len() == entry.len() {
            // A step after the branch (forward exit ahead of the increment)
            // still moves the counter between iterations.
            return at_branch.map(|mut at| {
                for (r, stepped) in at.iter_mut() {
                    *stepped |= live.get(r).copied().unwrap_or(false);
                }
                at
            });
        }
        entry = narrowed;
    }
}

/// Register-to-register copies as `(dest, source)` pairs.
fn copy_pairs(isa: LoopIsa, insn: &Insn) -> Vec<(String, String)> {
    let m = base_mnemonic(isa, &insn.mnemonic);
    let ops = operands(isa, insn);
    let both = |d: &String, s: &String| Some((reg(isa, d)?, reg(isa, s)?));
    let pair = match (isa, m, ops.as_slice()) {
        (LoopIsa::Thumb, "mov", [d, s])
        | (LoopIsa::RiscV, "mv", [d, s])
        | (LoopIsa::AArch64, "mov", [d, s])
        | (LoopIsa::Avr, "mov", [d, s]) => both(d, s),
        (LoopIsa::X86_64, "movq", [s, d]) => both(d, s),
        (LoopIsa::Avr, "movw", [d, s]) => {
            let (d, s) = (reg(isa, d), reg(isa, s));
            if let (Some(d), Some(s)) = (d, s)
                && let (Some(dh), Some(sh)) = (avr_pair_high(&d), avr_pair_high(&s))
            {
                return std::vec![(d, s), (dh, sh)];
            }
            None
        }
        _ => None,
    };
    pair.into_iter().collect()
}

/// Offsets of Thumb instructions inside an IT window. Their mnemonics carry
/// a condition suffix (`cmpne`, `addne`), so they never match the
/// unconditional forms the flag and step models recognise by name.
fn it_predicated(isa: LoopIsa, insns: &[Insn]) -> HashSet<u64> {
    let mut out = HashSet::new();
    if isa != LoopIsa::Thumb {
        return out;
    }
    let mut remaining = 0usize;
    for insn in insns {
        if remaining > 0 {
            out.insert(insn.offset);
            remaining -= 1;
            continue;
        }
        let m = insn.mnemonic.as_str();
        if let Some(pattern) = m.strip_prefix("it")
            && pattern.len() <= 3
            && pattern.chars().all(|c| c == 't' || c == 'e')
        {
            remaining = 1 + pattern.len();
        }
    }
    out
}

fn operand_text(isa: LoopIsa, insn: &Insn) -> String {
    let rest = INSN_RE
        .captures(&insn.full_line)
        .and_then(|c| c.get(3))
        .map(|m| m.as_str())
        .unwrap_or("");
    let mut text = rest.to_string();
    if let Some(at) = text.find('<') {
        text.truncate(at);
    }
    if let Some(at) = text.find('@') {
        text.truncate(at);
    }
    let comment = match isa {
        LoopIsa::AArch64 => Some("//"),
        LoopIsa::X86_64 => Some("#"),
        LoopIsa::Avr => Some(";"),
        LoopIsa::Thumb | LoopIsa::RiscV => None,
    };
    if let Some(marker) = comment
        && let Some(at) = text.find(marker)
    {
        text.truncate(at);
    }
    text.trim().to_string()
}

/// Split on top-level commas, keeping `[..]`, `{..}` and `(..)` intact.
fn operands(isa: LoopIsa, insn: &Insn) -> Vec<String> {
    let text = operand_text(isa, insn);
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            out.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn base_mnemonic(isa: LoopIsa, mnemonic: &str) -> &str {
    match isa {
        LoopIsa::Thumb => mnemonic
            .strip_suffix(".w")
            .or_else(|| mnemonic.strip_suffix(".n"))
            .unwrap_or(mnemonic),
        LoopIsa::RiscV => mnemonic.strip_prefix("c.").unwrap_or(mnemonic),
        _ => mnemonic,
    }
}

fn is_conditional_branch(isa: LoopIsa, mnemonic: &str) -> bool {
    let m = base_mnemonic(isa, mnemonic);
    match isa {
        LoopIsa::Thumb => matches!(
            m,
            "beq" | "bne" | "bcs" | "bhs" | "bcc" | "blo" | "bmi" | "bpl" | "bvs" | "bvc"
                | "bhi" | "bls" | "bge" | "blt" | "bgt" | "ble" | "cbz" | "cbnz"
        ),
        LoopIsa::RiscV => matches!(
            m,
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "bgt" | "ble" | "bgtu" | "bleu"
                | "beqz" | "bnez" | "blez" | "bgez" | "bltz" | "bgtz"
        ),
        LoopIsa::AArch64 => m.starts_with("b.") || matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz"),
        LoopIsa::X86_64 => m.starts_with('j') && !m.starts_with("jmp"),
        LoopIsa::Avr => m.starts_with("br") && m != "break",
    }
}

/// x86 AT&T mnemonics carry an optional size suffix (`addq`, `cmpl`).
fn x86_base(m: &str) -> &str {
    const BASES: &[&str] = &[
        "add", "sub", "cmp", "test", "inc", "dec", "lea", "mul", "imul", "div", "idiv", "xchg",
        "xadd", "bt", "nop", "ret", "push", "pop",
    ];
    for base in BASES {
        if m == *base {
            return base;
        }
        if let Some(rest) = m.strip_prefix(base)
            && matches!(rest, "b" | "w" | "l" | "q")
        {
            return base;
        }
    }
    m
}

fn is_unconditional_jump(isa: LoopIsa, mnemonic: &str) -> bool {
    let m = base_mnemonic(isa, mnemonic);
    match isa {
        LoopIsa::Thumb | LoopIsa::AArch64 => m == "b",
        LoopIsa::RiscV => m == "j",
        LoopIsa::X86_64 => m.starts_with("jmp"),
        LoopIsa::Avr => matches!(m, "rjmp" | "jmp"),
    }
}

fn is_branch(isa: LoopIsa, mnemonic: &str) -> bool {
    is_conditional_branch(isa, mnemonic) || is_unconditional_jump(isa, mnemonic)
}

/// Offset of the branch target when it lies in the same function.
fn in_function_target(block: &FunctionBlock, insn: &Insn, isa: LoopIsa) -> Option<u64> {
    let raw = if isa == LoopIsa::Avr {
        let reloc = insn.reloc.as_deref()?;
        let (section, offset) = split_symbol_offset(reloc);
        let own = section.strip_prefix(".text.").unwrap_or(section);
        if own != block.symbol.trim_start_matches('_') && own != block.symbol {
            return None;
        }
        return Some(offset);
    } else {
        let captures = TARGET_RE.captures(insn.full_line.trim_end())?;
        captures.get(1)?.as_str().to_string()
    };
    let (symbol, offset) = split_symbol_offset(&raw);
    (symbol == block.symbol).then_some(offset)
}

fn split_symbol_offset(raw: &str) -> (&str, u64) {
    match raw.rfind('+') {
        Some(at) => {
            let offset = raw[at + 1..].trim_start_matches("0x");
            (&raw[..at], u64::from_str_radix(offset, 16).unwrap_or(u64::MAX))
        }
        None => (raw, 0),
    }
}

/// Canonical register name for an operand that is exactly a register.
fn reg(isa: LoopIsa, operand: &str) -> Option<String> {
    let operand = operand.trim().trim_end_matches('!');
    match isa {
        LoopIsa::Thumb => THUMB_REG.is_match(operand).then(|| {
            match operand {
                "sb" => "r9",
                "sl" => "r10",
                "fp" => "r11",
                "ip" => "r12",
                other => other,
            }
            .to_string()
        }),
        LoopIsa::RiscV => RISCV_REG.is_match(operand).then(|| {
            match operand {
                "fp" => "s0",
                other => other,
            }
            .to_string()
        }),
        LoopIsa::AArch64 => AARCH64_REG.is_match(operand).then(|| match operand {
            "sp" | "wsp" => "sp".to_string(),
            other => std::format!("x{}", &other[1..]),
        }),
        LoopIsa::X86_64 => X86_REG
            .captures(operand)
            .and_then(|c| x86_canonical(&c[1]))
            .map(str::to_string),
        LoopIsa::Avr => AVR_REG.is_match(operand).then(|| operand.to_string()),
    }
}

fn x86_canonical(name: &str) -> Option<&'static str> {
    const LEGACY: &[(&str, [&str; 4])] = &[
        ("rax", ["rax", "eax", "ax", "al"]),
        ("rbx", ["rbx", "ebx", "bx", "bl"]),
        ("rcx", ["rcx", "ecx", "cx", "cl"]),
        ("rdx", ["rdx", "edx", "dx", "dl"]),
        ("rsi", ["rsi", "esi", "si", "sil"]),
        ("rdi", ["rdi", "edi", "di", "dil"]),
        ("rbp", ["rbp", "ebp", "bp", "bpl"]),
        ("rsp", ["rsp", "esp", "sp", "spl"]),
    ];
    for (canonical, names) in LEGACY {
        if names.contains(&name) {
            return Some(canonical);
        }
    }
    const NUMBERED: [&str; 8] = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
    NUMBERED.into_iter().find(|base| {
        name.strip_prefix(base)
            .is_some_and(|rest| matches!(rest, "" | "d" | "w" | "b"))
    })
}

fn is_imm(isa: LoopIsa, operand: &str) -> bool {
    match isa {
        LoopIsa::Thumb | LoopIsa::AArch64 => operand.starts_with('#'),
        LoopIsa::X86_64 => operand.starts_with('$'),
        LoopIsa::RiscV | LoopIsa::Avr => {
            let o = operand.trim_start_matches('-');
            HEX_IMM.is_match(o) || o.parse::<i64>().is_ok()
        }
    }
}

/// Caller-saved registers a call may clobber.
fn call_clobbers(isa: LoopIsa) -> &'static [&'static str] {
    match isa {
        LoopIsa::Thumb => &["r0", "r1", "r2", "r3", "r12", "lr"],
        LoopIsa::RiscV => &[
            "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7",
        ],
        LoopIsa::AArch64 => &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "x17", "x18", "x30",
        ],
        LoopIsa::X86_64 => &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        LoopIsa::Avr => &[
            "r0", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r30",
            "r31",
        ],
    }
}

fn is_call(isa: LoopIsa, mnemonic: &str) -> bool {
    let m = base_mnemonic(isa, mnemonic);
    match isa {
        LoopIsa::Thumb => matches!(m, "bl" | "blx"),
        LoopIsa::RiscV => matches!(m, "jal" | "jalr" | "call" | "tail"),
        LoopIsa::AArch64 => matches!(m, "bl" | "blr"),
        LoopIsa::X86_64 => m.starts_with("call"),
        LoopIsa::Avr => matches!(m, "call" | "rcall" | "icall" | "eicall"),
    }
}

// ── Deciding registers ──────────────────────────────────────────────────────

fn decision(
    isa: LoopIsa,
    before: &[&Insn],
    branch: &Insn,
    predicated: &HashSet<u64>,
) -> Option<Decision> {
    let ops = operands(isa, branch);
    let m = base_mnemonic(isa, &branch.mnemonic);
    match isa {
        LoopIsa::RiscV => {
            // Compare-and-branch: every register operand decides.
            let regs = ops[..ops.len().saturating_sub(1)]
                .iter()
                .filter_map(|o| reg(isa, o))
                .filter(|r| r != "zero" && r != "x0")
                .collect();
            Some(Decision { regs })
        }
        LoopIsa::Thumb | LoopIsa::AArch64 if matches!(m, "cbz" | "cbnz") => Some(Decision {
            regs: std::vec![reg(isa, ops.first()?)?],
        }),
        LoopIsa::AArch64 if matches!(m, "tbz" | "tbnz") => None,
        LoopIsa::Avr => avr_decision(before),
        _ => {
            let setter = before.iter().rev().find_map(|i| {
                if predicated.contains(&i.offset) {
                    return Some((FlagRole::Opaque, *i));
                }
                match flags_role(isa, i) {
                    FlagRole::Preserves => None,
                    role => Some((role, *i)),
                }
            });
            match setter? {
                (FlagRole::Sets, insn) => flag_setter_regs(isa, insn),
                _ => None,
            }
        }
    }
}

enum FlagRole {
    Sets,
    Preserves,
    /// Unknown or not modelled; stop and reject.
    Opaque,
}

fn flags_role(isa: LoopIsa, insn: &Insn) -> FlagRole {
    let m = base_mnemonic(isa, &insn.mnemonic);
    if m.starts_with('<') || m == "..." {
        return FlagRole::Opaque;
    }
    if is_call(isa, &insn.mnemonic) {
        return FlagRole::Opaque;
    }
    match isa {
        LoopIsa::Thumb => {
            static SETS: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(
                    r"^(cmp|cmn|tst|teq|(add|sub|adc|sbc|rsb|mov|mvn|and|orr|orn|eor|bic|lsl|lsr|asr|ror|rrx|mul|neg)s)$",
                )
                .unwrap()
            });
            if SETS.is_match(m) {
                FlagRole::Sets
            } else if m.starts_with("msr") {
                FlagRole::Opaque
            } else {
                FlagRole::Preserves
            }
        }
        LoopIsa::AArch64 => {
            static SETS: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(
                    r"^(cmp|cmn|tst|ccmp|ccmn|fcmpe?|fccmpe?|(add|sub|and|bic|neg|ngc|adc|sbc)s|msr|setf\d+|rmif|cfinv|axflag|xaflag)$",
                )
                .unwrap()
            });
            if SETS.is_match(m) {
                FlagRole::Sets
            } else {
                FlagRole::Preserves
            }
        }
        LoopIsa::X86_64 => {
            static PRESERVES: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(
                    r"^(mov[a-z]*|lea[a-z]?|cmov[a-z]+|set[a-z]+|push[a-z]?|pop[a-z]?|nop[a-z]?|not[a-z]?|bswap[a-z]?|xchg[a-z]?|c[wdq]t[a-z]+|cqto|cltd|p(xor|and|andn|or|add[bwdq]|sub[bwdq]|unpck[a-z]+|shuf[a-z]+|insr[bwdq]|extr[bwdq]|alignr|mul[a-z]+|sll[a-z]*|srl[a-z]*|sra[a-z]*|cmpeq[bwdq]|cmpgt[bwdq])|vp[a-z0-9]+|vmov[a-z0-9]+|v?(xor|and|andn|or)p[sd]|v?(unpck|shuf)[a-z]+|prefetch[a-z0-9]*)$",
                )
                .unwrap()
            });
            if m == "popf" || m == "popfq" {
                FlagRole::Opaque
            } else if PRESERVES.is_match(m) {
                FlagRole::Preserves
            } else {
                FlagRole::Sets
            }
        }
        LoopIsa::RiscV | LoopIsa::Avr => FlagRole::Opaque,
    }
}

/// Registers decided on by a flag setter, when it is a form we model.
fn flag_setter_regs(isa: LoopIsa, insn: &Insn) -> Option<Decision> {
    let ops = operands(isa, insn);
    let m = base_mnemonic(isa, &insn.mnemonic);
    let regs_of = |ops: &[String]| -> Option<Vec<String>> {
        ops.iter()
            .map(|o| {
                if is_imm(isa, o) {
                    Some(None)
                } else {
                    reg(isa, o).map(Some)
                }
            })
            .collect::<Option<Vec<_>>>()
            .map(|v| v.into_iter().flatten().collect())
    };
    match isa {
        LoopIsa::Thumb | LoopIsa::AArch64 => match m {
            "cmp" | "cmn" | "tst" => Some(Decision {
                regs: regs_of(&ops)?,
            }),
            "adds" | "subs" => {
                // `subs rD, rS, #k` flags reflect rS ± k; `subs r, #k` and
                // `subs r, r, #k` step r itself.
                let source = match ops.as_slice() {
                    [d, k] if is_imm(isa, k) => d,
                    [_, s, k] if is_imm(isa, k) => s,
                    _ => return None,
                };
                Some(Decision {
                    regs: std::vec![reg(isa, source)?],
                })
            }
            _ => None,
        },
        LoopIsa::X86_64 => {
            match (x86_base(m), ops.as_slice()) {
                ("cmp" | "test", [_, _]) => Some(Decision {
                    regs: regs_of(&ops)?,
                }),
                ("add" | "sub", [k, d]) if is_imm(isa, k) => Some(Decision {
                    regs: std::vec![reg(isa, d)?],
                }),
                ("inc" | "dec", [d]) => Some(Decision {
                    regs: std::vec![reg(isa, d)?],
                }),
                _ => None,
            }
        }
        LoopIsa::RiscV | LoopIsa::Avr => None,
    }
}

/// AVR flags come from a carry chain: `cp/cpi/sub/subi` head, then any
/// number of `cpc/sbc/sbci`, then the branch. Single-instruction counters
/// (`dec`, `inc`, `sbiw`, `adiw`, `tst`) decide on their own register(s).
fn avr_decision(before: &[&Insn]) -> Option<Decision> {
    let isa = LoopIsa::Avr;
    let mut regs = Vec::new();
    for insn in before.iter().rev() {
        let m = insn.mnemonic.as_str();
        let ops = operands(isa, insn);
        match m {
            "cpc" | "sbc" => {
                regs.extend(ops.iter().filter_map(|o| reg(isa, o)));
                continue;
            }
            "sbci" => {
                regs.push(reg(isa, ops.first()?)?);
                continue;
            }
            "cp" | "sub" => {
                regs.extend(ops.iter().filter_map(|o| reg(isa, o)));
            }
            "cpi" | "subi" | "dec" | "inc" | "tst" => {
                regs.push(reg(isa, ops.first()?)?);
            }
            "sbiw" | "adiw" => {
                let low = reg(isa, ops.first()?)?;
                regs.push(avr_pair_high(&low)?);
                regs.push(low);
            }
            "mov" | "movw" | "ldi" | "ld" | "ldd" | "lds" | "st" | "std" | "sts" | "push"
            | "pop" | "in" | "out" | "nop" | "swap" | "lpm" | "elpm"
                if regs.is_empty() =>
            {
                continue;
            }
            _ => return None,
        }
        return Some(Decision { regs });
    }
    None
}

fn avr_pair_high(low: &str) -> Option<String> {
    let n: u8 = low.strip_prefix('r')?.parse().ok()?;
    Some(std::format!("r{}", n + 1))
}

// ── Per-instruction effect on a register ────────────────────────────────────

fn effect(isa: LoopIsa, insn: &Insn, target: &str) -> Effect {
    let m = base_mnemonic(isa, &insn.mnemonic);
    if m.starts_with('<') {
        return Effect::Clobber;
    }
    if is_call(isa, &insn.mnemonic) {
        return if call_clobbers(isa).contains(&target) {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    let ops = operands(isa, insn);
    match isa {
        LoopIsa::Thumb => thumb_effect(m, &ops, target),
        LoopIsa::RiscV => riscv_effect(m, &ops, target),
        LoopIsa::AArch64 => aarch64_effect(m, &ops, target),
        LoopIsa::X86_64 => x86_effect(m, &ops, target),
        LoopIsa::Avr => avr_effect(m, &ops, target),
    }
}

/// Base register of a `[base, ...]!` or `[base], #k` memory operand with
/// writeback, when the writeback step is an immediate.
fn arm_writeback(isa: LoopIsa, ops: &[String]) -> Option<(String, bool)> {
    for (i, op) in ops.iter().enumerate() {
        let Some(inner) = op.strip_prefix('[') else {
            continue;
        };
        let pre = op.ends_with("]!");
        let close = inner.find(']')?;
        let base = reg(isa, inner[..close].split(',').next()?)?;
        let post = !pre && ops.get(i + 1).is_some();
        if pre {
            return Some((base, true));
        }
        if post {
            let step_is_imm = ops.get(i + 1).is_some_and(|k| is_imm(isa, k));
            return Some((base, step_is_imm));
        }
    }
    None
}

fn register_list(isa: LoopIsa, ops: &[String]) -> Vec<String> {
    ops.iter()
        .filter_map(|o| o.strip_prefix('{'))
        .flat_map(|o| o.trim_end_matches('}').split(','))
        .flat_map(|r| expand_range(isa, r.trim()))
        .collect()
}

fn expand_range(isa: LoopIsa, item: &str) -> Vec<String> {
    if let Some((a, b)) = item.split_once('-')
        && let (Some(a), Some(b)) = (reg(isa, a), reg(isa, b))
        && let (Some(a), Some(b)) = (
            a.strip_prefix('r').and_then(|n| n.parse::<u8>().ok()),
            b.strip_prefix('r').and_then(|n| n.parse::<u8>().ok()),
        )
    {
        return (a..=b).map(|n| std::format!("r{n}")).collect();
    }
    reg(isa, item).into_iter().collect()
}

fn thumb_effect(m: &str, ops: &[String], target: &str) -> Effect {
    let isa = LoopIsa::Thumb;
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    // Compares, branches, IT, barriers, hints: no register writes.
    if matches!(m, "cmp" | "cmn" | "tst" | "teq" | "nop" | "dmb" | "dsb" | "isb" | "bkpt")
        || m.starts_with("it")
        || is_branch(isa, m)
    {
        return Effect::Untouched;
    }
    if m == "push" {
        return if target == "sp" { Effect::Step } else { Effect::Untouched };
    }
    if m == "pop" {
        let list = register_list(isa, ops);
        return if target == "sp" {
            Effect::Step
        } else if list.iter().any(|r| r == target) {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    if m.starts_with("ldm") || m.starts_with("stm") {
        let list = register_list(isa, ops);
        if m.starts_with("ldm") && list.iter().any(|r| r == target) {
            return Effect::Clobber;
        }
        let base_wb = ops.first().filter(|o| o.ends_with('!'));
        return match base_wb {
            Some(b) if is(b) => Effect::Step,
            _ => Effect::Untouched,
        };
    }
    if m.starts_with("ldr") || m.starts_with("str") {
        let dests: &[String] = if m.starts_with("ldrd") || m.starts_with("strd") {
            &ops[..ops.len().min(2)]
        } else {
            &ops[..ops.len().min(1)]
        };
        if m.starts_with("ldr") && dests.iter().any(is) {
            return Effect::Clobber;
        }
        return match arm_writeback(isa, ops) {
            Some((base, imm)) if base == target => {
                if imm {
                    Effect::Step
                } else {
                    Effect::Clobber
                }
            }
            _ => Effect::Untouched,
        };
    }
    if matches!(m, "umull" | "umlal" | "smull" | "smlal" | "umaal") {
        return if ops.iter().take(2).any(is) {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let constant_step = matches!(m, "add" | "adds" | "sub" | "subs" | "addw" | "subw")
        && match ops {
            [_, k] => is_imm(isa, k),
            [_, s, k] => is(s) && is_imm(isa, k),
            _ => false,
        };
    if constant_step {
        Effect::Step
    } else {
        Effect::Clobber
    }
}

fn aarch64_effect(m: &str, ops: &[String], target: &str) -> Effect {
    let isa = LoopIsa::AArch64;
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    if matches!(m, "cmp" | "cmn" | "tst" | "ccmp" | "ccmn" | "nop" | "prfm" | "dmb" | "dsb" | "isb")
        || is_branch(isa, m)
        || m == "ret"
    {
        return Effect::Untouched;
    }
    let is_load = m.starts_with("ld");
    let is_store = m.starts_with("st");
    if is_load || is_store {
        let dest_count = if m.starts_with("ldp") || m.starts_with("stp") { 2 } else { 1 };
        if is_load && ops.iter().take(dest_count).any(is) {
            return Effect::Clobber;
        }
        return match arm_writeback(isa, ops) {
            Some((base, imm)) if base == target => {
                if imm {
                    Effect::Step
                } else {
                    Effect::Clobber
                }
            }
            _ => Effect::Untouched,
        };
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let constant_step = matches!(m, "add" | "adds" | "sub" | "subs")
        && matches!(ops, [_, s, k] if is(s) && is_imm(isa, k))
        && ops.len() == 3;
    if constant_step {
        Effect::Step
    } else {
        Effect::Clobber
    }
}

fn riscv_effect(m: &str, ops: &[String], target: &str) -> Effect {
    let isa = LoopIsa::RiscV;
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    if matches!(m, "sb" | "sh" | "sw" | "sd" | "fsw" | "fsd" | "fence" | "nop" | "ret" | "j")
        || is_conditional_branch(isa, m)
        || m.starts_with("sc.")
    {
        return Effect::Untouched;
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let constant_step = matches!(m, "addi" | "addiw")
        && matches!(ops, [_, s, k] if is(s) && is_imm(isa, k));
    if constant_step {
        Effect::Step
    } else {
        Effect::Clobber
    }
}

fn x86_effect(m: &str, ops: &[String], target: &str) -> Effect {
    let isa = LoopIsa::X86_64;
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    let base = x86_base(m);
    if matches!(base, "cmp" | "test" | "bt" | "nop" | "ret")
        || m.starts_with('j')
        || m.starts_with("prefetch")
    {
        return Effect::Untouched;
    }
    if m.starts_with("push") {
        return if target == "rsp" { Effect::Step } else { Effect::Untouched };
    }
    if m.starts_with("pop") {
        if target == "rsp" {
            return Effect::Step;
        }
        return if ops.first().is_some_and(is) { Effect::Clobber } else { Effect::Untouched };
    }
    // Implicit-operand instructions.
    if matches!(base, "mul" | "imul" | "div" | "idiv") && ops.len() <= 1 {
        return if matches!(target, "rax" | "rdx") || ops.first().is_some_and(is) {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    if matches!(m, "cqto" | "cltd" | "cwtd") {
        return if target == "rdx" { Effect::Clobber } else { Effect::Untouched };
    }
    if m.starts_with("rep") || m.starts_with("movs") && ops.is_empty() || m.starts_with("stos") {
        return if matches!(target, "rsi" | "rdi" | "rcx" | "rax") {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    if base == "xchg" || base == "xadd" {
        return if ops.iter().any(is) { Effect::Clobber } else { Effect::Untouched };
    }
    let Some(dest) = ops.last() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let constant_step = match (base, ops) {
        ("add" | "sub", [k, _]) => is_imm(isa, k),
        ("inc" | "dec", [_]) => true,
        ("lea", [mem, _]) => x86_lea_self_step(mem, target),
        _ => false,
    };
    if constant_step {
        Effect::Step
    } else {
        Effect::Clobber
    }
}

/// `lea k(%r), %r`: base only, no index, same register.
fn x86_lea_self_step(mem: &str, target: &str) -> bool {
    let Some(open) = mem.find('(') else {
        return false;
    };
    let inner = mem[open + 1..].trim_end_matches(')');
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    parts.len() == 1 && reg(LoopIsa::X86_64, parts[0]).as_deref() == Some(target)
}

fn avr_effect(m: &str, ops: &[String], target: &str) -> Effect {
    let isa = LoopIsa::Avr;
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    let pointer = |o: &str| -> Option<(&'static str, &'static str)> {
        let o = o.trim_matches(|c| c == '+' || c == '-');
        let o = o.split('+').next()?;
        match o {
            "X" => Some(("r26", "r27")),
            "Y" => Some(("r28", "r29")),
            "Z" => Some(("r30", "r31")),
            _ => None,
        }
    };
    let writeback = |o: &str| o.ends_with('+') || o.starts_with('-');
    let in_pair = |p: (&str, &str)| p.0 == target || p.1 == target;
    // Compares, branches, I/O and SREG bit set/clear (`sec`, `clz`, ...; not
    // `ser`/`clr`, which write a register).
    if matches!(
        m,
        "cp" | "cpc" | "cpi" | "tst" | "nop" | "out" | "sbi" | "cbi" | "wdr" | "bst" | "push"
            | "rjmp" | "jmp" | "ret" | "reti" | "sec" | "clc" | "sen" | "cln" | "sez" | "clz"
            | "sei" | "cli" | "ses" | "cls" | "sev" | "clv" | "set" | "clt" | "seh" | "clh"
    ) || m.starts_with("br")
    {
        return Effect::Untouched;
    }
    if matches!(m, "st" | "std") {
        // `st X+, r` steps the pointer; `std Y+q, r` does not.
        return match ops.first().map(String::as_str) {
            Some(o) if m == "st" && writeback(o) && pointer(o).is_some_and(in_pair) => Effect::Step,
            _ => Effect::Untouched,
        };
    }
    if matches!(m, "sts") {
        return Effect::Untouched;
    }
    if matches!(m, "ld" | "ldd" | "lpm" | "elpm") {
        if ops.first().is_some_and(is) {
            return Effect::Clobber;
        }
        return match ops.get(1).map(String::as_str) {
            Some(o) if m != "ldd" && writeback(o) && pointer(o).is_some_and(in_pair) => {
                Effect::Step
            }
            _ => Effect::Untouched,
        };
    }
    if matches!(m, "mul" | "muls" | "mulsu" | "fmul" | "fmuls" | "fmulsu") {
        return if matches!(target, "r0" | "r1") { Effect::Clobber } else { Effect::Untouched };
    }
    if matches!(m, "movw" | "adiw" | "sbiw") {
        let Some(low) = ops.first().and_then(|o| reg(isa, o)) else {
            return Effect::Clobber;
        };
        let high = avr_pair_high(&low).unwrap_or_default();
        if low != target && high != target {
            return Effect::Untouched;
        }
        return if m == "movw" {
            Effect::Clobber
        } else if ops.get(1).is_some_and(|k| is_imm(isa, k)) {
            Effect::Step
        } else {
            Effect::Clobber
        };
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    // `sbci`'s step depends on the low byte's borrow, itself driven by the
    // counter's own constant step, so a `subi/sbci` pair is still a counter.
    let constant_step = match m {
        "subi" | "sbci" => ops.get(1).is_some_and(|k| is_imm(isa, k)),
        "inc" | "dec" => true,
        _ => false,
    };
    if constant_step {
        Effect::Step
    } else {
        Effect::Clobber
    }
}

#[cfg(test)]
mod counted_loop_tests {
    use super::*;

    fn branches(listing: &str, isa: LoopIsa) -> Vec<(u64, bool)> {
        let blocks = split_blocks(listing);
        let block = &blocks[0];
        block
            .insns
            .iter()
            .enumerate()
            .filter(|(_, i)| is_conditional_branch(isa, &i.mnemonic))
            .map(|(index, i)| (i.offset, is_counted_loop_branch(block, index, isa)))
            .collect()
    }

    #[test]
    fn thumb_immediate_bounded_limb_loop() {
        let listing = "<ct_fix__x>:\n\
            \x20 3a:\tldr.w\tr0, [r6, r2, lsl #2]\n\
            \x20 3e:\tldr.w\tr5, [r1, r2, lsl #2]\n\
            \x20 42:\tadds\tr2, #0x1\n\
            \x20 44:\tcmp\tr2, #0x4\n\
            \x20 46:\teor.w\tr0, r0, r5\n\
            \x20 4a:\torr.w\tr3, r3, r0\n\
            \x20 4e:\tbne\t0x3a <ct_fix__x+0x3a> @ imm = #-0x18\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x4e, true)]);
    }

    #[test]
    fn thumb_writeback_countdown_and_temp_flags() {
        let listing = "<ct_fix__x>:\n\
            \x20 22:\tldrd\tr5, r6, [r2], #8\n\
            \x20 26:\tsubs\tr0, #0x1\n\
            \x20 28:\torr.w\tr3, r3, r6\n\
            \x20 2c:\tbne\t0x22 <ct_fix__x+0x22>\n\
            \x20 30:\tldrb\tr3, [r0], #1\n\
            \x20 34:\tstrb\tr3, [r2, r1]\n\
            \x20 3c:\tsubs\tr1, #0x1\n\
            \x20 3e:\tadds\tr3, r1, #0x1\n\
            \x20 40:\tbne\t0x30 <ct_fix__x+0x30>\n";
        assert_eq!(
            branches(listing, LoopIsa::Thumb),
            [(0x2c, true), (0x40, true)]
        );
    }

    #[test]
    fn thumb_value_driven_loop_is_rejected() {
        // `while x != 0 { x >>= 1 }`: the deciding register is shifted, not stepped.
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tlsrs\tr0, r0, #0x1\n\
            \x20 2:\tadds\tr1, #0x1\n\
            \x20 4:\tcmp\tr0, #0x0\n\
            \x20 6:\tbne\t0x0 <ct_fix__x>\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x6, false)]);
    }

    #[test]
    fn thumb_forward_value_branch_is_rejected() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tcmp\tr0, #0x0\n\
            \x20 2:\tbeq\t0x8 <ct_fix__x+0x8>\n\
            \x20 4:\tmovs\tr0, #0x1\n\
            \x20 8:\tbx\tlr\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x2, false)]);
    }

    #[test]
    fn thumb_call_clobbering_the_counter_is_rejected() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tbl\t0x0 <helper>\n\
            \x20 4:\tadds\tr0, #0x1\n\
            \x20 6:\tcmp\tr0, #0x4\n\
            \x20 8:\tbne\t0x0 <ct_fix__x>\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x8, false)]);
    }

    #[test]
    fn thumb_conditional_counter_update_is_rejected() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tit\tne\n\
            \x20 2:\taddne\tr0, #0x1\n\
            \x20 4:\tcmp\tr0, #0x4\n\
            \x20 6:\tbne\t0x0 <ct_fix__x>\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x6, false)]);
    }

    #[test]
    fn thumb_predicated_compare_decides_the_branch() {
        // `while i < 4 && a[i] != 0`, folded into an IT block: the branch
        // reads `cmpne`'s flags (loaded data), not the counter compare.
        let listing = "<nct_fix__x>:\n\
            \x20 18:\tadds\tr0, #0x1\n\
            \x20 1a:\tcmp\tr0, #0x4\n\
            \x20 1c:\titt\tne\n\
            \x20 1e:\tldrne.w\tr2, [r1, r0, lsl #2]\n\
            \x20 22:\tcmpne\tr2, #0x0\n\
            \x20 24:\tbne\t0x18 <nct_fix__x+0x18>\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x24, false)]);
    }

    #[test]
    fn forward_exit_from_counted_loop_is_accepted_but_not_an_inner_skip() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tcmp\tr2, #0x4\n\
            \x20 2:\tbeq\t0x10 <ct_fix__x+0x10>\n\
            \x20 4:\tldr\tr3, [r1, r2, lsl #2]\n\
            \x20 6:\tcmp\tr3, #0x0\n\
            \x20 8:\tbeq\t0xc <ct_fix__x+0xc>\n\
            \x20 a:\tadds\tr2, #0x1\n\
            \x20 c:\tadds\tr2, #0x0\n\
            \x20 e:\tb\t0x0 <ct_fix__x>\n\
            \x20 10:\tbx\tlr\n";
        assert_eq!(
            branches(listing, LoopIsa::Thumb),
            [(0x2, true), (0x8, false)]
        );
    }

    #[test]
    fn riscv_pointer_loop_and_inner_value_branch() {
        let listing = "<ct_fix__x>:\n\
            \x20 18:\tlw\ta5, 0x4(a0)\n\
            \x20 1a:\tlw\ta1, 0x4(a4)\n\
            \x20 1c:\tbeq\ta5, a1, 0x2a <ct_fix__x+0x2a>\n\
            \x20 20:\tsltu\tt1, a1, a5\n\
            \x20 2a:\tor\tt2, a2, t2\n\
            \x20 2c:\taddi\ta4, a4, -0x8\n\
            \x20 2e:\taddi\ta0, a0, -0x8\n\
            \x20 30:\tbne\ta4, t0, 0x18 <ct_fix__x+0x18>\n";
        assert_eq!(
            branches(listing, LoopIsa::RiscV),
            [(0x1c, false), (0x30, true)]
        );
    }

    #[test]
    fn aarch64_writeback_countdown_and_loaded_flag() {
        let listing = "<ct_fix__x>:\n\
            \x20 10:\tldr\tx9, [x8], #8\n\
            \x20 14:\tsubs\tx10, x10, #1\n\
            \x20 18:\tb.ne\t0x10 <ct_fix__x+0x10>\n\
            \x20 1c:\tldr\tx11, [x8]\n\
            \x20 20:\tcmp\tx11, #0\n\
            \x20 24:\tb.ne\t0x1c <ct_fix__x+0x1c>\n";
        assert_eq!(
            branches(listing, LoopIsa::AArch64),
            [(0x18, true), (0x24, false)]
        );
    }

    #[test]
    fn x86_counted_and_loaded_loops() {
        let listing = "<ct_fix__x>:\n\
            \x20 10:\tmovq\t(%rsi), %rdx\n\
            \x20 13:\taddq\t$0x8, %rsi\n\
            \x20 17:\tdecq\t%rcx\n\
            \x20 1a:\tjne\t0x10 <ct_fix__x+0x10>\n\
            \x20 1c:\tmovq\t(%rsi), %rax\n\
            \x20 1f:\ttestq\t%rax, %rax\n\
            \x20 22:\tjne\t0x1c <ct_fix__x+0x1c>\n";
        assert_eq!(
            branches(listing, LoopIsa::X86_64),
            [(0x1a, true), (0x22, false)]
        );
    }

    #[test]
    fn avr_relocated_pointer_loop_and_loaded_byte() {
        let listing = "<ct_fix__x>:\n\
            \x20 a:\tld\tr24, X+\n\
            \x20 c:\teor\tr18, r24\n\
            \x20 e:\tcp\tr26, r20\n\
            \x20 10:\tcpc\tr27, r21\n\
            \x20 12:\tbrne\t.-2\n\
            \t\t\t00000012:  R_AVR_7_PCREL\t.text.ct_fix__x+0xa\n\
            \x20 14:\tld\tr24, Z\n\
            \x20 16:\tcpi\tr24, 0x0\n\
            \x20 18:\tbrne\t.-2\n\
            \t\t\t00000018:  R_AVR_7_PCREL\t.text.ct_fix__x+0x14\n";
        assert_eq!(
            branches(listing, LoopIsa::Avr),
            [(0x12, true), (0x18, false)]
        );
    }

    const AVR_NOT_LOOP: &str = "<f>:\n\
        \x20 22:\tcp\tr24, r1\n\
        \x20 24:\tcpc\tr25, r1\n\
        \x20 26:\tbreq\t.-2\n\
        \t\t\t00000026:  R_AVR_7_PCREL\t.text.f+0x36\n\
        \x20 28:\tmovw\tr18, r24\n\
        \x20 2a:\tld\tr24, X+\n\
        \x20 2c:\tcom\tr24\n\
        \x20 2e:\tst\tZ+, r24\n\
        \x20 30:\tmovw\tr24, r18\n\
        \x20 32:\tsbiw\tr24, 0x1\n\
        \x20 34:\trjmp\t.-2\n\
        \t\t\t00000034:  R_AVR_13_PCREL\t.text.f+0x22\n\
        \x20 36:\tret\n";

    #[test]
    fn avr_counter_borrowed_as_scratch_and_restored() {
        assert_eq!(branches(AVR_NOT_LOOP, LoopIsa::Avr), [(0x26, true)]);
    }

    #[test]
    fn avr_borrowed_counter_without_restore_is_rejected() {
        // r24 keeps the complemented loaded byte; r25 takes it too.
        let listing = AVR_NOT_LOOP.replace("movw\tr24, r18", "mov\tr25, r24");
        assert_eq!(branches(&listing, LoopIsa::Avr), [(0x26, false)]);
    }

    #[test]
    fn avr_pointer_counter_through_x() {
        // Both cursors round-trip through X; the latch compares X to an end
        // pointer computed before the loop.
        let listing = "<ct_fix__x>:\n\
            \x20 b8:\tmovw\tr26, r22\n\
            \x20 ba:\tld\tr18, X+\n\
            \x20 bc:\tmovw\tr22, r26\n\
            \x20 be:\tld\tr19, Z+\n\
            \x20 c0:\teor\tr19, r18\n\
            \x20 c6:\tmovw\tr26, r20\n\
            \x20 c8:\tst\tX+, r19\n\
            \x20 ca:\tmovw\tr20, r26\n\
            \x20 cc:\tcp\tr26, r24\n\
            \x20 ce:\tcpc\tr27, r25\n\
            \x20 d0:\tbrne\t.-2\n\
            \t\t\t000000d0:  R_AVR_7_PCREL\t.text.ct_fix__x+0xb8\n";
        assert_eq!(branches(listing, LoopIsa::Avr), [(0xd0, true)]);
        // Same loop, but X is reloaded from data before the compare.
        let tainted = listing.replace("movw\tr20, r26", "ld\tr26, Z");
        assert_eq!(branches(&tainted, LoopIsa::Avr), [(0xd0, false)]);
    }

    #[test]
    fn restore_behind_an_internal_branch_is_rejected() {
        // The skip at 0x2e can jump past the restore, so on that path the
        // loaded byte reaches the compare.
        let listing = AVR_NOT_LOOP.replace(
            "\x20 2e:\tst\tZ+, r24\n",
            "\x20 2e:\tbreq\t.-2\n\t\t\t0000002e:  R_AVR_7_PCREL\t.text.f+0x32\n",
        );
        assert_eq!(
            branches(&listing, LoopIsa::Avr),
            [(0x26, false), (0x2e, false)]
        );
    }

    #[test]
    fn avr_multibyte_countdown() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tlsl\tr22\n\
            \x20 2:\trol\tr23\n\
            \x20 4:\tsubi\tr24, 0x1\n\
            \x20 6:\tsbci\tr25, 0x0\n\
            \x20 8:\tbrne\t.-2\n\
            \t\t\t00000008:  R_AVR_7_PCREL\t.text.ct_fix__x\n";
        assert_eq!(branches(listing, LoopIsa::Avr), [(0x8, true)]);
    }

    #[test]
    fn branch_into_another_function_is_not_a_loop() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tadds\tr0, #0x1\n\
            \x20 2:\tcmp\tr0, #0x4\n\
            \x20 4:\tbne\t0x0 <other>\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x4, false)]);
    }
}
