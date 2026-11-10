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
//   step (add/sub of an immediate, or load/store base writeback); or
// - loop-invariant: never written inside the body.
//
// Registers are read where the flags are set, not at the branch. At least
// one deciding register must make net nonzero progress per iteration.
//
// A second, narrower rule covers the bit-smear ladder in `subtle`'s primitive
// `ct_gt` (`pow = 1; while pow < BITS { x |= x >> pow; pow += pow }`) and
// Newton precision doubling: see `immediate_doubling_branch`. Unlike a constant
// step, a doubling register is also the shape of a secret normalization loop
// (`while d < n { d <<= 1 }`), so that rule requires every deciding register to
// come from an immediate and never from data.
//
// What the constant-step rule does NOT establish: that the counter's initial
// value or the invariant bound is public. `for _ in 0..secret` passes. Those are the
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
    /// Offset of the instruction that reads them (the flag setter, or the
    /// branch itself for compare-and-branch forms).
    at: u64,
}

/// Effect of one instruction on one register.
#[derive(Debug, PartialEq, Eq)]
enum Effect {
    Untouched,
    /// Constant step: `add r, r, #k`, base writeback, `inc`, ... with its
    /// amount when exact (`None` for carry-dependent high bytes).
    Step(Option<i64>),
    /// Any other write, including call clobbers and undecodable instructions.
    Clobber,
}

/// A register holding some counter's loop-entry value plus a net step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Counter {
    origin: String,
    delta: Option<i64>,
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
    constant_step_branch(block, index, isa) || immediate_doubling_branch(block, index, isa)
}

/// The widest loop in `block`, as the `(head, tail)` offsets of the backward
/// branch that spans the most code. In a ladder this is the loop over the
/// exponent bits.
pub fn outermost_loop(block: &FunctionBlock, isa: LoopIsa) -> Option<(u64, u64)> {
    block
        .insns
        .iter()
        .filter(|i| is_branch(isa, &i.mnemonic))
        .filter_map(|i| {
            in_function_target(block, i, isa)
                .filter(|head| *head <= i.offset)
                .map(|head| (head, i.offset))
        })
        .max_by_key(|(head, tail)| tail - head)
}

/// Where a branch sits relative to a loop `(head, tail)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopRole {
    /// The loop's back edge, at `tail`.
    BackEdge,
    /// Before the loop, jumping to the instruction right after `tail`: the
    /// check that skips a loop with zero iterations.
    Guard,
    /// Inside the loop, jumping out of it.
    Exit,
    /// Inside the loop, staying inside it.
    Body,
    /// Anywhere else.
    Outside,
}

/// The registers that decide the branch at `offset`: its own operands for
/// compare-and-branch forms, otherwise those of the instruction that set the
/// flags it reads. `None` when they cannot be determined.
pub fn branch_operands(block: &FunctionBlock, offset: u64, isa: LoopIsa) -> Option<Vec<String>> {
    let index = block.insns.iter().position(|i| i.offset == offset)?;
    let before: Vec<&Insn> = block.insns[..index].iter().collect();
    let predicated = it_predicated(isa, &block.insns);
    let regs = decision(isa, &before, &block.insns[index], &predicated)?.regs;
    (!regs.is_empty()).then_some(regs)
}

/// Whether no instruction strictly between offsets `after` and `before`
/// writes any of `regs`.
pub fn regs_untouched_between(
    block: &FunctionBlock,
    after: u64,
    before: u64,
    regs: &[String],
    isa: LoopIsa,
) -> bool {
    let mut previous = None;
    for insn in &block.insns {
        if insn.offset > after
            && insn.offset < before
            && regs.iter().any(|r| !matches!(effect(isa, insn, previous, r), Effect::Untouched))
        {
            return false;
        }
        previous = Some(insn);
    }
    true
}

/// The role of the branch at `offset` in the loop `(head, tail)`.
pub fn loop_role(block: &FunctionBlock, offset: u64, (head, tail): (u64, u64), isa: LoopIsa) -> LoopRole {
    let Some(insn) = block.insns.iter().find(|i| i.offset == offset) else {
        return LoopRole::Outside;
    };
    let target = in_function_target(block, insn, isa);
    if offset == tail {
        LoopRole::BackEdge
    } else if offset < head {
        let after_tail = block.insns.iter().map(|i| i.offset).find(|o| *o > tail);
        if target.is_some() && target == after_tail {
            LoopRole::Guard
        } else {
            LoopRole::Outside
        }
    } else if offset > tail {
        LoopRole::Outside
    } else if target.is_none_or(|t| t < head || t > tail) {
        LoopRole::Exit
    } else {
        LoopRole::Body
    }
}

fn constant_step_branch(block: &FunctionBlock, index: usize, isa: LoopIsa) -> bool {
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
    let Some((at, end)) =
        counters_at(isa, &body, &decision.regs, decision.at, &predicated, straight_line)
    else {
        return false;
    };
    let progress = |c: &Counter| {
        end.get(&c.origin).is_some_and(|e| {
            e.origin == c.origin
                && e.delta.is_some_and(|d| if isa == LoopIsa::Avr { d & 0xff != 0 } else { d != 0 })
        })
    };
    decision.regs.iter().all(|r| at.contains_key(r))
        && decision.regs.iter().any(|r| progress(&at[r]))
}

/// Is `block.insns[index]` a conditional branch inside a loop whose every
/// deciding register is a pure function of immediates, stepped only by
/// doubling? Its outcome then cannot depend on data, whatever the rest of the
/// body computes.
fn immediate_doubling_branch(block: &FunctionBlock, index: usize, isa: LoopIsa) -> bool {
    let insns = &block.insns;
    let branch = &insns[index];
    let Some(target) = in_function_target(block, branch, isa) else {
        return false;
    };
    let Some((head, tail)) = innermost_loop(block, branch.offset, target, isa) else {
        return false;
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
    let scan = ImmediateScan { block, isa, head, tail, body: &body, predicated: &predicated };
    !decision.regs.is_empty()
        && !scan.lands_between(decision.at, branch.offset)
        && decision.regs.iter().all(|r| scan.is_immediate_at(r, decision.at, 0))
}

/// The tightest loop holding `offset`: the branch's own back edge, or the
/// tightest back edge spanning it.
fn innermost_loop(
    block: &FunctionBlock,
    offset: u64,
    target: u64,
    isa: LoopIsa,
) -> Option<(u64, u64)> {
    if target <= offset {
        return Some((target, offset));
    }
    block
        .insns
        .iter()
        .filter(|i| i.offset > offset && is_branch(isa, &i.mnemonic))
        .filter_map(|i| {
            in_function_target(block, i, isa)
                .filter(|h| *h <= offset)
                .map(|h| (h, i.offset))
        })
        .min_by_key(|(h, j)| j - h)
}

struct ImmediateScan<'a> {
    block: &'a FunctionBlock,
    isa: LoopIsa,
    head: u64,
    tail: u64,
    body: &'a [&'a Insn],
    predicated: &'a HashSet<u64>,
}

impl ImmediateScan<'_> {
    fn writes(&self, insn: &Insn, previous: Option<&Insn>, target: &str) -> bool {
        !matches!(effect(self.isa, insn, previous, target), Effect::Untouched)
    }

    /// Instructions in the body writing `target`, in order.
    fn body_writes(&self, target: &str) -> Vec<&Insn> {
        let mut out = Vec::new();
        let mut previous = None;
        for insn in self.body {
            if self.writes(insn, previous, target) {
                out.push(*insn);
            }
            previous = Some(*insn);
        }
        out
    }

    /// Does `target` hold an immediate-derived value when `at` reads it?
    fn is_immediate_at(&self, target: &str, at: u64, depth: usize) -> bool {
        // Deeper than any lowering of the shapes this rule exists for.
        if depth > 4 {
            return false;
        }
        let writes = self.body_writes(target);
        let Some(last) = writes.iter().rev().find(|i| i.offset < at) else {
            // No write yet this iteration: invariant, or a doubling counter
            // read before its step. The first read sees `target`'s own pre-loop
            // value and later reads what a leading copy took from its scratch,
            // so both seeds have to be immediates.
            return (writes.is_empty() || self.is_doubling_counter(target))
                && self.loaded_with_immediate(target)
                && self.loaded_with_immediate(&self.seed_register(target));
        };
        if self.is_doubling_counter(target) {
            return self.loaded_with_immediate(&self.seed_register(target));
        }
        self.runs_once_per_iteration(last.offset)
            && !self.predicated.contains(&last.offset)
            && derived_source(self.isa, last, target)
                .is_some_and(|source| self.is_immediate_at(&source, last.offset, depth + 1))
    }

    /// `target`'s only write in the body doubles it (directly, or through a
    /// scratch register), on every iteration.
    fn is_doubling_counter(&self, target: &str) -> bool {
        let writes = self.body_writes(target);
        let [write] = writes.as_slice() else {
            return false;
        };
        if self.predicated.contains(&write.offset) || !self.runs_once_per_iteration(write.offset) {
            return false;
        }
        if doubling_source(self.isa, write, target).as_deref() == Some(target) {
            return true;
        }
        let Some((_, scratch)) =
            copy_pairs(self.isa, write).into_iter().find(|(d, _)| d == target)
        else {
            return false;
        };
        // The doubled value reaches the copy from earlier this iteration, or
        // around the back edge when the copy leads the body.
        let scratch_writes = self.body_writes(&scratch);
        let Some(doubled) = scratch_writes
            .iter()
            .rev()
            .find(|i| i.offset < write.offset)
            .or_else(|| scratch_writes.last())
        else {
            return false;
        };
        !self.predicated.contains(&doubled.offset)
            && self.runs_once_per_iteration(doubled.offset)
            && doubling_source(self.isa, doubled, &scratch).as_deref() == Some(target)
    }

    /// The register whose pre-loop value seeds doubling counter `target`: the
    /// scratch when a leading copy overwrites `target` before anything reads it.
    fn seed_register(&self, target: &str) -> String {
        let writes = self.body_writes(target);
        if let [write] = writes.as_slice()
            && let Some((_, scratch)) =
                copy_pairs(self.isa, write).into_iter().find(|(d, _)| d == target)
            && !self.body_writes(&scratch).iter().any(|i| i.offset < write.offset)
        {
            return scratch;
        }
        target.to_string()
    }

    /// No branch in the body can skip `offset`, or rerun it without taking the
    /// latch. A rerun lets data choose how far a doubling counter has advanced
    /// when the latch reads it.
    fn runs_once_per_iteration(&self, offset: u64) -> bool {
        !self.body.iter().any(|i| {
            if !is_branch(self.isa, &i.mnemonic) {
                return false;
            }
            let target = in_function_target(self.block, i, self.isa);
            if i.offset < offset {
                target.is_none_or(|t| t > offset)
            } else {
                i.offset != self.tail && target.is_some_and(|t| t >= self.head && t <= offset)
            }
        })
    }

    /// Can a branch in the body land after the flag-setting compare at `from`
    /// and reach `to` without running it? `to` would then read stale flags.
    fn lands_between(&self, from: u64, to: u64) -> bool {
        self.body.iter().any(|i| {
            is_branch(self.isa, &i.mnemonic)
                && in_function_target(self.block, i, self.isa).is_none_or(|t| t > from && t <= to)
        })
    }

    /// On the only path into the loop, the last write to `target` before the
    /// head is an immediate load.
    fn loaded_with_immediate(&self, target: &str) -> bool {
        let insns = &self.block.insns;
        let Some(head_at) = insns.iter().position(|i| i.offset == self.head) else {
            return false;
        };
        let load = insns[..head_at].iter().enumerate().rev().find_map(|(at, insn)| {
            if is_branch(self.isa, &insn.mnemonic) {
                return Some(None);
            }
            let previous = at.checked_sub(1).map(|p| &insns[p]);
            self.writes(insn, previous, target).then_some(Some(insn))
        });
        let Some(Some(load)) = load else {
            return false;
        };
        // A jump from outside the loop landing after the load, anywhere up to
        // the latch, enters without it.
        let entered_elsewhere = insns.iter().any(|i| {
            (i.offset < self.head || i.offset > self.tail)
                && is_branch(self.isa, &i.mnemonic)
                && in_function_target(self.block, i, self.isa)
                    .is_none_or(|t| t > load.offset && t <= self.tail)
        });
        !entered_elsewhere && is_immediate_load(self.isa, load, target)
    }
}

fn is_immediate_load(isa: LoopIsa, insn: &Insn, target: &str) -> bool {
    let m = base_mnemonic(isa, &insn.mnemonic);
    let ops = operands(isa, insn);
    let is = |o: &String| reg(isa, o).as_deref() == Some(target);
    match (isa, ops.as_slice()) {
        (LoopIsa::Thumb, [d, k]) => matches!(m, "mov" | "movs" | "movw") && is(d) && is_imm(isa, k),
        (LoopIsa::RiscV, [d, k]) => m == "li" && is(d) && is_imm(isa, k),
        (LoopIsa::AArch64, [d, k]) => m == "mov" && is(d) && is_imm(isa, k),
        (LoopIsa::X86_64, [k, d]) => matches!(m, "movl" | "movq") && is(d) && is_imm(isa, k),
        _ => false,
    }
}

/// The register `insn` doubles into `target`, if that is all it does.
fn doubling_source(isa: LoopIsa, insn: &Insn, target: &str) -> Option<String> {
    let m = base_mnemonic(isa, &insn.mnemonic);
    let ops = operands(isa, insn);
    let regs = |a: &String, b: &String| Some((reg(isa, a)?, reg(isa, b)?));
    let one = |k: &String| imm_value(isa, k) == Some(1);
    let (dest, source) = match (isa, ops.as_slice()) {
        (LoopIsa::Thumb, [d, s, k]) if matches!(m, "lsl" | "lsls") && one(k) => regs(d, s)?,
        (LoopIsa::Thumb, [d, k]) if matches!(m, "lsl" | "lsls") && one(k) => regs(d, d)?,
        (LoopIsa::Thumb, [d, a, b]) if matches!(m, "add" | "adds") => {
            let (a, b) = regs(a, b)?;
            if a != b {
                return None;
            }
            (reg(isa, d)?, a)
        }
        (LoopIsa::Thumb, [d, a]) if matches!(m, "add" | "adds") => {
            let (d, a) = regs(d, a)?;
            if d != a {
                return None;
            }
            (d, a)
        }
        (LoopIsa::AArch64, [d, s, k]) if m == "lsl" && one(k) => regs(d, s)?,
        (LoopIsa::RiscV, [d, s, k]) if m == "slli" && one(k) => regs(d, s)?,
        (LoopIsa::RiscV, [d, k]) if m == "slli" && one(k) => regs(d, d)?,
        (LoopIsa::RiscV, [d, a]) if m == "add" => {
            let (d, a) = regs(d, a)?;
            if d != a {
                return None;
            }
            (d, a)
        }
        (LoopIsa::AArch64 | LoopIsa::RiscV, [d, a, b]) if m == "add" => {
            let (a, b) = regs(a, b)?;
            if a != b {
                return None;
            }
            (reg(isa, d)?, a)
        }
        (LoopIsa::X86_64, [a, d]) if x86_base(m) == "add" => {
            let (a, d) = regs(a, d)?;
            if a != d {
                return None;
            }
            (d, a)
        }
        (LoopIsa::X86_64, [d]) if matches!(m, "shll" | "shlq") => regs(d, d)?,
        (LoopIsa::X86_64, [a, d]) if matches!(m, "leal" | "leaq") => {
            let (a, b) = a.strip_prefix("(")?.strip_suffix(")")?.split_once(',')?;
            let (a, b) = (reg(isa, a)?, reg(isa, b)?);
            if a != b {
                return None;
            }
            (reg(isa, d)?, a)
        }
        _ => return None,
    };
    (dest == target).then_some(source)
}

/// The register a shift-amount lowering computes `target` from, with only
/// immediates otherwise. RISC-V materializes `(n & 63) - 32` to choose a
/// double-word shift arm; no other ISA branches on it.
fn derived_source(isa: LoopIsa, insn: &Insn, target: &str) -> Option<String> {
    if isa != LoopIsa::RiscV {
        return None;
    }
    let m = base_mnemonic(isa, &insn.mnemonic);
    match operands(isa, insn).as_slice() {
        [d, s, k]
            if matches!(m, "andi" | "addi")
                && reg(isa, d).as_deref() == Some(target)
                && is_imm(isa, k) =>
        {
            reg(isa, s)
        }
        _ => None,
    }
}

/// Registers holding a counter value where the decision reads them, and at
/// the back edge. A register counts only if it again holds a counter value
/// at the back edge, so the set is the greatest fixpoint of one body pass.
/// Loaded data never enters it.
fn counters_at(
    isa: LoopIsa,
    body: &[&Insn],
    decision: &[String],
    decide_at: u64,
    predicated: &HashSet<u64>,
    straight_line: bool,
) -> Option<(HashMap<String, Counter>, HashMap<String, Counter>)> {
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
        let mut live: HashMap<String, Counter> = entry
            .iter()
            .map(|r| (r.clone(), Counter { origin: r.clone(), delta: Some(0) }))
            .collect();
        let mut at_decision = None;
        let mut previous: Option<&Insn> = None;
        for insn in body {
            if insn.offset == decide_at {
                at_decision = Some(live.clone());
            }
            let pairs = if straight_line { copy_pairs(isa, insn) } else { std::vec![] };
            let mut next = live.clone();
            for r in &universe {
                if let Some((_, s)) = pairs.iter().find(|(d, _)| d == r) {
                    match live.get(s) {
                        Some(c) => next.insert(r.clone(), c.clone()),
                        None => next.remove(r),
                    };
                    continue;
                }
                match effect(isa, insn, previous, r) {
                    Effect::Untouched => {}
                    // A predicated step is conditional, so not a constant one.
                    Effect::Step(_) if predicated.contains(&insn.offset) => {
                        next.remove(r);
                    }
                    Effect::Step(k) => {
                        if let Some(c) = next.get_mut(r) {
                            c.delta = c.delta.zip(k).map(|(d, k)| d.wrapping_add(k));
                        }
                    }
                    Effect::Clobber => {
                        next.remove(r);
                    }
                }
            }
            live = next;
            previous = Some(insn);
        }
        let narrowed: HashSet<String> =
            entry.iter().filter(|r| live.contains_key(*r)).cloned().collect();
        if narrowed.len() == entry.len() {
            return at_decision.map(|at| (at, live));
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
    const LEGACY: &[(&str, &[&str])] = &[
        ("rax", &["rax", "eax", "ax", "al", "ah"]),
        ("rbx", &["rbx", "ebx", "bx", "bl", "bh"]),
        ("rcx", &["rcx", "ecx", "cx", "cl", "ch"]),
        ("rdx", &["rdx", "edx", "dx", "dl", "dh"]),
        ("rsi", &["rsi", "esi", "si", "sil"]),
        ("rdi", &["rdi", "edi", "di", "dil"]),
        ("rbp", &["rbp", "ebp", "bp", "bpl"]),
        ("rsp", &["rsp", "esp", "sp", "spl"]),
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

/// Value of an immediate operand, when it is one.
fn imm_value(isa: LoopIsa, operand: &str) -> Option<i64> {
    if !is_imm(isa, operand) {
        return None;
    }
    let o = operand.trim_start_matches(['#', '$']);
    let (negative, o) = match o.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, o),
    };
    let magnitude = match o.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()? as i64,
        None => o.parse::<i64>().ok()?,
    };
    Some(if negative { magnitude.wrapping_neg() } else { magnitude })
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
    let on_branch = |regs| Some(Decision { regs, at: branch.offset });
    match isa {
        LoopIsa::RiscV => {
            // Compare-and-branch: every register operand decides.
            let regs = ops[..ops.len().saturating_sub(1)]
                .iter()
                .filter_map(|o| reg(isa, o))
                .filter(|r| r != "zero" && r != "x0")
                .collect();
            on_branch(regs)
        }
        LoopIsa::Thumb | LoopIsa::AArch64 if matches!(m, "cbz" | "cbnz") => {
            on_branch(std::vec![reg(isa, ops.first()?)?])
        }
        LoopIsa::AArch64 if matches!(m, "tbz" | "tbnz") => None,
        LoopIsa::X86_64 if matches!(m, "jcxz" | "jecxz" | "jrcxz") => {
            on_branch(std::vec!["rcx".to_string()])
        }
        LoopIsa::Avr => avr_decision(before, m),
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
                (FlagRole::Sets, insn) if setter_covers(isa, insn, m) => Some(Decision {
                    regs: flag_setter_regs(isa, insn)?,
                    at: insn.offset,
                }),
                _ => None,
            }
        }
    }
}

/// Does `setter` write every flag `branch` reads? x86 `inc`/`dec` leave CF
/// alone; Thumb `tst`/`teq` leave V (and C, unless shifting).
fn setter_covers(isa: LoopIsa, setter: &Insn, branch: &str) -> bool {
    let m = base_mnemonic(isa, &setter.mnemonic);
    match isa {
        LoopIsa::X86_64 if matches!(x86_base(m), "inc" | "dec") => !matches!(
            branch,
            "jb" | "jc" | "jnae" | "jae" | "jnb" | "jnc" | "ja" | "jnbe" | "jbe" | "jna"
        ),
        LoopIsa::Thumb if matches!(m, "tst" | "teq") => {
            matches!(branch, "beq" | "bne" | "bmi" | "bpl")
        }
        _ => true,
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
fn flag_setter_regs(isa: LoopIsa, insn: &Insn) -> Option<Vec<String>> {
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
            "cmp" | "cmn" | "tst" => regs_of(&ops),
            "adds" | "subs" => {
                // `subs rD, rS, #k` flags reflect rS ± k; `subs r, #k` and
                // `subs r, r, #k` step r itself.
                let source = match ops.as_slice() {
                    [d, k] if is_imm(isa, k) => d,
                    [_, s, k] if is_imm(isa, k) => s,
                    _ => return None,
                };
                Some(std::vec![reg(isa, source)?])
            }
            _ => None,
        },
        LoopIsa::X86_64 => match (x86_base(m), ops.as_slice()) {
            ("cmp" | "test", [_, _]) => regs_of(&ops),
            ("add" | "sub", [k, d]) if is_imm(isa, k) => Some(std::vec![reg(isa, d)?]),
            ("inc" | "dec", [d]) => Some(std::vec![reg(isa, d)?]),
            _ => None,
        },
        LoopIsa::RiscV | LoopIsa::Avr => None,
    }
}

/// AVR flags come from a carry chain: `cp/cpi/sub/subi` head, then any
/// number of `cpc/sbc/sbci`, then the branch. Single-instruction counters
/// (`dec`, `inc`, `sbiw`, `adiw`, `tst`) decide on their own register(s);
/// `inc`/`dec`/`tst` leave C and H alone, so carry branches after them are
/// rejected.
fn avr_decision(before: &[&Insn], branch: &str) -> Option<Decision> {
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
            "dec" | "inc" | "tst"
                if regs.is_empty()
                    && matches!(branch, "brcs" | "brcc" | "brlo" | "brsh" | "brhs" | "brhc") =>
            {
                return None;
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
        return Some(Decision { regs, at: insn.offset });
    }
    None
}

fn avr_pair_high(low: &str) -> Option<String> {
    let n: u8 = low.strip_prefix('r')?.parse().ok()?;
    Some(std::format!("r{}", n + 1))
}

// ── Per-instruction effect on a register ────────────────────────────────────

fn effect(isa: LoopIsa, insn: &Insn, previous: Option<&Insn>, target: &str) -> Effect {
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
        LoopIsa::Avr => avr_effect(m, &ops, previous, target),
    }
}

/// Base register of a `[base, #k]!` or `[base], #k` memory operand with
/// writeback, and the step when it is an immediate.
fn arm_writeback(isa: LoopIsa, ops: &[String]) -> Option<(String, Option<i64>)> {
    for (i, op) in ops.iter().enumerate() {
        let Some(inner) = op.strip_prefix('[') else {
            continue;
        };
        let close = inner.find(']')?;
        let mut parts = inner[..close].split(',').map(str::trim);
        let base = reg(isa, parts.next()?)?;
        if op.ends_with("]!") {
            let rest: Vec<&str> = parts.collect();
            let step = match rest.as_slice() {
                [] => Some(0),
                [k] => imm_value(isa, k),
                _ => None,
            };
            return Some((base, step));
        }
        if let Some(k) = ops.get(i + 1) {
            return Some((base, imm_value(isa, k)));
        }
    }
    None
}

/// Writeback through `base` as an effect on `target`.
fn writeback_effect(writeback: Option<(String, Option<i64>)>, target: &str) -> Effect {
    match writeback {
        Some((base, Some(k))) if base == target => Effect::Step(Some(k)),
        Some((base, None)) if base == target => Effect::Clobber,
        _ => Effect::Untouched,
    }
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
    let list_bytes = || 4 * register_list(isa, ops).len() as i64;
    if m == "push" {
        return if target == "sp" { Effect::Step(Some(-list_bytes())) } else { Effect::Untouched };
    }
    if m == "pop" {
        let list = register_list(isa, ops);
        return if target == "sp" {
            Effect::Step(Some(list_bytes()))
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
        let descending = m.ends_with("db") || m.ends_with("da") || m == "stmfd";
        return match base_wb {
            Some(b) if is(b) => {
                Effect::Step(Some(if descending { -list_bytes() } else { list_bytes() }))
            }
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
        return writeback_effect(arm_writeback(isa, ops), target);
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
    let step = match (m, ops) {
        ("add" | "adds" | "addw", [_, k]) => imm_value(isa, k),
        ("add" | "adds" | "addw", [_, s, k]) if is(s) => imm_value(isa, k),
        ("sub" | "subs" | "subw", [_, k]) => imm_value(isa, k).map(i64::wrapping_neg),
        ("sub" | "subs" | "subw", [_, s, k]) if is(s) => imm_value(isa, k).map(i64::wrapping_neg),
        _ => None,
    };
    step.map_or(Effect::Clobber, |k| Effect::Step(Some(k)))
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
        return writeback_effect(arm_writeback(isa, ops), target);
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let step = match (m, ops) {
        ("add" | "adds", [_, s, k]) if is(s) => imm_value(isa, k),
        ("sub" | "subs", [_, s, k]) if is(s) => imm_value(isa, k).map(i64::wrapping_neg),
        _ => None,
    };
    step.map_or(Effect::Clobber, |k| Effect::Step(Some(k)))
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
    let step = match (m, ops) {
        ("addi" | "addiw", [_, s, k]) if is(s) => imm_value(isa, k),
        _ => None,
    };
    step.map_or(Effect::Clobber, |k| Effect::Step(Some(k)))
}

/// x86 string instructions, which step `rsi`/`rdi` (and `rcx` under `rep`)
/// whether or not objdump prints their operands.
static X86_STRING_OP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(movs|lods|stos|scas|cmps|ins|outs)[bwlq]?$").unwrap());

/// Registers written implicitly, beyond any explicit destination.
fn x86_implicit_writes(m: &str) -> &'static [&'static str] {
    let base = m.trim_end_matches(['b', 'w', 'l', 'q']);
    match m {
        "cqto" | "cltd" | "cwtd" => &["rdx"],
        "cltq" | "cwtl" | "cbtw" | "lahf" | "xlat" | "xlatb" => &["rax"],
        "cpuid" => &["rax", "rbx", "rcx", "rdx"],
        "rdtsc" | "rdpmc" => &["rax", "rdx"],
        "rdtscp" => &["rax", "rcx", "rdx"],
        "syscall" => &["rax", "rcx", "r11"],
        "leave" | "leaveq" => &["rsp", "rbp"],
        "cmpxchg8b" | "cmpxchg16b" => &["rax", "rdx"],
        _ if base == "cmpxchg" => &["rax"],
        _ => &[],
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
        return if target == "rsp" { Effect::Step(Some(-8)) } else { Effect::Untouched };
    }
    if m.starts_with("pop") {
        if target == "rsp" {
            return Effect::Step(Some(8));
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
    if m.starts_with("rep") || X86_STRING_OP.is_match(m) {
        return if matches!(target, "rsi" | "rdi" | "rcx" | "rax") {
            Effect::Clobber
        } else {
            Effect::Untouched
        };
    }
    if x86_implicit_writes(m).contains(&target) {
        return Effect::Clobber;
    }
    if base == "xchg" || base == "xadd" {
        return if ops.iter().any(is) { Effect::Clobber } else { Effect::Untouched };
    }
    let Some(dest) = ops.last() else {
        // Operand-less forms not modelled above may write registers.
        let silent = matches!(
            m,
            "nop" | "ret" | "retq" | "endbr64" | "ud2" | "int3" | "hlt" | "pause" | "lfence"
                | "mfence" | "sfence" | "clc" | "stc" | "cmc" | "cld" | "std" | "vzeroupper"
        ) || !x86_implicit_writes(m).is_empty();
        return if silent { Effect::Untouched } else { Effect::Clobber };
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    let step = match (base, ops) {
        ("add", [k, _]) => imm_value(isa, k),
        ("sub", [k, _]) => imm_value(isa, k).map(i64::wrapping_neg),
        ("inc", [_]) => Some(1),
        ("dec", [_]) => Some(-1),
        ("lea", [mem, _]) => x86_lea_self_step(mem, target),
        _ => None,
    };
    step.map_or(Effect::Clobber, |k| Effect::Step(Some(k)))
}

/// `lea k(%r), %r`: base only, no index, same register; returns `k`.
fn x86_lea_self_step(mem: &str, target: &str) -> Option<i64> {
    let open = mem.find('(')?;
    let inner = mem[open + 1..].trim_end_matches(')');
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    if parts.len() != 1 || reg(LoopIsa::X86_64, parts[0]).as_deref() != Some(target) {
        return None;
    }
    let displacement = mem[..open].trim();
    if displacement.is_empty() {
        Some(0)
    } else {
        imm_value(LoopIsa::X86_64, &std::format!("${displacement}"))
    }
}

fn avr_effect(m: &str, ops: &[String], previous: Option<&Insn>, target: &str) -> Effect {
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
    // Post-increment / pre-decrement: the low byte moves by exactly one, the
    // high byte only on carry.
    let pointer_step = |o: &str| -> Effect {
        let Some((low, high)) = pointer(o) else {
            return Effect::Untouched;
        };
        let k = if o.ends_with('+') {
            1
        } else if o.starts_with('-') {
            -1
        } else {
            return Effect::Untouched;
        };
        if target == low {
            Effect::Step(Some(k))
        } else if target == high {
            Effect::Step(None)
        } else {
            Effect::Untouched
        }
    };
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
        return match ops.first() {
            Some(o) if m == "st" => pointer_step(o),
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
        return match ops.get(1) {
            Some(o) if m != "ldd" => pointer_step(o),
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
        let k = match m {
            "adiw" => ops.get(1).and_then(|k| imm_value(isa, k)),
            "sbiw" => ops.get(1).and_then(|k| imm_value(isa, k)).map(i64::wrapping_neg),
            _ => None,
        };
        return match k {
            Some(k) if target == low => Effect::Step(Some(k)),
            Some(_) => Effect::Step(None),
            None => Effect::Clobber,
        };
    }
    let Some(dest) = ops.first() else {
        return Effect::Untouched;
    };
    if !is(dest) {
        return Effect::Untouched;
    }
    match m {
        "subi" => ops
            .get(1)
            .and_then(|k| imm_value(isa, k))
            .map_or(Effect::Clobber, |k| Effect::Step(Some(k.wrapping_neg()))),
        "inc" => Effect::Step(Some(1)),
        "dec" => Effect::Step(Some(-1)),
        // `sbci` steps by its immediate plus the borrow in, so it is a counter
        // step only when that borrow comes from the same counter's next-lower
        // byte (`subi`/`sbci` directly before, one register down).
        "sbci" => {
            let chained = previous.is_some_and(|p| {
                matches!(p.mnemonic.as_str(), "subi" | "sbci")
                    && operands(isa, p)
                        .first()
                        .and_then(|o| reg(isa, o))
                        .and_then(|lower| avr_pair_high(&lower))
                        .as_deref()
                        == Some(target)
            });
            if chained && ops.get(1).is_some_and(|k| is_imm(isa, k)) {
                Effect::Step(None)
            } else {
                Effect::Clobber
            }
        }
        _ => Effect::Clobber,
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

    // Doubling counters: `subtle`'s primitive `ct_gt` ladder and Newton precision.

    #[test]
    fn doubling_ladder_from_immediate_is_accepted() {
        let thumb = "<ct_fix__x>:\n\
            \x20 54:\tmovs\tr5, #0x1\n\
            \x20 58:\tand\tr2, r5, #0x3f\n\
            \x20 5c:\tlsls\tr5, r5, #0x1\n\
            \x20 66:\tlsr.w\tr8, r9, r2\n\
            \x20 80:\torr.w\tr9, r9, r8\n\
            \x20 86:\tcmp\tr5, #0x40\n\
            \x20 88:\tblt\t0x58 <ct_fix__x+0x58> @ imm = #-0x34\n";
        assert_eq!(branches(thumb, LoopIsa::Thumb), [(0x88, true)]);
        let aarch64 = "<ct_fix__x>:\n\
            \x20 20:\tmov\tw8, #0x1                // =1\n\
            \x20 30:\tlsr\tx10, x9, x8\n\
            \x20 34:\tlsl\tw8, w8, #1\n\
            \x20 38:\tcmp\tw8, #0x40\n\
            \x20 3c:\torr\tx9, x10, x9\n\
            \x20 40:\tb.lt\t0x30 <ct_fix__x+0x30>\n";
        assert_eq!(branches(aarch64, LoopIsa::AArch64), [(0x40, true)]);
        let x86 = "<ct_fix__x>:\n\
            \x20 2d:\tmovl\t$0x1, %ecx\n\
            \x20 32:\tmovq\t%rax, %rdx\n\
            \x20 35:\tshrq\t%cl, %rax\n\
            \x20 38:\torq\t%rdx, %rax\n\
            \x20 3b:\taddl\t%ecx, %ecx\n\
            \x20 3d:\tcmpl\t$0x40, %ecx\n\
            \x20 40:\tjl\t0x32 <ct_fix__x+0x32>\n";
        assert_eq!(branches(x86, LoopIsa::X86_64), [(0x40, true)]);
        for step in ["c.slli\ta0, 0x1", "c.add\ta0, a0"] {
            let compressed = std::format!(
                "<ct_fix__x>:\n\
                \x20 00:\tli\ta0, 0x1\n\
                \x20 02:\tli\ta3, 0x40\n\
                \x20 04:\t{step}\n\
                \x20 06:\tblt\ta0, a3, 0x4 <ct_fix__x+0x4>\n"
            );
            assert_eq!(branches(&compressed, LoopIsa::RiscV), [(0x6, true)]);
        }
    }

    #[test]
    fn riscv_double_word_shift_arm_on_counter_is_accepted() {
        let listing = "<ct_fix__x>:\n\
            \x20 98:\tli\ta0, 0x1\n\
            \x20 9c:\tli\ta3, 0x40\n\
            \x20 a0:\tandi\ta5, a0, 0x3f\n\
            \x20 a4:\taddi\ta4, a5, -0x20\n\
            \x20 a8:\tbltz\ta4, 0xb2 <ct_fix__x+0xb2>\n\
            \x20 ac:\tsrl\ta5, s1, a5\n\
            \x20 b0:\tj\t0xc4 <ct_fix__x+0xc4>\n\
            \x20 b2:\tsrl\ts0, a1, a0\n\
            \x20 c2:\tor\ta5, a5, s0\n\
            \x20 ca:\tor\ta1, a1, a5\n\
            \x20 ce:\tslli\ta0, a0, 0x1\n\
            \x20 d2:\tblt\ta0, a3, 0xa0 <ct_fix__x+0xa0>\n";
        assert_eq!(
            branches(listing, LoopIsa::RiscV),
            [(0xa8, true), (0xd2, true)]
        );
    }

    #[test]
    fn doubling_through_scratch_register_is_accepted() {
        let listing = "<ct_fix__x>:\n\
            \x20 18:\tmovs\tr2, #0x1\n\
            \x20 1a:\tumull\tr3, r0, r1, r8\n\
            \x20 36:\tcmp\tr2, #0x20\n\
            \x20 38:\tmla\tr4, r0, r1, r3\n\
            \x20 3c:\tlsl.w\tr0, r2, #0x1\n\
            \x20 40:\tmov\tr1, r5\n\
            \x20 42:\tmov\tr2, r0\n\
            \x20 44:\tblo\t0x1a <ct_fix__x+0x1a> @ imm = #-0x2e\n";
        assert_eq!(branches(listing, LoopIsa::Thumb), [(0x44, true)]);
    }

    #[test]
    fn newton_precision_lowerings_are_accepted() {
        let x86 = "<ct_fix__x>:\n\
            \x20 15:\tmovl\t$0x1, %eax\n\
            \x20 1a:\tmovq\t%r12, %rcx\n\
            \x20 20:\timulq\t%r14, %rdx\n\
            \x20 31:\tleaq\t(%rax,%rax), %rcx\n\
            \x20 35:\tcmpq\t$0x20, %rax\n\
            \x20 39:\tmovq\t%rcx, %rax\n\
            \x20 3c:\tjb\t0x1a <ct_fix__x+0x1a>\n";
        assert_eq!(branches(x86, LoopIsa::X86_64), [(0x3c, true)]);
        // The copy leads the body and the scratch is data until the last write.
        let riscv = "<ct_fix__x>:\n\
            \x20 1e:\tli\ta7, 0x20\n\
            \x20 22:\tli\ta4, 0x1\n\
            \x20 24:\tmv\ta5, a4\n\
            \x20 26:\tmulhu\ta4, a0, s0\n\
            \x20 34:\tmul\ta4, a0, s0\n\
            \x20 3e:\tsub\ta4, a6, a4\n\
            \x20 60:\tslli\ta4, a5, 0x1\n\
            \x20 64:\tbltu\ta5, a7, 0x24 <ct_fix__x+0x24>\n";
        assert_eq!(branches(riscv, LoopIsa::RiscV), [(0x64, true)]);
    }

    #[test]
    fn rotated_copy_needs_doubling_and_immediate_seed() {
        // The scratch is seeded from memory.
        let loaded = "<ct_fix__x>:\n\
            \x20 1e:\tli\ta7, 0x20\n\
            \x20 22:\tlw\ta4, 0x0(a0)\n\
            \x20 24:\tmv\ta5, a4\n\
            \x20 60:\tslli\ta4, a5, 0x1\n\
            \x20 64:\tbltu\ta5, a7, 0x24 <ct_fix__x+0x24>\n";
        assert_eq!(branches(loaded, LoopIsa::RiscV), [(0x64, false)]);
        // The scratch's last write is data, so the counter is loaded each pass.
        let data = "<ct_fix__x>:\n\
            \x20 1e:\tli\ta7, 0x20\n\
            \x20 22:\tli\ta4, 0x1\n\
            \x20 24:\tmv\ta5, a4\n\
            \x20 60:\tslli\ta4, a5, 0x1\n\
            \x20 62:\tlw\ta4, 0x0(a0)\n\
            \x20 64:\tbltu\ta5, a7, 0x24 <ct_fix__x+0x24>\n";
        assert_eq!(branches(data, LoopIsa::RiscV), [(0x64, false)]);
        let lea_mixed = "<ct_fix__x>:\n\
            \x20 15:\tmovl\t$0x1, %eax\n\
            \x20 1a:\tmovq\t(%rdi), %rdx\n\
            \x20 31:\tleaq\t(%rax,%rdx), %rcx\n\
            \x20 35:\tcmpq\t$0x20, %rax\n\
            \x20 39:\tmovq\t%rcx, %rax\n\
            \x20 3c:\tjb\t0x1a <ct_fix__x+0x1a>\n";
        assert_eq!(branches(lea_mixed, LoopIsa::X86_64), [(0x3c, false)]);
    }

    #[test]
    fn secret_normalization_loops_are_rejected() {
        // `while d < n { d <<= 1 }` with `d` loaded: the classic division and
        // gcd normalization leak.
        let loaded_counter = "<ct_fix__x>:\n\
            \x20 10:\tldr\tr5, [r0]\n\
            \x20 14:\tlsls\tr5, r5, #0x1\n\
            \x20 16:\tcmp\tr5, #0x40\n\
            \x20 18:\tblt\t0x14 <ct_fix__x+0x14>\n";
        assert_eq!(branches(loaded_counter, LoopIsa::Thumb), [(0x18, false)]);
        let loaded_bound = "<ct_fix__x>:\n\
            \x20 10:\tmovs\tr5, #0x1\n\
            \x20 12:\tldr\tr3, [r0]\n\
            \x20 14:\tlsls\tr5, r5, #0x1\n\
            \x20 16:\tcmp\tr5, r3\n\
            \x20 18:\tblt\t0x14 <ct_fix__x+0x14>\n";
        assert_eq!(branches(loaded_bound, LoopIsa::Thumb), [(0x18, false)]);
        let aarch64 = "<ct_fix__x>:\n\
            \x20 10:\tldr\tw8, [x0]\n\
            \x20 14:\tlsl\tw8, w8, #1\n\
            \x20 18:\tcmp\tw8, #0x40\n\
            \x20 1c:\tb.lt\t0x14 <ct_fix__x+0x14>\n";
        assert_eq!(branches(aarch64, LoopIsa::AArch64), [(0x1c, false)]);
    }

    #[test]
    fn doubling_counter_tampering_is_rejected() {
        // A second write mixes data into the counter.
        let mixed = "<ct_fix__x>:\n\
            \x20 10:\tmovs\tr5, #0x1\n\
            \x20 12:\tldr\tr3, [r0]\n\
            \x20 14:\tlsls\tr5, r5, #0x1\n\
            \x20 16:\torrs\tr5, r3\n\
            \x20 18:\tcmp\tr5, #0x40\n\
            \x20 1a:\tblt\t0x14 <ct_fix__x+0x14>\n";
        assert_eq!(branches(mixed, LoopIsa::Thumb), [(0x1a, false)]);
        // The step sits behind a data branch, so the count depends on data.
        let skipped = "<ct_fix__x>:\n\
            \x20 10:\tmovs\tr5, #0x1\n\
            \x20 12:\tldr\tr3, [r0]\n\
            \x20 14:\tcmp\tr3, #0x0\n\
            \x20 16:\tbeq\t0x1a <ct_fix__x+0x1a>\n\
            \x20 18:\tlsls\tr5, r5, #0x1\n\
            \x20 1a:\tcmp\tr5, #0x40\n\
            \x20 1c:\tblt\t0x14 <ct_fix__x+0x14>\n";
        assert_eq!(
            branches(skipped, LoopIsa::Thumb),
            [(0x16, false), (0x1c, false)]
        );
        // A jump past the immediate load enters with an unknown value.
        let bypassed = "<ct_fix__x>:\n\
            \x20 0c:\tldr\tr5, [r0]\n\
            \x20 0e:\tb\t0x12 <ct_fix__x+0x12>\n\
            \x20 10:\tmovs\tr5, #0x1\n\
            \x20 12:\tlsls\tr5, r5, #0x1\n\
            \x20 14:\tcmp\tr5, #0x40\n\
            \x20 16:\tblt\t0x12 <ct_fix__x+0x12>\n";
        assert_eq!(branches(bypassed, LoopIsa::Thumb), [(0x16, false)]);
        // A jump into the body enters with an unknown value.
        let mid_entry = "<ct_fix__x>:\n\
            \x20 00:\tldr\tr5, [r0]\n\
            \x20 02:\tb\t0x0a <ct_fix__x+0xa>\n\
            \x20 04:\tmovs\tr5, #0x1\n\
            \x20 06:\tlsls\tr5, r5, #0x1\n\
            \x20 0a:\tcmp\tr5, #0x40\n\
            \x20 0c:\tblt\t0x06 <ct_fix__x+0x6>\n";
        assert_eq!(branches(mid_entry, LoopIsa::Thumb), [(0xc, false)]);
        // A body branch leaves backward and rejoins past the step.
        let rejoined = "<ct_fix__x>:\n\
            \x20 00:\tb\t0x06 <ct_fix__x+0x6>\n\
            \x20 02:\tldr\tr5, [r0]\n\
            \x20 04:\tb\t0x10 <ct_fix__x+0x10>\n\
            \x20 06:\tmovs\tr5, #0x1\n\
            \x20 08:\tldr\tr3, [r1]\n\
            \x20 0a:\tcmp\tr3, #0x0\n\
            \x20 0c:\tbeq\t0x02 <ct_fix__x+0x2>\n\
            \x20 0e:\tlsl.w\tr5, r5, #0x1\n\
            \x20 10:\tcmp\tr5, #0x40\n\
            \x20 12:\tblt\t0x08 <ct_fix__x+0x8>\n";
        assert_eq!(
            branches(rejoined, LoopIsa::Thumb),
            [(0xc, false), (0x12, false)]
        );
        // A data branch reruns the step, so data sets the count at the latch.
        let rerun = "<ct_fix__x>:\n\
            \x20 00:\tmovs\tr5, #0x1\n\
            \x20 02:\tlsl.w\tr5, r5, #0x1\n\
            \x20 06:\tldr\tr3, [r0]\n\
            \x20 08:\tcmp\tr3, #0x0\n\
            \x20 0a:\tbeq\t0x02 <ct_fix__x+0x2>\n\
            \x20 0c:\tcmp\tr5, #0x40\n\
            \x20 0e:\tblt\t0x02 <ct_fix__x+0x2>\n";
        assert_eq!(
            branches(rerun, LoopIsa::Thumb),
            [(0xa, false), (0xe, false)]
        );
        // A jump over the compare leaves the latch reading the loaded word's flags.
        let stale_flags = "<ct_fix__x>:\n\
            \x20 00:\tmovs\tr5, #0x1\n\
            \x20 02:\tldr\tr3, [r0]\n\
            \x20 04:\tcmp\tr3, #0x0\n\
            \x20 06:\tlsl.w\tr5, r5, #0x1\n\
            \x20 0a:\tb\t0x0e <ct_fix__x+0xe>\n\
            \x20 0c:\tcmp\tr5, #0x40\n\
            \x20 0e:\tblt\t0x04 <ct_fix__x+0x4>\n";
        assert_eq!(branches(stale_flags, LoopIsa::Thumb), [(0xe, false)]);
        // The compare reads the target before the copy reseeds it from the
        // immediate-loaded scratch, so the first decision is on loaded data.
        let read_before_copy = "<ct_fix__x>:\n\
            \x20 00:\tldr\tr5, [r0]\n\
            \x20 02:\tmovs\tr4, #0x1\n\
            \x20 04:\tcmp\tr5, #0x20\n\
            \x20 06:\tmov\tr5, r4\n\
            \x20 08:\tlsl.w\tr4, r5, #0x1\n\
            \x20 0c:\tblo\t0x04 <ct_fix__x+0x4>\n";
        assert_eq!(branches(read_before_copy, LoopIsa::Thumb), [(0xc, false)]);
        // The first read sees the immediate, but the copy then reseeds the
        // target from a loaded scratch, so later decisions are on loaded data.
        let reseeded_from_data = "<ct_fix__x>:\n\
            \x20 00:\tmovs\tr5, #0x1\n\
            \x20 02:\tldr\tr4, [r0]\n\
            \x20 04:\tcmp\tr5, #0x20\n\
            \x20 06:\tmov\tr5, r4\n\
            \x20 08:\tlsl.w\tr4, r5, #0x1\n\
            \x20 0c:\tblo\t0x04 <ct_fix__x+0x4>\n";
        assert_eq!(branches(reseeded_from_data, LoopIsa::Thumb), [(0xc, false)]);
        // A seed inside an IT window may not run.
        let predicated_seed = "<ct_fix__x>:\n\
            \x20 00:\tldr\tr5, [r0]\n\
            \x20 02:\tcmp\tr1, #0x0\n\
            \x20 04:\tit\tne\n\
            \x20 06:\tmovne\tr5, #0x1\n\
            \x20 08:\tlsl.w\tr5, r5, #0x1\n\
            \x20 0c:\tcmp\tr5, #0x40\n\
            \x20 0e:\tblt\t0x08 <ct_fix__x+0x8>\n";
        assert_eq!(branches(predicated_seed, LoopIsa::Thumb), [(0xe, false)]);
        // A RISC-V diamond on a loaded word is a value branch.
        let riscv = "<ct_fix__x>:\n\
            \x20 98:\tli\ta0, 0x1\n\
            \x20 9a:\tlw\ta5, 0x0(a2)\n\
            \x20 a4:\taddi\ta4, a5, -0x20\n\
            \x20 a8:\tbltz\ta4, 0xb2 <ct_fix__x+0xb2>\n\
            \x20 ac:\tsrl\ta5, s1, a5\n\
            \x20 b2:\tslli\ta0, a0, 0x1\n\
            \x20 b4:\tli\ta3, 0x40\n\
            \x20 b8:\tblt\ta0, a3, 0x9a <ct_fix__x+0x9a>\n";
        assert_eq!(branches(riscv, LoopIsa::RiscV)[0], (0xa8, false));
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

    #[test]
    fn x86_register_rewritten_after_flag_setter() {
        let listing = "<ct_fix__x>:\n\
            \x20 10:\tmovq\t(%rsi), %rax\n\
            \x20 13:\ttestq\t%rax, %rax\n\
            \x20 16:\tleaq\t0x1(%rcx), %rcx\n\
            \x20 1a:\tmovq\t%rcx, %rax\n\
            \x20 1d:\tjne\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(listing, LoopIsa::X86_64), [(0x1d, false)]);
    }

    #[test]
    fn x86_carry_branch_after_dec_reads_older_compare() {
        let listing = "<ct_fix__x>:\n\
            \x20 10:\tmovq\t(%rsi), %rax\n\
            \x20 13:\tcmpq\t$0x4, %rax\n\
            \x20 17:\tdecq\t%rcx\n\
            \x20 1a:\tjb\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(listing, LoopIsa::X86_64), [(0x1a, false)]);
    }

    #[test]
    fn x86_count_zero_jump_decides_on_rcx() {
        let listing = "<ct_fix__x>:\n\
            \x20 10:\tmovq\t(%rsi), %rcx\n\
            \x20 13:\tdecq\t%rdx\n\
            \x20 16:\tjrcxz\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(listing, LoopIsa::X86_64), [(0x16, false)]);
    }

    #[test]
    fn x86_high_byte_and_implicit_writes_clobber() {
        let high_byte = "<ct_fix__x>:\n\
            \x20 10:\tmovb\t(%rsi), %ah\n\
            \x20 12:\taddq\t$0x1, %rcx\n\
            \x20 16:\tcmpq\t%rcx, %rax\n\
            \x20 19:\tjne\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(high_byte, LoopIsa::X86_64), [(0x19, false)]);
        let implicit = "<ct_fix__x>:\n\
            \x20 10:\trdtsc\n\
            \x20 12:\taddq\t$0x1, %rcx\n\
            \x20 16:\tcmpq\t%rcx, %rax\n\
            \x20 19:\tjne\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(implicit, LoopIsa::X86_64), [(0x19, false)]);
    }

    #[test]
    fn aarch64_pre_index_register_offset_is_not_a_step() {
        let register = "<ct_fix__x>:\n\
            \x20 10:\tldr\tx11, [x8, x9]!\n\
            \x20 14:\tcmp\tx8, x10\n\
            \x20 18:\tb.ne\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(register, LoopIsa::AArch64), [(0x18, false)]);
        let immediate = "<ct_fix__x>:\n\
            \x20 10:\tldr\tx11, [x8, #8]!\n\
            \x20 14:\tcmp\tx8, x10\n\
            \x20 18:\tb.ne\t0x10 <ct_fix__x+0x10>\n";
        assert_eq!(branches(immediate, LoopIsa::AArch64), [(0x18, true)]);
    }

    #[test]
    fn thumb_zero_net_step_is_no_progress() {
        let zero = "<ct_fix__x>:\n\
            \x20 0:\tadds\tr0, #0x0\n\
            \x20 2:\tcmp\tr0, r1\n\
            \x20 4:\tbne\t0x0 <ct_fix__x>\n";
        assert_eq!(branches(zero, LoopIsa::Thumb), [(0x4, false)]);
        let net_zero = "<ct_fix__x>:\n\
            \x20 0:\tadds\tr0, #0x1\n\
            \x20 2:\tsubs\tr0, #0x1\n\
            \x20 4:\tcmp\tr0, r1\n\
            \x20 6:\tbne\t0x0 <ct_fix__x>\n";
        assert_eq!(branches(net_zero, LoopIsa::Thumb), [(0x6, false)]);
    }

    #[test]
    fn avr_unchained_sbci_is_not_a_step() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tld\tr20, Z\n\
            \x20 2:\tcp\tr20, r1\n\
            \x20 4:\tsbci\tr25, 0x0\n\
            \x20 6:\tsubi\tr24, 0x1\n\
            \x20 8:\tcp\tr24, r22\n\
            \x20 a:\tcpc\tr25, r23\n\
            \x20 c:\tbrne\t.-2\n\
            \t\t\t0000000c:  R_AVR_7_PCREL\t.text.ct_fix__x\n";
        assert_eq!(branches(listing, LoopIsa::Avr), [(0xc, false)]);
    }

    #[test]
    fn avr_carry_branch_after_inc_reads_older_compare() {
        let listing = "<ct_fix__x>:\n\
            \x20 0:\tld\tr20, Z\n\
            \x20 2:\tcp\tr20, r1\n\
            \x20 4:\tinc\tr24\n\
            \x20 6:\tbrcs\t.-2\n\
            \t\t\t00000006:  R_AVR_7_PCREL\t.text.ct_fix__x\n";
        assert_eq!(branches(listing, LoopIsa::Avr), [(0x6, false)]);
    }
}
