//! An analytical cycle model for Cortex-M0, Cortex-M3 and Cortex-M4 instruction sequences.
//!
//! Each executed instruction gets a cycle range under these assumptions: zero-wait-state
//! memory, no bus contention, no interrupts or exceptions, and every traced instruction
//! executed. A range covers what the listing alone cannot decide (pipeline refill after a
//! branch, multiplier configuration on Cortex-M0, early-terminating divides). Real parts with
//! flash wait states, caches or accelerators run slower or differently, so measure there.
//!
//! The figures follow the Technical Reference Manuals' instruction timings with these known
//! deviations, so the sum is a model estimate, not a guaranteed bracket:
//!
//! - Cortex-M3/M4 loads cost 2..3 each; adjacent loads and stores that pipeline can cost 1, so
//!   load-heavy code can run below the minimum.
//! - Cortex-M3 `tbb`/`tbh` cost 6..8 (the TRM gives 2 plus refill), and the Cortex-M3
//!   long multiply-accumulate ranges are the model's own (`umlal` 4..6, others 5..7).
//! - `isb` on Cortex-M3/M4 is 1..4 without the TRM's refetch term.
//! - An instruction whose condition fails inside an IT block still appears in a QEMU
//!   one-instruction-per-block trace and is charged as if it executed.
//! - Exclusive and unprivileged loads and stores (`ldrex`, `strex`, `ldrt`, ...) are costed
//!   as ordinary loads and stores.
//!
//! `mov pc, rN` and `add pc, rN` are costed as branches (3 cycles on Cortex-M0, 2..4 on
//! Cortex-M3/M4). Floating point, DSP and other unlisted instructions are errors, as are other
//! instructions that write `pc` (`ldr pc, [..]`) and Armv7-M instructions in a Cortex-M0 trace.

use std::collections::BTreeMap;
use std::fmt;
use std::string::{String, ToString};

use super::thumb::{
    conditional_branch, is_long_multiply, is_multiply, is_simple_alu, normalize_mnemonic,
    register_count, target_address,
};
use super::{Disassembly, Instruction};

/// The core whose timings apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CortexMCore {
    /// Cortex-M0 (not Cortex-M0+, whose branch and load timings differ); multiplies span the
    /// 1-cycle and 32-cycle multiplier options.
    M0,
    /// Cortex-M3.
    M3,
    /// Cortex-M4; floating-point and DSP instructions are not modelled.
    M4,
}

/// The cycles one instruction may take, and the timing class that set them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CycleCost {
    pub minimum: u64,
    pub maximum: u64,
    /// For example `load`, `conditional-branch`, `stack-transfer-return`.
    pub class: &'static str,
}

impl CycleCost {
    const fn fixed(cycles: u64, class: &'static str) -> Self {
        Self {
            minimum: cycles,
            maximum: cycles,
            class,
        }
    }

    const fn range(minimum: u64, maximum: u64, class: &'static str) -> Self {
        Self {
            minimum,
            maximum,
            class,
        }
    }
}

/// An instruction the model cannot cost.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CycleModelError {
    /// The mnemonic is outside the model.
    #[non_exhaustive]
    Unmodelled {
        address: u64,
        mnemonic: String,
        function: Option<String>,
    },
    /// A conditional branch was costed without knowing whether it was taken.
    #[non_exhaustive]
    UnknownDirection { address: u64, mnemonic: String },
    /// A traced PC has no decoded instruction.
    UnknownPc(u64),
    /// The PC after a conditional branch is neither its target nor the next instruction (an
    /// exception, a gap in the trace, or a wrongly inferred instruction size).
    #[non_exhaustive]
    UnexpectedSuccessor { address: u64, next: u64 },
}

impl fmt::Display for CycleModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmodelled {
                address,
                mnemonic,
                function,
            } => {
                write!(
                    formatter,
                    "{mnemonic} at {address:#x} is absent from the analytical model"
                )?;
                match function {
                    Some(function) => write!(formatter, " (in {function:?})"),
                    None => Ok(()),
                }
            }
            Self::UnknownDirection { address, mnemonic } => write!(
                formatter,
                "conditional branch {mnemonic} at {address:#x} has no direction"
            ),
            Self::UnknownPc(pc) => {
                write!(formatter, "traced PC {pc:#x} has no decoded instruction")
            }
            Self::UnexpectedSuccessor { address, next } => write!(
                formatter,
                "conditional branch at {address:#x} is followed by {next:#x}, neither its target \
                 nor the next instruction"
            ),
        }
    }
}

impl std::error::Error for CycleModelError {}

/// Armv7-M instructions (by normalized mnemonic) a Cortex-M0 cannot execute.
fn armv7m_only(raw: &str, mnemonic: &str) -> bool {
    raw.ends_with(".w")
        || mnemonic.starts_with("it")
        || matches!(
            mnemonic,
            "udiv"
                | "sdiv"
                | "tbb"
                | "tbh"
                | "ldrd"
                | "strd"
                | "cbz"
                | "cbnz"
                | "movw"
                | "movt"
                | "clz"
                | "mla"
                | "mls"
                | "umull"
                | "smull"
                | "umlal"
                | "smlal"
                | "umaal"
                | "ubfx"
                | "sbfx"
                | "bfi"
                | "bfc"
                | "rbit"
                | "orn"
        )
}

/// Whether the instruction's first operand, its destination, is `pc`.
fn writes_pc(operands: &str) -> bool {
    operands.split(',').next().unwrap_or_default().trim() == "pc"
}

/// The cycles `instruction` takes on `core`. `taken` must say whether a conditional branch
/// (including `cbz`/`cbnz`) was taken; it is ignored for anything else. An `Unmodelled` error
/// from here has no `function`; [`estimate_cycles`] fills it in.
pub fn instruction_cycles(
    core: CortexMCore,
    instruction: &Instruction,
    taken: Option<bool>,
) -> Result<CycleCost, CycleModelError> {
    use CortexMCore::{M0, M3};
    let fixed = CycleCost::fixed;
    let range = CycleCost::range;
    let conditional = conditional_branch(&instruction.mnemonic).is_some();
    let mnemonic = normalize_mnemonic(&instruction.mnemonic);
    let unmodelled = || CycleModelError::Unmodelled {
        address: instruction.address,
        mnemonic: instruction.mnemonic.clone(),
        function: None,
    };
    if (core == M0 && armv7m_only(&instruction.mnemonic, &mnemonic))
        || (core == M3 && mnemonic == "umaal")
    {
        return Err(unmodelled());
    }
    if writes_pc(&instruction.operands) {
        // `mov pc, rN` and `add pc, rN` (Thumb jump-table dispatch) branch to a register
        // value: 3 cycles on Cortex-M0, 1 plus the pipeline refill on Cortex-M3/M4. Loads
        // into `pc` other than `pop`/`ldm` are not modelled.
        return if mnemonic == "mov" || mnemonic == "add" {
            Ok(if core == M0 {
                fixed(3, "register-branch")
            } else {
                range(2, 4, "register-branch")
            })
        } else {
            Err(unmodelled())
        };
    }
    if conditional {
        let taken = taken.ok_or_else(|| CycleModelError::UnknownDirection {
            address: instruction.address,
            mnemonic: instruction.mnemonic.clone(),
        })?;
        return Ok(if core == M0 {
            fixed(if taken { 3 } else { 1 }, "conditional-branch")
        } else if taken {
            range(2, 4, "conditional-branch")
        } else {
            fixed(1, "conditional-branch")
        });
    }
    if mnemonic == "b" || mnemonic == "bx" {
        return Ok(if core == M0 {
            fixed(3, "branch")
        } else {
            range(2, 4, "branch")
        });
    }
    if mnemonic == "bl" {
        return Ok(if core == M0 {
            fixed(4, "call")
        } else {
            range(2, 4, "call")
        });
    }
    if mnemonic == "blx" {
        return Ok(if core == M0 {
            fixed(3, "call")
        } else {
            range(2, 4, "call")
        });
    }
    if mnemonic == "tbb" || mnemonic == "tbh" {
        return Ok(if core == M3 {
            range(6, 8, "table-branch")
        } else {
            range(3, 5, "table-branch")
        });
    }
    if mnemonic == "push" || mnemonic == "pop" {
        let registers = register_count(&instruction.operands);
        let returns = mnemonic == "pop" && instruction.operands.contains("pc");
        return Ok(if core == M0 && returns {
            fixed(registers.saturating_add(4), "stack-transfer-return")
        } else if returns {
            range(
                registers.saturating_add(2),
                registers.saturating_add(4),
                "stack-transfer-return",
            )
        } else {
            fixed(registers.saturating_add(1), "stack-transfer")
        });
    }
    if mnemonic.starts_with("ldm") || mnemonic.starts_with("stm") {
        let registers = register_count(&instruction.operands);
        let returns = mnemonic.starts_with("ldm") && instruction.operands.contains("pc");
        return Ok(if returns && core != M0 {
            range(
                registers.saturating_add(2),
                registers.saturating_add(4),
                "multiple-transfer-return",
            )
        } else {
            fixed(registers.saturating_add(1), "multiple-transfer")
        });
    }
    if mnemonic.starts_with("ldr") {
        if mnemonic == "ldrd" {
            return Ok(fixed(3, "doubleword-load"));
        }
        return Ok(if core == M0 {
            fixed(2, "load")
        } else {
            range(2, 3, "load")
        });
    }
    if mnemonic.starts_with("str") {
        if mnemonic == "strd" {
            return Ok(fixed(3, "doubleword-store"));
        }
        return Ok(if core == M0 {
            fixed(2, "store")
        } else {
            range(1, 2, "store")
        });
    }
    if mnemonic == "sdiv" || mnemonic == "udiv" {
        return Ok(range(2, 12, "hardware-divide"));
    }
    if is_long_multiply(&mnemonic) {
        return Ok(if core == M0 {
            range(2, 33, "long-multiply")
        } else if core == M3 {
            match mnemonic.as_str() {
                "smull" | "umull" => range(3, 5, "long-multiply"),
                "umlal" | "umaal" => range(4, 6, "long-multiply-accumulate"),
                _ => range(5, 7, "long-multiply-accumulate"),
            }
        } else {
            fixed(1, "long-multiply")
        });
    }
    if is_multiply(&mnemonic) {
        return Ok(if core == M0 {
            range(1, 32, "multiply")
        } else if core == M3 && matches!(mnemonic.as_str(), "mla" | "mls") {
            fixed(2, "multiply-accumulate")
        } else {
            fixed(1, "multiply")
        });
    }
    if matches!(mnemonic.as_str(), "dmb" | "dsb" | "isb") {
        return Ok(if core == M0 {
            fixed(4, "barrier")
        } else {
            range(1, 4, "barrier")
        });
    }
    if matches!(mnemonic.as_str(), "mrs" | "msr") {
        return Ok(if core == M0 {
            fixed(4, "special-register")
        } else {
            range(1, 2, "special-register")
        });
    }
    if matches!(mnemonic.as_str(), "cpsid" | "cpsie") {
        return Ok(if core == M0 {
            fixed(1, "interrupt-mask")
        } else {
            range(1, 2, "interrupt-mask")
        });
    }
    if mnemonic.starts_with("it") {
        return Ok(range(0, 1, "if-then"));
    }
    if matches!(mnemonic.as_str(), "wfe" | "wfi") {
        return Ok(if core == M0 {
            fixed(2, "sleep-entry")
        } else {
            fixed(1, "sleep-entry")
        });
    }
    if is_simple_alu(&mnemonic) {
        return Ok(fixed(1, "alu"));
    }
    Err(unmodelled())
}

/// The modelled cycles of one address over a trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AddressCycles {
    pub executions: u64,
    pub minimum: u64,
    pub maximum: u64,
    /// The timing class of the first execution.
    pub class: String,
}

/// The modelled cycles of an executed instruction sequence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CycleEstimate {
    pub minimum: u64,
    pub maximum: u64,
    pub taken_conditional: u64,
    pub not_taken_conditional: u64,
    pub per_address: BTreeMap<u64, AddressCycles>,
    /// Executions per normalized mnemonic (`bne.w` counts as `b`).
    pub histogram: BTreeMap<String, u64>,
}

/// Costs the executed PCs `pcs` (in execution order, Thumb bit cleared) on `core`.
///
/// `pcs` must list every executed instruction (QEMU `-d exec,nochain` with
/// `one-insn-per-tb=on`; plain `-d exec` logs only block starts). A conditional branch is not
/// taken when the next PC is the following instruction, taken when it is the branch target,
/// and an [`CycleModelError::UnexpectedSuccessor`] otherwise (an exception, a trace gap, or a
/// wrongly inferred size), so exceptions are never silently costed. The last PC of the
/// sequence has no successor and counts as not taken, which biases the estimate low by at
/// most one refill. Sums saturate.
pub fn estimate_cycles(
    core: CortexMCore,
    disassembly: &Disassembly,
    pcs: &[u64],
) -> Result<CycleEstimate, CycleModelError> {
    let mut estimate = CycleEstimate::default();
    for (index, pc) in pcs.iter().copied().enumerate() {
        let instruction = disassembly
            .instructions
            .get(&pc)
            .ok_or(CycleModelError::UnknownPc(pc))?;
        let next_pc = pcs.get(index.saturating_add(1)).copied();
        let taken = match (conditional_branch(&instruction.mnemonic), next_pc) {
            (None, _) => None,
            (Some(_), None) => Some(false),
            (Some(_), Some(next)) => {
                if next
                    == instruction
                        .address
                        .saturating_add(u64::from(instruction.size))
                {
                    Some(false)
                } else if target_address(&instruction.operands) == Some(next) {
                    Some(true)
                } else {
                    return Err(CycleModelError::UnexpectedSuccessor { address: pc, next });
                }
            }
        };
        match taken {
            Some(true) => estimate.taken_conditional = estimate.taken_conditional.saturating_add(1),
            Some(false) => {
                estimate.not_taken_conditional = estimate.not_taken_conditional.saturating_add(1);
            }
            None => {}
        }
        let cost = instruction_cycles(core, instruction, taken).map_err(|error| match error {
            CycleModelError::Unmodelled {
                address, mnemonic, ..
            } => CycleModelError::Unmodelled {
                address,
                mnemonic,
                function: disassembly
                    .functions
                    .get(&instruction.owner)
                    .map(|function| function.name.clone()),
            },
            other => other,
        })?;
        estimate.minimum = estimate.minimum.saturating_add(cost.minimum);
        estimate.maximum = estimate.maximum.saturating_add(cost.maximum);
        let address = estimate.per_address.entry(pc).or_default();
        address.executions = address.executions.saturating_add(1);
        address.minimum = address.minimum.saturating_add(cost.minimum);
        address.maximum = address.maximum.saturating_add(cost.maximum);
        if address.class.is_empty() {
            address.class = cost.class.to_string();
        }
        let count = estimate
            .histogram
            .entry(normalize_mnemonic(&instruction.mnemonic))
            .or_default();
        *count = count.saturating_add(1);
    }
    Ok(estimate)
}

#[cfg(test)]
mod tests;
