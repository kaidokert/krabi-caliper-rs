//! An analytical cycle model for Cortex-M0, Cortex-M3 and Cortex-M4 instruction sequences.
//!
//! Each executed instruction gets a cycle range from the core's published instruction timings
//! under these assumptions: zero-wait-state memory, no bus contention, no interrupts or
//! exceptions, and no stalls beyond those the timings list. A range covers what the listing
//! alone cannot decide (pipeline refill after a branch, multiplier configuration on
//! Cortex-M0, early-terminating divides). The sum over a dynamic trace brackets the sequence
//! on such a core; real parts with flash wait states, caches or accelerators run slower or
//! differently, so measure there.
//!
//! Instructions outside the model (floating point, DSP, exclusives, and anything else not
//! listed) are errors, not guesses.

use std::collections::BTreeMap;
use std::fmt;
use std::string::{String, ToString};

use super::thumb::{
    conditional_branch, is_long_multiply, is_multiply, is_simple_alu, normalize_mnemonic,
    register_count,
};
use super::{Disassembly, Instruction};

/// The core whose timings apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CortexMCore {
    /// Armv6-M; multiplies span the 1-cycle and 32-cycle multiplier options.
    M0,
    M3,
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
        }
    }
}

impl std::error::Error for CycleModelError {}

/// The cycles `instruction` takes on `core`. `taken` must say whether a conditional branch
/// (including `cbz`/`cbnz`) was taken; it is ignored for anything else.
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
    Err(CycleModelError::Unmodelled {
        address: instruction.address,
        mnemonic: instruction.mnemonic.clone(),
        function: None,
    })
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
/// A conditional branch counts as taken when the next PC in `pcs` is not the following
/// instruction; the last PC of the sequence has no successor and counts as not taken. Sums
/// saturate.
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
        let taken = conditional_branch(&instruction.mnemonic).map(|_| {
            next_pc.is_some_and(|next| {
                next != instruction
                    .address
                    .saturating_add(u64::from(instruction.size))
            })
        });
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
