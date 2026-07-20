//! Canonical instruction-policy vocabulary shared by static CT gates.

pub const THUMB_FORBIDDEN: &[&str] = &[
    r"^b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.[nw])?$",
    r"^cbn?z$",
    r"^tb[bh]$",
];
pub const THUMB_ALLOWED: &[&str] = &[r"^it[te]{0,3}$"];

pub const RISCV_FORBIDDEN: &[&str] = &[
    r"^b(eq|ne|lt|ge|gt|le|ltu|geu|gtu|leu)z?$",
    r"^c\.b(eqz|nez)$",
];

pub const AVR_FORBIDDEN: &[&str] = &[
    r"^br(cc|cs|eq|ge|hc|hs|id|ie|lo|lt|mi|ne|pl|sh|tc|ts|vc|vs|bs|bc)$",
    r"^s(bic|bis|brc|brs)$",
    r"^cpse$",
];

pub const AARCH64_FORBIDDEN: &[&str] = &[
    r"^b\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)$",
    r"^cbn?z$",
    r"^tbn?z$",
];
pub const AARCH64_ALLOWED: &[&str] = &[r"^cs(el|inc|inv|neg|et|etm)$", r"^ccmp[en]?$", r"^ccmn$"];

pub const X86_64_FORBIDDEN: &[&str] =
    &[r"^j(e|ne|z|nz|a|ae|b|be|c|nc|g|ge|l|le|o|no|s|ns|p|np|pe|po|cxz|ecxz|rcxz)$"];
pub const X86_64_ALLOWED: &[&str] = &[r"^cmov[a-z]+$", r"^set[a-z]+$", r"^sbb[bwlq]?$"];

pub const THUMB_CALL: &[&str] = &[r"^blx?$"];
pub const AARCH64_CALL: &[&str] = &[r"^bl$", r"^blr$"];
/// `auipc` carries `R_RISCV_CALL_PLT` in staticlib call sequences, so omitting
/// it can silently hide reachable helpers from a call-graph walk.
pub const RISCV_CALL: &[&str] = &[r"^jal$", r"^jalr$", r"^c\.jal$", r"^c\.jalr$", r"^auipc$"];
pub const AVR_CALL: &[&str] = &[r"^r?call$", r"^icall$", r"^eicall$"];
pub const X86_64_CALL: &[&str] = &[r"^callq?$"];

pub struct ConditionalBranchSpec {
    pub triple: &'static str,
    pub mnemonics: &'static [&'static str],
    pub normalize: fn(&str) -> &str,
}

fn thumb_normalize(mnemonic: &str) -> &str {
    mnemonic
        .strip_suffix(".n")
        .or_else(|| mnemonic.strip_suffix(".w"))
        .unwrap_or(mnemonic)
}

fn passthrough(mnemonic: &str) -> &str {
    mnemonic
}

const THUMB_CONDITIONAL_BRANCHES: &[&str] = &[
    "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge",
    "blt", "bgt", "ble", "cbz", "cbnz", "tbz", "tbnz",
];
const RISCV_CONDITIONAL_BRANCHES: &[&str] = &[
    "beq", "bne", "blt", "bge", "bltu", "bgeu", "bgtz", "bltz", "bnez", "beqz", "bgez", "blez",
    "bgt", "ble", "bgtu", "bleu", "c.beqz", "c.bnez",
];

pub const CONDITIONAL_BRANCH_ISAS: &[ConditionalBranchSpec] = &[
    ConditionalBranchSpec {
        triple: "thumbv7em-none-eabi",
        mnemonics: THUMB_CONDITIONAL_BRANCHES,
        normalize: thumb_normalize,
    },
    ConditionalBranchSpec {
        triple: "thumbv7m-none-eabi",
        mnemonics: THUMB_CONDITIONAL_BRANCHES,
        normalize: thumb_normalize,
    },
    ConditionalBranchSpec {
        triple: "thumbv6m-none-eabi",
        mnemonics: THUMB_CONDITIONAL_BRANCHES,
        normalize: thumb_normalize,
    },
    ConditionalBranchSpec {
        triple: "riscv32imc-unknown-none-elf",
        mnemonics: RISCV_CONDITIONAL_BRANCHES,
        normalize: passthrough,
    },
    ConditionalBranchSpec {
        triple: "riscv32imac-unknown-none-elf",
        mnemonics: RISCV_CONDITIONAL_BRANCHES,
        normalize: passthrough,
    },
];

pub fn conditional_branch_spec(triple: &str) -> Option<&'static ConditionalBranchSpec> {
    CONDITIONAL_BRANCH_ISAS
        .iter()
        .find(|isa| isa.triple == triple)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_covers_known_drift_regressions() {
        assert!(AVR_FORBIDDEN[0].contains("bs|bc"));
        assert!(RISCV_CALL.contains(&r"^auipc$"));
        let thumb = conditional_branch_spec("thumbv7em-none-eabi").unwrap();
        assert_eq!((thumb.normalize)("beq.w"), "beq");
    }
}
