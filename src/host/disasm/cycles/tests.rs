use super::*;

fn instruction(mnemonic: &str, operands: &str) -> Instruction {
    Instruction {
        address: 0,
        size: 2,
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
        owner: 0,
    }
}

fn cost(core: CortexMCore, mnemonic: &str, operands: &str, taken: Option<bool>) -> (u64, u64) {
    let cost = instruction_cycles(core, &instruction(mnemonic, operands), taken).unwrap();
    (cost.minimum, cost.maximum)
}

use CortexMCore::{M0, M3, M4};

#[test]
fn branches_depend_on_direction_and_core() {
    assert_eq!(cost(M0, "bne", "0x20", Some(false)), (1, 1));
    assert_eq!(cost(M0, "bne", "0x20", Some(true)), (3, 3));
    assert_eq!(cost(M4, "bne.w", "0x20", Some(true)), (2, 4));
    assert_eq!(cost(M3, "cbz", "r0, 0x20", Some(false)), (1, 1));
    assert!(matches!(
        instruction_cycles(M3, &instruction("beq", "0x20"), None),
        Err(CycleModelError::UnknownDirection { .. })
    ));
    assert_eq!(cost(M0, "b", "0x20", None), (3, 3));
    assert_eq!(cost(M4, "bx", "lr", None), (2, 4));
    assert_eq!(cost(M0, "bl", "0x20", None), (4, 4));
    assert_eq!(cost(M0, "blx", "r3", None), (3, 3));
    assert_eq!(cost(M3, "tbb", "[pc, r0]", None), (6, 8));
    assert_eq!(cost(M4, "tbh", "[pc, r0, lsl #1]", None), (3, 5));
}

#[test]
fn transfers_count_registers() {
    assert_eq!(cost(M3, "push", "{r4-r7, lr}", None), (6, 6));
    assert_eq!(cost(M4, "pop", "{r4-r7, pc}", None), (7, 9));
    assert_eq!(cost(M0, "pop", "{r4, pc}", None), (6, 6));
    assert_eq!(cost(M0, "ldm", "r0!, {r1, r2}", None), (3, 3));
    assert_eq!(cost(M4, "ldm.w", "sp!, {r4, pc}", None), (4, 6));
    assert_eq!(cost(M0, "ldr", "r0, [r1]", None), (2, 2));
    assert_eq!(cost(M3, "ldrb.w", "r0, [r1, #0x4]", None), (2, 3));
    assert_eq!(cost(M4, "ldrd", "r0, r1, [r2]", None), (3, 3));
    assert_eq!(cost(M3, "str", "r0, [r1]", None), (1, 2));
    assert_eq!(cost(M0, "strh", "r0, [r1]", None), (2, 2));
}

#[test]
fn arithmetic_and_system_classes() {
    assert_eq!(cost(M0, "muls", "r0, r1, r0", None), (1, 32));
    assert_eq!(cost(M3, "mla", "r0, r1, r2, r3", None), (2, 2));
    assert_eq!(cost(M4, "mla", "r0, r1, r2, r3", None), (1, 1));
    assert_eq!(cost(M3, "umull", "r0, r1, r2, r3", None), (3, 5));
    assert_eq!(cost(M3, "umlal", "r0, r1, r2, r3", None), (4, 6));
    assert_eq!(cost(M4, "smlal", "r0, r1, r2, r3", None), (1, 1));
    assert_eq!(cost(M3, "udiv", "r0, r1, r2", None), (2, 12));
    assert_eq!(cost(M0, "dmb", "sy", None), (4, 4));
    assert_eq!(cost(M4, "mrs", "r0, primask", None), (1, 2));
    assert_eq!(cost(M0, "cpsid", "i", None), (1, 1));
    assert_eq!(cost(M4, "ite", "eq", None), (0, 1));
    assert_eq!(cost(M0, "wfi", "", None), (2, 2));
    assert_eq!(cost(M4, "adds", "r0, #0x1", None), (1, 1));
    assert_eq!(cost(M4, "addeq", "r0, #0x1", None), (1, 1));
    let unmodelled = instruction_cycles(M4, &instruction("vadd.f32", "s0, s1, s2"), None);
    assert!(matches!(
        unmodelled,
        Err(CycleModelError::Unmodelled { ref mnemonic, .. }) if mnemonic == "vadd.f32"
    ));
}

#[test]
fn rejects_what_the_core_or_model_cannot_cost() {
    let rejected = |core, mnemonic: &str, operands: &str| {
        matches!(
            instruction_cycles(core, &instruction(mnemonic, operands), None),
            Err(CycleModelError::Unmodelled { function: None, .. })
        )
    };
    // Armv7-M instructions in a Cortex-M0 trace.
    for mnemonic in [
        "udiv", "tbb", "ldrd", "ite", "cbz", "movw", "clz", "mla", "umull",
    ] {
        assert!(rejected(M0, mnemonic, "r0, r1, r2"), "{mnemonic}");
    }
    assert!(rejected(M0, "ldr.w", "r0, [r1]"));
    assert!(rejected(M3, "umaal", "r0, r1, r2, r3"));
    // Register moves into pc are branches; other loads into pc are not modelled.
    assert_eq!(cost(M0, "mov", "pc, r1", None), (3, 3));
    assert_eq!(cost(M4, "add", "pc, r2", None), (2, 4));
    assert_eq!(cost(M3, "moveq", "pc, r0", None), (1, 4));
    assert!(rejected(M4, "ldr.w", "pc, [r0, r1, lsl #2]"));
    // Reading pc is not a branch.
    assert_eq!(cost(M4, "cmp", "pc, r1", None), (1, 1));
    // Ordinary forms stay modelled.
    assert_eq!(cost(M0, "mov", "r0, r1", None), (1, 1));
    assert_eq!(cost(M4, "ldr", "r0, [pc, #0x4]", None), (2, 3));
    assert_eq!(cost(M4, "ldmdb", "r0, {r1, r2}", None), (3, 3));
    assert_eq!(cost(M0, "pop", "{r4, r5}", None), (3, 3));
    // `ble` is a conditional branch, not `bl`.
    assert_eq!(cost(M0, "ble", "0x20", Some(true)), (3, 3));
}

const NM: &str = "00000100 00000010 T f\n";
const OBJDUMP: &str = "
00000100 <f>:
     100: \tmovs\tr0, #0x0
     102: \tadds\tr0, #0x1
     104: \tcmp\tr0, #0x2
     106: \tbne\t0x102 <f+0x2>
     108: \tbx\tlr
     10a: \tvadd.f32\ts0, s1, s2
";

#[test]
fn estimates_follow_the_trace() {
    let d = Disassembly::parse(NM, OBJDUMP).unwrap();
    // The loop runs twice: bne is taken once, then falls through.
    let pcs = [0x100, 0x102, 0x104, 0x106, 0x102, 0x104, 0x106, 0x108];
    let m0 = estimate_cycles(M0, &d, &pcs).unwrap();
    assert_eq!((m0.taken_conditional, m0.not_taken_conditional), (1, 1));
    // movs 1 + 2 * (adds 1 + cmp 1) + bne taken 3 + bne not taken 1 + bx 3.
    assert_eq!((m0.minimum, m0.maximum), (12, 12));
    let m4 = estimate_cycles(M4, &d, &pcs).unwrap();
    // As above with bne taken 2..4, not taken 1 and bx 2..4.
    assert_eq!((m4.minimum, m4.maximum), (10, 14));
    let bne = &m4.per_address[&0x106];
    assert_eq!(
        (bne.executions, bne.minimum, bne.maximum, bne.class.as_str()),
        (2, 3, 5, "conditional-branch")
    );
    assert_eq!(m4.histogram["b"], 2);
    assert_eq!(m4.histogram["adds"], 2);
    // A conditional branch at the end of the sequence counts as not taken.
    let last = estimate_cycles(M0, &d, &[0x104, 0x106]).unwrap();
    assert_eq!(last.not_taken_conditional, 1);
    assert!(matches!(
        estimate_cycles(M0, &d, &[0x101]),
        Err(CycleModelError::UnknownPc(0x101))
    ));
    let error = estimate_cycles(M4, &d, &[0x10a]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "vadd.f32 at 0x10a is absent from the analytical model (in \"f\")"
    );
    assert_eq!(
        estimate_cycles(M4, &d, &[]).unwrap(),
        CycleEstimate::default()
    );
    // A successor that is neither the target nor the next instruction (an exception entry,
    // say) is an error rather than a taken branch.
    assert!(matches!(
        estimate_cycles(M4, &d, &[0x106, 0x400]),
        Err(CycleModelError::UnexpectedSuccessor {
            address: 0x106,
            next: 0x400
        })
    ));
}
