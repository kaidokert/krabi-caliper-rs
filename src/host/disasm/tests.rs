use super::thumb::*;
use super::*;

/// `nm -S -n -C` for a small image. `alias` shares `entry`'s address and comes second.
const NM: &str = "\
00000100 00000020 T entry
00000100 00000020 T alias
00000120 0000000c T leaf::h0123456789abcdef
0000012c 00000010 t indirect
00000140 00000006 T recursive
20000000 00000004 B STATE
";

/// `objdump -d --demangle --no-show-raw-insn` for the same image, in LLVM's layout.
const OBJDUMP: &str = "
image:\tfile format elf32-littlearm

Disassembly of section .text:

00000100 <entry>:
     100: \tpush\t{r4, r5, r7, lr}
     102: \tsub\tsp, #0x10
     104: \tcmp\tr0, #0x0
     106: \tbne\t0x10e <entry+0xe>       @ imm = #0x4
     108: \tbl\t0x120 <leaf::h0123456789abcdef> @ imm = #0x14
     10c: \tb\t0x112 <entry+0x12>
     10e: \tbl\t0x12c <indirect>
     112: \tadd\tsp, #0x10
     114: \tpop\t{r4, r5, r7, pc}
     116: \t.word\t0x20000000
     11a: \tldr\tr0, [pc, #0x4]
     11c: \tnop

00000120 <leaf::h0123456789abcdef>:
     120: \tpush.w\t{r4-r11, lr}
     124: \tsub.w\tsp, sp, #0x100
     128: \tbx\tlr

0000012c <indirect>:
     12c: \tpush\t{r7, lr}
     12e: \tblx\tr3
     130: \tb.w\t0x120 <leaf::h0123456789abcdef>
     134: \tpop\t{r7, pc}

00000140 <recursive>:
     140: \tpush\t{lr}
     142: \tbl\t0x140 <recursive>
     144: \tpop\t{pc}
";

fn sample() -> Disassembly {
    Disassembly::parse(NM, OBJDUMP).unwrap()
}

#[test]
fn functions_take_nm_names_and_sizes() {
    let d = sample();
    let names = d
        .functions
        .values()
        .map(|f| (f.address, f.size, f.name.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            (0x100, 0x20, "entry"),
            (0x120, 0xc, "leaf::h0123456789abcdef"),
            (0x12c, 0x10, "indirect"),
            (0x140, 6, "recursive"),
        ]
    );
    // Directives are not instructions; the instruction after one belongs to the function.
    assert!(!d.instructions.contains_key(&0x116));
    assert_eq!(d.owner_of(0x11c).unwrap().name, "entry");
    assert!(d.owner_of(0x200).is_none());
}

#[test]
fn instruction_sizes_come_from_neighbours_and_are_clamped() {
    let d = sample();
    let size = |address| d.instructions[&address].size;
    assert_eq!(size(0x100), 2);
    assert_eq!(size(0x108), 4);
    // The literal pool after `pop` makes the gap 6 bytes: clamped to 4.
    assert_eq!(size(0x114), 4);
    // The last instruction runs to the function end (0x120): 4 bytes.
    assert_eq!(size(0x11c), 4);
    assert_eq!(size(0x120), 4);
    assert_eq!(d.instructions[&0x106].operands, "0x10e <entry+0xe>");
    assert_eq!(d.instructions[&0x120].mnemonic, "push.w");
}

#[test]
fn call_edges_and_frames() {
    let d = sample();
    let entry = &d.functions[&0x100];
    // Branches inside the function are not edges; calls to other starts are.
    assert_eq!(entry.calls, BTreeSet::from([0x120, 0x12c]));
    assert!(entry.unresolved_calls.is_empty());
    assert_eq!(entry.local_stack_upper, 4 * 4 + 0x10);
    let leaf = &d.functions[&0x120];
    assert_eq!(leaf.local_stack_upper, 9 * 4 + 0x100);
    let indirect = &d.functions[&0x12c];
    // A tail branch to another function counts as an edge.
    assert_eq!(indirect.calls, BTreeSet::from([0x120]));
    assert_eq!(indirect.unresolved_calls, ["0x12e: blx r3"]);
    // A self-call is not an edge, but it is recorded.
    assert!(d.functions[&0x140].calls.is_empty());
    assert!(d.functions[&0x140].calls_self);
    assert!(!entry.calls_self);
    assert!(d.functions.values().all(|f| f.uncounted.is_empty()));
}

#[test]
fn what_the_estimate_cannot_see_is_listed() {
    let nm = "00000100 00000040 T f\n00000200 00000004 T g\n";
    let objdump = "
00000100 <f>:
     100: \tvpush\t{d8}
     104: \tsubw\tsp, sp, #0x404
     108: \tsub\tsp, #16
     10a: \tadd\tsp, r1
     10c: \tstr\tr0, [sp, #-0x8]!
     110: \tbx\tr3
     112: \tmov\tpc, r2
     114: \tldr\tpc, [r0]
     118: \tbl\t0x300
     11c: \tb\t120 <g>
     120: \tb\t0x204 <g+0x4>
     124: \tb\t0x100 <f>
     128: \tbne\t0x110 <f+0x10>
     12a: \ttbb\t[pc, r0]
     12e: \tbx\tlr

00000200 <g>:
     200: \tbx\tlr
";
    let d = Disassembly::parse(nm, objdump).unwrap();
    let f = &d.functions[&0x100];
    let reasons = f
        .uncounted
        .iter()
        .map(|line| line.split_once(' ').unwrap().1)
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        [
            "vpush {d8} (vpush not counted)",
            "subw sp, sp, #0x404 (subw not counted)",
            "sub sp, #16 (stack adjustment not counted)",
            "add sp, r1 (register stack adjustment not counted)",
            "str r0, [sp, #-0x8]! (pre-indexed store to sp not counted)",
            "bx r3 (indirect branch)",
            "mov pc, r2 (indirect branch)",
            "ldr pc, [r0] (indirect branch)",
            "bl 0x300 (target starts no function)",
            "b 120 <g> (indirect branch)",
            "b 0x204 <g+0x4> (target starts no function)",
        ]
    );
    // A `b` to its own start is a loop, not recursion; internal branches and table branches
    // are fine.
    assert!(!f.calls_self);
    assert!(f.calls.is_empty());
    assert_eq!(f.local_stack_upper, 0);
    assert_eq!(
        d.composed_stack_upper(0x100).unwrap(),
        ComposedStack {
            bytes: 0,
            bounded: false
        }
    );
}

#[test]
fn shared_callees_compose_once_and_identically() {
    // A diamond: a calls b and c, both call d. Each level doubles the paths.
    let mut nm = String::new();
    let mut objdump = String::new();
    let levels = 40u64;
    for level in 0..levels {
        for side in 0..2u64 {
            let address = 0x1000 + level * 0x20 + side * 0x10;
            nm.push_str(&format!("{address:08x} 00000010 T f{level}_{side}\n"));
            objdump.push_str(&format!(
                "{address:08x} <f{level}_{side}>:\n {address:x}: \tpush\t{{r7, lr}}\n"
            ));
            if level + 1 < levels {
                for next in 0..2u64 {
                    let target = 0x1000 + (level + 1) * 0x20 + next * 0x10;
                    objdump.push_str(&format!(
                        " {:x}: \tbl\t{target:#x} <f{}_{next}>\n",
                        address + 2 + next * 4,
                        level + 1
                    ));
                }
            }
        }
    }
    let d = Disassembly::parse(&nm, &objdump).unwrap();
    // 2^40 paths; memoised composition still answers at once.
    assert_eq!(
        d.composed_stack_upper(0x1000).unwrap(),
        ComposedStack {
            bytes: 8 * levels,
            bounded: true
        }
    );
}

#[test]
fn lookups_and_reachability() {
    let d = sample();
    assert_eq!(d.find_exact("entry").unwrap().address, 0x100);
    assert!(matches!(
        d.find_exact("alias"),
        Err(DisasmError::NoSuchFunction(_))
    ));
    assert_eq!(d.find_unique("::h0123").unwrap().address, 0x120);
    assert!(matches!(
        d.find_unique("e"),
        Err(DisasmError::NotUnique { matches: 4, .. })
    ));
    assert!(matches!(
        d.find_unique("absent"),
        Err(DisasmError::NotUnique { matches: 0, .. })
    ));
    assert_eq!(
        d.reachable_from(0x100, UnresolvedCallPolicy::Allow)
            .unwrap(),
        BTreeSet::from([0x100, 0x120, 0x12c])
    );
    assert!(matches!(
        d.reachable_from(0x100, UnresolvedCallPolicy::Reject),
        Err(DisasmError::UnresolvedCalls { .. })
    ));
    assert!(matches!(
        d.reachable_from(0x999, UnresolvedCallPolicy::Allow),
        Err(DisasmError::MissingFunction(0x999))
    ));
}

#[test]
fn composed_stack_follows_the_deepest_chain() {
    let d = sample();
    assert_eq!(
        d.composed_stack_upper(0x120).unwrap(),
        ComposedStack {
            bytes: 0x124,
            bounded: true
        }
    );
    // entry (0x20) + max(leaf 0x124, indirect 8 + leaf 0x124), and the indirect call makes it
    // unbounded.
    assert_eq!(
        d.composed_stack_upper(0x100).unwrap(),
        ComposedStack {
            bytes: 0x20 + 8 + 0x124,
            bounded: false
        }
    );
    assert!(matches!(
        Disassembly::parse(
            NM,
            "00000140 <recursive>:\n 140: \tbl\t0x150 <other>\n00000150 <other>:\n 150: \tb\t0x140 <recursive>\n"
        )
        .unwrap()
        .composed_stack_upper(0x140),
        Err(DisasmError::Recursive(0x140))
    ));
    // Direct recursion through `bl` to its own start.
    assert!(matches!(
        d.composed_stack_upper(0x140),
        Err(DisasmError::Recursive(0x140))
    ));
    assert!(matches!(
        Disassembly::parse(NM, "nothing here\n"),
        Err(DisasmError::Empty)
    ));
}

#[test]
fn thumb_helpers() {
    assert_eq!(normalize_mnemonic("bne.w"), "b");
    assert_eq!(normalize_mnemonic("bls"), "b");
    assert_eq!(normalize_mnemonic("addeq"), "add");
    assert_eq!(normalize_mnemonic("bics"), "bics");
    assert_eq!(normalize_mnemonic("push.w"), "push");
    assert_eq!(normalize_mnemonic("vpush"), "vpush");
    assert!(is_control_transfer("cbz"));
    assert!(is_control_transfer("tbb"));
    assert!(!is_control_transfer("bic"));
    assert_eq!(target_address("0x10f <x>"), Some(0x10e));
    assert_eq!(target_address("r3"), None);
    assert_eq!(immediate_value("sp, sp, #0x100"), Some(0x100));
    assert_eq!(immediate_value("sp, sp, #16"), None);
    assert_eq!(register_count("{r4-r11, lr}"), 9);
    assert_eq!(register_count("{r7, lr}"), 2);
    assert_eq!(register_count("r0, r1"), 0);
}

/// GNU `objdump -d -l` layout: tab-separated columns and `path:line` annotations.
const LINES: &str = "\
00001000 <compute>:
compute():
/src/app/src\\filter.rs:10
    1000:\tb580      \tpush\t{r7, lr}
/src/app/src/filter.rs:11
    1002:\t4401      \tadd\tr1, r0
    1004:\t0000      \t.word\t0x00000000
/src/app/src/other.rs:3
    1008:\t4770      \tbx\tlr
/src/app/src/filter.rs:40
    100a:\tbf00      \tnop
";

#[test]
fn line_attribution_counts_instructions_in_range() {
    assert_eq!(
        line_attributed_instructions(LINES, "src/filter.rs", 10..=11, true),
        2
    );
    // Without skipping directives, the literal word counts too.
    assert_eq!(
        line_attributed_instructions(LINES, "src/filter.rs", 10..=11, false),
        3
    );
    assert_eq!(
        line_attributed_instructions(LINES, "filter.rs", 40..=40, true),
        1
    );
    assert_eq!(
        line_attributed_instructions(LINES, "src/other.rs", 1..=2, true),
        0
    );
    let body = function_body(LINES, "compute").unwrap();
    assert!(body.starts_with("00001000 <compute>:\n"));
    assert!(function_body(LINES, "absent").is_none());
}

#[test]
fn first_stack_allocation_takes_one_per_function() {
    let listing = "\
00000100 <app::filter::run::h1>:
     100: b580  push {r7, lr}
     102: b084  sub sp, #0x10
     104: b082  sub sp, #0x8
00000200 <app::filter::run::h2>:
     200: b088  sub sp, #0x20
00000300 <app::other>:
     300: b0c0  sub sp, #0x100
";
    assert_eq!(
        first_stack_allocation(listing, "filter::run", false).unwrap(),
        0x20
    );
    assert!(matches!(
        first_stack_allocation(listing, "absent", false),
        Err(DisasmError::NoExplicitFrame(_))
    ));
    assert_eq!(first_stack_allocation(listing, "absent", true).unwrap(), 0);
}

#[test]
fn chain_budget_reports_every_frame_and_the_total() {
    let frames = BTreeMap::from([("entry", 16), ("a", 8), ("b", 24), ("c", 40), ("d", 32)]);
    let mut budget = ChainBudget::new("entry", 16, 100);
    budget.serial = vec![("a".to_string(), 8), ("b".to_string(), 16)];
    budget.nested = vec![("c".to_string(), 64), ("d".to_string(), 64)];
    budget.overhead = 4;
    budget.entry_overhead = 8;
    let lines = budget
        .check(|name| Ok(frames[name]))
        .unwrap()
        .into_iter()
        .map(|line| (line.name.clone(), line.bytes, line.within()))
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            ("a".to_string(), 8, true),
            ("b".to_string(), 24, false),
            ("c".to_string(), 40, true),
            ("d".to_string(), 32, true),
            ("entry".to_string(), 16, true),
            ("chain".to_string(), 16 + 32 + 40 + 4 + 8, true),
        ]
    );
    // Sums saturate instead of overflowing.
    let mut huge = ChainBudget::new("entry", u64::MAX, u64::MAX);
    huge.serial = vec![("a".to_string(), u64::MAX), ("b".to_string(), u64::MAX)];
    let lines = huge.check(|_| Ok(u64::MAX)).unwrap();
    assert_eq!(lines.last().unwrap().bytes, u64::MAX);
}

#[test]
fn llvm_line_annotations_and_tool_errors() {
    // LLVM's `objdump -l` prints `; path:line` comments.
    let listing = "\
00001000 <compute>:
; compute():
; /src/app/src/filter.rs:10
    1000: \tpush\t{r7, lr}
; /src/app/src/other.rs:3
    1002: \tbx\tlr
";
    assert_eq!(
        line_attributed_instructions(listing, "src/filter.rs", 10..=10, true),
        1
    );
    let missing = DisasmTools::new("krabi-caliper-no-such-nm", "krabi-caliper-no-such-objdump");
    let error = Disassembly::from_elf("image", &missing).unwrap_err();
    assert!(matches!(error, DisasmError::Tool { .. }), "{error}");
    assert!(error.to_string().contains("krabi-caliper-no-such-nm"));
}
