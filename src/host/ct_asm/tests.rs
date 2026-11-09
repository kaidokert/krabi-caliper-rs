#[cfg(test)]
mod tests {
    use super::*;

    /// Ladder violations for a RISC-V listing under counted-loop acceptance.
    fn riscv_ladder(listing: &str, allowance: usize) -> Vec<u64> {
        let blocks = split_blocks(listing);
        let block = &blocks[0];
        let patterns =
            Patterns::new(crate::host::isa::RISCV_FORBIDDEN, &[], &[], &[], &[]).unwrap();
        let loops = Some(LoopIsa::RiscV);
        let (found, accepted) = split_counted(block, scan_block(block, &patterns, false), loops);
        ladder_violations(block, found, &accepted, allowance, loops)
            .iter()
            .map(|v| v.offset)
            .collect()
    }

    /// A counted ladder loop: `a0` counts down by one to zero.
    fn counted_ladder(body: &str) -> std::string::String {
        std::format!(
            "<ct_fix__x>:\n\
            \x20 00:\tli\ta0, 0x40\n\
            \x20 04:\tlw\ta2, 0x0(a1)\n\
            {body}\
            \x20 20:\taddi\ta0, a0, -0x1\n\
            \x20 24:\tbnez\ta0, 0x4 <ct_fix__x+0x4>\n\
            \x20 28:\tret\n"
        )
    }

    #[test]
    fn counted_ladder_loop_alone_passes() {
        // Passing with no allowance shows the model accepts the back edge.
        assert_eq!(riscv_ladder(&counted_ladder(""), 0), [0u64; 0]);
    }

    #[test]
    fn counted_ladder_does_not_free_the_allowance_for_a_body_branch() {
        let listing = counted_ladder(
            "\x20 08:\tbeqz\ta2, 0x10 <ct_fix__x+0x10>\n\
            \x20 0c:\txor\ta3, a3, a2\n",
        );
        assert_eq!(riscv_ladder(&listing, 1), [0x8]);
    }

    #[test]
    fn counted_ladder_does_not_free_the_allowance_for_an_early_exit() {
        let listing = counted_ladder("\x20 08:\tbnez\ta2, 0x28 <ct_fix__x+0x28>\n");
        assert_eq!(riscv_ladder(&listing, 1), [0x8]);
    }

    #[test]
    fn allowance_covers_an_uncounted_back_edge_and_zero_trip_guard() {
        // The back edge tests a loaded bound, so the model does not accept it.
        let listing = "<ct_fix__x>:\n\
            \x20 00:\tlw\ta0, 0x0(a1)\n\
            \x20 04:\tbeqz\ta0, 0x14 <ct_fix__x+0x14>\n\
            \x20 08:\tlw\ta2, 0x4(a1)\n\
            \x20 0c:\tsrl\ta0, a0, a2\n\
            \x20 10:\tbnez\ta0, 0x8 <ct_fix__x+0x8>\n\
            \x20 14:\tret\n";
        assert_eq!(riscv_ladder(listing, 2), [0u64; 0]);
        assert_eq!(riscv_ladder(listing, 1), [0x10]);
        let with_body = listing.replace(
            "\x20 0c:\tsrl\ta0, a0, a2\n",
            "\x20 0c:\tbeqz\ta2, 0x10 <ct_fix__x+0x10>\n\x20 0e:\tsrl\ta0, a0, a2\n",
        );
        assert_eq!(riscv_ladder(&with_body, 2), [0xc]);
    }
    #[test]
    fn thumb_it_does_not_mask_a_conditional_branch() {
        let blocks = split_blocks("<ct_fix__x>:\n  0: it eq\n  2: beq 0x8\n");
        let patterns =
            Patterns::new(&[r"^b(?:eq|ne)$"], &[r"^it[te]{0,3}$"], &[], &[], &[]).unwrap();
        let found = scan_block(&blocks[0], &patterns, true);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mnemonic, "beq");
    }
    #[test]
    fn relocation_drives_reachability() {
        let blocks = split_blocks(
            "<ct_fix__x>:\n  0: bl 0x0\n  0: R_ARM_THM_CALL helper\n<helper>:\n  0: bx lr\n",
        );
        let calls = [Regex::new(r"^bl$").unwrap()];
        let reached = compute_reachable_symbols(&blocks, &calls);
        assert!(reached.contains("helper"));
    }

    #[test]
    fn avr_section_relocation_drives_reachability() {
        let blocks = split_blocks(
            "<ct_fix__x>:\n  0: call 0x0\n  0: R_AVR_CALL .text.helper\n<helper>:\n  0: ret\n",
        );
        let calls = [Regex::new(r"^call$").unwrap()];
        let reached = compute_reachable_symbols(&blocks, &calls);
        assert!(reached.contains("helper"));
    }

    #[test]
    fn parses_nested_generic_symbols_and_architecture_neutral_implicit_offsets() {
        let blocks = split_blocks(
            "<ct_fix__generic::<core::option::Option<u8>>>:\n  nop\n  ret\n",
        );
        assert_eq!(
            blocks[0].symbol,
            "ct_fix__generic::<core::option::Option<u8>>"
        );
        assert_eq!(blocks[0].insns[0].offset, 0);
        assert_eq!(blocks[0].insns[1].offset, 1);
        assert_eq!(
            extract_target("bl <helper::<core::option::Option<u8>>>").as_deref(),
            Some("helper::<core::option::Option<u8>>")
        );
    }

    #[test]
    fn policy_regex_errors_are_structured() {
        assert!(Patterns::new(&["("], &[], &[], &[], &[]).is_err());
        assert!(Patterns::new(&[], &[], &[], &["("], &[]).is_err());
    }

    #[test]
    fn ladder_report_requires_positive_and_every_negative_control() {
        let report = LadderReport {
            target: "thumb".to_string(),
            ladder_symbols_matched: 0,
            ladder_symbols_expected: 0,
            ladder_branches_seen: 0,
            ladder_branches_allowed: 0,
            counted_loop_branches: 0,
            positive_fixtures_checked: 0,
            negative_controls_checked: 1,
            negative_controls_tripped: 1,
            negative_controls_failed_to_trip: Vec::new(),
            ladder_violations: Vec::new(),
        };
        assert_ne!(report.exit_code(), 0);

        let report = LadderReport {
            positive_fixtures_checked: 1,
            negative_controls_checked: 2,
            negative_controls_failed_to_trip: Vec::from([
                "nct_fix__neg__missed".to_string(),
            ]),
            ..report
        };
        assert_ne!(report.exit_code(), 0);
    }

    const TEST_CALIBRATIONS: &[SymbolCalibration] = &[
        SymbolCalibration {
            display_name: "first ladder",
            selector: "first_ladder",
            expected_branches: 1,
        },
        SymbolCalibration {
            display_name: "second ladder",
            selector: "second_ladder",
            expected_branches: 2,
        },
    ];

    fn calibrated_test_target() -> CalibratedSymbolsTarget {
        CalibratedSymbolsTarget {
            triple: "thumbv7em-none-eabi",
            priority: 1,
            toolchain: "stable",
            forbidden: crate::host::isa::THUMB_FORBIDDEN,
            allowed_cmov: crate::host::isa::THUMB_ALLOWED,
            calibrations: TEST_CALIBRATIONS,
            extra_cargo_args: &[],
        }
    }

    #[test]
    fn calibrated_symbols_preserve_independent_exact_counts() {
        let blocks = split_blocks(
            "<first_ladder>:\n  0: beq 0x8\n  2: b 0xa\n\
             <second_ladder>:\n  0: bne 0x8\n  2: cbz r0, 0xa\n",
        );
        let checks = calibrate_blocks(&blocks, &calibrated_test_target()).unwrap();
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(SymbolCalibrationResult::passes));
        assert_eq!(checks[0].branches_seen, 1);
        assert_eq!(checks[1].branches_seen, 2);
    }

    #[test]
    fn calibrated_symbols_fail_closed_on_missing_or_duplicate_symbols() {
        let missing = split_blocks("<first_ladder>:\n  0: beq 0x8\n");
        let checks = calibrate_blocks(&missing, &calibrated_test_target()).unwrap();
        assert_eq!(checks[1].symbols_matched, 0);
        assert_ne!(
            CalibratedSymbolsReport {
                target: "thumbv7em-none-eabi".into(),
                checks,
            }
            .exit_code(),
            0
        );

        let duplicate = split_blocks(
            "<first_ladder>:\n  0: beq 0x8\n\
             <other_first_ladder>:\n  0: beq 0x8\n\
             <second_ladder>:\n  0: bne 0x8\n  2: cbz r0, 0xa\n",
        );
        let checks = calibrate_blocks(&duplicate, &calibrated_test_target()).unwrap();
        assert_eq!(checks[0].symbols_matched, 2);
        assert_ne!(
            CalibratedSymbolsReport {
                target: "thumbv7em-none-eabi".into(),
                checks,
            }
            .exit_code(),
            0
        );
    }

    #[test]
    fn calibrated_symbols_reject_bad_client_regex() {
        let mut target = calibrated_test_target();
        target.calibrations = &[SymbolCalibration {
            display_name: "bad",
            selector: "(",
            expected_branches: 0,
        }];
        assert!(calibrate_blocks(&[], &target).is_err());
    }
}
