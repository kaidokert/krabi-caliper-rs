#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thumb_it_does_not_mask_a_conditional_branch() {
        let blocks = split_blocks("<ct_fix__x>:\n  0: it eq\n  2: beq 0x8\n");
        let patterns = Patterns::new(&[r"^b(?:eq|ne)$"], &[r"^it[te]{0,3}$"], &[], &[], &[]);
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
