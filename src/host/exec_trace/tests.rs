use super::*;
use std::string::ToString;

fn pcs(values: &[u64]) -> Vec<Result<u64, ExecTraceError>> {
    values.iter().copied().map(Ok).collect()
}

fn read(log: &[u8]) -> Result<Vec<u64>, ExecTraceError> {
    ExecTracePcs::new(log, "log").collect()
}

#[test]
fn reads_trace_lines_in_every_known_shape() {
    let mut log = b"\
Trace 0: 0x7f0000000100 [00000000/00000136/00000000/ff200000] main
----------------
IN: main
Trace 1: 0x7f0000000140 [00000000/00000139/00000000/ff200000] main\r
Linking TBs 0x0 [00000136] index 0 -> 0x0 [00000138]
Trace 0x7f0000000180 [0000000000000000/0000000000000142/00000000/ff200000] old layout
"
    .to_vec();
    // Stray non-UTF-8 guest output does not stop the read.
    log.extend_from_slice(b"\xff\xfe guest bytes\n");
    log.extend_from_slice(b"Trace 0: 0x0 [0/0x150/0/0]");
    // The bit 0 is cleared, CRLF is fine, and lines that are not Trace lines are skipped.
    assert_eq!(read(&log).unwrap(), [0x136, 0x138, 0x142, 0x150]);
    assert_eq!(parse_exec_trace_line(b"no brackets"), None);
    assert_eq!(
        parse_exec_trace_line(b"Trace 0: 0x0 [0/137/0/0]"),
        Some(Ok(0x137))
    );
}

#[test]
fn a_trace_line_without_a_pc_is_an_error() {
    let log = b"Trace 0: 0x0 [0/136/0/0]\nTrace 0: 0x0 [zz/qq/00]\nTrace 0: 0x0 [0/138/0/0]\n";
    let mut stream = ExecTracePcs::new(&log[..], "log");
    assert_eq!(stream.next().unwrap().unwrap(), 0x136);
    let error = stream.next().unwrap().unwrap_err();
    assert!(matches!(
        error,
        ExecTraceError::MalformedLine { line: 2, .. }
    ));
    assert_eq!(error.to_string(), "log:2: Trace line without a readable PC");
    // The stream stops after an error.
    assert!(stream.next().is_none());
}

#[test]
fn function_markers_skip_the_begin_body_and_exclude_the_end() {
    let begin = TraceMarker::function(0x100, 8);
    let end = TraceMarker::function(0x200, 8);
    let trace = pcs(&[
        0x50, 0x100, 0x102, 0x104, 0x300, 0x302, 0x100, 0x304, 0x200, 0x202, 0x400,
    ]);
    let intervals = marker_intervals(trace, &begin, &end, None).unwrap();
    // A begin hit inside an open interval does not restart it.
    assert_eq!(intervals, [vec![0x300, 0x302, 0x100, 0x304]]);
}

#[test]
fn odd_thumb_symbol_values_mark_the_right_instructions() {
    // Thumb function symbols have bit 0 set.
    let begin = TraceMarker::function(0x101, 4);
    let end = TraceMarker::Address(0x201);
    assert!(begin.contains(0x100) && begin.contains(0x102) && !begin.contains(0x104));
    let intervals =
        marker_intervals(pcs(&[0x100, 0x102, 0x104, 0x200]), &begin, &end, None).unwrap();
    assert_eq!(intervals, [vec![0x104]]);
}

#[test]
fn edge_cases_of_marker_order() {
    let begin = TraceMarker::function(0x100, 8);
    // An end inside the begin range is ignored while skipping the begin body.
    let inner_end = TraceMarker::Address(0x104);
    assert_eq!(
        marker_intervals(pcs(&[0x100, 0x104, 0x300, 0x104]), &begin, &inner_end, None).unwrap(),
        [vec![0x300]]
    );
    // With begin == end, an interval runs from leaving one hit to the next.
    assert_eq!(
        marker_intervals(
            pcs(&[0x100, 0x300, 0x302, 0x100, 0x400]),
            &begin,
            &begin,
            None
        )
        .unwrap(),
        [vec![0x300, 0x302]]
    );
    // An end before any begin is ignored.
    let end = TraceMarker::Address(0x200);
    assert_eq!(
        marker_intervals(pcs(&[0x200, 0x100, 0x200]), &begin, &end, None).unwrap(),
        [Vec::<u64>::new()]
    );
}

#[test]
fn address_markers_repeat_and_limits_stop_early() {
    let begin = TraceMarker::Address(0x100);
    let end = TraceMarker::Address(0x200);
    let trace = || {
        pcs(&[
            0x100, 0x102, 0x10, 0x200, 0x20, 0x100, 0x200, 0x100, 0x30, 0x31, 0x200, 0x100,
        ])
    };
    assert!(matches!(
        marker_intervals(trace(), &begin, &end, None),
        Err(ExecTraceError::IncompleteInterval { completed: 3 })
    ));
    let intervals = marker_intervals(trace(), &begin, &end, Some(3)).unwrap();
    // With an address marker, the rest of the begin function is counted.
    assert_eq!(intervals, [vec![0x102, 0x10], vec![], vec![0x30, 0x31]]);
    assert_eq!(
        marker_intervals(trace(), &begin, &end, Some(1)).unwrap(),
        [vec![0x102, 0x10]]
    );
    assert!(
        marker_intervals(trace(), &begin, &end, Some(0))
            .unwrap()
            .is_empty()
    );
    // A limit above what the trace holds returns what there is.
    assert_eq!(
        marker_intervals(pcs(&[0x100, 0x1, 0x200]), &begin, &end, Some(5)).unwrap(),
        [vec![0x1]]
    );
    assert!(matches!(
        marker_intervals(pcs(&[1, 2, 3]), &begin, &end, None),
        Err(ExecTraceError::NoInterval)
    ));
    // Ending while still in the begin body is incomplete too.
    assert!(matches!(
        marker_intervals(pcs(&[0x100]), &begin, &end, None),
        Err(ExecTraceError::IncompleteInterval { completed: 0 })
    ));
    // Errors from the source propagate.
    let failing = vec![Ok(0x100), Err(ExecTraceError::NoInterval), Ok(0x200)];
    assert!(matches!(
        marker_intervals(failing, &begin, &end, None),
        Err(ExecTraceError::NoInterval)
    ));
}

#[test]
fn commands_resolve_relative_traces_against_cwd() {
    let run = QemuExecTrace::new(
        "qemu-system-arm",
        ["-machine", "lm3s6965evb", "-kernel", "app"],
    )
    .attempts(0)
    .cwd("work")
    .timeout(Duration::from_secs(5));
    assert_eq!(run.attempts, 1);
    let trace = Path::new("trace.log");
    assert_eq!(run.trace_path(trace), Path::new("work").join("trace.log"));
    let spec = run.spec(trace);
    let expected: Vec<OsString> = [
        "-machine",
        "lm3s6965evb",
        "-kernel",
        "app",
        "-accel",
        "tcg,one-insn-per-tb=on",
        "-d",
        "exec,nochain",
        "-D",
    ]
    .into_iter()
    .map(OsString::from)
    .chain([Path::new("work").join("trace.log").into_os_string()])
    .collect();
    assert_eq!(spec.args, expected);
    assert_eq!(spec.cwd, Path::new("work"));
    assert_eq!(spec.timeout, Duration::from_secs(5));
    // Absolute traces stay as they are.
    let absolute = std::env::temp_dir().join("trace.log");
    assert_eq!(run.trace_path(&absolute), absolute);
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "krabi-caliper-exec-trace-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn capture_reports_every_failed_attempt() {
    let directory = scratch("missing");
    let trace = directory.join("trace.log");
    fs::write(&trace, "stale").unwrap();
    let error = QemuExecTrace::new("krabi-caliper-no-such-qemu", ["-kernel", "app"])
        .attempts(2)
        .capture(&trace)
        .unwrap_err();
    assert!(
        matches!(&error, ExecTraceError::Capture { attempts: 2, last, source: Some(_) } if last.starts_with("attempt 2/2")),
        "{error}"
    );
    // The stale trace is gone, so nobody reads it as this run's.
    assert!(!trace.exists());
    fs::remove_dir_all(directory).unwrap();
}

/// A stand-in for QEMU: writes the file after `-D` and exits successfully.
#[cfg(unix)]
fn fake_qemu(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = directory.join("fake-qemu");
    fs::write(
        &script,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -D ]; then echo 'Trace 0: 0x0 [0/101/0/0]' > \"$2\"; fi\n  shift\ndone\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
#[test]
fn capture_writes_the_trace_under_cwd() {
    let directory = scratch("fake");
    let qemu = fake_qemu(&directory);
    let (path, attempts) = QemuExecTrace::new(qemu, ["-kernel", "app"])
        .cwd(&directory)
        .capture(Path::new("trace.log"))
        .unwrap();
    assert_eq!((path.clone(), attempts), (directory.join("trace.log"), 1));
    assert_eq!(
        ExecTracePcs::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        [0x100]
    );
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn capture_times_out_a_run_that_never_exits() {
    use std::os::unix::fs::PermissionsExt;
    let directory = scratch("hang");
    // Ignores the QEMU arguments and never exits on its own.
    let hang = directory.join("hanging-qemu");
    fs::write(&hang, "#!/bin/sh\nexec sleep 30\n").unwrap();
    fs::set_permissions(&hang, fs::Permissions::from_mode(0o755)).unwrap();
    let error = QemuExecTrace::new(hang, ["-kernel", "app"])
        .timeout(Duration::from_millis(200))
        .capture(&directory.join("trace.log"))
        .unwrap_err();
    assert!(
        matches!(&error, ExecTraceError::Capture { last, .. } if last.contains("timed out")),
        "{error}"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn output_tails_respect_character_boundaries() {
    let long = "é".repeat(OUTPUT_TAIL_BYTES);
    let kept = tail(&long);
    assert!(kept.len() <= OUTPUT_TAIL_BYTES);
    assert!(kept.chars().all(|character| character == 'é'));
    assert_eq!(tail("short"), "short");
}
