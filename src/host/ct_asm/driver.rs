/// Client-owned target policy consumed by the shared assembly driver.
pub trait TargetPolicy {
    fn triple(&self) -> &'static str;
    fn priority(&self) -> u8;
    fn toolchain(&self) -> &'static str;
    fn forbidden(&self) -> &'static [&'static str];
    fn allowed(&self) -> &'static [&'static str];
    fn thumb_it_blocks(&self) -> bool {
        self.triple().starts_with("thumb")
    }
    fn calls(&self) -> &'static [&'static str] {
        &[]
    }
    fn allowed_helpers(&self) -> &'static [&'static str] {
        &[]
    }
    fn extra_allowed_helpers(&self) -> &'static [&'static str] {
        &[]
    }
    fn extra_cargo_args(&self) -> &'static [&'static str] {
        &[]
    }
    fn ladder_allowed_branches(&self) -> usize {
        0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WholeSurfaceTarget {
    pub triple: &'static str,
    pub priority: u8,
    pub toolchain: &'static str,
    pub forbidden: &'static [&'static str],
    pub allowed_cmov: &'static [&'static str],
    pub thumb_it_blocks: bool,
    pub call_mnemonics: &'static [&'static str],
    pub allowed_helpers: &'static [&'static str],
    pub extra_allowed_helpers: &'static [&'static str],
    pub extra_cargo_args: &'static [&'static str],
}
impl TargetPolicy for WholeSurfaceTarget {
    fn triple(&self) -> &'static str {
        self.triple
    }
    fn priority(&self) -> u8 {
        self.priority
    }
    fn toolchain(&self) -> &'static str {
        self.toolchain
    }
    fn forbidden(&self) -> &'static [&'static str] {
        self.forbidden
    }
    fn allowed(&self) -> &'static [&'static str] {
        self.allowed_cmov
    }
    fn thumb_it_blocks(&self) -> bool {
        self.thumb_it_blocks
    }
    fn calls(&self) -> &'static [&'static str] {
        self.call_mnemonics
    }
    fn allowed_helpers(&self) -> &'static [&'static str] {
        self.allowed_helpers
    }
    fn extra_allowed_helpers(&self) -> &'static [&'static str] {
        self.extra_allowed_helpers
    }
    fn extra_cargo_args(&self) -> &'static [&'static str] {
        self.extra_cargo_args
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LadderTarget {
    pub triple: &'static str,
    pub priority: u8,
    pub toolchain: &'static str,
    pub forbidden: &'static [&'static str],
    pub allowed_cmov: &'static [&'static str],
    pub ladder_allowed_branches: usize,
    pub extra_cargo_args: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct CalibratedSymbolsTarget {
    pub triple: &'static str,
    pub priority: u8,
    pub toolchain: &'static str,
    pub forbidden: &'static [&'static str],
    pub allowed_cmov: &'static [&'static str],
    pub calibrations: &'static [SymbolCalibration],
    pub extra_cargo_args: &'static [&'static str],
}

impl TargetPolicy for CalibratedSymbolsTarget {
    fn triple(&self) -> &'static str {
        self.triple
    }
    fn priority(&self) -> u8 {
        self.priority
    }
    fn toolchain(&self) -> &'static str {
        self.toolchain
    }
    fn forbidden(&self) -> &'static [&'static str] {
        self.forbidden
    }
    fn allowed(&self) -> &'static [&'static str] {
        self.allowed_cmov
    }
    fn extra_cargo_args(&self) -> &'static [&'static str] {
        self.extra_cargo_args
    }
}
impl TargetPolicy for LadderTarget {
    fn triple(&self) -> &'static str {
        self.triple
    }
    fn priority(&self) -> u8 {
        self.priority
    }
    fn toolchain(&self) -> &'static str {
        self.toolchain
    }
    fn forbidden(&self) -> &'static [&'static str] {
        self.forbidden
    }
    fn allowed(&self) -> &'static [&'static str] {
        self.allowed_cmov
    }
    fn extra_cargo_args(&self) -> &'static [&'static str] {
        self.extra_cargo_args
    }
    fn ladder_allowed_branches(&self) -> usize {
        self.ladder_allowed_branches
    }
}

#[derive(Clone, Copy)]
pub struct DriverConfig<'a> {
    /// Cargo workspace containing `ct-fixtures`.
    pub workspace: &'a Path,
    pub fixture_package: &'a str,
    pub fixture_features: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub struct WholeSurfaceConfig<'a> {
    pub driver: DriverConfig<'a>,
    pub memory_class_negatives: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub struct LadderConfig<'a> {
    pub driver: DriverConfig<'a>,
    pub default_ladder: &'a str,
}

#[derive(Clone, Copy)]
pub struct CalibratedSymbolsConfig<'a> {
    pub driver: DriverConfig<'a>,
}

#[derive(Default)]
struct DriverArgs {
    target: Option<String>,
    json_out: Option<PathBuf>,
    list_targets: bool,
    skip_build: bool,
    archive: Option<PathBuf>,
    ladder: Option<String>,
    expect_ladder: Option<usize>,
}

pub fn run_whole_surface<T: TargetPolicy>(
    targets: &[T],
    config: WholeSurfaceConfig<'_>,
) -> ExitCode {
    let args = match parse_driver_args(false) {
        Ok(v) => v,
        Err(e) => return usage_error(&e, false),
    };
    if args.list_targets {
        print_targets(targets);
        return ExitCode::SUCCESS;
    }
    let Some((triple, spec)) = select_target(targets, args.target.clone()) else {
        return ExitCode::from(2);
    };
    let text = match acquire_disassembly(spec, config.driver, &args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    let blocks = split_blocks(&text);
    let patterns = Patterns::new(
        spec.forbidden(),
        spec.allowed(),
        spec.calls(),
        spec.allowed_helpers(),
        spec.extra_allowed_helpers(),
    );
    let reachable = compute_reachable_symbols(&blocks, &patterns.call);
    let mut fixture_count = 0;
    let mut fixture_violations = Vec::new();
    let mut neg_seen = BTreeSet::new();
    let mut neg_tripped = BTreeSet::new();
    let mut helper_violations = Vec::new();
    let mut helpers_scanned = 0;
    let mut helpers_allowlisted = 0;
    for block in &blocks {
        if is_positive_fixture(&block.symbol) {
            fixture_count += 1;
            fixture_violations.extend(scan_block(block, &patterns, spec.thumb_it_blocks()));
            continue;
        }
        if is_negative_control(&block.symbol) {
            if config
                .memory_class_negatives
                .iter()
                .any(|name| block.symbol.contains(name))
            {
                continue;
            }
            let name = block.symbol.trim_start_matches('_').to_string();
            neg_seen.insert(name.clone());
            if !scan_block(block, &patterns, spec.thumb_it_blocks()).is_empty() {
                neg_tripped.insert(name);
            }
            continue;
        }
        if !reachable.contains(&block.symbol) {
            continue;
        }
        if is_allowed_helper(&block.symbol, &patterns.allowed_helpers) {
            helpers_allowlisted += 1;
            continue;
        }
        helpers_scanned += 1;
        helper_violations.extend(scan_block(block, &patterns, spec.thumb_it_blocks()));
    }
    let report = WholeSurfaceReport {
        target: triple,
        fixtures_checked: fixture_count,
        negative_controls_checked: neg_seen.len(),
        helpers_scanned,
        helpers_allowlisted,
        ct_violations: fixture_violations.into_iter().map(Into::into).collect(),
        helper_violations: helper_violations.into_iter().map(Into::into).collect(),
        negative_controls_failed_to_trip: negative_failures(&neg_seen, &neg_tripped),
    };
    report.print_human();
    write_report(args.json_out.as_deref(), &report);
    if fixture_count == 0 || neg_seen.is_empty() {
        eprintln!(
            "error: fixture archive self-test failed: positive or negative fixture set is empty"
        );
        return ExitCode::FAILURE;
    }
    if report.exit_code() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn run_ladder<T: TargetPolicy>(targets: &[T], config: LadderConfig<'_>) -> ExitCode {
    let args = match parse_driver_args(true) {
        Ok(v) => v,
        Err(e) => return usage_error(&e, true),
    };
    if args.list_targets {
        print_targets(targets);
        return ExitCode::SUCCESS;
    }
    let Some((triple, spec)) = select_target(targets, args.target.clone()) else {
        return ExitCode::from(2);
    };
    let text = match acquire_disassembly(spec, config.driver, &args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    let blocks = split_blocks(&text);
    let patterns = Patterns::new(spec.forbidden(), spec.allowed(), &[], &[], &[]);
    let ladder = match Regex::new(args.ladder.as_deref().unwrap_or(config.default_ladder)) {
        Ok(v) => v,
        Err(e) => return usage_error(&format!("bad --ladder regex: {e}"), true),
    };
    let mut matched = 0;
    let mut seen = 0;
    let mut violations = Vec::new();
    let mut negatives = 0;
    let mut positives = 0;
    for block in &blocks {
        if ladder.is_match(&block.symbol) {
            matched += 1;
            let mut found = scan_block(block, &patterns, spec.thumb_it_blocks());
            seen += found.len();
            if found.len() > spec.ladder_allowed_branches() {
                violations.extend(found.split_off(spec.ladder_allowed_branches()));
            }
            continue;
        }
        if is_positive_fixture(&block.symbol) {
            positives += 1;
        }
        if is_negative_control(&block.symbol)
            && !scan_block(block, &patterns, spec.thumb_it_blocks()).is_empty()
        {
            negatives += 1;
        }
    }
    let report = LadderReport {
        target: triple,
        ladder_symbols_matched: matched,
        ladder_symbols_expected: args.expect_ladder.unwrap_or(positives),
        ladder_branches_seen: seen,
        ladder_branches_allowed: spec.ladder_allowed_branches(),
        negative_controls_tripped: negatives,
        ladder_violations: violations.into_iter().map(Into::into).collect(),
    };
    report.print_human();
    write_report(args.json_out.as_deref(), &report);
    if report.exit_code() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Run an exact, multi-symbol conditional-branch calibration.
///
/// Unlike [`run_ladder`], each target owns an ordered set of selectors and an
/// independent exact branch count for every selector. The gate fails closed
/// when a selector matches zero or multiple symbols, so LTO or symbol drift
/// cannot silently reduce the checked surface.
pub fn run_calibrated_symbols(
    targets: &[CalibratedSymbolsTarget],
    config: CalibratedSymbolsConfig<'_>,
) -> ExitCode {
    let args = match parse_driver_args(false) {
        Ok(v) => v,
        Err(e) => return usage_error(&e, false),
    };
    if args.list_targets {
        print_targets(targets);
        return ExitCode::SUCCESS;
    }
    let requested = args
        .target
        .clone()
        .or_else(|| targets.first().map(|target| target.triple.to_string()));
    let Some((triple, spec)) = select_target(targets, requested) else {
        return ExitCode::from(2);
    };
    if spec.calibrations.is_empty() {
        eprintln!("error: calibrated-symbol policy for {triple} is empty");
        return ExitCode::FAILURE;
    }
    let text = match acquire_disassembly(spec, config.driver, &args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    let blocks = split_blocks(&text);
    let checks = match calibrate_blocks(&blocks, spec) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    let report = CalibratedSymbolsReport {
        target: triple,
        checks,
    };
    report.print_human();
    write_report(args.json_out.as_deref(), &report);
    if report.exit_code() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn calibrate_blocks(
    blocks: &[FunctionBlock],
    spec: &CalibratedSymbolsTarget,
) -> Result<Vec<SymbolCalibrationResult>, String> {
    let patterns = Patterns::new(spec.forbidden(), spec.allowed(), &[], &[], &[]);
    spec.calibrations
        .iter()
        .map(|calibration| {
            let selector = match Regex::new(calibration.selector) {
                Ok(value) => value,
                Err(error) => {
                    return Err(format!(
                        "bad calibrated selector {:?} for {}: {error}",
                        calibration.selector, calibration.display_name
                    ));
                }
            };
            let matched = blocks
                .iter()
                .filter(|block| selector.is_match(&block.symbol))
                .collect::<Vec<_>>();
            let branch_evidence = matched
                .iter()
                .flat_map(|block| scan_block(block, &patterns, spec.thumb_it_blocks()))
                .map(Into::into)
                .collect::<Vec<_>>();
            Ok(SymbolCalibrationResult {
                display_name: calibration.display_name.to_string(),
                selector: calibration.selector.to_string(),
                symbols_matched: matched.len(),
                expected_branches: calibration.expected_branches,
                branches_seen: branch_evidence.len(),
                matched_symbols: matched.iter().map(|block| block.symbol.clone()).collect(),
                branch_evidence,
            })
        })
        .collect()
}

fn parse_driver_args(ladder: bool) -> Result<DriverArgs, String> {
    let mut out = DriverArgs::default();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => out.target = Some(args.next().ok_or("--target requires a triple")?),
            "--json-out" => {
                out.json_out = Some(args.next().ok_or("--json-out requires a path")?.into())
            }
            "--list-targets" => out.list_targets = true,
            "--skip-build" => out.skip_build = true,
            "--archive" => {
                out.archive = Some(args.next().ok_or("--archive requires a path")?.into())
            }
            "--ladder" if ladder => {
                out.ladder = Some(args.next().ok_or("--ladder requires a regex")?)
            }
            "--expect-ladder" if ladder => {
                out.expect_ladder = Some(
                    args.next()
                        .ok_or("--expect-ladder requires a count")?
                        .parse()
                        .map_err(|_| "--expect-ladder requires an integer")?,
                )
            }
            "-h" | "--help" => {
                print_help(ladder);
                std::process::exit(0);
            }
            value if !value.starts_with('-') && out.target.is_none() => {
                out.target = Some(value.to_string())
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(out)
}

fn usage_error(message: &str, ladder: bool) -> ExitCode {
    eprintln!("error: {message}");
    print_help(ladder);
    ExitCode::from(2)
}
fn print_help(ladder: bool) {
    eprintln!(
        "ct-driver — disassemble CT fixtures and gate forbidden conditional branches\n\nUsage: ct-driver [--target TRIPLE] [--json-out PATH] [--skip-build] [--archive PATH]{}\n       ct-driver --list-targets",
        if ladder {
            " [--ladder REGEX] [--expect-ladder N]"
        } else {
            ""
        }
    );
}
fn print_targets<T: TargetPolicy>(targets: &[T]) {
    for t in targets {
        println!(
            "[{}] {}  (toolchain: {})",
            t.priority(),
            t.triple(),
            t.toolchain()
        );
    }
}
fn select_target<T: TargetPolicy>(
    targets: &[T],
    requested: Option<String>,
) -> Option<(String, &T)> {
    let triple = requested
        .or_else(host_triple)
        .unwrap_or_else(|| "x86_64-unknown-linux-gnu".to_string());
    match targets.iter().find(|t| t.triple() == triple) {
        Some(t) => Some((triple, t)),
        None => {
            eprintln!("error: unknown target triple '{triple}'. Use --list-targets.");
            None
        }
    }
}
fn host_triple() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.strip_prefix("host: ")
            .map(str::trim)
            .map(ToString::to_string)
    })
}

fn acquire_disassembly<T: TargetPolicy>(
    spec: &T,
    config: DriverConfig<'_>,
    args: &DriverArgs,
) -> Result<String, String> {
    if !args.skip_build {
        build_fixtures(spec, config)?;
    }
    let archive = args
        .archive
        .clone()
        .map(Ok)
        .unwrap_or_else(|| find_archive(spec, config));
    run_objdump(spec, &archive?)
}
fn build_fixtures<T: TargetPolicy>(spec: &T, config: DriverConfig<'_>) -> Result<(), String> {
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(config.workspace)
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg(config.fixture_package);
    if !config.fixture_features.is_empty() {
        command
            .arg("--features")
            .arg(config.fixture_features.join(","));
    }
    if host_triple().as_deref() != Some(spec.triple()) {
        command.arg("--target").arg(spec.triple());
    }
    command.args(spec.extra_cargo_args());
    eprintln!("[ct-driver] {:?}", command);
    let status = command.status().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo build exited with {status}"))
    }
}
fn find_archive<T: TargetPolicy>(spec: &T, config: DriverConfig<'_>) -> Result<PathBuf, String> {
    let target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| config.workspace.join("target"));
    let leaf = format!("lib{}.a", config.fixture_package.replace('-', "_"));
    let mut candidates = Vec::new();
    if host_triple().as_deref() == Some(spec.triple()) {
        candidates.push(target.join("release").join(&leaf));
    }
    candidates.push(target.join(spec.triple()).join("release").join(&leaf));
    candidates
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| format!("could not find {leaf} under {}", target.display()))
}
fn llvm_objdump() -> PathBuf {
    if let (Ok(sysroot), Some(host)) = (
        Command::new("rustc").args(["--print", "sysroot"]).output(),
        host_triple(),
    ) {
        if sysroot.status.success() {
            let p = Path::new(String::from_utf8_lossy(&sysroot.stdout).trim())
                .join("lib/rustlib")
                .join(host)
                .join("bin")
                .join(format!("llvm-objdump{}", env::consts::EXE_SUFFIX));
            if p.exists() {
                return p;
            }
        }
    }
    "llvm-objdump".into()
}
fn run_objdump<T: TargetPolicy>(spec: &T, archive: &Path) -> Result<String, String> {
    let mut command = Command::new(llvm_objdump());
    command.args(["--disassemble", "--no-show-raw-insn", "--reloc"]);
    if spec.triple().starts_with("avr-") || spec.triple() == "avr-none" {
        command.arg("--triple=avr");
    }
    command.arg(archive);
    let out = command.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "llvm-objdump failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
fn write_report<T: Serialize>(path: Option<&Path>, report: &T) {
    let Some(path) = path else { return };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::File::create(path)
        .and_then(|f| serde_json::to_writer_pretty(f, report).map_err(std::io::Error::other))
    {
        Ok(()) => {}
        Err(e) => eprintln!("warning: writing JSON report failed: {e}"),
    }
}
