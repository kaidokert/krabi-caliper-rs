//! Shared Valgrind taint acquisition and CT-grind campaign policy.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;
use std::{eprintln, format, print};

use super::backends::CommandSpec;

/// Canonical host invocation for a CT-grind fixture binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CtgrindCommand {
    pub binary: PathBuf,
    pub cwd: PathBuf,
    pub valgrind: OsString,
    pub timeout: Duration,
    pub quiet: bool,
    pub extra_args: Vec<OsString>,
}

impl CtgrindCommand {
    pub fn new(binary: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            cwd: cwd.into(),
            valgrind: "valgrind".into(),
            timeout: Duration::from_secs(300),
            quiet: true,
            extra_args: Vec::new(),
        }
    }

    pub fn command_spec(&self) -> CommandSpec {
        let mut spec = CommandSpec::new(self.valgrind.clone(), self.cwd.clone())
            .args(["--tool=memcheck", "--error-limit=no", "--error-exitcode=0"])
            .timeout(self.timeout);
        if self.quiet {
            spec = spec.arg("-q");
        }
        spec = spec.args(self.extra_args.iter().cloned());
        spec.arg(self.binary.as_os_str())
    }
}

/// One registered constant-time fixture.
pub struct CtgrindFixture {
    pub name: &'static str,
    pub run: fn(),
}

inventory::collect!(CtgrindFixture);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CtgrindReport {
    pub positive_passed: usize,
    pub positive_failed: Vec<&'static str>,
    pub negative_seen: usize,
    pub negative_missed: Vec<&'static str>,
    pub unclassified: Vec<&'static str>,
}

impl CtgrindReport {
    pub fn passed(&self) -> bool {
        self.positive_passed > 0
            && self.negative_seen > 0
            && self.positive_failed.is_empty()
            && self.negative_missed.is_empty()
            && self.unclassified.is_empty()
    }

    pub fn render(&self) -> String {
        let mut output = format!(
            "==== CT-ctgrind report ====\n  ct_fix__*       passed: {}  failed: {}\n  nct_fix__neg__* tripped: {}/{}\n",
            self.positive_passed,
            self.positive_failed.len(),
            self.negative_seen - self.negative_missed.len(),
            self.negative_seen,
        );
        for fixture in &self.positive_failed {
            output.push_str(&format!(
                "    FAIL (positive tripped Valgrind): {fixture}\n"
            ));
        }
        for fixture in &self.negative_missed {
            output.push_str(&format!("    FAIL (negative didn't trip): {fixture}\n"));
        }
        for fixture in &self.unclassified {
            output.push_str(&format!(
                "    FAIL (unclassified fixture name): {fixture}\n"
            ));
        }
        if self.positive_passed + self.positive_failed.len() == 0 {
            output.push_str("error: no positive fixtures registered — registry empty?\n");
        }
        if self.negative_seen == 0 {
            output.push_str("error: no negative controls registered — registry empty?\n");
        }
        output
    }
}

fn classify(results: impl IntoIterator<Item = (&'static str, bool)>) -> CtgrindReport {
    let mut report = CtgrindReport::default();
    for (name, tripped) in results {
        if name.starts_with("ct_fix__") {
            if tripped {
                report.positive_failed.push(name);
            } else {
                report.positive_passed += 1;
            }
        } else if name.starts_with("nct_fix__neg__") {
            report.negative_seen += 1;
            if !tripped {
                report.negative_missed.push(name);
            }
        } else {
            report.unclassified.push(name);
        }
    }
    report
}

/// Runs registered fixtures in stable name order and enforces both protected
/// fixture and detector-control policies.
pub fn run_registered() -> ExitCode {
    if !is_under_valgrind() {
        eprintln!(
            "error: ct-ctgrind must be run under valgrind \
             (e.g. `valgrind --tool=memcheck --error-limit=no --error-exitcode=0 ct-ctgrind`)"
        );
        return ExitCode::from(2);
    }

    let mut fixtures: Vec<&CtgrindFixture> =
        inventory::iter::<CtgrindFixture>.into_iter().collect();
    fixtures.sort_by_key(|fixture| fixture.name);
    let report = classify(fixtures.into_iter().map(|fixture| {
        let before = count_errors();
        (fixture.run)();
        let after = count_errors();
        (fixture.name, after > before)
    }));
    print!("{}", report.render());
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn taint<T>(values: &[T]) {
    mark_undefined(values.as_ptr().cast(), std::mem::size_of_val(values));
}

pub fn taint_val<T>(value: &T) {
    mark_undefined((value as *const T).cast(), std::mem::size_of::<T>());
}

pub fn untaint<T>(values: &[T]) {
    mark_defined(values.as_ptr().cast(), std::mem::size_of_val(values));
}

pub fn untaint_val<T>(value: &T) {
    mark_defined((value as *const T).cast(), std::mem::size_of::<T>());
}

#[cfg(target_os = "linux")]
pub fn is_under_valgrind() -> bool {
    crabgrind::valgrind::running_mode() != crabgrind::valgrind::RunningMode::Native
}

#[cfg(not(target_os = "linux"))]
pub fn is_under_valgrind() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn count_errors() -> usize {
    crabgrind::valgrind::count_errors()
}

#[cfg(not(target_os = "linux"))]
pub fn count_errors() -> usize {
    0
}

#[cfg(target_os = "linux")]
pub fn mark_undefined(address: *const u8, len: usize) {
    use std::ffi::c_void;
    crabgrind::memcheck::mark_memory(
        address.cast::<c_void>(),
        len,
        crabgrind::memcheck::MemState::Undefined,
    )
    .expect("memcheck mark_mem(Undefined) client request failed");
}

#[cfg(not(target_os = "linux"))]
pub fn mark_undefined(_: *const u8, _: usize) {}

#[cfg(target_os = "linux")]
pub fn mark_defined(address: *const u8, len: usize) {
    use std::ffi::c_void;
    crabgrind::memcheck::mark_memory(
        address.cast::<c_void>(),
        len,
        crabgrind::memcheck::MemState::Defined,
    )
    .expect("memcheck mark_mem(Defined) client request failed");
}

#[cfg(not(target_os = "linux"))]
pub fn mark_defined(_: *const u8, _: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_clean_positives_and_a_tripping_negative_control() {
        let pass = classify([("ct_fix__clean", false), ("nct_fix__neg__branch", true)]);
        assert!(pass.passed());

        let missed = classify([("ct_fix__clean", false), ("nct_fix__neg__branch", false)]);
        assert!(!missed.passed());
        assert_eq!(missed.negative_missed, ["nct_fix__neg__branch"]);

        let leak = classify([("ct_fix__leak", true), ("nct_fix__neg__branch", true)]);
        assert!(!leak.passed());
        assert_eq!(leak.positive_failed, ["ct_fix__leak"]);
    }

    #[test]
    fn canonical_command_disables_error_saturation() {
        let command = CtgrindCommand::new("target/release/gate", ".").command_spec();
        assert_eq!(
            command.args,
            [
                "--tool=memcheck",
                "--error-limit=no",
                "--error-exitcode=0",
                "-q",
                "target/release/gate",
            ]
            .map(OsString::from)
        );
    }
}
