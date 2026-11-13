# Krabi Caliper user guide

Krabi Caliper provides a common vocabulary for cycle counts, instruction
counts, stack high-water marks, binary footprint, repeated benchmarks, and
constant-time experiments. Target code emits typed evidence through a small
`no_std` API; host tooling can run campaigns and retain the commands, firmware,
raw output, metadata, and reports needed to interpret that evidence.

## Target integration

For measurement fixtures built as examples, tests, or benchmarks, select only
the target facilities used and keep them out of the normal dependency graph:

```toml
[dev-dependencies]
krabi-caliper = { version = "0.2", features = ["cortex-m", "semihosting", "stack"] }
```

Use `[dependencies]` instead when instrumentation is compiled into a normal
library or binary target.

Application-owned counters can be adapted without adopting a particular HAL:

```rust
use krabi_caliper::{Counter, ReadCounter, Unit};

let mut counter = ReadCounter::new(
    || read_extended_timer(),
    Unit::TimerTicks,
    Some(15_625),
);

let start = counter.now();
operation_under_test();
let elapsed = counter.elapsed(start);
```

The returned `Measurement` retains its unit, optional frequency, and wrap
state. Architecture adapters build on the same measurement and reporting
types.

Target facilities include:

- allocation-free measurements, samples, summaries, and repeated benchmarks;
- stack painting through an application-supplied memory contract;
- Cortex-M SysTick and DWT, RISC-V cycle/instruction CSRs, and ATmega2560
  Timer1 adapters;
- the versioned `EM_*` event protocol over formatting sinks, `ufmt`, RTT,
  semihosting, or application-owned UART output;
- balanced paired acquisition and deterministic fixtures.

## Host campaigns

Install the Cargo subcommand:

```sh
cargo install krabi-caliper --features cli,campaign
```

Place `krabi-caliper.toml` beside the fixture:

```toml
[profiles.qemu-m3]
preset = "qemu-cortex-m3"
timeout-seconds = 30

[[case-sets.smoke]]
name = "baseline"
example = "baseline"
features = ["baseline"]
expected-benchmark = "my-benchmark"

[campaigns.smoke]
profile = "qemu-m3"
case-set = "smoke"
```

Then validate or run it:

```sh
cargo krabi-caliper validate-config
cargo krabi-caliper run smoke
```

Commands are announced by default and complete stdout and stderr are retained
for failed builds and runs. Use `--silent` only when command announcements are
not wanted.

For a scarce hardware runner, build the firmware on a hosted runner and pass
the prepared bundle to the hardware job:

```sh
# Hosted build job
cargo krabi-caliper build smoke --output target/prepared

# Hardware execution job, after downloading the complete prepared directory
cargo krabi-caliper run smoke --prepared target/prepared/manifest.json
```

Prepared execution does not invoke Cargo. It requires the same clean source
commit, verifies the selected cases and every firmware SHA-256 digest, and
resolves runner-only bindings such as probe selectors only in the execution
job. CI remains responsible for artifact transfer and for acquiring any
hardware lock after the bundle has been downloaded.

Host facilities include Cargo artifact discovery, timeouts, retained logs, ELF
footprint extraction, comparisons, JSON/CSV/Markdown reports, CT-grind
integration, panic-path auditing, Welch analysis, and combined DWT/ETM
evidence.

## Counting instructions from QEMU execution traces

`host::exec_trace` (with `host`) counts the instructions an image executes
between two markers, from QEMU's per-instruction exec log:

```rust,ignore
use krabi_caliper::host::exec_trace::{
    ExecTracePcs, QemuExecTrace, TraceMarker, marker_intervals,
};

let (trace, _attempts) = QemuExecTrace::new(
    "qemu-system-arm",
    ["-cpu", "cortex-m4", "-machine", "mps2-an386", "-nographic",
     "-semihosting-config", "enable=on,target=native", "-kernel", "app.elf"],
)
.attempts(3)
.timeout(std::time::Duration::from_secs(120))
.capture(std::path::Path::new("target/trace.log"))?;
// Marker functions from the symbol table: value (bit 0 is ignored) and size.
let begin = TraceMarker::function(0x1001, 4);
let end = TraceMarker::function(0x1005, 4);
let intervals = marker_intervals(ExecTracePcs::open(&trace)?, &begin, &end, None)?;
let counts: Vec<usize> = intervals.iter().map(Vec::len).collect();
```

`capture` appends `-accel tcg,one-insn-per-tb=on -d exec,nochain -D <trace>`,
which makes every executed instruction one log line (QEMU 8.1 or later). It
kills a run at the timeout, which also bounds the trace size, and retries
failed runs. A relative trace path is resolved against `cwd`. The image must
exit on its own, for example through semihosting.

An interval opens on a PC in `begin` and skips PCs that stay in `begin` right
after it. It then holds every later PC up to (not including) the first PC in
`end`, including callees, returns into `begin` and interrupt handlers.
`TraceMarker::Address` marks a single address instead of a function. Pass a
limit to stop after that many intervals. A trace that ends inside an interval,
or never reaches `begin`, is an error, as is a `Trace` line without a readable
PC. Each interval keeps its PCs, so callers can attribute them to functions
(for example with a disassembly) before counting. PCs and markers are compared
with bit 0 cleared (Thumb), and the CPU index is ignored, so trace single-core
machines.

These are instruction counts from an emulator, not cycles: QEMU models no
pipeline, caches or wait states. Record the QEMU version with the counts, since
the log format and translation belong to QEMU.

## Feature groups

- Target core: `paired`, `stack`, `deterministic-rng`
- Architectures: `cortex-m`, `cortex-m-dwt`, `risc-v`, `avr`,
  `avr-atmega2560`
- Target transports: `rtt`, `semihosting`, `uart`, `ufmt`
- Host analysis: `host`, `campaign`, `ctgrind`
- Cargo subcommand: `cli` plus `campaign`

Default features are empty. Hardware-specific features are opt-in so the core
measurement types remain portable and `no_std`.

## Measurement contracts

Krabi Caliper records evidence; it cannot make an uncontrolled experiment
comparable. Callers remain responsible for clock configuration, counter
ownership, interrupt behaviour, stack bounds, compiler and linker settings,
probe selection, and target reset state.

In particular:

- DWT cycle counts wrap at 32 bits.
- ARMv6-M cores do not provide the DWT cycle counter.
- ATmega2560 Timer1 wrap extension requires its overflow handler and global
  interrupts to be enabled.
- Debugger output must remain outside measured intervals.
- Cycle-count agreement is useful regression evidence, not proof of identical
  execution traces.

Campaign reports retain available configuration and toolchain identity so
comparisons can reject or expose incompatible evidence.

## Development checks

```sh
cargo test --all-features
cargo check --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
```
