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
  Timer1 adapters (Timer1 at a chosen prescaler, `Timer1Prescale`, from `/1`
  for one tick per CPU cycle to `/1024` for long intervals; the overflow ISR
  must run within 0x8000 ticks of each wrap);
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

### Runner presets

A profile's `preset` supplies the runner command, the target and the recorded
board, MCU and transport. A field set in the profile overrides the preset's
value.

- `qemu-cortex-m0`, `qemu-cortex-m3`, `qemu-cortex-m4`: QEMU, reporting over
  semihosting.
- `qemu-riscv32-sifive-e`: QEMU, reporting over UART.
- `simavr-atmega2560`: simavr, reporting over UART.
- `probe-rs-rtt`: physical hardware through `probe-rs run`, reporting over RTT.

### `probe-rs-rtt`

```toml
[venues.bench]
bindings = { PROBE_RS_CHIP = "STM32L431KCUx", PROBE_RS_PROBE = "0483:374f:000000000000" }

[profiles.l431]
preset = "probe-rs-rtt"
target = "thumbv7em-none-eabihf"
venue = "bench"
```

The preset needs two bindings, from a venue's `bindings` or the environment:

- `PROBE_RS_CHIP`: the probe-rs chip name, recorded as the MCU.
- `PROBE_RS_PROBE`: the probe selector. Use `VID:PID:Serial` when several
  probes of one model are attached; `VID:PID` matches each of them. The
  selector is not part of the configuration identity, so replacing a probe
  does not block comparisons.

The profile sets `target`, because the target triple depends on the chip.

The firmware must report over RTT (the `rtt` feature). With
`cortex_m_reporter!("<feature>")`, list that feature in the profile's
`build-features`; without it the firmware reports over semihosting and the run
times out.

The run ends at the first `EM_OUTCOME` event. On Unix probe-rs then gets SIGINT
so it can detach from the target, and is killed if it has not exited within
three seconds. On Windows it is killed after those three seconds. A timeout
kills it at once.

`build --output` needs neither binding, so firmware can be built where no probe
is attached. `validate` and `run` resolve every profile in the file, so set the
bindings wherever those commands run, or keep hardware profiles in a separate
configuration file.

`mcu` and `probe` set in a profile are recorded metadata only. `args` replaces
the whole command line, including the chip and probe selectors.

Host facilities include Cargo artifact discovery, timeouts, retained logs, ELF
footprint extraction, comparisons, JSON/CSV/Markdown reports, CT-grind
integration, panic-path auditing, Welch analysis, and combined DWT/ETM
evidence.

`read_elf_footprint` counts each section as text, read-only data, data or BSS,
by name and then by section kind, and skips the rest.
`read_elf_unclassified_sections` lists the allocated, non-empty sections it
skips, such as a linker-script `.uninit` region or `.got`, so a size gate can
require the list to be empty. Runtime reservations such as `riscv-rt`'s
`.stack` and `.heap` are listed too; a gate allows those by name.

`cargo krabi-caliper audit-elf` checks a built image for symbols and strings
that must or must not be there, for example that a feature compiled out or that
an allocator, formatting or soft float never reached the image:

```sh
cargo krabi-caliper audit-elf target/thumbv7m-none-eabi/release/app \
  --forbid-symbol core::panicking --forbid-symbol __rust_alloc \
  --forbid-string "panicked at" --require-symbol app::feature::enable
```

- Symbol rules are substrings of a symbol's name, as stored or demangled, with
  or without hashes and crate disambiguators. `core::panicking` matches legacy
  and v0 mangling.
- Only a defined symbol satisfies a required rule. Any mention, including an
  undefined reference, breaks a forbidden one.
- String rules search the contents of allocated sections, which is what reaches
  the target. `--string-scope whole-file` also searches debug information and
  symbol tables.
- `--rules` reads the same rules from a TOML file, and `--json` writes every
  image's report.

The command reports every broken rule and fails if any image breaks one. A
non-ELF file, an unreadable section, and rules with nothing to search (symbol
rules on a stripped image) are errors.

The library is `host::elf_audit`. Its `elf_symbols` lists the symbols the audit
examines in each form a rule matches, for checks a substring cannot express,
such as an anchored pattern or every match. It also fails on an image with no
symbols.

## Disassembly and static stack bounds

`host::disasm` (with `host`) reads a linked Arm Thumb image through LLVM's
`nm -S -n -C` and `objdump -d --demangle --no-show-raw-insn`:

```rust,ignore
use krabi_caliper::host::disasm::{Disassembly, DisasmTools, UnresolvedCallPolicy};

fn stack_of(elf: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let image = Disassembly::from_elf(elf, &DisasmTools::cargo_binutils())?;
    let root = image.find_unique("app::measured::")?.address;
    let _reachable = image.reachable_from(root, UnresolvedCallPolicy::Reject)?;
    let stack = image.composed_stack_upper(root)?;
    if !stack.bounded {
        return Err("the analysis skipped something below the root".into());
    }
    Ok(stack.bytes)
}
```

Each function carries its `nm` size, instructions, static call edges (calls,
tail calls and conditional branches into another function) and a frame
estimate: four bytes per pushed register plus every `sub sp, #0x..`.
`composed_stack_upper` sums frames along the deepest static chain and rejects
recursion; `composed_stack_upper_with(root, RecursionPolicy::CountOnce)` instead
counts each recursive frame once and clears `bounded`, for recursion that is
bounded in practice (library sorts, for example). It is a heuristic, not a proof: indirect calls, indirect branches,
table branches (`tbb`/`tbh`), branches to addresses that start no function, and
stack adjustments it does not count (`subw`, `vpush`, register adjustments,
`mov sp, rN` other than directly before a `pop`, decimal immediates) are listed
per function and clear `bounded`. Exception entry and interrupt handlers are never
included. Literal-pool words that objdump decodes as branches also show up as
uncounted, so a cleared `bounded` needs a look at the listed lines rather than
being an error by itself. Read the listing with current LLVM tools: GNU objdump's decimal
immediates and bare targets are not parsed (they show up as uncounted). Names
are the LLVM tools' demangled names, hashes included, so record those tools'
versions with the measurement.

For objdump listings, `function_body` extracts one function,
`line_attributed_instructions` counts instructions that `objdump -d -l`
attributes to a source line range, `first_stack_allocation` reads explicit
frame allocations, and `ChainBudget` checks a chain of known frames against
per-frame and total ceilings.

### Analytical Cortex-M cycle model

`host::disasm::cycles` costs an executed instruction sequence (for example the
PCs of a QEMU execution trace) with Cortex-M0, Cortex-M3 or Cortex-M4
instruction timings:

```rust,ignore
use krabi_caliper::host::disasm::cycles::{CortexMCore, estimate_cycles};

let estimate = estimate_cycles(CortexMCore::M4, &image, &pcs)?;
println!("{}..{} cycles", estimate.minimum, estimate.maximum);
```

The PCs must list every executed instruction: trace with `-d exec,nochain` and
`one-insn-per-tb=on` (see `host::exec_trace`), since plain `-d exec` logs only
block starts. The timings assume zero-wait-state memory, no bus contention and
no interrupts. A range covers what a listing cannot decide: pipeline refill
after a branch, the Cortex-M0 multiplier option, and early-terminating divides.
`M0` means Cortex-M0, not M0+, whose timings differ. A conditional branch's
direction comes from the next PC; a successor that is neither its target nor
the next instruction (an exception, say) is an error. Floating point, DSP,
non-branch writes to `pc` and Armv7-M instructions on `M0` are errors rather
than guesses.

The figures follow the Technical Reference Manuals with documented deviations,
so they are a model estimate rather than a guaranteed bracket. On M3/M4,
pipelined adjacent loads can cost less than the per-load minimum, and the M3
table-branch and long multiply-accumulate ranges are the model's own.
Condition-failed instructions inside IT blocks are charged as executed.
Exclusive loads and stores are costed as ordinary ones. The module
documentation lists the deviations in full. The result also gives per-address cycles and timing
classes, branch-direction counts and a mnemonic histogram. Parts with flash
wait states, caches or accelerators run differently, so measure on them.

## Counting instructions from QEMU execution traces

`host::exec_trace` (feature `host`) counts the instructions an image executes
between two markers, from QEMU's per-instruction execution log:

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

`QemuExecTrace::capture`:

- appends `-accel tcg,one-insn-per-tb=on -d exec,nochain -D <trace>`, which
  writes one log line per executed instruction (QEMU 8.1 or later);
- resolves a relative trace path against `cwd`;
- kills a run at the timeout, which also bounds the trace size;
- retries failed runs up to `attempts`.

The image must exit on its own, for example through semihosting.

Markers are a function's range, from `TraceMarker::function(value, size)`, or
one address, `TraceMarker::Address`. Bit 0 is cleared from markers and PCs, so
Thumb symbol values can be passed as they are.

`marker_intervals` cuts the trace into intervals:

- An interval opens on a PC in `begin`. PCs that stay in `begin` right after it
  are skipped.
- It holds every PC up to, but not including, the first PC in `end`, including
  callees, returns into `begin` and interrupt handlers.
- A begin hit inside an open interval does not restart it.
- With a limit, reading stops after that many intervals.

A trace that ends inside an interval or never reaches `begin` is an error, as
is a `Trace` line without a readable PC.

Each interval keeps its PCs, so callers can attribute them to functions, for
example with a disassembly, before counting.

The log's CPU index is ignored, so use single-core machines: PCs from several
cores would be read as one sequence.

These are instruction counts from an emulator, not cycles: QEMU models no
pipeline, caches or wait states. The log format can change between QEMU
versions, so record the QEMU version with the counts.

## Feature groups

- Target core: `paired`, `stack`, `deterministic-rng`
- Architectures: `cortex-m`, `cortex-m-dwt`, `risc-v`, `avr`,
  `avr-atmega2560`
- Target transports: `rtt`, `semihosting`, `uart`, `ufmt`
  (with `uart` and `ufmt` together, `protocol::uart::ufmt_reporter` reports
  through any `protocol::uart::WriteByte` transmitter without requiring
  `core::fmt`)
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
