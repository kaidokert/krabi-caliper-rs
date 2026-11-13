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

## Recording provenance

A figure is comparable with another only when both came from the same sources,
dependencies, tools and images. `host::provenance` (with `campaign`) records
those inputs as content hashes and version lines:

```rust
use krabi_caliper::host::provenance::{Provenance, SourceTree};

let sources = SourceTree::new(".")
    .file("Cargo.toml")
    .file("memory.x")
    .directory("src")
    .extension("rs");
let record = Provenance::new()
    .source_tree(&sources)?
    .lockfile("Cargo.lock".as_ref())?
    .tool("rustc", "rustc", ["--version"])?
    .tool("emulator", "qemu-system-arm", ["--version"])?
    .image("app", "target/thumbv7m-none-eabi/release/app".as_ref())?;
```

The source-tree digest covers exactly the selected files (directories are
searched for the listed extensions, skipping `target`), including their
relative paths, so adding, renaming or editing a selected file changes it and
nothing else does. It is independent of the checkout location and the host's
path separator. Missing files and failing tools are errors. Store the record
beside the results, and use `Provenance::differences` to list what changed
between two records; deciding whether a change invalidates a comparison is up
to the caller.

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
