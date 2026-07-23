# Krabi Caliper user guide

Krabi Caliper provides a common vocabulary for cycle counts, instruction
counts, stack high-water marks, binary footprint, repeated benchmarks, and
constant-time experiments. Target code emits typed evidence through a small
`no_std` API; host tooling can run campaigns and retain the commands, firmware,
raw output, metadata, and reports needed to interpret that evidence.

## Target integration

Select only the facilities used by the target:

```toml
[dev-dependencies]
krabi-caliper = { version = "0.1", features = ["cortex-m", "semihosting", "stack"] }
```

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

Host facilities include Cargo artifact discovery, timeouts, retained logs, ELF
footprint extraction, comparisons, JSON/CSV/Markdown reports, CT-grind
integration, panic-path auditing, Welch analysis, and combined DWT/ETM
evidence.

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
- ATmega2560 Timer1 wrap extension requires its overflow handler and enabled
  global interrupts.
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
