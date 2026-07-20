# krabi-caliper-rs
# Krabi Caliper

Portable measurement primitives for embedded Rust targets and host-side
analysis.

This repository is being assembled through small, dependency-ordered changes.
The current API provides architecture-neutral, allocation-free counter,
sample, and reporting types suitable for `no_std` firmware. Additional target
adapters, reporting transports, and host campaign tooling will be added in
subsequent reviewed changes.

## Current API

- Runtime-qualified measurements retaining unit, frequency, and counter-wrap
  evidence.
- Exact rational operations-per-second conversion without floating point.
- Application-owned counter adaptation through `ReadCounter`.
- Fixed-capacity raw sample collection and summary statistics without
  allocation.
- Repeated benchmark lifecycles, external measurement boundaries, paired
  campaign suites, and reproducible non-cryptographic fixture streams.
- Borrowed typed measurement events and a versioned `EM_*` text encoding for
  any `core::fmt::Write` sink.
- Optional balanced paired acquisition and deterministic comparison policies
  for constant-time experiments.
- Optional downward-growing stack painting, high-water measurement, and
  chunked occupancy inspection behind an application-supplied memory contract.
- Optional Cortex-M DWT cycle counting on supported cores, with
  application-owned peripherals and critical-section implementation. The
  `cortex-m-dwt` feature intentionally rejects ARMv6-M targets.
- Optional machine-mode RISC-V `mcycle` and `minstret` adapters with atomic
  RV32 high/low snapshots and compiler ordering boundaries.
- Optional ATmega2560 Timer1 wrap extension with application-owned clock and
  global interrupt policy.
- Optional RTT, Cortex-M semihosting, and application-owned byte-UART adapters
  for the same text reporting protocol.
- Optional host-side protocol parsing, owned evidence, JSON/Markdown reports,
  ELF footprint extraction, and Welch timing analysis.
- Visible process-group-aware command execution, host timestamp boundaries,
  and a portable simavr Cargo runner.

```sh
cargo test --all-features
cargo check --no-default-features
```

The crate requires Rust 1.86 or newer and uses the Rust 2024 edition.

## License

Licensed under either Apache-2.0 or MIT, at your option.
