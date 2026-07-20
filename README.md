# krabi-caliper-rs
# Krabi Caliper

Portable measurement primitives for embedded Rust targets and host-side
analysis.

This repository is being assembled through small, dependency-ordered changes.
The current API provides architecture-neutral, allocation-free counter,
sample, and reporting types suitable for `no_std` firmware. Target counter
backends, reporting transports, stack measurement, paired constant-time
acquisition, and host campaign tooling will be added in subsequent reviewed
changes.

## Current API

- Runtime-qualified measurements retaining unit, frequency, and counter-wrap
  evidence.
- Exact rational operations-per-second conversion without floating point.
- Application-owned counter adaptation through `ReadCounter`.
- Fixed-capacity raw sample collection and summary statistics without
  allocation.
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

```sh
cargo test --all-features
cargo check --no-default-features
```

The crate requires Rust 1.86 or newer and uses the Rust 2024 edition.

## License

Licensed under either Apache-2.0 or MIT, at your option.
