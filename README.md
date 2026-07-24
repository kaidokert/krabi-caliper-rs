# Krabi Caliper

[![Rust CI](https://github.com/kaidokert/krabi-caliper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/kaidokert/krabi-caliper-rs/actions/workflows/ci.yml)

Measurement tools for embedded Rust firmware and the host processes that build,
run, and analyse it.

Krabi Caliper gives embedded projects one `no_std` measurement model and one
host-side evidence pipeline for:

- cycle, instruction, stack, and binary-footprint measurement;
- repeated and paired constant-time experiments;
- Cortex-M, RISC-V, AVR, QEMU, and simavr targets;
- retained build/run evidence with JSON, CSV, and Markdown reports.

It is a library, not an embedded application framework. Applications retain
ownership of their HAL or PAC, clocks, linker layout, interrupts, runtime,
debug probes, and hardware topology.

## Use it

Measurement fixtures built as examples, tests, or benchmarks can keep Caliper
as a development dependency:

```toml
[dev-dependencies]
krabi-caliper = { version = "0.1", features = ["cortex-m", "semihosting", "stack"] }
```

Use `[dependencies]` instead when instrumentation is part of a normal library
or binary target.

Install the host tooling and run a configured campaign:

```sh
cargo install krabi-caliper --features cli,campaign
cargo krabi-caliper run smoke
```

See the [user guide](docs/user-guide.md) for target integration, campaign
configuration, feature selection, and measurement contracts.

Default features are empty. Krabi Caliper uses Rust 2024 and requires Rust
1.86 or newer.

## License

Licensed under either Apache-2.0 or MIT, at your option.
