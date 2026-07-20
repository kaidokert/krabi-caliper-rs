# krabi-caliper-rs
# Krabi Caliper

Portable measurement primitives for embedded Rust targets and host-side
analysis.

This repository is being assembled through small, dependency-ordered changes.
The initial API provides architecture-neutral, allocation-free counter and
sample types suitable for `no_std` firmware. Target counter backends,
reporting transports, stack measurement, paired constant-time acquisition,
and host campaign tooling will be added in subsequent reviewed changes.

## Current API

- Runtime-qualified measurements retaining unit, frequency, and counter-wrap
  evidence.
- Exact rational operations-per-second conversion without floating point.
- Application-owned counter adaptation through `ReadCounter`.
- Fixed-capacity raw sample collection and summary statistics without
  allocation.

```sh
cargo test --all-features
cargo check --no-default-features
```

The crate requires Rust 1.86 or newer and uses the Rust 2024 edition.

## License

Licensed under either Apache-2.0 or MIT, at your option.
