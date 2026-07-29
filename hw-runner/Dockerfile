# Hardware constant-time job image: flash + measure on a bench rig via
# probe-rs + krabi-caliper. RIG-AGNOSTIC — the probe serial, clock, uhubctl
# coords etc. arrive at runtime from the mounted rig .env (${KRABI_PROBE} and
# friends). This image is only the toolchain + probe access; nothing here is
# board- or bench-specific, so one image serves every rig.
#
# Built in CI (.github/workflows/build-hw-runner-image.yml) on a GitHub-hosted
# arm64 runner and published as :caliper-<version>. Stable releases can also
# advance :latest. Each repo's hw-ct workflow references it via `container:`.
FROM rust:1-bookworm

# probe-rs needs libusb + libudev (build + run). uhubctl for power-cycle recovery
# (fiddly from a container — walks host /sys; see hw-ct.yml note). git/curl come
# from the rust base (buildpack-deps) — needed by actions/checkout.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libusb-1.0-0-dev libudev-dev pkg-config cmake \
        usbutils uhubctl \
    && rm -rf /var/lib/apt/lists/*

# Cross target for the Cortex-M firmware krabi-caliper builds + flashes.
RUN rustup target add thumbv7em-none-eabihf

# probe-rs CLI (the `probe-rs` binary lives in the probe-rs-tools crate).
# Pin the version so `probe-rs list`/`run` behaviour is reproducible.
# Drop the cargo registry/git cache IN THE SAME LAYER — cargo install downloads
# every dependency's source (~GB) and it's dead weight at runtime. Kept as its
# own layer so it stays cached across caliper bumps.
ARG PROBE_RS_VERSION=0.29.1
RUN cargo install probe-rs-tools --version ${PROBE_RS_VERSION} --locked \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# The measurement harness, invoked as `cargo krabi-caliper`. Pinned EXACT so a
# later crates.io release can't silently change what the image runs — the build
# workflow overrides this ARG from the release tag. Needs cli + campaign features
# (the cargo-krabi-caliper bin's required-features). Same in-layer cache cleanup.
ARG KRABI_CALIPER_VERSION=0.1.5
RUN cargo install krabi-caliper --version =${KRABI_CALIPER_VERSION} --locked --features cli,campaign \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# cargo + the installed bins are on PATH via the rust base image
# (/usr/local/cargo/bin), so `cargo krabi-caliper` and `probe-rs` just work.
