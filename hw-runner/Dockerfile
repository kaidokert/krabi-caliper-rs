# Hardware constant-time job image: flash + measure on a bench rig via
# probe-rs + krabi-caliper. RIG-AGNOSTIC — the probe serial, clock, uhubctl
# coords etc. arrive at runtime from the mounted rig .env (${KRABI_PROBE} and
# friends). This image is only the toolchain + probe access; nothing here is
# F407- or bench-specific, so one image serves every rig.
#
# Built and published by .github/workflows/hw-runner-image.yml as
# ghcr.io/kaidokert/krabi-hw-runner:caliper-<KRABI_CALIPER_VERSION>-probe-rs-<PROBE_RS_TAG>-<distro>-<recipe>,
# the image .github/workflows/hw-ct.yml runs hardware jobs in. <recipe> is a
# hash of this file, so any edit here publishes under a new tag and the
# defaults in hw-ct.yml must follow (CI reports the expected value).
FROM rust:1-trixie

# probe-rs needs libusb + libudev (build + run). uhubctl for power-cycle recovery
# (fiddly from a container — walks host /sys; see hw-ct.yml note). git/curl come
# from the rust base (buildpack-deps) — needed by actions/checkout.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libusb-1.0-0-dev libudev-dev pkg-config cmake \
        usbutils uhubctl \
    && rm -rf /var/lib/apt/lists/*

# Cross target for the Cortex-M firmware krabi-caliper builds + flashes.
RUN rustup target add thumbv7em-none-eabihf

# probe-rs CLI (the `probe-rs` binary lives in the probe-rs-tools crate), built
# from the kaidokert/probe-rs fork at a fixed tag: the same build every bench
# host and dev box runs, carrying fixes not yet released upstream (0.29.1 from
# crates.io hangs the probe; see kaidokert/fixed-bigint-rs#198).
# Drop the cargo registry/git cache IN THE SAME LAYER — cargo install downloads
# every dependency's source (~GB) and it's dead weight at runtime. Kept as its
# own layer so it stays cached across caliper bumps.
ARG PROBE_RS_GIT=https://github.com/kaidokert/probe-rs
ARG PROBE_RS_TAG=v0.32.0-kk.2
RUN cargo install probe-rs-tools --git ${PROBE_RS_GIT} --tag ${PROBE_RS_TAG} --locked \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# The measurement harness, invoked as `cargo krabi-caliper`, from crates.io.
# Pinned EXACT so a later release can't silently change what the bench runs.
# Needs both cli + campaign features (the cargo-krabi-caliper bin's
# required-features). Same in-layer cache cleanup.
ARG KRABI_CALIPER_VERSION=0.4.0-alpha.1
RUN cargo install krabi-caliper --version =${KRABI_CALIPER_VERSION} --locked --features cli,campaign \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# cargo + the installed bins are on PATH via the rust base image
# (/usr/local/cargo/bin), so `cargo krabi-caliper` and `probe-rs` just work.
