//! Architecture-specific target measurement adapters.

#[cfg(feature = "avr")]
pub mod avr;

#[cfg(feature = "cortex-m")]
pub mod cortex_m;

#[cfg(all(
    feature = "risc-v",
    any(target_arch = "riscv32", target_arch = "riscv64")
))]
pub mod risc_v;
