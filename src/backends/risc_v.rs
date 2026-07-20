//! RISC-V machine-mode architectural counter adapters.

use core::arch::asm;

use crate::{Counter, Measurement, Unit};

#[inline(always)]
#[cfg(target_arch = "riscv32")]
fn read_csr64<const LOW: usize, const HIGH: usize>() -> u64 {
    loop {
        let hi1: u32;
        let lo: u32;
        let hi2: u32;
        // SAFETY: the selected CSRs are read-only observations. Omitting
        // `nomem` keeps each read sequence as a compiler memory barrier.
        unsafe {
            asm!(
                "csrr {hi1}, {high}",
                "csrr {lo}, {low}",
                "csrr {hi2}, {high}",
                hi1 = out(reg) hi1,
                lo = out(reg) lo,
                hi2 = out(reg) hi2,
                low = const LOW,
                high = const HIGH,
                options(nostack),
            );
        }
        if hi1 == hi2 {
            return ((hi1 as u64) << 32) | lo as u64;
        }
    }
}

#[inline(always)]
#[cfg(target_arch = "riscv64")]
fn read_csr64<const LOW: usize, const HIGH: usize>() -> u64 {
    let value: u64;
    let _ = HIGH;
    // SAFETY: the selected CSR is a read-only observation. Omitting `nomem`
    // keeps the read as a compiler memory barrier.
    unsafe {
        asm!(
            "csrr {value}, {low}",
            value = out(reg) value,
            low = const LOW,
            options(nostack),
        );
    }
    value
}

fn elapsed_measurement(start: u64, end: u64, unit: Unit, frequency_hz: Option<u64>) -> Measurement {
    let mut measurement = Measurement::new(end.wrapping_sub(start), unit).with_wrapped(end < start);
    measurement.frequency_hz = frequency_hz;
    measurement
}

/// The machine-mode `mcycle`/`mcycleh` cycle counter.
///
/// Reading these CSRs requires execution in machine mode. The application
/// owns counter-inhibit policy and clock qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McycleCounter {
    frequency_hz: Option<u64>,
}

impl McycleCounter {
    pub const fn new(frequency_hz: Option<u64>) -> Self {
        Self { frequency_hz }
    }
}

impl Counter for McycleCounter {
    type Instant = u64;

    #[inline(always)]
    fn now(&mut self) -> Self::Instant {
        read_csr64::<0xB00, 0xB80>()
    }

    #[inline(always)]
    fn elapsed(&mut self, start: Self::Instant) -> Measurement {
        elapsed_measurement(start, self.now(), Unit::CoreCycles, self.frequency_hz)
    }
}

/// The machine-mode `minstret`/`minstreth` retired-instruction counter.
///
/// Reading these CSRs requires execution in machine mode. The application
/// owns counter-inhibit policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MinstretCounter;

impl MinstretCounter {
    pub const fn new() -> Self {
        Self
    }
}

impl Counter for MinstretCounter {
    type Instant = u64;

    #[inline(always)]
    fn now(&mut self) -> Self::Instant {
        read_csr64::<0xB02, 0xB82>()
    }

    #[inline(always)]
    fn elapsed(&mut self, start: Self::Instant) -> Measurement {
        elapsed_measurement(start, self.now(), Unit::Instructions, None)
    }
}
