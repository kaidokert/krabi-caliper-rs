//! RISC-V machine-mode architectural counter adapters.

use core::arch::asm;

#[cfg(feature = "stack")]
use crate::stack::{DescendingStack, StackConfig};
#[cfg(feature = "stack")]
use crate::{Benchmark, BenchmarkError, BenchmarkReporter, BenchmarkResult, CounterPlatform};
use crate::{Counter, Measurement, Unit};

#[cfg(feature = "stack")]
use crate::FootprintError;
#[cfg(feature = "stack")]
use crate::report::{Field, MeasurementRecord, OutcomeRecord, StackRecord, StackReporter};
#[cfg(feature = "stack")]
use crate::stack::paint_riscv_runtime;

const CSR_MCYCLE: usize = 0xB00;
const CSR_MINSTRET: usize = 0xB02;
const CSR_MCYCLEH: usize = 0xB80;
const CSR_MINSTRETH: usize = 0xB82;

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
        read_csr64::<CSR_MCYCLE, CSR_MCYCLEH>()
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
        read_csr64::<CSR_MINSTRET, CSR_MINSTRETH>()
    }

    #[inline(always)]
    fn elapsed(&mut self, start: Self::Instant) -> Measurement {
        elapsed_measurement(start, self.now(), Unit::Instructions, None)
    }
}

/// A 32-bit MMIO UART transmit FIFO whose high bit reports `full`.
#[cfg(feature = "uart")]
pub struct MmioTxFifo32<const TXDATA: usize>;

#[cfg(feature = "uart")]
impl<const TXDATA: usize> MmioTxFifo32<TXDATA> {
    /// # Safety
    /// `TXDATA` must be a writable transmit-data register exclusively owned by this writer.
    pub const unsafe fn new() -> Self {
        Self
    }
}

#[cfg(feature = "uart")]
impl<const TXDATA: usize> crate::protocol::uart::WriteByte for MmioTxFifo32<TXDATA> {
    fn write_byte(&mut self, byte: u8) {
        let register = TXDATA as *mut u32;
        unsafe {
            while core::ptr::read_volatile(register) & (1 << 31) != 0 {}
            core::ptr::write_volatile(register, byte as u32);
        }
    }
}

/// Writes one application-authorized 32-bit MMIO control register.
///
/// # Safety
/// `address` must identify a writable register owned by the caller.
pub unsafe fn write_mmio32(address: usize, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

/// Client-owned policy for one RISC-V footprint operation.
#[cfg(feature = "stack")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FootprintConfig<'a> {
    pub benchmark: &'a str,
    pub fields: &'a [Field<'a>],
    pub cycle_frequency_hz: Option<u64>,
}

#[cfg(feature = "stack")]
impl<'a> FootprintConfig<'a> {
    pub const fn new(benchmark: &'a str, fields: &'a [Field<'a>]) -> Self {
        Self {
            benchmark,
            fields,
            cycle_frequency_hz: None,
        }
    }

    pub const fn frequency_hz(mut self, frequency_hz: u64) -> Self {
        self.cycle_frequency_hz = Some(frequency_hz);
        self
    }
}

/// Paints the runtime stack, measures one operation, and emits canonical events.
///
/// # Safety
/// The `riscv-rt` linker stack must be exclusively owned while the probe is active.
#[cfg(feature = "stack")]
pub unsafe fn run_footprint<const SAFE_ZONE_BYTES: usize, R: StackReporter>(
    reporter: impl FnOnce() -> R,
    config: FootprintConfig<'_>,
    operation: fn() -> bool,
) -> Result<bool, FootprintError<R::Error>> {
    let stack_probe =
        unsafe { paint_riscv_runtime::<SAFE_ZONE_BYTES>() }.map_err(FootprintError::Stack)?;
    let mut cycles = McycleCounter::new(config.cycle_frequency_hz);
    let mut instructions = MinstretCounter::new();
    let cycles_start = cycles.now();
    let instructions_start = instructions.now();
    let passed = operation();
    let instruction_measurement = instructions.elapsed(instructions_start);
    let cycle_measurement = cycles.elapsed(cycles_start);
    let stack = unsafe { stack_probe.measure() };
    let mut reporter = reporter();

    reporter
        .measurement(&MeasurementRecord {
            benchmark: config.benchmark,
            measurement: instruction_measurement,
            counter: Some("minstret"),
            fields: config.fields,
        })
        .map_err(FootprintError::Reporter)?;
    reporter
        .measurement(&MeasurementRecord {
            benchmark: config.benchmark,
            measurement: cycle_measurement,
            counter: Some("mcycle"),
            fields: config.fields,
        })
        .map_err(FootprintError::Reporter)?;
    reporter
        .stack_measurement(&StackRecord {
            benchmark: config.benchmark,
            measurement: stack,
            fields: config.fields,
        })
        .map_err(FootprintError::Reporter)?;
    reporter
        .outcome(&OutcomeRecord {
            benchmark: config.benchmark,
            passed,
            fields: config.fields,
        })
        .map_err(FootprintError::Reporter)?;
    Ok(passed)
}

/// Runs a repeated cycle benchmark with a caller-owned stack allocation.
///
/// # Safety
/// The caller must uphold [`Benchmark::run_with_stack`]'s exclusive stack
/// access contract for the supplied allocation.
#[cfg(feature = "stack")]
pub unsafe fn run_benchmark<const N: usize, R: BenchmarkReporter>(
    cycle_frequency_hz: Option<u64>,
    reporter: &mut R,
    benchmark: &Benchmark<'_, N>,
    stack: &impl DescendingStack,
    stack_config: StackConfig,
    operation: impl FnMut() -> bool,
) -> Result<BenchmarkResult<N>, BenchmarkError<R::Error>> {
    let mut platform = CounterPlatform::new(McycleCounter::new(cycle_frequency_hz));
    unsafe { benchmark.run_with_stack(&mut platform, reporter, stack, stack_config, operation) }
}

/// Debugger-safe terminal loop for RISC-V measurement firmware.
///
/// This intentionally avoids `wfi`: attached debuggers can interact poorly
/// with architectural wait instructions. A command runner should terminate
/// the target after observing its completion record.
pub fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
