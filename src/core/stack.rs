//! Portable high-water measurement for downward-growing embedded stacks.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::NonNull;

pub const DEFAULT_SENTINEL: u8 = 0xaa;

/// Target-specific description of a downward-growing stack.
///
/// # Safety
///
/// `bottom` and `top` must bound one writable stack allocation that remains
/// valid for the duration of every borrow of this provider. `bottom` is
/// inclusive and `top` is exclusive. The stack pointer may range from
/// `bottom` through `top`, inclusive; `sp == top` represents an empty
/// full-descending stack.
pub unsafe trait DescendingStack {
    fn bottom(&self) -> NonNull<u8>;
    fn top(&self) -> NonNull<u8>;
    fn current_stack_pointer(&self) -> NonNull<u8>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct StackConfig {
    pub safe_zone_bytes: usize,
    pub sentinel: u8,
}

impl StackConfig {
    pub const fn new(safe_zone_bytes: usize) -> Self {
        Self {
            safe_zone_bytes,
            sentinel: DEFAULT_SENTINEL,
        }
    }

    pub const fn sentinel(mut self, sentinel: u8) -> Self {
        self.sentinel = sentinel;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum StackError {
    InvalidBounds,
    StackPointerOutOfBounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct StackMeasurement {
    /// Conservative usage including the live frame and safe zone at paint time.
    pub high_water_bytes: usize,
    pub available_bytes: usize,
    pub painted_bytes: usize,
    pub safe_zone_bytes: usize,
    /// True when the lowest sentinel was overwritten or nothing could be painted.
    pub overflowed: bool,
}

/// Occupancy classification for one stack-map chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host", serde(rename_all = "kebab-case"))]
pub enum StackChunkState {
    Unused,
    Partial,
    Used,
}

/// Architecture-neutral view over a downward-growing stack.
///
/// The model reports offsets rather than target pointer widths, leaving text
/// layout and transport to the caller.
pub struct StackMap<'stack> {
    bottom: *const u8,
    len: usize,
    sentinel: u8,
    stack: PhantomData<&'stack UnsafeCell<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host", derive(serde::Deserialize, serde::Serialize))]
pub struct StackChunk {
    pub offset: usize,
    pub len: usize,
    pub used_bytes: usize,
    pub state: StackChunkState,
}

impl<'stack> StackMap<'stack> {
    /// Creates a view over a stack allocation.
    ///
    /// # Safety
    ///
    /// No other execution context may write the stack allocation while the
    /// returned map or any iterator borrowing it is used.
    pub unsafe fn new(
        stack: &'stack impl DescendingStack,
        sentinel: u8,
    ) -> Result<Self, StackError> {
        let bottom = stack.bottom().as_ptr() as usize;
        let top = stack.top().as_ptr() as usize;
        if bottom >= top {
            return Err(StackError::InvalidBounds);
        }
        Ok(Self {
            bottom: bottom as *const u8,
            len: top - bottom,
            sentinel,
            stack: PhantomData,
        })
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates fixed-size occupancy chunks. A zero chunk size yields no items.
    pub fn chunks(&self, chunk_bytes: usize) -> StackChunks<'_, 'stack> {
        StackChunks {
            map: self,
            offset: 0,
            chunk_bytes,
        }
    }
}

pub struct StackChunks<'map, 'stack> {
    map: &'map StackMap<'stack>,
    offset: usize,
    chunk_bytes: usize,
}

impl Iterator for StackChunks<'_, '_> {
    type Item = StackChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.map.len || self.chunk_bytes == 0 {
            return None;
        }
        let len = self.chunk_bytes.min(self.map.len - self.offset);
        let mut used_bytes = 0;
        for index in 0..len {
            // SAFETY: offset + index is bounded by the validated stack range.
            let value =
                unsafe { core::ptr::read_volatile(self.map.bottom.add(self.offset + index)) };
            used_bytes += usize::from(value != self.map.sentinel);
        }
        let chunk = StackChunk {
            offset: self.offset,
            len,
            used_bytes,
            state: if used_bytes == 0 {
                StackChunkState::Unused
            } else if used_bytes == len {
                StackChunkState::Used
            } else {
                StackChunkState::Partial
            },
        };
        self.offset += len;
        Some(chunk)
    }
}

#[derive(Debug)]
pub struct StackProbe<'stack> {
    bottom: NonNull<u8>,
    top: NonNull<u8>,
    painted_end: NonNull<u8>,
    config: StackConfig,
    stack: PhantomData<&'stack UnsafeCell<u8>>,
}

impl<'stack> StackProbe<'stack> {
    /// Paints unused stack below the current live frame.
    ///
    /// # Safety
    ///
    /// No interrupt, task, scheduler, or other execution context may access
    /// this stack allocation during the call. The caller may allow stack use
    /// again after painting and before measuring the result.
    pub unsafe fn paint(
        stack: &'stack impl DescendingStack,
        config: StackConfig,
    ) -> Result<Self, StackError> {
        let bottom = stack.bottom();
        let top = stack.top();
        let sp = stack.current_stack_pointer();
        let bottom_addr = bottom.as_ptr() as usize;
        let top_addr = top.as_ptr() as usize;
        let sp_addr = sp.as_ptr() as usize;

        if bottom_addr >= top_addr {
            return Err(StackError::InvalidBounds);
        }
        if sp_addr < bottom_addr || sp_addr > top_addr {
            return Err(StackError::StackPointerOutOfBounds);
        }

        let painted_end_addr = sp_addr
            .saturating_sub(config.safe_zone_bytes)
            .max(bottom_addr);
        let painted_bytes = painted_end_addr - bottom_addr;
        if painted_bytes != 0 {
            // SAFETY: DescendingStack guarantees writable bounds, and this
            // interval was validated to end below the current SP.
            unsafe { core::ptr::write_bytes(bottom.as_ptr(), config.sentinel, painted_bytes) };
        }
        // SAFETY: the address lies within the validated stack allocation.
        let painted_end = unsafe { NonNull::new_unchecked(painted_end_addr as *mut u8) };
        Ok(Self {
            bottom,
            top,
            painted_end,
            config,
            stack: PhantomData,
        })
    }

    /// Scans the painted region and returns conservative high-water evidence.
    ///
    /// # Safety
    ///
    /// No other execution context may write the painted stack region during
    /// this scan. Stack activity between [`Self::paint`] and this call is the
    /// workload being measured and is allowed.
    pub unsafe fn measure(&self) -> StackMeasurement {
        let bottom = self.bottom.as_ptr() as usize;
        let top = self.top.as_ptr() as usize;
        let painted_end = self.painted_end.as_ptr() as usize;
        let mut current = bottom;
        while current < painted_end {
            // SAFETY: current remains within the provider's allocation.
            if unsafe { core::ptr::read_volatile(current as *const u8) } != self.config.sentinel {
                break;
            }
            current += 1;
        }
        StackMeasurement {
            high_water_bytes: top - current,
            available_bytes: top - bottom,
            painted_bytes: painted_end - bottom,
            safe_zone_bytes: self.config.safe_zone_bytes,
            overflowed: painted_end == bottom || current == bottom,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::UnsafeCell;

    use super::*;

    struct FakeStack {
        memory: UnsafeCell<[u8; 64]>,
        sp_offset: usize,
    }

    impl FakeStack {
        fn new(fill: u8, sp_offset: usize) -> Self {
            Self {
                memory: UnsafeCell::new([fill; 64]),
                sp_offset,
            }
        }

        fn pointer_at(&self, offset: usize) -> *mut u8 {
            self.memory.get().cast::<u8>().wrapping_add(offset)
        }

        fn byte(&self, offset: usize) -> u8 {
            // SAFETY: callers use offsets within the fixed test allocation.
            unsafe { core::ptr::read_volatile(self.pointer_at(offset)) }
        }

        fn write(&self, offset: usize, value: u8) {
            // SAFETY: callers use offsets within the fixed test allocation.
            unsafe { core::ptr::write_volatile(self.pointer_at(offset), value) }
        }
    }

    // SAFETY: the UnsafeCell allocation is writable and the test controls all access.
    unsafe impl DescendingStack for FakeStack {
        fn bottom(&self) -> NonNull<u8> {
            NonNull::new(self.pointer_at(0)).unwrap()
        }

        fn top(&self) -> NonNull<u8> {
            NonNull::new(self.pointer_at(64)).unwrap()
        }

        fn current_stack_pointer(&self) -> NonNull<u8> {
            NonNull::new(self.pointer_at(self.sp_offset)).unwrap()
        }
    }

    #[test]
    fn paints_below_live_stack_and_reports_high_water() {
        let stack = FakeStack::new(0, 56);
        // SAFETY: the test exclusively owns and accesses this fake stack.
        let probe = unsafe { StackProbe::paint(&stack, StackConfig::new(8)) }.unwrap();
        assert!((0..48).all(|offset| stack.byte(offset) == DEFAULT_SENTINEL));
        stack.write(40, 0);
        // SAFETY: no other context can access the fake stack during the scan.
        let measurement = unsafe { probe.measure() };
        assert_eq!(measurement.high_water_bytes, 24);
        assert!(!measurement.overflowed);
    }

    #[test]
    fn detects_lower_bound_overflow() {
        let stack = FakeStack::new(0, 56);
        // SAFETY: the test exclusively owns and accesses this fake stack.
        let probe = unsafe { StackProbe::paint(&stack, StackConfig::new(8)) }.unwrap();
        stack.write(0, 0);
        // SAFETY: no other context can access the fake stack during the scan.
        assert!(unsafe { probe.measure() }.overflowed);
    }

    #[test]
    fn reports_an_unpaintable_safe_zone_conservatively() {
        let stack = FakeStack::new(0, 32);
        // SAFETY: the test exclusively owns and accesses this fake stack.
        let probe = unsafe { StackProbe::paint(&stack, StackConfig::new(64)) }.unwrap();
        // SAFETY: no other context can access the fake stack during the scan.
        let measurement = unsafe { probe.measure() };
        assert_eq!(
            measurement,
            StackMeasurement {
                high_water_bytes: 64,
                available_bytes: 64,
                painted_bytes: 0,
                safe_zone_bytes: 64,
                overflowed: true,
            }
        );
    }

    #[test]
    fn accepts_one_past_top_as_an_empty_stack_pointer() {
        let stack = FakeStack::new(0, 64);
        // SAFETY: the test exclusively owns and accesses this fake stack.
        let probe = unsafe { StackProbe::paint(&stack, StackConfig::new(8)) }.unwrap();
        assert!((0..56).all(|offset| stack.byte(offset) == DEFAULT_SENTINEL));
        // SAFETY: no other context can access the fake stack during the scan.
        assert_eq!(unsafe { probe.measure() }.painted_bytes, 56);
    }

    #[test]
    fn stack_map_reports_unused_partial_and_used_chunks() {
        let stack = FakeStack::new(DEFAULT_SENTINEL, 64);
        for offset in 20..48 {
            stack.write(offset, 0);
        }
        // SAFETY: the test performs no writes while the map is observed.
        let map = unsafe { StackMap::new(&stack, DEFAULT_SENTINEL) }.unwrap();
        let chunks: std::vec::Vec<_> = map.chunks(16).collect();
        assert_eq!(chunks[0].state, StackChunkState::Unused);
        assert_eq!(chunks[1].state, StackChunkState::Partial);
        assert_eq!(chunks[1].used_bytes, 12);
        assert_eq!(chunks[2].state, StackChunkState::Used);
        assert_eq!(chunks[3].state, StackChunkState::Unused);
    }

    #[test]
    fn rejects_invalid_stack_pointer_and_bounds() {
        let invalid_sp = FakeStack::new(0, 65);
        assert_eq!(
            // SAFETY: validation rejects the pointer before accessing memory.
            unsafe { StackProbe::paint(&invalid_sp, StackConfig::new(8)) }.unwrap_err(),
            StackError::StackPointerOutOfBounds
        );

        struct InvalidBounds;
        // SAFETY: no memory is accessed because the equal bounds are rejected.
        unsafe impl DescendingStack for InvalidBounds {
            fn bottom(&self) -> NonNull<u8> {
                NonNull::dangling()
            }
            fn top(&self) -> NonNull<u8> {
                NonNull::dangling()
            }
            fn current_stack_pointer(&self) -> NonNull<u8> {
                NonNull::dangling()
            }
        }
        assert_eq!(
            // SAFETY: validation rejects the bounds before accessing memory.
            unsafe { StackProbe::paint(&InvalidBounds, StackConfig::new(0)) }.unwrap_err(),
            StackError::InvalidBounds
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn serde_round_trips_stack_evidence() {
        let measurement = StackMeasurement {
            high_water_bytes: 320,
            available_bytes: 8192,
            painted_bytes: 7800,
            safe_zone_bytes: 64,
            overflowed: false,
        };
        let encoded = serde_json::to_string(&measurement).unwrap();
        assert_eq!(
            serde_json::from_str::<StackMeasurement>(&encoded).unwrap(),
            measurement
        );
    }
}
