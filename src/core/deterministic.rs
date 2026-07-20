//! Reproducible, explicitly non-cryptographic fixture data.

use core::convert::Infallible;

/// SplitMix64 stream for reproducible tests and matched measurement trials.
///
/// This is not a cryptographically secure random-number generator. Seeds and
/// the policy for resetting/matching streams remain fixture-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureRng {
    state: u64,
    draws: u64,
}

impl FixtureRng {
    pub const fn new(seed: u64) -> Self {
        Self {
            state: seed,
            draws: 0,
        }
    }

    pub const fn draws(&self) -> u64 {
        self.draws
    }

    pub fn next_word(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.draws = self.draws.wrapping_add(1);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Fills without slice-length assertions, keeping panic-audit artifacts
    /// free of formatting and `copy_from_slice` failure machinery.
    pub fn fill_bytes_unchecked_length(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_word().to_le_bytes();
            for (destination, source) in chunk.iter_mut().zip(bytes) {
                *destination = source;
            }
        }
    }
}

impl rand_core::TryRng for FixtureRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_word() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_word())
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_bytes_unchecked_length(destination);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixtureRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_and_draw_accounting_are_reproducible() {
        let mut left = FixtureRng::new(7);
        let mut right = FixtureRng::new(7);
        let mut bytes = [0; 17];
        left.fill_bytes_unchecked_length(&mut bytes);
        let mut expected = [0; 17];
        right.fill_bytes_unchecked_length(&mut expected);
        assert_eq!(bytes, expected);
        assert_eq!(left.draws(), 3);
    }
}
