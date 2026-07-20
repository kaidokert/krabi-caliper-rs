//! Generic byte-oriented UART transport.
//!
//! Applications retain ownership of device initialization and MMIO while the
//! adapter supplies the same `fmt::Write` interface used by other reporters.

use core::fmt;

use crate::report::TextReporter;

pub trait WriteByte {
    fn write_byte(&mut self, byte: u8);
}

pub struct UartWriter<T> {
    tx: T,
}

pub type UartReporter<T> = TextReporter<UartWriter<T>>;

pub const fn reporter<T>(tx: T) -> UartReporter<T> {
    TextReporter::new(UartWriter::new(tx))
}

impl<T> UartWriter<T> {
    pub const fn new(tx: T) -> Self {
        Self { tx }
    }

    pub fn into_inner(self) -> T {
        self.tx
    }
}

impl<T: WriteByte> fmt::Write for UartWriter<T> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            self.tx.write_byte(byte);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    struct Buffer<'a> {
        bytes: &'a mut [u8],
        used: usize,
    }

    impl WriteByte for Buffer<'_> {
        fn write_byte(&mut self, byte: u8) {
            self.bytes[self.used] = byte;
            self.used += 1;
        }
    }

    #[test]
    fn adapts_byte_transmitters_to_fmt_write() {
        let mut bytes = [0_u8; 8];
        let mut writer = reporter(Buffer {
            bytes: &mut bytes,
            used: 0,
        });

        write!(writer, "EM_TEST").unwrap();
        let buffer = writer.into_inner().into_inner();
        assert_eq!(&buffer.bytes[..buffer.used], b"EM_TEST");
    }
}
