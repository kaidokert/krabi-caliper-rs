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

/// A [`UfmtReporter`](crate::report::UfmtReporter) over a byte transmitter, for targets that
/// keep `core::fmt` out of the image.
#[cfg(feature = "ufmt")]
pub type UfmtUartReporter<T> = crate::report::UfmtReporter<UartWriter<T>>;

/// Wraps a byte transmitter in a [`UfmtUartReporter`].
#[cfg(feature = "ufmt")]
pub const fn ufmt_reporter<T>(tx: T) -> UfmtUartReporter<T> {
    crate::report::UfmtReporter::new(UartWriter::new(tx))
}

#[cfg(feature = "ufmt")]
impl<T: WriteByte> ufmt::uWrite for UartWriter<T> {
    type Error = core::convert::Infallible;

    fn write_str(&mut self, value: &str) -> Result<(), Self::Error> {
        for byte in value.bytes() {
            self.tx.write_byte(byte);
        }
        Ok(())
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

    #[cfg(feature = "ufmt")]
    #[test]
    fn ufmt_reporter_writes_the_same_lines_as_the_text_reporter() {
        use crate::report::{Field, MeasurementRecord, Reporter};
        use crate::{Measurement, Unit};

        let record = MeasurementRecord {
            benchmark: "update",
            measurement: Measurement::new(130, Unit::TimerTicks),
            counter: Some("timer1"),
            fields: &[Field::token("word", "i8")],
        };
        let mut text = [0_u8; 160];
        let mut expected = reporter(Buffer {
            bytes: &mut text,
            used: 0,
        });
        expected.indexed_measurement(&record, 3).unwrap();
        let expected = expected.into_inner().into_inner();

        let mut bytes = [0_u8; 160];
        let mut writer = ufmt_reporter(Buffer {
            bytes: &mut bytes,
            used: 0,
        });
        writer.indexed_measurement(&record, 3).unwrap();
        let buffer = writer.into_inner().into_inner();
        assert_eq!(
            &buffer.bytes[..buffer.used],
            &expected.bytes[..expected.used]
        );
        assert!(buffer.bytes[..buffer.used].starts_with(b"EM_MEASUREMENT "));
    }
}
