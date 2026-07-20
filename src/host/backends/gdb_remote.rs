use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::string::{String, ToString};
use std::time::Duration;
use std::vec;
use std::vec::Vec;

#[derive(Debug)]
pub struct RemoteError(String);

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RemoteError {}

pub struct GdbRemote {
    stream: TcpStream,
}

impl GdbRemote {
    pub fn connect(address: impl ToSocketAddrs, timeout: Duration) -> Result<Self, RemoteError> {
        let address = address
            .to_socket_addrs()
            .map_err(error)?
            .next()
            .ok_or_else(|| RemoteError("GDB server address resolved to nothing".into()))?;
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(error)?;
        stream.set_read_timeout(Some(timeout)).map_err(error)?;
        stream.set_write_timeout(Some(timeout)).map_err(error)?;
        Ok(Self { stream })
    }

    pub fn query(&mut self, payload: &[u8]) -> Result<Vec<u8>, RemoteError> {
        let mut packet = Vec::with_capacity(payload.len() + 4);
        packet.push(b'$');
        packet.extend_from_slice(payload);
        packet.push(b'#');
        let checksum = payload
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        packet.extend_from_slice(format_hex_byte(checksum).as_bytes());
        self.stream.write_all(&packet).map_err(error)?;
        let acknowledgement = read_byte(&mut self.stream)?;
        if acknowledgement != b'+' {
            return Err(RemoteError(format_args_owned(format_args!(
                "GDB server rejected packet with byte {acknowledgement:#04x}"
            ))));
        }
        loop {
            let response = self.read_packet()?;
            if is_console_output(&response) {
                continue;
            }
            return Ok(response);
        }
    }

    pub fn monitor(&mut self, command: &str) -> Result<(), RemoteError> {
        let encoded = hex_encode(command.as_bytes());
        let payload = format_args_owned(format_args!("qRcmd,{encoded}"));
        let response = self.query(payload.as_bytes())?;
        // J-Link GDB Server returns its monitor text as a single hexadecimal
        // response packet and does not append the usual terminal `OK` packet.
        if response == b"OK"
            || (response.len() % 2 == 0
                && !response.is_empty()
                && response.iter().all(|byte| byte.is_ascii_hexdigit()))
        {
            Ok(())
        } else {
            require_ok(&response, command)
        }
    }

    pub fn write_u32(&mut self, address: u64, value: u32) -> Result<(), RemoteError> {
        let bytes = value.to_le_bytes();
        let payload = format_args_owned(format_args!("M{address:x},4:{}", hex_encode(&bytes)));
        let response = self.query(payload.as_bytes())?;
        require_ok(&response, "memory write")
    }

    pub fn read_u32(&mut self, address: u64) -> Result<u32, RemoteError> {
        let payload = format_args_owned(format_args!("m{address:x},4"));
        let response = self.query(payload.as_bytes())?;
        let bytes = hex_decode(&response)?;
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| RemoteError("GDB memory read did not return four bytes".into()))?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn start_streaming_trace(&mut self) -> Result<(), RemoteError> {
        let response = self.query(b"qSeggerSTRACE:start")?;
        require_nonnegative_i32(&response, "start streaming trace")
    }

    pub fn stop_streaming_trace(&mut self) -> Result<(), RemoteError> {
        let response = self.query(b"qSeggerSTRACE:stop")?;
        require_nonnegative_i32(&response, "stop streaming trace")
    }

    pub fn continue_until_halt(&mut self) -> Result<Vec<u8>, RemoteError> {
        self.query(b"c")
    }

    pub fn recent_instructions(&mut self, count: u32) -> Result<Vec<u32>, RemoteError> {
        let payload = format_args_owned(format_args!("qSeggerSTRACE:read:{count:x}"));
        let response = hex_decode(&self.query(payload.as_bytes())?)?;
        if response.len() < 4 {
            return Err(RemoteError("short STRACE read response".into()));
        }
        let returned = u32::from_be_bytes(response[0..4].try_into().unwrap()) as usize;
        if response.len() != 4 + returned * 4 {
            return Err(RemoteError("malformed STRACE read response".into()));
        }
        Ok(response[4..]
            .chunks_exact(4)
            .map(|item| u32::from_be_bytes(item.try_into().unwrap()))
            .collect())
    }

    pub fn instruction_stats(
        &mut self,
        address: u32,
        halfwords: u32,
    ) -> Result<InstructionStats, RemoteError> {
        let mut command = b"$qSeggerSTRACE:GetInstStats:".to_vec();
        command.extend_from_slice(&address.to_le_bytes());
        command.extend_from_slice(&halfwords.to_le_bytes());
        command.extend_from_slice(&11u32.to_le_bytes());
        self.stream.write_all(&command).map_err(error)?;

        let expected = 4usize + 8 * 3 * (halfwords as usize + 1);
        let mut response = vec![0; expected];
        self.stream.read_exact(&mut response).map_err(error)?;
        let return_value = i32::from_le_bytes(response[0..4].try_into().unwrap());
        if return_value < 0 {
            return Err(RemoteError(format_args_owned(format_args!(
                "GetInstStats failed with {return_value}"
            ))));
        }
        let mut offset = 4;
        let mut take_counts = || {
            let values = response[offset..offset + halfwords as usize * 8]
                .chunks_exact(8)
                .map(|item| u64::from_le_bytes(item.try_into().unwrap()))
                .collect::<Vec<_>>();
            offset += halfwords as usize * 8;
            let sum = u64::from_le_bytes(response[offset..offset + 8].try_into().unwrap());
            offset += 8;
            (values, sum)
        };
        let (fetch, fetch_sum) = take_counts();
        let (execute, execute_sum) = take_counts();
        let (skip, skip_sum) = take_counts();
        Ok(InstructionStats {
            address,
            fetch,
            execute,
            skip,
            fetch_sum,
            execute_sum,
            skip_sum,
        })
    }

    fn read_packet(&mut self) -> Result<Vec<u8>, RemoteError> {
        while read_byte(&mut self.stream)? != b'$' {}
        let mut encoded = Vec::new();
        loop {
            let byte = read_byte(&mut self.stream)?;
            if byte == b'#' {
                break;
            }
            encoded.push(byte);
        }
        let checksum_bytes = [read_byte(&mut self.stream)?, read_byte(&mut self.stream)?];
        let expected = decode_hex_byte(checksum_bytes)?;
        let actual = encoded
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        if actual != expected {
            self.stream.write_all(b"-").map_err(error)?;
            return Err(RemoteError("GDB response checksum mismatch".into()));
        }
        self.stream.write_all(b"+").map_err(error)?;
        unescape(&encoded)
    }
}

#[derive(Clone, Debug)]
pub struct InstructionStats {
    pub address: u32,
    pub fetch: Vec<u64>,
    pub execute: Vec<u64>,
    pub skip: Vec<u64>,
    pub fetch_sum: u64,
    pub execute_sum: u64,
    pub skip_sum: u64,
}

fn require_ok(response: &[u8], operation: &str) -> Result<(), RemoteError> {
    if response == b"OK" {
        Ok(())
    } else {
        Err(RemoteError(format_args_owned(format_args!(
            "{operation} failed: {}",
            String::from_utf8_lossy(response)
        ))))
    }
}

fn require_nonnegative_i32(response: &[u8], operation: &str) -> Result<(), RemoteError> {
    let decoded;
    let response = if response.len() == 8 && response.iter().all(|byte| byte.is_ascii_hexdigit()) {
        decoded = hex_decode(response)?;
        decoded.as_slice()
    } else {
        response
    };
    if response.len() != 4 {
        return Err(RemoteError(format_args_owned(format_args!(
            "{operation} returned {} bytes instead of four",
            response.len()
        ))));
    }
    let value = i32::from_be_bytes(response.try_into().unwrap());
    if value < 0 {
        Err(RemoteError(format_args_owned(format_args!(
            "{operation} failed with {value}"
        ))))
    } else {
        Ok(())
    }
}

fn is_console_output(response: &[u8]) -> bool {
    response.first() == Some(&b'O')
        && response.len() > 1
        && response[1..].len() % 2 == 0
        && response[1..].iter().all(|byte| byte.is_ascii_hexdigit())
}

fn read_byte(reader: &mut impl Read) -> Result<u8, RemoteError> {
    let mut byte = [0];
    reader.read_exact(&mut byte).map_err(error)?;
    Ok(byte[0])
}

fn unescape(encoded: &[u8]) -> Result<Vec<u8>, RemoteError> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'}' {
            index += 1;
            let byte = *encoded
                .get(index)
                .ok_or_else(|| RemoteError("truncated GDB escape".into()))?;
            decoded.push(byte ^ 0x20);
        } else {
            decoded.push(encoded[index]);
        }
        index += 1;
    }
    Ok(decoded)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format_hex_byte(*byte));
    }
    output
}

fn hex_decode(bytes: &[u8]) -> Result<Vec<u8>, RemoteError> {
    if bytes.len() % 2 != 0 {
        return Err(RemoteError("odd-length hexadecimal response".into()));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| decode_hex_byte([pair[0], pair[1]]))
        .collect()
}

fn format_hex_byte(byte: u8) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    String::from_utf8([DIGITS[(byte >> 4) as usize], DIGITS[(byte & 15) as usize]].to_vec())
        .unwrap()
}

fn decode_hex_byte(bytes: [u8; 2]) -> Result<u8, RemoteError> {
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    nibble(bytes[0])
        .zip(nibble(bytes[1]))
        .map(|(high, low)| high << 4 | low)
        .ok_or_else(|| RemoteError("invalid hexadecimal byte".into()))
}

fn format_args_owned(arguments: fmt::Arguments<'_>) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    output.write_fmt(arguments).unwrap();
    output
}

fn error(error: io::Error) -> RemoteError {
    RemoteError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_codec_round_trips() {
        assert_eq!(hex_encode(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode(b"00abff").unwrap(), [0, 0xab, 0xff]);
    }

    #[test]
    fn unescapes_remote_binary_payloads() {
        assert_eq!(unescape(&[b'a', b'}', b'#' ^ 0x20]).unwrap(), b"a#");
    }
}
