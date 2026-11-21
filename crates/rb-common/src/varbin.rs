//! Big-endian binary reading and writing with unsigned varint lengths, as
//! `encoding/binary` and `sing/common/varbin` do it.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The input ended early (Go `io.ErrUnexpectedEOF` / `io.EOF`).
    UnexpectedEof,
    /// A varint longer than 64 bits (Go `binary.ReadUvarint` overflow).
    Overflow,
    /// Any other malformed content.
    Invalid(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::UnexpectedEof => f.write_str("unexpected EOF"),
            ReadError::Overflow => f.write_str("binary: varint overflows a 64-bit integer"),
            ReadError::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ReadError {}

/// A reader over a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    pub fn read_u8(&mut self) -> Result<u8, ReadError> {
        let byte = *self.data.get(self.position).ok_or(ReadError::UnexpectedEof)?;
        self.position += 1;
        Ok(byte)
    }

    /// Go `binary.Read` of a `bool`: one byte, non-zero is true.
    pub fn read_bool(&mut self) -> Result<bool, ReadError> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ReadError> {
        if self.remaining() < length {
            return Err(ReadError::UnexpectedEof);
        }
        let bytes = &self.data[self.position..self.position + length];
        self.position += length;
        Ok(bytes)
    }

    pub fn read_u16(&mut self) -> Result<u16, ReadError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, ReadError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Go `binary.ReadUvarint`.
    pub fn read_uvarint(&mut self) -> Result<u64, ReadError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        for index in 0..10 {
            let byte = self.read_u8()?;
            if byte < 0x80 {
                if index == 9 && byte > 1 {
                    return Err(ReadError::Overflow);
                }
                return Ok(value | (u64::from(byte) << shift));
            }
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
        }
        Err(ReadError::Overflow)
    }

    /// A count read from the input, refused before anything is allocated
    /// when the rest of the input cannot hold `count` items of `item_size`
    /// bytes (Go grows its slice while reading and fails at the end of the
    /// input instead).
    pub fn checked_count(&self, count: u64, item_size: usize) -> Result<usize, ReadError> {
        let size = count.checked_mul(item_size as u64).ok_or(ReadError::UnexpectedEof)?;
        if size > self.remaining() as u64 {
            return Err(ReadError::UnexpectedEof);
        }
        Ok(count as usize)
    }

    /// `varbin.ReadSlice[uint16]`.
    pub fn read_u16_slice(&mut self) -> Result<Vec<u16>, ReadError> {
        let count = self.read_uvarint()?;
        let count = self.checked_count(count, 2)?;
        (0..count).map(|_| self.read_u16()).collect()
    }

    /// `varbin.ReadSlice[uint64]`.
    pub fn read_u64_slice(&mut self) -> Result<Vec<u64>, ReadError> {
        let count = self.read_uvarint()?;
        let count = self.checked_count(count, 8)?;
        (0..count).map(|_| self.read_u64()).collect()
    }

    /// `varbin.ReadSlice[byte]`.
    pub fn read_byte_slice(&mut self) -> Result<Vec<u8>, ReadError> {
        let count = self.read_uvarint()?;
        let count = self.checked_count(count, 1)?;
        Ok(self.read_bytes(count)?.to_vec())
    }
}

/// `binary.AppendUvarint`.
pub fn write_uvarint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push(value as u8 | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_round_trip() {
        for value in [0u64, 1, 127, 128, 300, 1 << 40, u64::MAX] {
            let mut buffer = Vec::new();
            write_uvarint(&mut buffer, value);
            assert_eq!(Reader::new(&buffer).read_uvarint().unwrap(), value);
        }
        assert_eq!(Reader::new(&[0xff; 11]).read_uvarint(), Err(ReadError::Overflow));
        assert_eq!(Reader::new(&[0x80]).read_uvarint(), Err(ReadError::UnexpectedEof));
    }

    #[test]
    fn huge_counts_fail_without_allocating() {
        let mut buffer = Vec::new();
        write_uvarint(&mut buffer, 1 << 40);
        assert_eq!(Reader::new(&buffer).read_u16_slice(), Err(ReadError::UnexpectedEof));
        assert_eq!(Reader::new(&buffer).read_byte_slice(), Err(ReadError::UnexpectedEof));
    }
}
