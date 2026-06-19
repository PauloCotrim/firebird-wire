//! XDR (RFC 4506) encoding/decoding as used by the Firebird wire protocol.
//!
//! Everything is big-endian and padded to a 4-byte boundary. Integers are
//! 32-bit on the wire even when the logical value is smaller. This module
//! provides in-memory [`XdrWriter`]/[`XdrReader`] helpers plus clumplet
//! builders for the various parameter buffers (DPB/TPB/SPB/BPB/batch PB).

use crate::error::{Error, Result};

/// Round `n` up to the next multiple of 4.
#[inline]
pub const fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Builds an XDR byte stream in memory.
#[derive(Debug, Default, Clone)]
pub struct XdrWriter {
    buf: Vec<u8>,
}

impl XdrWriter {
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(64) }
    }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Append a 32-bit big-endian integer.
    #[inline]
    pub fn put_i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[inline]
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a 64-bit big-endian integer (two XDR words).
    #[inline]
    pub fn put_i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[inline]
    pub fn put_f64(&mut self, v: f64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append raw bytes with no length prefix and no padding.
    #[inline]
    pub fn put_raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Pad the buffer with zero bytes up to the next 4-byte boundary.
    #[inline]
    pub fn align(&mut self) -> &mut Self {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
        self
    }

    /// Append an XDR opaque/string: 4-byte length, the data, then zero padding
    /// to a 4-byte boundary. This is the `cstring`/`buffer` shape used for DPBs,
    /// SQL text, message blobs, etc.
    pub fn put_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.put_i32(data.len() as i32);
        self.buf.extend_from_slice(data);
        self.align();
        self
    }

    /// Convenience for [`Self::put_bytes`] on a string slice.
    #[inline]
    pub fn put_str(&mut self, s: &str) -> &mut Self {
        self.put_bytes(s.as_bytes())
    }
}

/// Reads an XDR byte stream produced by the server.
#[derive(Debug, Clone)]
pub struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(Error::protocol(format!(
                "short XDR read: need {n} bytes, have {}",
                self.remaining()
            )));
        }
        Ok(())
    }

    #[inline]
    pub fn get_i32(&mut self) -> Result<i32> {
        self.need(4)?;
        let v = i32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    #[inline]
    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(self.get_i32()? as u32)
    }

    #[inline]
    pub fn get_i64(&mut self) -> Result<i64> {
        self.need(8)?;
        let v = i64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    #[inline]
    pub fn get_f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.get_i64()? as u64))
    }

    /// Read `n` raw bytes with no padding.
    pub fn get_raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Skip padding to the next 4-byte boundary, relative to the start of the buffer.
    #[inline]
    pub fn align(&mut self) -> Result<()> {
        let pad = pad4(self.pos) - self.pos;
        if pad > 0 {
            self.need(pad)?;
            self.pos += pad;
        }
        Ok(())
    }

    /// Read a length-prefixed, 4-byte-aligned opaque buffer (mirror of
    /// [`XdrWriter::put_bytes`]).
    pub fn get_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.get_i32()? as usize;
        let data = self.get_raw(len)?;
        self.align()?;
        Ok(data)
    }

    /// Like [`Self::get_bytes`] but returns an owned copy.
    pub fn get_bytes_owned(&mut self) -> Result<Vec<u8>> {
        Ok(self.get_bytes()?.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Parameter buffer (clumplet) builders
// ---------------------------------------------------------------------------

/// A parameter buffer (DPB/TPB/SPB/BPB) built as a sequence of clumplets.
///
/// "Traditional" clumplets are `tag(1) + length(1) + value`. Firebird DPB
/// version 2 instead uses 4-byte lengths; this builder follows the classic
/// 1-byte form which every server still accepts for the items we emit.
#[derive(Debug, Clone)]
pub struct ParameterBuffer {
    buf: Vec<u8>,
}

impl ParameterBuffer {
    /// Start a buffer with the given version byte (e.g. `DPB_VERSION1`).
    pub fn new(version: u8) -> Self {
        Self { buf: vec![version] }
    }

    /// Start a buffer with no leading version byte (batch PB and some SPBs).
    pub fn raw() -> Self {
        Self { buf: Vec::new() }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        // A lone version byte counts as "no parameters".
        self.buf.len() <= 1
    }

    /// A bare tag with no value.
    pub fn tag(&mut self, tag: u8) -> &mut Self {
        self.buf.push(tag);
        self
    }

    /// `tag + len + bytes`, length encoded as a single byte (value <= 255).
    pub fn bytes(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= u8::MAX as usize, "clumplet value too long");
        self.buf.push(tag);
        self.buf.push(value.len() as u8);
        self.buf.extend_from_slice(value);
        self
    }

    #[inline]
    pub fn string(&mut self, tag: u8, value: &str) -> &mut Self {
        self.bytes(tag, value.as_bytes())
    }

    /// A clumplet whose value is a little-endian integer of the minimal width.
    /// Firebird parameter-buffer integers are little-endian (unlike the XDR
    /// frame), encoded with the smallest number of bytes that fit.
    pub fn int(&mut self, tag: u8, value: i32) -> &mut Self {
        let le = value.to_le_bytes();
        // Number of significant bytes (at least 1).
        let mut n = 4;
        while n > 1 && le[n - 1] == 0 {
            n -= 1;
        }
        self.bytes(tag, &le[..n])
    }

    /// A clumplet carrying a fixed-width little-endian `u32` value.
    pub fn int_u32(&mut self, tag: u8, value: u32) -> &mut Self {
        self.bytes(tag, &value.to_le_bytes())
    }

    /// A clumplet carrying a fixed-width little-endian `u64` value (batch PB).
    pub fn int_u64(&mut self, tag: u8, value: u64) -> &mut Self {
        self.bytes(tag, &value.to_le_bytes())
    }

    /// `tag + len + bytes` using a 4-byte little-endian length, as required by
    /// the batch parameter buffer's variable-length items.
    pub fn bytes_be_len4(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Decode a little-endian integer of up to 8 bytes (parameter-buffer / info
/// item value).
pub fn read_le_int(bytes: &[u8]) -> i64 {
    let mut v: i64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        v |= (b as i64) << (8 * i);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ints_and_bytes() {
        let mut w = XdrWriter::new();
        w.put_i32(-7).put_i64(1 << 40).put_bytes(b"hello").put_str("hi");
        let bytes = w.into_vec();

        let mut r = XdrReader::new(&bytes);
        assert_eq!(r.get_i32().unwrap(), -7);
        assert_eq!(r.get_i64().unwrap(), 1 << 40);
        assert_eq!(r.get_bytes().unwrap(), b"hello");
        assert_eq!(r.get_bytes().unwrap(), b"hi");
        assert!(r.is_empty());
    }

    #[test]
    fn put_bytes_is_padded() {
        let mut w = XdrWriter::new();
        w.put_bytes(b"abc"); // 4 (len) + 3 (data) + 1 (pad) = 8
        assert_eq!(w.len(), 8);
        assert_eq!(&w.as_slice()[4..7], b"abc");
        assert_eq!(w.as_slice()[7], 0);
    }

    #[test]
    fn clumplet_minimal_int_width() {
        let mut pb = ParameterBuffer::new(crate::wire::consts::DPB_VERSION1);
        pb.int(crate::wire::consts::dpb::SQL_DIALECT, 3);
        // version(1) + tag(1) + len(1) + 1 byte value
        assert_eq!(pb.as_slice(), &[1, 63, 1, 3]);
    }

    #[test]
    fn le_int_decode() {
        assert_eq!(read_le_int(&[0x10, 0x27]), 10000);
        assert_eq!(read_le_int(&[0xff]), 255);
    }
}
