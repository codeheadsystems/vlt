//! Strict big-endian reader and writer for the spec's byte layouts.

use crate::error::{InputKind, IntegrityKind as K, Result, input, integrity};
use crate::limits::COUNTER_CAP;
use zeroize::Zeroizing;

/// A cursor over input that checks every length against what remains before slicing.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return integrity(K::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    /// A `u64` counter, at most the cap.
    pub(crate) fn counter(&mut self) -> Result<u64> {
        let v = self.u64()?;
        if v > COUNTER_CAP {
            return integrity(K::CounterCap);
        }
        Ok(v)
    }

    /// `str16`: a `u16` length and that many bytes of UTF-8.
    pub(crate) fn str16(&mut self) -> Result<&'a str> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        core::str::from_utf8(b).or(integrity(K::InvalidUtf8))
    }

    /// `bytes32`: a `u32` length, checked against `max` before anything is read.
    pub(crate) fn bytes32(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return integrity(K::SizeLimit);
        }
        self.take(n)
    }

    /// Reject trailing bytes.
    pub(crate) fn finish(self) -> Result<()> {
        if self.remaining() != 0 {
            return integrity(K::TrailingBytes);
        }
        Ok(())
    }
}

/// Byte writer. Its buffer is zeroized on drop, and growth copies into a new buffer and zeroizes
/// the old one, so secret plaintext never lingers in freed memory. Length overflow of a `str16` or
/// `bytes32` is a caller error.
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Writer::with_capacity(256)
    }

    pub(crate) fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Zeroizing::new(Vec::with_capacity(n)),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    fn reserve(&mut self, extra: usize) {
        let need = self.buf.len() + extra;
        if need > self.buf.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(need.max(self.buf.capacity() * 2)));
            grown.extend_from_slice(&self.buf);
            // The old buffer is zeroized as `Zeroizing` drops it.
            self.buf = grown;
        }
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.reserve(b.len());
        self.buf.extend_from_slice(b);
        self
    }

    /// Append `n` zero bytes.
    pub(crate) fn zeros(&mut self, n: usize) -> &mut Self {
        self.reserve(n);
        let len = self.buf.len();
        self.buf.resize(len + n, 0);
        self
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn i64(&mut self, v: i64) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn str16(&mut self, s: &[u8]) -> Result<&mut Self> {
        let n = u16::try_from(s.len()).or(input(InputKind::TooLarge))?;
        self.u16(n);
        Ok(self.bytes(s))
    }

    pub(crate) fn bytes32(&mut self, s: &[u8]) -> Result<&mut Self> {
        let n = u32::try_from(s.len()).or(input(InputKind::TooLarge))?;
        self.u32(n);
        Ok(self.bytes(s))
    }

    /// The written bytes, for output that is not secret, such as ciphertext.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut *self.buf)
    }

    /// The written bytes, kept in a zeroizing buffer.
    pub(crate) fn into_secret(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// The length the padded plaintext must have so that `prefix + plaintext + tag` is the smallest
/// multiple of `block` that holds `body` bytes of plaintext.
pub(crate) fn padded_plain_len(prefix: usize, body: usize, block: usize) -> usize {
    let total = prefix + body + crate::limits::TAG_LEN;
    let rounded = total.div_ceil(block) * block;
    rounded - prefix - crate::limits::TAG_LEN
}

/// Check that `padding` is all zero and that the whole object length is the minimal multiple of
/// `block` for the `body` bytes that precede the padding.
pub(crate) fn check_padding(
    prefix: usize,
    body: usize,
    padding: &[u8],
    block: usize,
) -> Result<()> {
    if padding.iter().any(|&b| b != 0) {
        return integrity(K::Padding);
    }
    if body + padding.len() != padded_plain_len(prefix, body, block) {
        return integrity(K::PaddedSize);
    }
    Ok(())
}
