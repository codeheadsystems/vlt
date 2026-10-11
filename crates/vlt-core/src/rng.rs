//! Randomness. Internal functions take a `rand_core` RNG and draw explicit byte arrays in an order
//! vlt code defines, so tests can replay vector inputs. Production calls use the OS generator.

use crate::error::{Error, Result};
use rand_core::TryCryptoRng;

/// Draw `N` bytes.
pub(crate) fn draw<const N: usize, R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    rng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

/// The OS generator.
pub(crate) fn os() -> getrandom::SysRng {
    getrandom::SysRng
}

/// Test RNG that serves queued bytes and panics when it runs out, so a miscounted draw in a test
/// fails loudly instead of repeating bytes.
#[cfg(test)]
pub(crate) struct BufferRng {
    bytes: Vec<u8>,
    pos: usize,
}

#[cfg(test)]
impl BufferRng {
    pub(crate) fn new(parts: &[&[u8]]) -> Self {
        BufferRng {
            bytes: parts.concat(),
            pos: 0,
        }
    }

    pub(crate) fn assert_consumed(&self) {
        assert_eq!(self.pos, self.bytes.len(), "BufferRng not fully consumed");
    }
}

#[cfg(test)]
impl rand_core::TryRng for BufferRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "BufferRng exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

#[cfg(test)]
impl TryCryptoRng for BufferRng {}
