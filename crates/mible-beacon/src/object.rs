//! The objects an advertisement carries: `id (u16 LE) ‖ length (u8) ‖ data`.

use crate::EncodeError;

/// Bytes before an object's data.
const OBJECT_HEADER_LEN: usize = 3;

/// One object, borrowing its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Object<'a> {
    /// What the object reports, e.g. `0x4E16` for a Smart Scale S200's
    /// weigh-in.
    pub id: u16,
    /// The object's data.
    pub data: &'a [u8],
}

impl<'a> Object<'a> {
    /// An object.
    #[must_use]
    pub const fn new(id: u16, data: &'a [u8]) -> Self {
        Self { id, data }
    }

    /// Appends the encoded object to `out`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::ObjectTooLong`] if the data exceeds 255 bytes,
    /// [`EncodeError::BufferTooSmall`] if `out` cannot hold the object (and
    /// `out` is then left as it was).
    pub fn encode<const N: usize>(
        &self,
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), EncodeError> {
        let len = u8::try_from(self.data.len()).map_err(|_too_long| EncodeError::ObjectTooLong)?;
        let needed = OBJECT_HEADER_LEN.saturating_add(self.data.len());
        if out.capacity().saturating_sub(out.len()) < needed {
            return Err(EncodeError::BufferTooSmall);
        }
        let [lo, hi] = self.id.to_le_bytes();
        out.extend_from_slice(&[lo, hi, len])
            .and_then(|()| out.extend_from_slice(self.data))
            .map_err(|_full| EncodeError::BufferTooSmall)
    }
}

/// Iterates over the objects in a payload.
///
/// Stops at the first object whose data runs past the end of the payload;
/// [`Objects::remainder`] then holds the bytes that were not parsed.
#[derive(Debug, Clone)]
pub struct Objects<'a> {
    /// The bytes not yet parsed.
    rest: &'a [u8],
}

/// Iterates over the objects in a (decrypted or plain) payload.
#[must_use]
pub const fn objects(payload: &[u8]) -> Objects<'_> {
    Objects { rest: payload }
}

impl<'a> Objects<'a> {
    /// The bytes not parsed into objects: empty once a well-formed payload
    /// is exhausted.
    #[must_use]
    pub const fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Objects<'a> {
    type Item = Object<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&[lo, hi, len], rest) = self.rest.split_first_chunk::<OBJECT_HEADER_LEN>()?;
        let (data, rest) = rest.split_at_checked(usize::from(len))?;
        self.rest = rest;
        Some(Object::new(u16::from_le_bytes([lo, hi]), data))
    }
}

impl core::iter::FusedIterator for Objects<'_> {}

#[cfg(test)]
mod tests {
    use super::{Object, objects};
    use crate::EncodeError;

    /// Consecutive objects come out in order, and a well-formed payload
    /// leaves no remainder.
    #[test]
    fn iterates() {
        let payload = [0x16, 0x4e, 0x02, 0xaa, 0xbb, 0x01, 0x10, 0x00];
        let mut iter = objects(&payload);
        assert_eq!(
            iter.next(),
            Some(Object::new(0x4e16, &[0xaa, 0xbb])),
            "first"
        );
        assert_eq!(iter.next(), Some(Object::new(0x1001, &[])), "empty data");
        assert_eq!(iter.next(), None, "end");
        assert!(iter.remainder().is_empty(), "nothing left");
    }

    /// A truncated object ends the iteration and stays in the remainder.
    #[test]
    fn stops_at_truncation() {
        let payload = [0x01, 0x10, 0x00, 0x16, 0x4e, 0x09, 0xaa];
        let mut iter = objects(&payload);
        assert_eq!(iter.next(), Some(Object::new(0x1001, &[])), "whole object");
        assert_eq!(iter.next(), None, "truncated");
        assert_eq!(iter.next(), None, "fused");
        assert_eq!(iter.remainder(), &[0x16, 0x4e, 0x09, 0xaa], "remainder");
        assert_eq!(objects(&[0x16, 0x4e]).next(), None, "short header");
    }

    /// Encoding appends, and refuses what does not fit without writing.
    #[test]
    fn encodes() {
        let mut out = heapless::Vec::<u8, 6>::new();
        Object::new(0x4e16, &[0xaa]).encode(&mut out).unwrap();
        assert_eq!(out.as_slice(), &[0x16, 0x4e, 0x01, 0xaa], "encoded");
        assert_eq!(
            Object::new(0x1001, &[0; 1]).encode(&mut out),
            Err(EncodeError::BufferTooSmall),
            "does not fit"
        );
        assert_eq!(out.len(), 4, "unchanged");
        let mut big = heapless::Vec::<u8, 300>::new();
        assert_eq!(
            Object::new(0x1001, &[0; 256]).encode(&mut big),
            Err(EncodeError::ObjectTooLong),
            "too long"
        );
    }
}
