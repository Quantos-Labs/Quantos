//! # Zero-Copy Serialization
//!
//! Avoids memory copies during serialization/deserialization of
//! cryptographic data structures using the `bytes` crate.
//!
//! ## Benefits
//! - Eliminates copy overhead for large signatures (3KB+)
//! - Reference-counted buffers for efficient sharing
//! - Slice views without allocation

use bytes::{Bytes, BytesMut, BufMut};

/// Zero-copy signature wrapper.
#[derive(Clone, Debug)]
pub struct ZeroCopySignature {
    data: Bytes,
}

impl ZeroCopySignature {
    /// Creates from existing bytes (zero-copy if Bytes).
    pub fn from_bytes(data: Bytes) -> Self {
        Self { data }
    }

    /// Creates from a slice (requires copy).
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(slice),
        }
    }

    /// Creates from a Vec (takes ownership, no copy).
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(vec),
        }
    }

    /// Gets as slice (zero-copy).
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Gets the length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Checks if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Converts to Bytes (zero-copy).
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    /// Gets a sub-slice (zero-copy).
    pub fn slice(&self, range: std::ops::Range<usize>) -> Self {
        Self {
            data: self.data.slice(range),
        }
    }
}

impl AsRef<[u8]> for ZeroCopySignature {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Zero-copy public key wrapper.
#[derive(Clone, Debug)]
pub struct ZeroCopyPublicKey {
    data: Bytes,
}

impl ZeroCopyPublicKey {
    pub fn from_bytes(data: Bytes) -> Self {
        Self { data }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(slice),
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(vec),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for ZeroCopyPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Zero-copy transaction data for network transmission.
#[derive(Clone, Debug)]
pub struct ZeroCopyTransaction {
    /// Raw transaction bytes
    raw: Bytes,
    /// Offset to signature within raw bytes
    signature_offset: usize,
    /// Signature length
    signature_len: usize,
    /// Offset to public key
    pubkey_offset: usize,
    /// Public key length
    pubkey_len: usize,
}

impl ZeroCopyTransaction {
    /// Creates a new zero-copy transaction from raw bytes.
    pub fn new(
        raw: Bytes,
        signature_offset: usize,
        signature_len: usize,
        pubkey_offset: usize,
        pubkey_len: usize,
    ) -> Self {
        Self {
            raw,
            signature_offset,
            signature_len,
            pubkey_offset,
            pubkey_len,
        }
    }

    /// Gets the signature (zero-copy slice).
    pub fn signature(&self) -> &[u8] {
        &self.raw[self.signature_offset..self.signature_offset + self.signature_len]
    }

    /// Gets the public key (zero-copy slice).
    pub fn public_key(&self) -> &[u8] {
        &self.raw[self.pubkey_offset..self.pubkey_offset + self.pubkey_len]
    }

    /// Gets the raw bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Gets the raw bytes as Bytes (zero-copy clone).
    pub fn raw_bytes(&self) -> Bytes {
        self.raw.clone()
    }

    /// Total size.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

/// Buffer builder for efficient serialization.
pub struct ZeroCopyBuilder {
    buffer: BytesMut,
}

impl ZeroCopyBuilder {
    /// Creates a new builder with specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Creates a builder sized for a typical transaction.
    pub fn for_transaction() -> Self {
        // Typical transaction: ~4KB (signature + pubkey + data)
        Self::with_capacity(4096)
    }

    /// Creates a builder sized for a batch of transactions.
    pub fn for_batch(count: usize) -> Self {
        Self::with_capacity(count * 4096)
    }

    /// Appends bytes.
    pub fn put_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_slice(data);
        self
    }

    /// Appends a u8.
    pub fn put_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.put_u8(value);
        self
    }

    /// Appends a u16 (little endian).
    pub fn put_u16_le(&mut self, value: u16) -> &mut Self {
        self.buffer.put_u16_le(value);
        self
    }

    /// Appends a u32 (little endian).
    pub fn put_u32_le(&mut self, value: u32) -> &mut Self {
        self.buffer.put_u32_le(value);
        self
    }

    /// Appends a u64 (little endian).
    pub fn put_u64_le(&mut self, value: u64) -> &mut Self {
        self.buffer.put_u64_le(value);
        self
    }

    /// Appends a length-prefixed byte slice.
    pub fn put_length_prefixed(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_u32_le(data.len() as u32);
        self.buffer.put_slice(data);
        self
    }

    /// Gets the current position.
    pub fn position(&self) -> usize {
        self.buffer.len()
    }

    /// Reserves additional capacity.
    pub fn reserve(&mut self, additional: usize) -> &mut Self {
        self.buffer.reserve(additional);
        self
    }

    /// Finalizes and returns the built Bytes.
    pub fn build(self) -> Bytes {
        self.buffer.freeze()
    }

    /// Gets a reference to the current buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

/// Buffer reader for efficient deserialization.
pub struct ZeroCopyReader {
    buffer: Bytes,
    position: usize,
}

impl ZeroCopyReader {
    /// Creates a new reader.
    pub fn new(buffer: Bytes) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    /// Reads bytes (zero-copy).
    pub fn read_bytes(&mut self, len: usize) -> Option<Bytes> {
        if self.position + len > self.buffer.len() {
            return None;
        }
        let slice = self.buffer.slice(self.position..self.position + len);
        self.position += len;
        Some(slice)
    }

    /// Reads bytes as slice (zero-copy, but tied to reader lifetime).
    pub fn read_slice(&mut self, len: usize) -> Option<&[u8]> {
        if self.position + len > self.buffer.len() {
            return None;
        }
        let slice = &self.buffer[self.position..self.position + len];
        self.position += len;
        Some(slice)
    }

    /// Reads a u8.
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.position >= self.buffer.len() {
            return None;
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Some(value)
    }

    /// Reads a u16 (little endian).
    pub fn read_u16_le(&mut self) -> Option<u16> {
        if self.position + 2 > self.buffer.len() {
            return None;
        }
        let value = u16::from_le_bytes([
            self.buffer[self.position],
            self.buffer[self.position + 1],
        ]);
        self.position += 2;
        Some(value)
    }

    /// Reads a u32 (little endian).
    pub fn read_u32_le(&mut self) -> Option<u32> {
        if self.position + 4 > self.buffer.len() {
            return None;
        }
        let value = u32::from_le_bytes([
            self.buffer[self.position],
            self.buffer[self.position + 1],
            self.buffer[self.position + 2],
            self.buffer[self.position + 3],
        ]);
        self.position += 4;
        Some(value)
    }

    /// Reads a u64 (little endian).
    pub fn read_u64_le(&mut self) -> Option<u64> {
        if self.position + 8 > self.buffer.len() {
            return None;
        }
        let bytes: [u8; 8] = self.buffer[self.position..self.position + 8]
            .try_into()
            .ok()?;
        let value = u64::from_le_bytes(bytes);
        self.position += 8;
        Some(value)
    }

    /// Reads a length-prefixed byte slice (zero-copy).
    /// Validates length to prevent overflow and unreasonable allocations.
    pub fn read_length_prefixed(&mut self) -> Option<Bytes> {
        let len_u32 = self.read_u32_le()?;
        
        // Prevent overflow on 32-bit platforms and unreasonable allocations
        const MAX_REASONABLE_LENGTH: u32 = 10 * 1024 * 1024; // 10MB — tightened for crypto protocol
        if len_u32 > MAX_REASONABLE_LENGTH {
            return None;
        }
        
        let len = len_u32 as usize;
        
        // Validate that we have enough data remaining
        if len > self.remaining() {
            return None;
        }
        
        self.read_bytes(len)
    }

    /// Gets the current position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Gets remaining bytes.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Checks if at end.
    pub fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_signature() {
        let data = vec![1u8; 3293];
        let sig = ZeroCopySignature::from_vec(data.clone());
        
        assert_eq!(sig.len(), 3293);
        assert_eq!(sig.as_slice(), data.as_slice());
    }

    #[test]
    fn test_zero_copy_builder_reader() {
        let mut builder = ZeroCopyBuilder::with_capacity(256);
        
        builder
            .put_u8(1)
            .put_u16_le(1000)
            .put_u32_le(100000)
            .put_u64_le(10000000000)
            .put_length_prefixed(b"hello world");
        
        let bytes = builder.build();
        let mut reader = ZeroCopyReader::new(bytes);
        
        assert_eq!(reader.read_u8(), Some(1));
        assert_eq!(reader.read_u16_le(), Some(1000));
        assert_eq!(reader.read_u32_le(), Some(100000));
        assert_eq!(reader.read_u64_le(), Some(10000000000));
        
        let data = reader.read_length_prefixed().unwrap();
        assert_eq!(data.as_ref(), b"hello world");
    }

    #[test]
    fn test_zero_copy_transaction() {
        let mut builder = ZeroCopyBuilder::for_transaction();
        
        // Simulate transaction structure
        let pubkey = vec![2u8; 1952];
        let signature = vec![3u8; 3293];
        let data = vec![4u8; 100];
        
        let pubkey_offset = builder.position();
        builder.put_bytes(&pubkey);
        
        let sig_offset = builder.position();
        builder.put_bytes(&signature);
        
        builder.put_bytes(&data);
        
        let raw = builder.build();
        let tx = ZeroCopyTransaction::new(raw, sig_offset, 3293, pubkey_offset, 1952);
        
        assert_eq!(tx.signature().len(), 3293);
        assert_eq!(tx.public_key().len(), 1952);
    }
}
