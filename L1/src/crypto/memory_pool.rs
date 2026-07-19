//! # Memory Pool for Cryptographic Operations
//!
//! Pre-allocated memory pools to avoid repeated allocations during
//! high-throughput cryptographic operations.
//!
//! ## Benefits
//! - Eliminates allocation overhead (~100ns per allocation)
//! - Reduces memory fragmentation
//! - Improves cache locality
//! - Thread-local pools for lock-free access

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crossbeam_queue::ArrayQueue;

/// Size constants for ML-DSA-65 (re-exported from ml_dsa module)
pub use crate::crypto::ml_dsa::{MLDSA65_PUBLIC_KEY_SIZE, MLDSA65_SECRET_KEY_SIZE, MLDSA65_SIGNATURE_SIZE};
pub const HASH_SIZE: usize = 32;

/// A pooled buffer that returns to pool on drop.
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Option<Arc<BufferPool>>,
    /// Prevent double-free by tracking if already returned (atomic for thread safety)
    returned: AtomicBool,
}

impl PooledBuffer {
    /// Creates a new pooled buffer without a pool (standalone).
    pub fn standalone(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
            pool: None,
            returned: AtomicBool::new(false),
        }
    }

    /// Gets the buffer as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Gets the buffer as a slice.
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

    /// Converts to Vec, detaching from pool.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.pool = None;
        self.returned.store(true, Ordering::Release); // Mark as returned to prevent Drop
        std::mem::take(&mut self.data)
    }

    /// Clears the buffer (zeros it).
    pub fn clear(&mut self) {
        self.data.fill(0);
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Atomically check-and-set to prevent double-free
        if self.returned.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            if let Some(pool) = &self.pool {
                let mut data = std::mem::take(&mut self.data);
                data.fill(0); // Security: zero before returning to pool
                pool.return_buffer(data);
            }
        }
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// Lock-free buffer pool using crossbeam queue.
pub struct BufferPool {
    buffers: ArrayQueue<Vec<u8>>,
    buffer_size: usize,
    max_buffers: usize,
}

impl BufferPool {
    /// Creates a new buffer pool.
    pub fn new(buffer_size: usize, max_buffers: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            buffers: ArrayQueue::new(max_buffers),
            buffer_size,
            max_buffers,
        });

        // Pre-allocate buffers
        for _ in 0..max_buffers {
            let _ = pool.buffers.push(vec![0u8; buffer_size]);
        }

        pool
    }

    /// Gets a buffer from the pool.
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let data = self.buffers.pop().unwrap_or_else(|| vec![0u8; self.buffer_size]);
        PooledBuffer {
            data,
            pool: Some(Arc::clone(self)),
            returned: AtomicBool::new(false),
        }
    }

    /// Returns a buffer to the pool.
    fn return_buffer(&self, buffer: Vec<u8>) {
        if buffer.len() == self.buffer_size {
            let _ = self.buffers.push(buffer);
        }
    }

    /// Gets the number of available buffers.
    pub fn available(&self) -> usize {
        self.buffers.len()
    }

    /// Gets the pool capacity.
    pub fn capacity(&self) -> usize {
        self.max_buffers
    }
}

// Thread-local memory pool for maximum performance.
thread_local! {
    static SIGNATURE_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(
        (0..16).map(|_| vec![0u8; MLDSA65_SIGNATURE_SIZE]).collect()
    );
    
    static HASH_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(
        (0..64).map(|_| vec![0u8; HASH_SIZE]).collect()
    );
    
    static PUBKEY_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(
        (0..16).map(|_| vec![0u8; MLDSA65_PUBLIC_KEY_SIZE]).collect()
    );
}

/// Gets a signature buffer from thread-local pool.
pub fn get_signature_buffer() -> Vec<u8> {
    SIGNATURE_POOL.with(|pool| {
        pool.borrow_mut().pop().unwrap_or_else(|| vec![0u8; MLDSA65_SIGNATURE_SIZE])
    })
}

/// Returns a signature buffer to thread-local pool.
pub fn return_signature_buffer(mut buffer: Vec<u8>) {
    if buffer.len() == MLDSA65_SIGNATURE_SIZE {
        buffer.fill(0);
        SIGNATURE_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            // Strict limit to prevent unbounded growth
            if p.len() < 16 {
                p.push(buffer);
            }
        });
    }
}

/// Gets a hash buffer from thread-local pool.
pub fn get_hash_buffer() -> Vec<u8> {
    HASH_POOL.with(|pool| {
        pool.borrow_mut().pop().unwrap_or_else(|| vec![0u8; HASH_SIZE])
    })
}

/// Returns a hash buffer to thread-local pool.
pub fn return_hash_buffer(mut buffer: Vec<u8>) {
    if buffer.len() == HASH_SIZE {
        buffer.fill(0);
        HASH_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            if p.len() < 128 {
                p.push(buffer);
            }
        });
    }
}

/// Gets a public key buffer from thread-local pool.
pub fn get_pubkey_buffer() -> Vec<u8> {
    PUBKEY_POOL.with(|pool| {
        pool.borrow_mut().pop().unwrap_or_else(|| vec![0u8; MLDSA65_PUBLIC_KEY_SIZE])
    })
}

/// Returns a public key buffer to thread-local pool.
pub fn return_pubkey_buffer(mut buffer: Vec<u8>) {
    if buffer.len() == MLDSA65_PUBLIC_KEY_SIZE {
        buffer.fill(0);
        PUBKEY_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            if p.len() < 32 {
                p.push(buffer);
            }
        });
    }
}

/// Global memory pools for shared access.
pub struct GlobalPools {
    pub signatures: Arc<BufferPool>,
    pub hashes: Arc<BufferPool>,
    pub public_keys: Arc<BufferPool>,
    pub messages: Arc<BufferPool>,
}

impl GlobalPools {
    /// Creates new global pools with specified capacities.
    pub fn new(capacity: usize) -> Self {
        Self {
            signatures: BufferPool::new(MLDSA65_SIGNATURE_SIZE, capacity),
            hashes: BufferPool::new(HASH_SIZE, capacity * 4),
            public_keys: BufferPool::new(MLDSA65_PUBLIC_KEY_SIZE, capacity),
            messages: BufferPool::new(1024, capacity * 2), // 1KB messages
        }
    }

    /// Gets a signature buffer.
    pub fn get_signature(&self) -> PooledBuffer {
        self.signatures.get()
    }

    /// Gets a hash buffer.
    pub fn get_hash(&self) -> PooledBuffer {
        self.hashes.get()
    }

    /// Gets a public key buffer.
    pub fn get_public_key(&self) -> PooledBuffer {
        self.public_keys.get()
    }

    /// Gets a message buffer.
    pub fn get_message(&self) -> PooledBuffer {
        self.messages.get()
    }

    /// Gets pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            signatures_available: self.signatures.available(),
            signatures_capacity: self.signatures.capacity(),
            hashes_available: self.hashes.available(),
            hashes_capacity: self.hashes.capacity(),
            public_keys_available: self.public_keys.available(),
            public_keys_capacity: self.public_keys.capacity(),
            messages_available: self.messages.available(),
            messages_capacity: self.messages.capacity(),
        }
    }
}

impl Default for GlobalPools {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Pool statistics.
#[derive(Clone, Debug)]
pub struct PoolStats {
    pub signatures_available: usize,
    pub signatures_capacity: usize,
    pub hashes_available: usize,
    pub hashes_capacity: usize,
    pub public_keys_available: usize,
    pub public_keys_capacity: usize,
    pub messages_available: usize,
    pub messages_capacity: usize,
}

impl PoolStats {
    /// Calculates total memory used by pools.
    pub fn total_memory_bytes(&self) -> usize {
        self.signatures_capacity * MLDSA65_SIGNATURE_SIZE +
        self.hashes_capacity * HASH_SIZE +
        self.public_keys_capacity * MLDSA65_PUBLIC_KEY_SIZE +
        self.messages_capacity * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(32, 10);
        
        let mut buf1 = pool.get();
        let mut buf2 = pool.get();
        
        buf1.as_mut_slice()[0] = 1;
        buf2.as_mut_slice()[0] = 2;
        
        assert_eq!(buf1.as_slice()[0], 1);
        assert_eq!(buf2.as_slice()[0], 2);
        
        // Return buffers
        drop(buf1);
        drop(buf2);
        
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn test_thread_local_pool() {
        let buf1 = get_signature_buffer();
        assert_eq!(buf1.len(), MLDSA65_SIGNATURE_SIZE);
        
        return_signature_buffer(buf1);
        
        let buf2 = get_signature_buffer();
        assert_eq!(buf2.len(), MLDSA65_SIGNATURE_SIZE);
    }

    #[test]
    fn test_global_pools() {
        let pools = GlobalPools::new(100);
        
        let sig = pools.get_signature();
        let hash = pools.get_hash();
        let pk = pools.get_public_key();
        
        assert_eq!(sig.len(), MLDSA65_SIGNATURE_SIZE);
        assert_eq!(hash.len(), HASH_SIZE);
        assert_eq!(pk.len(), MLDSA65_PUBLIC_KEY_SIZE);
        
        let stats = pools.stats();
        println!("Total pool memory: {} bytes", stats.total_memory_bytes());
    }

    #[test]
    fn test_pooled_buffer_into_vec() {
        let pool = BufferPool::new(32, 10);
        let mut buf = pool.get();
        buf.as_mut_slice()[0] = 42;
        
        let vec = buf.into_vec();
        assert_eq!(vec[0], 42);
        assert_eq!(vec.len(), 32);
    }
}
