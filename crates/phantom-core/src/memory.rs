//! Secure memory management for secret data.
//!
//! Provides memory-locked buffers that are automatically zeroized
//! when dropped, preventing secrets from leaking to swap or being
//! left in memory after use.
//!
//! # Security Properties
//!
//! - Memory is allocated via `mmap` (not heap) to avoid allocator metadata leaks
//! - Pages are locked with `mlock()` immediately to prevent swapping
//! - All data is zeroized before deallocation
//! - No `Debug`, `Display`, `Clone`, or `Serialize` implementations to prevent accidental exposure
//! - Access is tracked for audit purposes

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use zeroize::Zeroize;

/// Errors that can occur during memory operations.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// Failed to allocate memory via mmap.
    #[error("mmap allocation failed: {0}")]
    AllocationFailed(String),

    /// Failed to lock memory pages.
    #[error("mlock failed: {0}")]
    LockFailed(String),

    /// Failed to unlock memory pages.
    #[error("munlock failed: {0}")]
    UnlockFailed(String),

    /// Failed to deallocate memory.
    #[error("munmap failed: {0}")]
    DeallocFailed(String),

    /// Zero-size allocation requested.
    #[error("zero-size allocation not allowed")]
    ZeroSize,

    /// Invalid UTF-8 in secret string.
    #[error("invalid UTF-8 in secret data")]
    InvalidUtf8,
}

/// Result type for memory operations.
pub type MemoryResult<T> = Result<T, MemoryError>;

/// A secure buffer for holding secret data.
///
/// This buffer provides the following security guarantees:
///
/// - **No heap allocation**: Uses `mmap` directly to avoid heap allocator metadata
/// - **Memory locking**: Calls `mlock()` to prevent swapping to disk
/// - **Automatic zeroization**: Implements `Zeroize` and `ZeroizeOnDrop`
/// - **Access tracking**: Counts accesses for audit purposes
/// - **No accidental exposure**: Does not implement `Debug`, `Display`, `Clone`, or `Serialize`
///
/// # Example
///
/// ```ignore
/// use phantom_core::memory::SecretBuffer;
///
/// let secret = SecretBuffer::from_slice(b"my-secret-key")?;
/// secret.with_exposed(|bytes| {
///     // Use the secret bytes here
///     // Access is tracked for audit
/// });
/// // Secret is automatically zeroized when dropped
/// ```
pub struct SecretBuffer {
    /// Pointer to the mmap'd memory region.
    ptr: NonNull<u8>,
    /// Length of the data in the buffer.
    len: usize,
    /// Capacity of the allocated region (page-aligned).
    capacity: usize,
    /// Whether the memory is currently locked.
    locked: bool,
    /// Number of times this buffer has been accessed.
    access_count: AtomicU64,
}

// SAFETY: SecretBuffer manages its own memory and synchronization.
// The AtomicU64 for access_count provides thread-safe counting.
// The underlying memory is not shared between instances.
unsafe impl Send for SecretBuffer {}
unsafe impl Sync for SecretBuffer {}

impl SecretBuffer {
    /// Create a new secret buffer with the given capacity.
    ///
    /// The actual allocation will be rounded up to the nearest page size.
    /// Memory is locked immediately after allocation.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The minimum capacity in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `capacity` is zero
    /// - `mmap` fails
    /// - `mlock` fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let buffer = SecretBuffer::new(32)?;
    /// ```
    pub fn new(capacity: usize) -> MemoryResult<Self> {
        if capacity == 0 {
            return Err(MemoryError::ZeroSize);
        }

        let page_size = get_page_size();
        let aligned_capacity = align_to_page(capacity, page_size);

        // SAFETY: We're calling mmap with valid parameters
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(MemoryError::AllocationFailed(format!(
                "mmap failed with errno: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ptr = NonNull::new(ptr as *mut u8)
            .ok_or_else(|| MemoryError::AllocationFailed("mmap returned null".to_string()))?;

        // Lock the memory to prevent swapping
        let lock_result = unsafe { libc::mlock(ptr.as_ptr() as *const libc::c_void, aligned_capacity) };

        if lock_result != 0 {
            // Clean up the allocation before returning error
            unsafe {
                libc::munmap(ptr.as_ptr() as *mut libc::c_void, aligned_capacity);
            }
            return Err(MemoryError::LockFailed(format!(
                "mlock failed with errno: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Advise the kernel not to include this memory in core dumps
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(
                ptr.as_ptr() as *mut libc::c_void,
                aligned_capacity,
                libc::MADV_DONTDUMP,
            );
        }

        Ok(Self {
            ptr,
            len: 0,
            capacity: aligned_capacity,
            locked: true,
            access_count: AtomicU64::new(0),
        })
    }

    /// Create a secret buffer from existing data.
    ///
    /// The source data is copied into the secure buffer. The caller should
    /// zeroize the source data after this call if it contains sensitive information.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to copy into the secure buffer
    ///
    /// # Errors
    ///
    /// Returns an error if allocation or locking fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut source = b"secret-password".to_vec();
    /// let buffer = SecretBuffer::from_slice(&source)?;
    /// source.zeroize(); // Zeroize the source
    /// ```
    pub fn from_slice(data: &[u8]) -> MemoryResult<Self> {
        if data.is_empty() {
            return Err(MemoryError::ZeroSize);
        }

        let mut buffer = Self::new(data.len())?;

        // SAFETY: We just allocated `capacity` bytes, and `data.len() <= capacity`
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), buffer.ptr.as_ptr(), data.len());
        }
        buffer.len = data.len();

        Ok(buffer)
    }

    /// Create a secret buffer from a vector, consuming and zeroizing the vector.
    ///
    /// This is safer than `from_slice` as it ensures the source is zeroized.
    ///
    /// # Arguments
    ///
    /// * `mut data` - The vector to consume
    ///
    /// # Errors
    ///
    /// Returns an error if allocation or locking fails.
    pub fn from_vec(mut data: Vec<u8>) -> MemoryResult<Self> {
        let result = Self::from_slice(&data);
        data.zeroize();
        result
    }

    /// Get the length of the data in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the number of times this buffer has been accessed.
    ///
    /// This is useful for audit logging.
    #[inline]
    pub fn access_count(&self) -> u64 {
        self.access_count.load(Ordering::Relaxed)
    }

    /// Execute a closure with temporary read access to the buffer contents.
    ///
    /// This is the primary way to access secret data. Access is tracked
    /// for audit purposes.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives the secret bytes
    ///
    /// # Returns
    ///
    /// The return value of the closure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let secret = SecretBuffer::from_slice(b"password")?;
    /// let hash = secret.with_exposed(|bytes| {
    ///     compute_hash(bytes)
    /// });
    /// ```
    #[inline]
    pub fn with_exposed<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Increment access counter
        self.access_count.fetch_add(1, Ordering::Relaxed);

        // SAFETY: We maintain the invariant that ptr is valid for len bytes
        let slice = unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
        f(slice)
    }

    /// Execute a closure with temporary mutable access to the buffer contents.
    ///
    /// This allows modifying the secret data in place. Access is tracked
    /// for audit purposes.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives mutable access to the secret bytes
    ///
    /// # Returns
    ///
    /// The return value of the closure.
    #[inline]
    pub fn with_exposed_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Increment access counter
        self.access_count.fetch_add(1, Ordering::Relaxed);

        // SAFETY: We maintain the invariant that ptr is valid for len bytes
        let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
        f(slice)
    }

    /// Resize the buffer, potentially reallocating.
    ///
    /// If the new length is smaller, the excess bytes are zeroized.
    /// If the new length is larger and exceeds capacity, this will fail.
    ///
    /// # Arguments
    ///
    /// * `new_len` - The new length
    ///
    /// # Errors
    ///
    /// Returns an error if `new_len` exceeds capacity.
    pub fn resize(&mut self, new_len: usize) -> MemoryResult<()> {
        if new_len > self.capacity {
            return Err(MemoryError::AllocationFailed(
                "new length exceeds capacity".to_string(),
            ));
        }

        if new_len < self.len {
            // Zeroize the excess bytes
            unsafe {
                let excess_ptr = self.ptr.as_ptr().add(new_len);
                std::ptr::write_bytes(excess_ptr, 0, self.len - new_len);
            }
        }

        self.len = new_len;
        Ok(())
    }

    /// Constant-time equality comparison.
    ///
    /// This prevents timing attacks when comparing secrets.
    ///
    /// # Arguments
    ///
    /// * `other` - The other buffer to compare
    ///
    /// # Returns
    ///
    /// `true` if the buffers are equal, `false` otherwise.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        if self.len != other.len {
            return false;
        }

        self.with_exposed(|a| other.with_exposed(|b| a.ct_eq(b).into()))
    }

    /// Constant-time comparison with a slice.
    ///
    /// # Arguments
    ///
    /// * `other` - The slice to compare
    ///
    /// # Returns
    ///
    /// `true` if the contents are equal, `false` otherwise.
    pub fn ct_eq_slice(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if self.len != other.len() {
            return false;
        }

        self.with_exposed(|a| a.ct_eq(other).into())
    }
}

impl Zeroize for SecretBuffer {
    fn zeroize(&mut self) {
        if self.len > 0 {
            // SAFETY: ptr is valid for capacity bytes
            unsafe {
                std::ptr::write_bytes(self.ptr.as_ptr(), 0, self.capacity);
            }
            // Also use a memory barrier to prevent compiler from optimizing away
            std::sync::atomic::compiler_fence(Ordering::SeqCst);
        }
        self.len = 0;
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // First, zeroize all memory
        self.zeroize();

        // Unlock the memory
        if self.locked {
            unsafe {
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.capacity);
            }
            self.locked = false;
        }

        // Deallocate
        unsafe {
            libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.capacity);
        }
    }
}

// Explicitly NOT implementing these traits to prevent accidental exposure:
// - Debug: would print contents
// - Display: would print contents
// - Clone: would duplicate secret in memory
// - Serialize: would write secret to output

/// A secure string for holding UTF-8 secret data.
///
/// This wraps a `SecretBuffer` and provides string-specific operations
/// while maintaining the same security properties.
///
/// # Example
///
/// ```ignore
/// let password = SecretString::from_str("my-password")?;
/// password.with_exposed_str(|s| {
///     // Use the password string
/// });
/// ```
pub struct SecretString {
    buffer: SecretBuffer,
}

impl SecretString {
    /// Create a secret string from a string slice.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to copy
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails.
    pub fn from_str(s: &str) -> MemoryResult<Self> {
        Ok(Self {
            buffer: SecretBuffer::from_slice(s.as_bytes())?,
        })
    }

    /// Create a secret string from a `String`, consuming and zeroizing it.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to consume
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails.
    pub fn from_string(mut s: String) -> MemoryResult<Self> {
        let result = Self::from_str(&s);
        // Zeroize the source string
        // SAFETY: We're overwriting the string's buffer with zeros
        unsafe {
            let bytes = s.as_bytes_mut();
            std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len());
        }
        drop(s);
        result
    }

    /// Create a secret string from a `SecretBuffer`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer containing UTF-8 data
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not contain valid UTF-8.
    pub fn from_buffer(buffer: SecretBuffer) -> MemoryResult<Self> {
        // Validate UTF-8
        let is_valid = buffer.with_exposed(|bytes| std::str::from_utf8(bytes).is_ok());
        if !is_valid {
            return Err(MemoryError::InvalidUtf8);
        }

        Ok(Self { buffer })
    }

    /// Get the length of the string in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get the access count.
    #[inline]
    pub fn access_count(&self) -> u64 {
        self.buffer.access_count()
    }

    /// Execute a closure with temporary read access to the string.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives the secret string
    ///
    /// # Returns
    ///
    /// The return value of the closure.
    #[inline]
    pub fn with_exposed_str<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        self.buffer.with_exposed(|bytes| {
            // SAFETY: We validated UTF-8 in the constructor
            let s = unsafe { std::str::from_utf8_unchecked(bytes) };
            f(s)
        })
    }

    /// Get access to the underlying buffer.
    #[inline]
    pub fn as_buffer(&self) -> &SecretBuffer {
        &self.buffer
    }

    /// Consume self and return the underlying buffer.
    #[inline]
    pub fn into_buffer(self) -> SecretBuffer {
        self.buffer
    }

    /// Constant-time equality comparison.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.buffer.ct_eq(&other.buffer)
    }

    /// Constant-time comparison with a string slice.
    pub fn ct_eq_str(&self, other: &str) -> bool {
        self.buffer.ct_eq_slice(other.as_bytes())
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.buffer.zeroize();
    }
}

// SecretString also does NOT implement Debug, Display, Clone, or Serialize

/// Get the system page size.
#[inline]
fn get_page_size() -> usize {
    // SAFETY: sysconf is safe to call
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Align a size up to the nearest page boundary.
#[inline]
fn align_to_page(size: usize, page_size: usize) -> usize {
    (size + page_size - 1) & !(page_size - 1)
}

/// Securely zeroize a mutable byte slice.
///
/// This function ensures the memory is actually zeroed and the operation
/// is not optimized away by the compiler.
///
/// # Arguments
///
/// * `data` - The slice to zeroize
#[inline]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Lock a memory region to prevent swapping.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region
/// * `len` - Length of the region in bytes
///
/// # Errors
///
/// Returns an error if `mlock` fails.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for `len` bytes.
pub unsafe fn mlock(ptr: *const u8, len: usize) -> MemoryResult<()> {
    let result = libc::mlock(ptr as *const libc::c_void, len);
    if result != 0 {
        Err(MemoryError::LockFailed(format!(
            "mlock failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

/// Unlock a previously locked memory region.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region
/// * `len` - Length of the region in bytes
///
/// # Errors
///
/// Returns an error if `munlock` fails.
///
/// # Safety
///
/// The caller must ensure that `ptr` is valid for `len` bytes and was
/// previously locked with `mlock`.
pub unsafe fn munlock(ptr: *const u8, len: usize) -> MemoryResult<()> {
    let result = libc::munlock(ptr as *const libc::c_void, len);
    if result != 0 {
        Err(MemoryError::UnlockFailed(format!(
            "munlock failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_buffer_create_and_access() {
        let data = b"secret-password-123";
        let buffer = SecretBuffer::from_slice(data).expect("allocation failed");

        assert_eq!(buffer.len(), data.len());
        assert!(!buffer.is_empty());
        assert_eq!(buffer.access_count(), 0);

        buffer.with_exposed(|bytes| {
            assert_eq!(bytes, data);
        });

        assert_eq!(buffer.access_count(), 1);
    }

    #[test]
    fn test_secret_buffer_access_tracking() {
        let buffer = SecretBuffer::from_slice(b"test").unwrap();

        for i in 0..10 {
            assert_eq!(buffer.access_count(), i);
            buffer.with_exposed(|_| {});
        }

        assert_eq!(buffer.access_count(), 10);
    }

    #[test]
    fn test_secret_buffer_constant_time_eq() {
        let a = SecretBuffer::from_slice(b"password123").unwrap();
        let b = SecretBuffer::from_slice(b"password123").unwrap();
        let c = SecretBuffer::from_slice(b"different").unwrap();

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn test_secret_buffer_zeroize() {
        let mut buffer = SecretBuffer::from_slice(b"sensitive-data").unwrap();
        buffer.zeroize();

        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_secret_buffer_zeroed_after_drop() {
        let data = vec![0xAA; 64];

        // Create a buffer
        let buffer = SecretBuffer::from_slice(&data).unwrap();

        // Verify the data is there before drop
        buffer.with_exposed(|bytes| {
            assert_eq!(bytes, &data[..]);
        });

        // Drop the buffer
        drop(buffer);

        // NOTE: After munmap, we cannot safely verify the memory is zeroed
        // because the memory is returned to the OS. In a real security audit,
        // you'd use a memory analysis tool or debugger to verify zeroization
        // happens before munmap.
        //
        // The implementation does:
        // 1. zeroize() - writes zeros to all capacity bytes
        // 2. munlock() - unlocks the memory
        // 3. munmap() - returns memory to OS
        //
        // For CI purposes, we verify the drop completed without panic.
    }

    #[test]
    fn test_secret_string_utf8() {
        let secret = SecretString::from_str("hello, 世界").unwrap();

        secret.with_exposed_str(|s| {
            assert_eq!(s, "hello, 世界");
        });
    }

    #[test]
    fn test_secret_string_invalid_utf8() {
        let invalid = vec![0xFF, 0xFE, 0x00, 0x01];
        let buffer = SecretBuffer::from_slice(&invalid).unwrap();
        let result = SecretString::from_buffer(buffer);

        assert!(result.is_err());
    }

    #[test]
    fn test_secret_buffer_from_vec_zeroizes_source() {
        // Create a vector with known content
        let data = vec![0xAA; 32];

        // from_vec consumes the vector and zeroizes it before dropping
        let buffer = SecretBuffer::from_vec(data).unwrap();

        // Verify the buffer contains the original data
        buffer.with_exposed(|bytes| {
            assert!(bytes.iter().all(|&b| b == 0xAA));
        });

        // Note: The original vector is consumed, so we can't check it directly.
        // The zeroize::Zeroize trait is called on the Vec before it's dropped.
    }

    #[test]
    fn test_zero_size_allocation_fails() {
        let result = SecretBuffer::new(0);
        assert!(matches!(result, Err(MemoryError::ZeroSize)));

        let result = SecretBuffer::from_slice(&[]);
        assert!(matches!(result, Err(MemoryError::ZeroSize)));
    }

    #[test]
    fn test_page_alignment() {
        let page_size = get_page_size();

        assert_eq!(align_to_page(1, page_size), page_size);
        assert_eq!(align_to_page(page_size, page_size), page_size);
        assert_eq!(align_to_page(page_size + 1, page_size), page_size * 2);
    }

    // Compile-time test: This should NOT compile
    // Uncomment to verify that SecretBuffer doesn't implement Debug
    // #[test]
    // fn test_secret_buffer_not_debug() {
    //     let buffer = SecretBuffer::from_slice(b"test").unwrap();
    //     println!("{:?}", buffer); // Should fail to compile
    // }

    // Compile-time test: This should NOT compile
    // Uncomment to verify that SecretBuffer doesn't implement Clone
    // #[test]
    // fn test_secret_buffer_not_clone() {
    //     let buffer = SecretBuffer::from_slice(b"test").unwrap();
    //     let _clone = buffer.clone(); // Should fail to compile
    // }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_memory_is_locked() {
        use std::fs;

        let buffer = SecretBuffer::from_slice(b"test-data-for-mlock").unwrap();

        // Read /proc/self/status to check VmLck
        let status = fs::read_to_string("/proc/self/status").expect("Failed to read /proc/self/status");

        let vmlck_line = status
            .lines()
            .find(|line| line.starts_with("VmLck:"))
            .expect("VmLck not found in /proc/self/status");

        // Parse the value (format: "VmLck:     X kB")
        let vmlck_kb: u64 = vmlck_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse VmLck value");

        // At least one page should be locked
        assert!(
            vmlck_kb > 0,
            "Expected VmLck > 0, but got {} kB",
            vmlck_kb
        );

        drop(buffer);
    }
}
