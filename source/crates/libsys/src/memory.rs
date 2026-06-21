//! Memory operations for libsys

/// Allocate memory (similar to malloc)
pub fn malloc(size: usize) -> *mut u8 {
    // TODO: Implement using brk/sbrk
    core::ptr::null_mut()
}

/// Free memory
pub fn free(_ptr: *mut u8) {
    // TODO
}

/// Reallocate memory
pub fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    // TODO
    let _ = ptr;
    core::ptr::null_mut()
}

/// Allocate zero-initialized memory
pub fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let total = nmemb * size;
    let ptr = malloc(total);
    if !ptr.is_null() {
        unsafe {
            core::ptr::write_bytes(ptr, 0, total);
        }
    }
    ptr
}
