// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! RAII guard for pointers that must be released with `LocalFree`.
//!
//! Several Windows security APIs hand the caller a pointer to memory the
//! OS allocated via `LocalAlloc` and require it to be freed with
//! [`LocalFree`] — for example the security descriptor returned by
//! `GetNamedSecurityInfoW`, or the string from `ConvertSidToStringSidW`.
//!
//! Freeing such a pointer manually at the end of a function is correct
//! only as long as no early return (`?`, a `return`, a validation step)
//! sneaks in between the allocation and the free. [`NetApiBuffer`] already
//! solved exactly this leak class for `NetApi*` buffers (review round 10
//! finding 3); [`LocalFreeGuard`] is the equivalent for `LocalAlloc`-owned
//! pointers (engine review 2026-06-13 finding 4). The guard calls
//! `LocalFree` in `Drop`, so every exit path releases the resource.
//!
//! [`NetApiBuffer`]: crate::netapi::NetApiBuffer

use windows_sys::Win32::Foundation::LocalFree;

/// RAII guard that frees a `LocalAlloc`-owned pointer with `LocalFree`
/// on drop. A null pointer is allowed and is never freed.
pub struct LocalFreeGuard {
    ptr: *mut core::ffi::c_void,
}

impl LocalFreeGuard {
    /// Wraps a pointer the OS allocated via `LocalAlloc`, transferring the
    /// free responsibility to the guard.
    ///
    /// # Safety
    ///
    /// `ptr` must be null, or a pointer that must be released with
    /// `LocalFree` and is not freed (or aliased into another guard)
    /// elsewhere — otherwise a double free would result.
    pub unsafe fn new(ptr: *mut core::ffi::c_void) -> Self {
        Self { ptr }
    }

    /// Returns the wrapped pointer. Ownership stays with the guard; the
    /// pointer is only valid while the guard is alive.
    pub fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.ptr
    }
}

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was a LocalAlloc-owned pointer handed to the
            // guard via `new`; the guard owns the free responsibility and
            // nulls the pointer after freeing, so there is no double free.
            unsafe {
                LocalFree(self.ptr);
            }
            self.ptr = core::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_guard_drops_without_freeing() {
        // A null guard must be a safe no-op on drop (no LocalFree call).
        // SAFETY: null is an explicitly allowed input.
        let guard = unsafe { LocalFreeGuard::new(core::ptr::null_mut()) };
        assert!(guard.as_ptr().is_null());
        drop(guard); // must not crash
    }
}
