// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//!
//! [`NetShareEnum`], [`NetShareGetInfo`], [`NetUserEnum`],
//! freizugeben.
//!
//! leakte.
//!
//! entfaellt.
//!
//! RAII guard for buffers allocated by `NetApi*` functions.
//!
//! Background: many `NetApi*` functions (for example [`NetShareEnum`],
//! [`NetShareGetInfo`], [`NetUserEnum`], [`NetLocalGroupGetMembers`])
//! allocate a buffer internally on success and hand the caller an
//! out-pointer. The caller must release that buffer with
//! [`NetApiBufferFree`].
//!
//! If an early return happens in between (a `?`, a `return`
//! statement, a panic-resistant path, or any other early exit),
//! `NetApiBufferFree` is never reached and the buffer leaks. Review
//! round 10 finding 3 spotted exactly that: `get_share_dacl` called
//! `parse_share_dacl(...)?` before freeing the buffer — an `Err` from
//! the parser leaked.
//!
//! Solution: this type wraps the buffer and calls `NetApiBufferFree`
//! in `Drop`. Every path — success, `?`, `return`, panic — returns the
//! resource correctly. As a bonus the code becomes more readable
//! because the manual `NetApiBufferFree(buf.cast())` at the end of
//! every path disappears.
//!
//! [`NetApiBufferFree`]: https://learn.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree

use std::marker::PhantomData;
use std::ptr;
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

///
///
/// RAII guard for a buffer allocated by a `NetApi*` function. The
/// type parameter `T` is the concrete struct type that the
/// out-pointer addresses (for example `SHARE_INFO_502`).
///
/// Construction is done via [`NetApiBuffer::from_raw`] **only after**
/// the successful NetApi call. A null pointer is allowed and does not
/// trigger a Free (modelled as "no buffer allocated", which can
/// happen on failed calls).
pub struct NetApiBuffer<T> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

impl<T> NetApiBuffer<T> {
    /// `NetApi*`-Funktion gelieferten Puffer-Pointer.
    ///
    /// # Safety
    ///
    ///
    ///   (a double free would be UB).
    ///
    /// Takes ownership of a buffer pointer returned by a `NetApi*`
    /// function.
    ///
    /// # Safety
    ///
    /// `ptr` must be either
    ///
    /// * `null`, or
    /// * a pointer that a `NetApi*` function successfully allocated
    ///   and whose free responsibility is transferred to
    ///   be freed elsewhere (a "double free" would be UB).
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    ///
    /// Convenience constructor via out-pointer slot: returns a
    /// `*mut *mut T` that a `NetApi*` function can write its buffer
    /// into. Once the function returns, the stored pointer is treated
    /// as owned.
    pub fn null() -> Self {
        Self {
            ptr: ptr::null_mut(),
            _marker: PhantomData,
        }
    }

    /// dereferenzieren.
    ///
    /// Returns the raw pointer. Valid only as long as the guard
    /// lives. When the guard is dropped the buffer is freed and the
    /// caller must not dereference the pointer afterwards.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }

    ///
    /// Returns an out-pointer slot for direct use in a `NetApi*`
    /// signature: `&mut buf.out_ptr()`. The pointer in the slot is
    /// freed when the guard is dropped.
    pub fn out_ptr(&mut self) -> *mut *mut T {
        &mut self.ptr
    }

    /// Whether the guard actually holds a buffer.
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

impl<T> Drop for NetApiBuffer<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: only a successful NetApi call sets a non-null
            // pointer. Free responsibility was transferred to the
            // guard via `from_raw`. Double-free is prevented by the
            // caller avoiding aliasing.
            unsafe {
                NetApiBufferFree(self.ptr.cast());
            }
            self.ptr = ptr::null_mut();
        }
    }
}

// `NetApiBuffer` holds a raw pointer — deliberately neither `Send`
// nor `Sync` because NetApi allocator semantics should be ensured per
// thread. Callers must drop the guard on the same thread that
// constructed it.

#[cfg(test)]
mod tests {
    use super::*;

    /// `ptr != null`.
    /// Sanity test: a null pointer leads to no Free call (Drop is a
    /// no-op). Verifies the NetApiBufferFree precondition `ptr != null`.
    #[test]
    fn drop_on_null_is_no_op() {
        let guard: NetApiBuffer<u8> = NetApiBuffer::null();
        assert!(guard.is_null());
        drop(guard); // must not panic
    }

    /// Sanity test: `out_ptr` returns a writable slot that holds a
    /// non-null pointer after writing.
    #[test]
    fn out_ptr_can_be_written_and_read_back() {
        let mut guard: NetApiBuffer<u8> = NetApiBuffer::null();
        let slot = guard.out_ptr();
        // ungueltiges Free macht.
        // We don't write a real NetApi pointer here because we can't
        // free it without the real allocator. We only verify `slot`
        // is writable — and reset it to null before drop.
        unsafe {
            *slot = 0xDEAD_BEEF as *mut u8;
        }
        assert!(!guard.is_null());
        // Reset to null before drop to avoid invalid free.
        unsafe {
            *guard.out_ptr() = std::ptr::null_mut();
        }
    }
}
