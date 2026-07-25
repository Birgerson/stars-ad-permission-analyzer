// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! RAII guard for buffers allocated by `NetApi*` functions.
//!
//! Background: many `NetApi*` functions (for example `NetShareEnum`,
//! `NetShareGetInfo`, `NetUserEnum`, `NetLocalGroupGetMembers`)
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
    /// Takes ownership of a buffer pointer returned by a `NetApi*`
    /// function.
    ///
    /// # Safety
    ///
    /// `ptr` must be either
    ///
    /// * `null`, or
    /// * a pointer that a `NetApi*` function successfully allocated,
    ///   whose free responsibility is transferred to this guard and
    ///   that is not also freed elsewhere (a double free would be UB).
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Creates an empty guard that owns no buffer. Use together with
    /// [`out_ptr`](Self::out_ptr) to obtain a writable slot that a
    /// `NetApi*` function can fill; the stored pointer is then treated
    /// as owned and freed on drop.
    pub fn null() -> Self {
        Self {
            ptr: ptr::null_mut(),
            _marker: PhantomData,
        }
    }

    /// Returns the raw pointer. Valid only as long as the guard
    /// lives. When the guard is dropped the buffer is freed and the
    /// caller must not dereference the pointer afterwards.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Returns an out-pointer slot for direct use in a `NetApi*`
    /// signature: `&mut buf.out_ptr()`. The pointer in the slot is
    /// freed when the guard is dropped.
    ///
    /// Intended for a **fresh** guard ([`NetApiBuffer::null`]): if the
    /// guard already owned a buffer, whatever the API writes into the
    /// slot would replace that pointer *without freeing it* — the debug
    /// assertion pins this constraint (win_safe review 2026-07-25, W-3).
    /// Every workspace call site creates a fresh guard per call.
    pub fn out_ptr(&mut self) -> *mut *mut T {
        debug_assert!(
            self.ptr.is_null(),
            "out_ptr() on a NetApiBuffer that already owns a buffer would leak it"
        );
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
        // We don't write a real NetApi pointer here because we can't
        // free it without the real allocator. We only verify `slot`
        // is writable — and reset it to null before drop. The reset goes
        // through the *same* slot (not a second `out_ptr()` call), which
        // also respects the fresh-guard debug assertion (W-3).
        // SAFETY: `slot` points at the guard's own pointer field; writing
        // a dummy value is fine as long as it is nulled before drop.
        unsafe {
            *slot = 0xDEAD_BEEF as *mut u8;
        }
        assert!(!guard.is_null());
        // SAFETY: same slot as above — reset to null so drop never frees
        // the dummy value.
        unsafe {
            *slot = std::ptr::null_mut();
        }
    }
}
