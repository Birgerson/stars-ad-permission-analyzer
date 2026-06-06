// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! RAII-Guard fuer von `NetApi*`-Funktionen allozierte Puffer.
//!
//! Hintergrund: viele `NetApi*`-Funktionen (zum Beispiel
//! [`NetShareEnum`], [`NetShareGetInfo`], [`NetUserEnum`],
//! [`NetLocalGroupGetMembers`]) allozieren bei Erfolg einen Puffer
//! intern und uebergeben dem Aufrufer einen Out-Pointer. Der Aufrufer
//! ist verpflichtet, diesen Puffer mit [`NetApiBufferFree`] wieder
//! freizugeben.
//!
//! Wenn dazwischen ein `?` aus der Funktion herausspringt (oder eine
//! `return`-Statement, ein `panic`-resistenter Pfad oder eine andere
//! Form von Early-Return), wird `NetApiBufferFree` nicht erreicht und
//! der Puffer leakt. Genau das hatte Review-Runde 10 Finding 3
//! identifiziert: `get_share_dacl` ruft `parse_share_dacl(...)?` auf,
//! bevor der Puffer freigegeben wird — ein `Err` aus dem Parser
//! leakte.
//!
//! Loesung: dieser Typ kapselt den Puffer und ruft `NetApiBufferFree`
//! im `Drop`. Damit gibt jeder Pfad — Erfolg, `?`, `return`, Panic —
//! die Ressource korrekt frei. Plus: der Code wird lesbarer, weil das
//! manuelle `NetApiBufferFree(buf.cast())` am Ende jedes Pfads
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

/// RAII-Guard fuer einen von einer `NetApi*`-Funktion allozierten
/// Puffer. Der Typ-Parameter `T` ist der konkrete Struktur-Typ, den
/// der Out-Pointer adressiert (zum Beispiel `SHARE_INFO_502`).
///
/// Konstruktion erfolgt ueber [`NetApiBuffer::from_raw`] **erst nach**
/// dem erfolgreichen NetApi-Call. Ein Null-Pointer ist erlaubt und
/// loest keinen Free aus (Modell „kein Puffer allokiert", was bei
/// fehlgeschlagenen Calls vorkommen kann).
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
    /// Uebernimmt die Verantwortung fuer einen von einer
    /// `NetApi*`-Funktion gelieferten Puffer-Pointer.
    ///
    /// # Safety
    ///
    /// `ptr` muss entweder
    ///
    /// * `null` sein, oder
    /// * ein Pointer, den eine `NetApi*`-Funktion erfolgreich
    ///   alloziert hat und dessen Free-Verantwortung auf `NetApiBuffer`
    ///   uebergeht. Insbesondere darf derselbe Pointer nicht
    ///   gleichzeitig von einer anderen Stelle freigegeben werden
    ///   („double free" waere ein UB).
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
    ///   `NetApiBuffer`. In particular the same pointer must not also
    ///   be freed elsewhere (a "double free" would be UB).
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Konstruktion ueber einen Out-Pointer-Helper: gibt einen
    /// `*mut *mut T`-Slot zurueck, in den eine `NetApi*`-Funktion
    /// ihren Puffer schreiben kann. Sobald die Funktion zurueckkehrt,
    /// wird der gespeicherte Pointer als verwaltet betrachtet.
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

    /// Liefert den Raw-Pointer aus. Lebt nur so lange wie der Guard.
    /// Wenn der Guard fallen gelassen wird, wird der Puffer
    /// freigegeben — der Aufrufer darf den Pointer danach nicht mehr
    /// dereferenzieren.
    ///
    /// Returns the raw pointer. Valid only as long as the guard
    /// lives. When the guard is dropped the buffer is freed and the
    /// caller must not dereference the pointer afterwards.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Liefert den Out-Pointer-Slot zum direkten Einsetzen in eine
    /// `NetApi*`-Signatur: `&mut buf.out_ptr()`. Der Pointer im Slot
    /// wird beim Drop des Guards freigegeben.
    ///
    /// Returns an out-pointer slot for direct use in a `NetApi*`
    /// signature: `&mut buf.out_ptr()`. The pointer in the slot is
    /// freed when the guard is dropped.
    pub fn out_ptr(&mut self) -> *mut *mut T {
        &mut self.ptr
    }

    /// Pruefen, ob der Guard tatsaechlich einen Puffer haelt.
    /// Whether the guard actually holds a buffer.
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

impl<T> Drop for NetApiBuffer<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: nur ein erfolgreicher NetApi-Call setzt einen
            // Non-Null-Pointer. Die Free-Verantwortung wurde per
            // `from_raw` an den Guard uebergeben. Doppel-Free ist
            // durch Aliasing-Vermeidung des Aufrufers ausgeschlossen.
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

// `NetApiBuffer` haelt einen Raw-Pointer — bewusst weder `Send` noch
// `Sync`, weil die NetApi-Allocator-Semantik thread-lokal abgesichert
// werden soll. Aufrufer muessen den Guard im selben Thread droppen,
// in dem sie ihn erzeugt haben.
// `NetApiBuffer` holds a raw pointer — deliberately neither `Send`
// nor `Sync` because NetApi allocator semantics should be ensured per
// thread. Callers must drop the guard on the same thread that
// constructed it.

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-Test: ein Null-Pointer fuehrt zu keinem Free-Aufruf
    /// (Drop ist no-op). Verifiziert die NetApiBufferFree-Bedingung
    /// `ptr != null`.
    /// Sanity test: a null pointer leads to no Free call (Drop is a
    /// no-op). Verifies the NetApiBufferFree precondition `ptr != null`.
    #[test]
    fn drop_on_null_is_no_op() {
        let guard: NetApiBuffer<u8> = NetApiBuffer::null();
        assert!(guard.is_null());
        drop(guard); // darf nicht panicken / abstuerzen
    }

    /// Sanity-Test: `out_ptr` liefert einen schreibbaren Slot, der
    /// nach dem Schreiben einen Non-Null-Pointer enthaelt.
    /// Sanity test: `out_ptr` returns a writable slot that holds a
    /// non-null pointer after writing.
    #[test]
    fn out_ptr_can_be_written_and_read_back() {
        let mut guard: NetApiBuffer<u8> = NetApiBuffer::null();
        let slot = guard.out_ptr();
        // Wir schreiben hier KEINEN echten NetApi-Pointer rein, weil
        // wir den nicht freigeben koennen ohne den echten Allocator.
        // Wir simulieren nur, dass `slot` schreibbar ist — und setzen
        // ihn anschliessend wieder auf null, damit Drop kein
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
