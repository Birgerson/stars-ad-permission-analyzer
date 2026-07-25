// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Safe wrappers for Windows API resources.
//!
//! [`netapi`] wraps buffers allocated by `NetApi*` functions in a RAII
//! guard that calls `NetApiBufferFree` in `Drop`; [`localalloc`] does the
//! same for `LocalAlloc`-owned pointers via `LocalFree`; [`sid`] builds
//! on that guard for the shared SID-to-string conversion. That way every
//! path — including a `?` early return — releases the resource correctly.
//!
//! The crate is `windows`-only. On non-Windows platforms the library
//! compiles empty so workspace builds (CI on Linux) do not fail.

#[cfg(windows)]
pub mod localalloc;
#[cfg(windows)]
pub mod netapi;
#[cfg(windows)]
pub mod sid;
