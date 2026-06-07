// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Sichere Wrapper fuer Windows-API-Ressourcen.
//!
//! Aktuelles Modul: [`netapi`] kapselt von `NetApi`-Funktionen
//! die Ressource korrekt frei.
//!
//! Safe wrappers for Windows API resources.
//!
//! Current module: [`netapi`] wraps buffers allocated by `NetApi`
//! functions in a RAII guard that calls `NetApiBufferFree` in `Drop`.
//! That way every path — including a `?` early return — releases the
//! resource correctly.
//!
//! Linux) nicht scheitern.
//!
//! The crate is `windows`-only. On non-Windows platforms the library
//! compiles empty so workspace builds (CI on Linux) do not fail.

#[cfg(windows)]
pub mod netapi;
