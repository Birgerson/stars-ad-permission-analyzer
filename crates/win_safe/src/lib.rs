// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Sichere Wrapper fuer Windows-API-Ressourcen.
//!
//! Aktuelles Modul: [`netapi`] kapselt von `NetApi`-Funktionen
//! allozierte Puffer mit einem RAII-Guard, der `NetApiBufferFree` im
//! `Drop` aufruft. Damit gibt jeder Pfad — auch ein `?`-Early-Return —
//! die Ressource korrekt frei.
//!
//! Safe wrappers for Windows API resources.
//!
//! Current module: [`netapi`] wraps buffers allocated by `NetApi`
//! functions in a RAII guard that calls `NetApiBufferFree` in `Drop`.
//! That way every path — including a `?` early return — releases the
//! resource correctly.
//!
//! Der Crate ist `windows`-only. Auf Nicht-Windows-Plattformen
//! kompiliert die Bibliothek leer, damit Workspace-Builds (CI auf
//! Linux) nicht scheitern.
//!
//! The crate is `windows`-only. On non-Windows platforms the library
//! compiles empty so workspace builds (CI on Linux) do not fail.

#[cfg(windows)]
pub mod netapi;
