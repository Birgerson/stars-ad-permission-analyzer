# ADR 0002 — Crate name `adpa_core` instead of `core`

**Status:** Accepted
**Date:** 2026-05-20

## Context

The core crate was initially named `core`. Rust's built-in `core` crate (`std::core`, `core::pin`, `core::future`, …) is referenced directly by proc macros such as `async_trait`. A local crate named `core` overlaps that namespace and triggers compile errors like `cannot find pin in core`.

## Decision

The crate is renamed to `adpa_core` (AD Permission Analyzer Core).

## Rationale

- Avoids the collision with Rust's built-in `core` crate.
- The name `adpa_core` is unambiguous and self-describing.
- All other crates import via `use adpa_core::…`.

## Consequences

- All Cargo.toml dependencies and `use` paths updated.
- The `doctest = false` workaround in `core/Cargo.toml` removed.
- Doctests now run normally again.
