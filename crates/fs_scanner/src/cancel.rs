// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Cooperative cancellation token for long-running scans.
//!
//! The walker checks the token at recursion boundaries. Callers (CLI, GUI) hold
//! a clone and may call `cancel()` from another thread.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Thread-sicheres, klonbares Abbruch-Token.
/// Thread-safe, cloneable cancellation token.
///
/// All clones share the same flag — `cancel()` on one clone affects all of them.
#[derive(Clone, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a new, non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Affects all clones.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    /// Resets the token so it can be reused for a new run.
    pub fn reset(&self) {
        self.flag.store(false, Ordering::Relaxed);
    }

    /// Checks whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::CancellationToken;

    #[test]
    fn new_token_is_not_cancelled() {
        assert!(!CancellationToken::new().is_cancelled());
    }

    #[test]
    fn cancel_sets_the_flag() {
        let t = CancellationToken::new();
        t.cancel();
        assert!(t.is_cancelled());
    }

    #[test]
    fn reset_clears_the_flag() {
        let t = CancellationToken::new();
        t.cancel();
        t.reset();
        assert!(!t.is_cancelled());
    }

    #[test]
    fn clones_share_the_same_flag() {
        let a = CancellationToken::new();
        let b = a.clone();
        a.cancel();
        assert!(b.is_cancelled(), "cancel on one clone must affect all");
    }
}
