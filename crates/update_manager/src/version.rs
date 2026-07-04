// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Application version parsing and precedence for the update policy.
//!
//! Implements the SemVer precedence rules the update flow actually needs
//! (deep review 2026-07-04, finding F4): a **pre-release orders before its
//! final release** (`1.1.0-rc1 < 1.1.0`), so a system running an `-rcN`
//! build accepts the final build as an upgrade instead of rejecting it as
//! "not newer". Build metadata (`+…`) is accepted and ignored for
//! precedence (SemVer §10). The same parser backs the manifest schema
//! check, so a manifest with `app_version: "latest"` is rejected at schema
//! time instead of failing later at policy time.

use std::cmp::Ordering;

use adpa_core::error::CoreError;

/// A parsed application version: dotted numeric core plus an optional
/// pre-release identifier list. Ordering follows SemVer §11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppVersion {
    /// Numeric core segments (`1.2.3` → `[1, 2, 3]`). Shorter cores are
    /// padded with zeros for comparison, so `1.2` equals `1.2.0`.
    core: Vec<u64>,
    /// Pre-release identifiers (`-rc.1` → `[Alpha("rc"), Num(1)]`).
    /// `None` means a final release, which orders **after** any
    /// pre-release of the same core.
    pre: Option<Vec<PreReleaseId>>,
}

/// One dot-separated pre-release identifier (SemVer §9/§11): purely
/// numeric identifiers compare numerically and order before alphanumeric
/// ones; alphanumeric identifiers compare in ASCII order.
///
/// Practical note for this project's `rcN` style: `rc1`/`rc2` are single
/// *alphanumeric* identifiers, so they compare lexically — fine up to
/// `rc9`, but `rc10 < rc9` lexically. Two-digit release candidates must
/// be written `rc.10` (numeric identifier) to order numerically.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreReleaseId {
    Num(u64),
    Alpha(String),
}

impl AppVersion {
    /// Parses `MAJOR.MINOR.PATCH[-pre.release][+build]`. The core must be
    /// dotted-numeric; pre-release identifiers must be non-empty ASCII
    /// alphanumerics/hyphens; build metadata is validated for shape but
    /// carries no precedence.
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(CoreError::Validation("version must not be empty".into()));
        }
        // Split off build metadata first (`+` binds after `-` in SemVer).
        let (rest, build) = match s.split_once('+') {
            Some((r, b)) => (r, Some(b)),
            None => (s, None),
        };
        if let Some(b) = build {
            validate_identifier_list(b, "build metadata", input)?;
        }
        let (core_str, pre_str) = match rest.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (rest, None),
        };
        let core = core_str
            .split('.')
            .map(|seg| {
                seg.parse::<u64>().map_err(|e| {
                    CoreError::Validation(format!(
                        "version segment '{seg}' in '{input}' is not numeric: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<u64>, CoreError>>()?;
        let pre = match pre_str {
            None => None,
            Some(p) => {
                validate_identifier_list(p, "pre-release", input)?;
                Some(
                    p.split('.')
                        .map(|id| match id.parse::<u64>() {
                            Ok(n) => PreReleaseId::Num(n),
                            Err(_) => PreReleaseId::Alpha(id.to_owned()),
                        })
                        .collect(),
                )
            }
        };
        Ok(Self { core, pre })
    }

    /// True when this is a pre-release (`-…`) build.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }
}

/// Rejects empty identifiers (`1.0.0-`, `1.0.0-a..b`) and characters
/// outside `[0-9A-Za-z-]` in a dot-separated identifier list.
fn validate_identifier_list(list: &str, what: &str, input: &str) -> Result<(), CoreError> {
    for id in list.split('.') {
        if id.is_empty() {
            return Err(CoreError::Validation(format!(
                "{what} in '{input}' contains an empty identifier"
            )));
        }
        if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(CoreError::Validation(format!(
                "{what} identifier '{id}' in '{input}' contains characters outside [0-9A-Za-z-]"
            )));
        }
    }
    Ok(())
}

impl Ord for AppVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Core: numeric, zero-padded to equal length (`1.2` == `1.2.0`).
        let len = self.core.len().max(other.core.len());
        for i in 0..len {
            let a = self.core.get(i).copied().unwrap_or(0);
            let b = other.core.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        // Equal cores: a final release outranks any of its pre-releases
        // (SemVer §11.3) — the F4 fix: `1.1.0-rc1 < 1.1.0`.
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => compare_prerelease(a, b),
        }
    }
}

impl PartialOrd for AppVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// SemVer §11.4: identifier-by-identifier; numeric < alphanumeric;
/// numeric vs numeric numerically; alpha vs alpha in ASCII order; when
/// all shared identifiers are equal, the shorter list orders first
/// (`rc < rc.1`).
fn compare_prerelease(a: &[PreReleaseId], b: &[PreReleaseId]) -> Ordering {
    for (ai, bi) in a.iter().zip(b.iter()) {
        let ord = match (ai, bi) {
            (PreReleaseId::Num(x), PreReleaseId::Num(y)) => x.cmp(y),
            (PreReleaseId::Num(_), PreReleaseId::Alpha(_)) => Ordering::Less,
            (PreReleaseId::Alpha(_), PreReleaseId::Num(_)) => Ordering::Greater,
            (PreReleaseId::Alpha(x), PreReleaseId::Alpha(y)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> AppVersion {
        AppVersion::parse(s).unwrap()
    }

    // --- Parsing ---

    #[test]
    fn parses_plain_and_prerelease_and_build() {
        assert!(!v("1.2.3").is_prerelease());
        assert!(v("1.2.3-rc1").is_prerelease());
        assert!(!v("1.2.3+build5").is_prerelease());
        assert!(v("1.2.3-rc.1+build5").is_prerelease());
    }

    #[test]
    fn rejects_non_numeric_core() {
        assert!(AppVersion::parse("latest").is_err());
        assert!(AppVersion::parse("1.x.0").is_err());
        assert!(AppVersion::parse("").is_err());
        assert!(AppVersion::parse("1..2").is_err());
    }

    #[test]
    fn rejects_malformed_prerelease() {
        // Trailing dash / empty identifiers are not valid SemVer.
        assert!(AppVersion::parse("1.0.0-").is_err());
        assert!(AppVersion::parse("1.0.0-a..b").is_err());
        assert!(AppVersion::parse("1.0.0-rc_1").is_err());
    }

    // --- Precedence ---

    #[test]
    fn prerelease_orders_before_its_final_release() {
        // The F4 case: a system on `-rc1` must see the final as newer.
        assert_eq!(v("1.1.0-rc1").cmp(&v("1.1.0")), Ordering::Less);
        assert_eq!(v("1.1.0").cmp(&v("1.1.0-rc1")), Ordering::Greater);
    }

    #[test]
    fn prerelease_identifiers_order_per_semver() {
        assert_eq!(v("1.1.0-rc1").cmp(&v("1.1.0-rc2")), Ordering::Less);
        assert_eq!(v("1.1.0-rc1").cmp(&v("1.1.0-rc1")), Ordering::Equal);
        assert_eq!(v("1.0.0-alpha").cmp(&v("1.0.0-beta")), Ordering::Less);
        // Numeric identifiers compare numerically: rc.2 < rc.10.
        assert_eq!(v("1.0.0-rc.2").cmp(&v("1.0.0-rc.10")), Ordering::Less);
        // Numeric orders before alphanumeric.
        assert_eq!(v("1.0.0-1").cmp(&v("1.0.0-alpha")), Ordering::Less);
        // Shorter identifier list orders first when the prefix matches.
        assert_eq!(v("1.0.0-rc").cmp(&v("1.0.0-rc.1")), Ordering::Less);
    }

    #[test]
    fn core_ordering_and_zero_padding_unchanged() {
        assert_eq!(v("1.10.0").cmp(&v("1.9.5")), Ordering::Greater);
        assert_eq!(v("1.2").cmp(&v("1.2.0")), Ordering::Equal);
        assert_eq!(v("0.9.0").cmp(&v("1.0.0")), Ordering::Less);
    }

    #[test]
    fn build_metadata_carries_no_precedence() {
        assert_eq!(v("1.2.3+abc").cmp(&v("1.2.3+xyz")), Ordering::Equal);
        assert_eq!(v("1.2.3+abc").cmp(&v("1.2.3")), Ordering::Equal);
    }
}
