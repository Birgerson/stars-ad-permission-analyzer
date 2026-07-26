// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Manual, read-only update check (ADR 0061).
//!
//! Answers exactly one question — "is a newer version published at the
//! configured source?" — and deliberately nothing more: no download, no
//! installation, no automatic polling. The check runs only when the user
//! triggers it (GUI button / `adpa check-update`), because Stars runs on
//! domain controllers where unsolicited outbound traffic is unacceptable
//! and often impossible.
//!
//! The source URL is user-configurable and must be validated through
//! `validation::update_source::validate_update_source` **before** it
//! reaches [`check_release_source`] — callers (CLI/GUI worker) own that
//! step, mirroring every other input boundary in the project.
//!
//! Everything except the thin HTTPS fetch is network-free testable:
//! response parsing, tag normalization and the SemVer comparison (backed
//! by the tested [`crate::version::AppVersion`], including the F4
//! rc-before-final precedence).

use adpa_core::error::CoreError;
use serde::Deserialize;

use crate::version::AppVersion;

/// Default update source: the official Stars release feed on GitHub.
/// The GitHub REST endpoint returns the latest non-draft, non-prerelease
/// release as JSON with a `tag_name` field.
pub const DEFAULT_UPDATE_SOURCE: &str =
    "https://api.github.com/repos/Birgerson/stars-ad-permission-analyzer/releases/latest";

/// Upper bound for the response body. A release-info JSON is a few KB;
/// anything beyond this cap is either the wrong endpoint or hostile.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Network timeout for the whole request.
const TIMEOUT_SECONDS: u64 = 10;

/// Outcome of an update check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCheckResult {
    /// Version of the running installation (as passed by the caller).
    pub current_version: String,
    /// Version published at the source (tag with any leading `v` removed).
    pub latest_version: String,
    /// `true` when the published version is strictly newer under SemVer
    /// precedence (a final release IS newer than its running rc — F4).
    pub update_available: bool,
    /// Human-facing release page URL, when the source provides one.
    pub release_url: Option<String>,
}

/// The subset of the release JSON the check needs. Unknown fields are
/// ignored on purpose — the GitHub response carries dozens of them.
#[derive(Debug, Deserialize)]
struct LatestRelease {
    tag_name: String,
    #[serde(default)]
    html_url: Option<String>,
}

/// Parses a release-info JSON body (GitHub `releases/latest` shape).
///
/// Network-free — testable without any HTTP. Fails loudly when the body
/// is not JSON or lacks a usable `tag_name`, naming what was wrong.
pub fn parse_latest_release(body: &str) -> Result<(String, Option<String>), CoreError> {
    let release: LatestRelease = serde_json::from_str(body).map_err(|e| {
        CoreError::Validation(format!(
            "update source did not return valid release JSON: {e}"
        ))
    })?;
    let tag = release.tag_name.trim();
    if tag.is_empty() {
        return Err(CoreError::Validation(
            "update source returned an empty tag_name".into(),
        ));
    }
    Ok((tag.to_owned(), release.html_url))
}

/// Strips a single leading `v`/`V` from a release tag (`v1.7.9` → `1.7.9`).
pub fn normalize_tag(tag: &str) -> &str {
    tag.strip_prefix(['v', 'V']).unwrap_or(tag)
}

/// Compares the running version against a release tag.
///
/// Network-free. Both sides go through [`AppVersion`], so precedence is
/// real SemVer: `1.7.8 < 1.7.9`, and a system running `1.7.9-rc1` sees
/// the final `1.7.9` as an update (F4). An unparseable tag is a loud
/// error naming the tag — never a silent "no update".
pub fn evaluate_release_tag(
    current_version: &str,
    tag: &str,
    release_url: Option<String>,
) -> Result<UpdateCheckResult, CoreError> {
    let latest_str = normalize_tag(tag);
    let current = AppVersion::parse(current_version).map_err(|e| {
        CoreError::Validation(format!(
            "installed version '{current_version}' is not a valid version: {e}"
        ))
    })?;
    let latest = AppVersion::parse(latest_str).map_err(|e| {
        CoreError::Validation(format!("published tag '{tag}' is not a valid version: {e}"))
    })?;
    Ok(UpdateCheckResult {
        current_version: current_version.to_owned(),
        latest_version: latest_str.to_owned(),
        update_available: latest > current,
        release_url,
    })
}

/// Performs the full manual check against an **already validated** HTTPS
/// source: fetch → parse → compare.
///
/// The caller must have run the URL through
/// `validation::update_source::validate_update_source`. The fetch uses a
/// 10-second timeout, caps the response at 256 KB, and sends the
/// User-Agent header the GitHub API requires. Network errors surface as
/// clear messages ("could not reach …") — on an offline DC that is the
/// expected, honest answer, not a failure of the tool.
pub fn check_release_source(
    validated_source_url: &str,
    current_version: &str,
) -> Result<UpdateCheckResult, CoreError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECONDS))
        .build();
    let response = agent
        .get(validated_source_url)
        .set(
            "User-Agent",
            concat!("stars-adpa-update-check/", env!("CARGO_PKG_VERSION")),
        )
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => CoreError::Validation(format!(
                "update source answered with HTTP {code} — check the source URL \
                 (a repository without published releases answers 404)"
            )),
            other => CoreError::Validation(format!("could not reach the update source: {other}")),
        })?;

    let mut body = String::new();
    use std::io::Read;
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| {
            CoreError::Validation(format!("could not read the update-source response: {e}"))
        })?;

    let (tag, release_url) = parse_latest_release(&body)?;
    evaluate_release_tag(current_version, &tag, release_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Parsing (network-free) ---

    #[test]
    fn parses_github_release_shape() {
        let body = r#"{
            "tag_name": "v1.7.9",
            "html_url": "https://github.com/x/y/releases/tag/v1.7.9",
            "name": "Stars 1.7.9",
            "draft": false
        }"#;
        let (tag, url) = parse_latest_release(body).unwrap();
        assert_eq!(tag, "v1.7.9");
        assert_eq!(
            url.as_deref(),
            Some("https://github.com/x/y/releases/tag/v1.7.9")
        );
    }

    #[test]
    fn parse_tolerates_missing_html_url() {
        let (tag, url) = parse_latest_release(r#"{"tag_name":"v1.0.0"}"#).unwrap();
        assert_eq!(tag, "v1.0.0");
        assert!(url.is_none());
    }

    #[test]
    fn parse_rejects_garbage_and_missing_tag() {
        assert!(parse_latest_release("not json").is_err());
        assert!(parse_latest_release(r#"{"name":"no tag here"}"#).is_err());
        let err = parse_latest_release(r#"{"tag_name":"   "}"#).unwrap_err();
        assert!(format!("{err}").contains("empty tag_name"));
    }

    // --- Tag normalization ---

    #[test]
    fn normalizes_leading_v_only_once_and_case_insensitively() {
        assert_eq!(normalize_tag("v1.7.9"), "1.7.9");
        assert_eq!(normalize_tag("V1.7.9"), "1.7.9");
        assert_eq!(normalize_tag("1.7.9"), "1.7.9");
        // Only a single leading v is a tag convention — anything else is
        // the tag's own problem and fails version parsing loudly.
        assert_eq!(normalize_tag("vv1.0"), "v1.0");
    }

    // --- Comparison (network-free) ---

    #[test]
    fn newer_release_is_reported_as_update() {
        let r = evaluate_release_tag("1.7.8", "v1.7.9", None).unwrap();
        assert!(r.update_available);
        assert_eq!(r.latest_version, "1.7.9");
        assert_eq!(r.current_version, "1.7.8");
    }

    #[test]
    fn equal_and_older_releases_are_not_updates() {
        assert!(
            !evaluate_release_tag("1.7.8", "v1.7.8", None)
                .unwrap()
                .update_available
        );
        assert!(
            !evaluate_release_tag("1.7.8", "v1.7.7", None)
                .unwrap()
                .update_available
        );
    }

    /// F4 end-to-end at the check layer: a system running the rc must see
    /// the final release as an update.
    #[test]
    fn final_release_is_update_for_running_rc() {
        let r = evaluate_release_tag("1.7.9-rc1", "v1.7.9", None).unwrap();
        assert!(r.update_available);
    }

    #[test]
    fn prerelease_tag_is_not_update_over_its_final() {
        let r = evaluate_release_tag("1.7.9", "v1.7.9-rc2", None).unwrap();
        assert!(!r.update_available);
    }

    /// An unparseable tag must be a loud error naming the tag — a silent
    /// "no update" would hide a broken source forever.
    #[test]
    fn unparseable_tag_fails_loudly() {
        let err = evaluate_release_tag("1.7.8", "latest", None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("latest") && msg.contains("not a valid version"));
    }

    #[test]
    fn release_url_is_passed_through() {
        let r = evaluate_release_tag("1.0.0", "v2.0.0", Some("https://x/rel".into())).unwrap();
        assert_eq!(r.release_url.as_deref(), Some("https://x/rel"));
    }
}
