// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! The identity input that the Analyze, Groups and Scan Tree tabs share
//! (ADR 0082): the pre-loaded identity list behind the live suggestions,
//! the suggestion models, and the local name → SID lookup.

use std::cell::RefCell;

use crate::worker::{IdentitySearchResult, IdentitySuggestion};
use crate::IdentitySuggestionVm;

thread_local! {
    /// Pre-loaded identity list for the live search. Filled once after
    /// app start; keystroke filtering runs purely locally against this
    /// cache without a worker round-trip.
    static IDENTITY_CACHE: RefCell<Vec<IdentitySuggestion>> = const { RefCell::new(Vec::new()) };
}

/// At most this many suggestions are shown so the list stays scannable —
/// typing more specifically narrows the results.
pub const MAX_SUGGESTIONS: usize = 15;

pub fn empty_suggestion_model() -> slint::ModelRc<IdentitySuggestionVm> {
    slint::ModelRc::new(slint::VecModel::<IdentitySuggestionVm>::from(Vec::<
        IdentitySuggestionVm,
    >::new()))
}

/// Filters the list cached in `IDENTITY_CACHE` against the query string
/// and returns a Slint ModelRc that can be assigned directly to a
/// `[IdentitySuggestionVm]` property, capped at `MAX_SUGGESTIONS`.
pub fn filter_suggestions_model(query: &str) -> slint::ModelRc<IdentitySuggestionVm> {
    filter_suggestions_model_kinds(query, false)
}

/// `groups_only` keeps only group suggestions (`G` = domain/local group,
/// `L` = BUILTIN group) — used by the Groups tab's Members direction, where a
/// group is expected and user entries are noise (review 2026-07-03, F5).
pub fn filter_suggestions_model_kinds(
    query: &str,
    groups_only: bool,
) -> slint::ModelRc<IdentitySuggestionVm> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return empty_suggestion_model();
    }
    let suggestions: Vec<IdentitySuggestionVm> = IDENTITY_CACHE.with(|c| {
        c.borrow()
            .iter()
            .filter(|s| !groups_only || s.kind_icon == "G" || s.kind_icon == "L")
            .filter(|s| {
                s.qualified.to_lowercase().contains(&q) || s.name.to_lowercase().contains(&q)
            })
            .take(MAX_SUGGESTIONS)
            .map(|s| IdentitySuggestionVm {
                name: s.name.clone().into(),
                qualified: s.qualified.clone().into(),
                kind_icon: s.kind_icon.clone().into(),
                description: s.description.clone().into(),
                // Local entries have no pre-resolved SID; picking one runs an
                // LSA lookup (see the Analyze tab's pick-suggestion).
                sid: slint::SharedString::new(),
            })
            .collect()
    });
    slint::ModelRc::new(slint::VecModel::from(suggestions))
}

/// Builds the picker model from live directory-search hits, reusing the same
/// `IdentitySuggestionVm` rows the local autocomplete uses. Capped at
/// `MAX_SUGGESTIONS` so the list stays scannable. The SID travels in the row
/// so picking a hit fills the SID field directly (no LSA round-trip).
pub fn suggestions_model_from_search(
    results: &[IdentitySearchResult],
) -> slint::ModelRc<IdentitySuggestionVm> {
    let vms: Vec<IdentitySuggestionVm> = results
        .iter()
        .take(MAX_SUGGESTIONS)
        .map(|r| IdentitySuggestionVm {
            name: r.pick_name().into(),
            qualified: r.display_label().into(),
            kind_icon: r.kind_icon().into(),
            description: r.sid.clone().into(),
            sid: r.sid.clone().into(),
        })
        .collect();
    slint::ModelRc::new(slint::VecModel::from(vms))
}

/// Stores the identity list the worker enumerated at app start.
pub fn handle_identities_loaded(result: Result<Vec<IdentitySuggestion>, String>) {
    match result {
        Ok(list) => {
            let count = list.len();
            IDENTITY_CACHE.with(|c| *c.borrow_mut() = list);
            tracing::info!(target: "stars-gui", count, "identity cache populated");
        }
        Err(e) => {
            // Cache stays empty; the live search just shows no suggestions.
            // "Resolve SID" keeps working because it only uses
            // LookupAccountNameW.
            tracing::warn!(target: "stars-gui", error = %e, "identity enumeration failed — live search disabled");
        }
    }
}

/// Windows-only.
/// Translates a user/group name to a SID via the local LSA
/// (`LookupAccountNameW`). Success calls `on_sid` with the resolved SID,
/// failure calls `on_error` with a short message. Empty input is treated
/// as an error that lists the accepted formats. On non-Windows the lookup
/// deliberately does not exist — the entire SAM path is Windows-only.
#[cfg(windows)]
pub fn resolve_name_to_sid(
    name: &str,
    mut on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        on_error(
            "Please enter a user or group name. \
             Accepted formats: DOMAIN\\user, user@domain.lab, \
             plain sAMAccountName (with LDAP server), or a raw SID (S-1-5-21-…)."
                .to_string(),
        );
        return;
    }
    match ad_resolver::lookup_sid_for_account(None, trimmed) {
        Ok(sid) => {
            on_sid(sid.0);
            on_error(String::new());
        }
        Err(e) => on_error(format!("'{trimmed}' could not be resolved: {e}")),
    }
}

#[cfg(not(windows))]
pub fn resolve_name_to_sid(
    _name: &str,
    mut _on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    on_error("Name → SID resolution needs Windows (LSA API).".to_string());
}
