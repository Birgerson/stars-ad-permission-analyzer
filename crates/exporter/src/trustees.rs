// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Aufbau der pfadzentrischen Trustee-Listen (`PathTrustee` /
//! `PathTrustees`) fuer Auditberichte. Beantwortet die zweite Audit-
//! Frage „wer steht ueberhaupt in der DACL?" identitaetsfrei und ist
//! damit das Pendant zur identitaetsbezogenen
//! `EffectivePermission`-Berechnung.
//!
//! Builds the path-centric trustee lists (`PathTrustee` / `PathTrustees`)
//! for audit reports. Answers the second audit question "who is on the
//! DACL at all?" without an identity context and is the counterpart to
//! the identity-bound `EffectivePermission` computation.
//!
//! Das Modul wurde fuer Review Runde 9 Finding 1 aus
//! `crates/gui/src/worker.rs` extrahiert: die GUI baut die Trustees
//! seit ADR 0038 korrekt, die CLI hatte aber bisher keinen Zugriff auf
//! diese Logik und schickte den Exportern leere `path_trustees`. Jetzt
//! teilen GUI und CLI denselben Helper, ohne dass eine der beiden
//! eine Abhaengigkeit auf die jeweils andere bekommt.
//!
//! Extracted from `crates/gui/src/worker.rs` for round-9 finding 1: the
//! GUI has been building trustees correctly since ADR 0038, but the CLI
//! lacked access to that logic and sent empty `path_trustees` to the
//! exporters. Now both share the same helper without either depending
//! on the other.

use adpa_core::model::{PathTrustee, PathTrusteeEntry, TrusteeCategory};
use share_scanner::get_share_dacl;

/// Optionaler Share-Overlay, der einmal pro Share gelesen und an alle
/// Pfade unterhalb dieses Shares angehaengt wird. Schliesst Review
/// Runde 3 Finding 3 (kein stiller Skip der Share-DACL). Mit Review-
/// Runde 10 Finding 4 sind Eintraege jetzt `PathTrusteeEntry`, sodass
/// Lesefehler und NULL-DACL eindeutig als Diagnose-Variante getragen
/// werden und nicht mehr als synthetisches Allow-ACE getarnt sind.
///
/// Optional share overlay, read once per share and attached to every
/// path below that share. Closes round-3 finding 3 (no silent skips of
/// the share DACL). Since round-10 finding 4 entries are
/// `PathTrusteeEntry` so read failures and NULL DACLs are carried as
/// the dedicated diagnostic variant instead of being disguised as a
/// synthetic Allow ACE.
#[derive(Debug, Clone, Default)]
pub struct ShareTrusteeOverlay {
    pub trustees: Vec<PathTrusteeEntry>,
}

/// Liest die Share-DACL einmal und produziert eine
/// [`ShareTrusteeOverlay`]. Bei NULL-DACL wird eine eigenstaendige
/// `PathTrusteeEntry::Diagnostic`-Variante angefuegt; bei einem
/// Lesefehler ebenfalls — der Renderer und JSON-Konsumenten koennen
/// damit eindeutig zwischen "echter ACE" und "Diagnose" unterscheiden.
///
/// Reads the share DACL once and produces a [`ShareTrusteeOverlay`].
/// A NULL DACL yields a dedicated `PathTrusteeEntry::Diagnostic`
/// variant; a read failure does the same — renderers and JSON
/// consumers can now distinguish unambiguously between "real ACE" and
/// "diagnostic".
pub fn read_share_overlay(server: &str, share_name: &str) -> ShareTrusteeOverlay {
    let mut trustees: Vec<PathTrusteeEntry> = Vec::new();
    match get_share_dacl(server, share_name) {
        Ok(scan) => match scan.dacl {
            share_scanner::ShareDacl::NullDacl => {
                trustees.push(PathTrusteeEntry::diagnostic(
                    TrusteeCategory::Share,
                    "Share NULL DACL — no SMB restriction (effective: Everyone full access)",
                ));
            }
            share_scanner::ShareDacl::Acl(perms) => {
                for p in perms {
                    trustees.push(PathTrusteeEntry::Ace(PathTrustee {
                        sid: p.sid.clone(),
                        display_name: None,
                        kind: p.kind.clone(),
                        mask: p.mask,
                        inherited: false,
                        inheritance_flags: 0,
                        propagation_flags: 0,
                        category: TrusteeCategory::Share,
                    }));
                }
            }
        },
        Err(e) => {
            trustees.push(PathTrusteeEntry::diagnostic(
                TrusteeCategory::Share,
                format!("Share-DACL nicht lesbar / share DACL not readable: {e}"),
            ));
        }
    }
    ShareTrusteeOverlay { trustees }
}

/// Baut die rohe Trustee-Liste aus einem bereits gelesenen
/// [`FileSystemObject`]. Bei vorhandenem SMB-Kontext wird die Share-
/// DACL pro Aufruf neu gelesen — fuer Scans, die viele Pfade pro Share
/// haben, sollte stattdessen einmal [`read_share_overlay`] aufgerufen
/// und das Ergebnis ueber [`build_path_trustees_with_share`] weitergegeben
/// werden.
///
/// Builds the raw trustee list from an already-loaded `FileSystemObject`.
/// If an SMB context is given the share DACL is read once per call —
/// scans with many paths per share should instead read the overlay once
/// via [`read_share_overlay`] and pass it via
/// [`build_path_trustees_with_share`].
///
/// Diese Variante macht **selbst** eine SID→Name-Aufloesung pro Aufruf —
/// sinnvoll fuer den Analyze-Pfad (genau ein Objekt). Scan-Pfade
/// sollten stattdessen [`build_path_trustees_with_share_and_names`]
/// nutzen und die SID→Name-Map einmal pro Scan bauen.
///
/// This variant performs SID→name resolution **itself** per call —
/// appropriate for the analyze path (exactly one object). Scan paths
/// should instead use [`build_path_trustees_with_share_and_names`]
/// and build the SID→name map once per scan.
pub fn build_path_trustees(
    fso: &adpa_core::model::FileSystemObject,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Vec<PathTrusteeEntry> {
    let share_overlay = match (smb_server, share_name) {
        (Some(server), Some(name)) => Some(read_share_overlay(server, name)),
        _ => None,
    };
    build_path_trustees_with_share(fso, share_overlay.as_ref())
}

/// Wie [`build_path_trustees`], aber mit bereits gelesenem Share-
/// Overlay. Macht selbst eine SID→Name-Aufloesung — siehe
/// [`build_path_trustees_with_share_and_names`] fuer die Scan-Variante,
/// die eine vorab gebaute Map akzeptiert.
///
/// Like [`build_path_trustees`] but with a pre-read share overlay.
/// Performs SID→name resolution itself — see
/// [`build_path_trustees_with_share_and_names`] for the scan variant
/// that accepts a pre-built map.
pub fn build_path_trustees_with_share(
    fso: &adpa_core::model::FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrusteeEntry> {
    // Round-10 Finding 2: die einfache Variante ruft jetzt die Caller-
    // owned-Map-Variante mit einer **leeren** Map auf — keine Code-
    // Duplikation. Damit die `with_share`-Form weiterhin selbst LSA
    // aufloest, machen wir den Lookup hier und uebergeben die
    // resultierende Map. So bleibt die alte Schnittstelle erhalten.
    // Round-10 finding 2: the simple form now delegates to the
    // caller-owned-map variant with an **empty** map — no duplication.
    // To keep the `with_share` form resolving SIDs itself, we do the
    // lookup here and hand in the resulting map. The old surface API
    // is preserved.
    #[cfg(windows)]
    let sid_names: std::collections::BTreeMap<String, String> = {
        let sids = collect_ace_sids_for_resolution(fso, share_overlay);
        ad_resolver::build_sid_name_map(&[], sids)
            .into_iter()
            .collect()
    };
    #[cfg(not(windows))]
    let sid_names: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    build_path_trustees_with_share_and_names(fso, share_overlay, &sid_names)
}

/// Sammelt alle ACE-SIDs aus FSO-DACL und Share-Overlay, die einer
/// LSA-Aufloesung beduerfen. Diagnose-Eintraege haben keine SID und
/// werden uebersprungen. Leere SIDs (z. B. aus historischen
/// Diagnose-Pseudo-Zeilen) ebenso. Pub im Crate, damit der Scan-Pfad
/// dieselbe Sammelregel nutzen kann wie die per-Pfad-Form.
///
/// Collects all ACE SIDs from FSO DACL and share overlay that need an
/// LSA lookup. Diagnostic entries carry no SID and are skipped. Empty
/// SIDs (e.g. from historical diagnostic pseudo-rows) likewise. Public
/// inside the crate so the scan path can use the same collection rule
/// as the per-path form.
pub fn collect_ace_sids_for_resolution(
    fso: &adpa_core::model::FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !fso.null_dacl {
        for ace in &fso.dacl {
            if !ace.sid.0.is_empty() {
                out.push(ace.sid.0.clone());
            }
        }
    }
    if let Some(overlay) = share_overlay {
        for entry in &overlay.trustees {
            if let PathTrusteeEntry::Ace(ace) = entry {
                if !ace.sid.0.is_empty() {
                    out.push(ace.sid.0.clone());
                }
            }
        }
    }
    out
}

/// Wie [`build_path_trustees_with_share`], aber mit einer **vorab
/// gebauten** SID→Name-Map. Das ist die Scan-Variante: der Aufrufer
/// sammelt einmal pro Scan alle SIDs (siehe
/// [`collect_ace_sids_for_resolution`]), ruft **einmal**
/// `ad_resolver::build_sid_name_map(...)` und uebergibt die Map an
/// jeden Pfad-Aufruf.
///
/// Hintergrund (Review-Runde 10 Finding 2): die einfache Form macht
/// einen LSA-Lookup pro Pfad — bei 50.000 Pfaden mit denselben
/// BUILTIN-SIDs ist das tausendfach derselbe Lookup. Die Caller-owned-
/// Map ersetzt das durch **einen** Lookup pro Scan.
///
/// Like [`build_path_trustees_with_share`] but with a **pre-built**
/// SID→name map. This is the scan variant: the caller collects all
/// SIDs once per scan (see [`collect_ace_sids_for_resolution`]), calls
/// `ad_resolver::build_sid_name_map(...)` **once**, and hands the map
/// to every per-path call.
///
/// Background (review round 10 finding 2): the simple form does one
/// LSA lookup per path — for 50,000 paths with the same BUILTIN SIDs
/// that is the same lookup repeated thousands of times. The
/// caller-owned map replaces that with **one** lookup per scan.
pub fn build_path_trustees_with_share_and_names(
    fso: &adpa_core::model::FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
    sid_names: &std::collections::BTreeMap<String, String>,
) -> Vec<PathTrusteeEntry> {
    let mut out: Vec<PathTrusteeEntry> = Vec::new();

    // NTFS-DACL
    if fso.null_dacl {
        // NULL-DACL als typisierte Diagnose statt synthetischem Allow-ACE
        // (Review-Runde 10 Finding 4).
        // NULL DACL as a typed diagnostic instead of a synthetic Allow ACE
        // (review round 10 finding 4).
        out.push(PathTrusteeEntry::diagnostic(
            TrusteeCategory::Ntfs,
            "NTFS NULL DACL — no access restriction (effective: Everyone full access)",
        ));
    } else {
        for ace in &fso.dacl {
            out.push(PathTrusteeEntry::Ace(PathTrustee {
                sid: ace.sid.clone(),
                display_name: None,
                kind: ace.kind.clone(),
                mask: ace.mask,
                inherited: ace.inherited,
                inheritance_flags: ace.inheritance_flags,
                propagation_flags: ace.propagation_flags,
                category: TrusteeCategory::Ntfs,
            }));
        }
    }

    // Share-Overlay anhaengen — wenn der Aufrufer einen SMB-Kontext hat.
    if let Some(overlay) = share_overlay {
        out.extend(overlay.trustees.iter().cloned());
    }

    // Round-10 Finding 2: ACE-Display-Names aus der vorgegebenen Map
    // setzen — KEIN LSA-Aufruf pro Pfad. Diagnose-Eintraege werden NICHT
    // angefasst — sie tragen die Begruendung selbst.
    // Round-10 finding 2: set ACE display names from the supplied map —
    // NO LSA call per path. Diagnostic entries are NOT touched — they
    // carry their own reason.
    for entry in &mut out {
        if let PathTrusteeEntry::Ace(ace) = entry {
            if ace.display_name.is_none() {
                if let Some(name) = sid_names.get(&ace.sid.0) {
                    ace.display_name = Some(name.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{AccessMask, AceEntry, AceKind, FileSystemObject, NormalizedPath, Sid};

    fn ace(sid: &str, kind: AceKind, mask: u32, inherited: bool) -> AceEntry {
        AceEntry {
            sid: Sid(sid.to_owned()),
            kind,
            mask: AccessMask(mask),
            inherited,
            inheritance_flags: 0,
            propagation_flags: 0,
        }
    }

    fn fso(dacl: Vec<AceEntry>) -> FileSystemObject {
        FileSystemObject {
            path: NormalizedPath(r"C:\Test".to_owned()),
            is_directory: true,
            owner_sid: None,
            dacl,
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: Vec::new(),
            null_dacl: false,
        }
    }

    /// Round-9 Finding 1: build_path_trustees_with_share schreibt fuer
    /// die GUI und CLI dasselbe Ergebnis. Hier ohne Share-Overlay: nur
    /// die NTFS-DACL fliesst in die Trustees, beide Kategorien werden
    /// nicht vermischt.
    /// Round-9 finding 1: build_path_trustees_with_share emits the same
    /// list for GUI and CLI. Here without share overlay — only NTFS DACL
    /// contributes.
    #[test]
    fn ntfs_only_yields_all_ntfs_trustees() {
        let f = fso(vec![
            ace("S-1-5-32-544", AceKind::Allow, 0x001F01FF, true),
            ace("S-1-5-21-1-2-3-1000", AceKind::Allow, 0x00120089, false),
            ace("S-1-5-21-1-2-3-1001", AceKind::Deny, 0x00100000, false),
        ]);
        let trustees = build_path_trustees_with_share(&f, None);
        assert_eq!(trustees.len(), 3, "all NTFS ACEs must surface as trustees");
        assert!(
            trustees
                .iter()
                .all(|t| matches!(t.category(), TrusteeCategory::Ntfs)),
            "without overlay no Share-category entry must appear"
        );
        let sids: Vec<&str> = trustees
            .iter()
            .filter_map(|t| match t {
                PathTrusteeEntry::Ace(a) => Some(a.sid.0.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            sids,
            vec!["S-1-5-32-544", "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001"]
        );
    }

    /// Round-10 Finding 4: NULL-DACL ist jetzt eine eigenstaendige
    /// Diagnose-Variante, nicht mehr ein synthetisches Allow-ACE.
    /// Round-10 finding 4: NULL DACL is now a dedicated diagnostic
    /// variant, no longer a synthetic Allow ACE.
    #[test]
    fn null_dacl_yields_typed_diagnostic_not_synthetic_ace() {
        let f = FileSystemObject {
            path: NormalizedPath(r"C:\Loose".to_owned()),
            is_directory: false,
            owner_sid: None,
            dacl: vec![],
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: Vec::new(),
            null_dacl: true,
        };
        let trustees = build_path_trustees_with_share(&f, None);
        assert_eq!(trustees.len(), 1, "exactly one diagnostic for NULL DACL");
        match &trustees[0] {
            PathTrusteeEntry::Ace(_) => panic!(
                "NULL DACL must be a typed Diagnostic, not a synthetic Allow ACE \
                 (regression of round-10 finding 4)"
            ),
            PathTrusteeEntry::Diagnostic { category, message } => {
                assert_eq!(*category, TrusteeCategory::Ntfs);
                assert!(
                    message.contains("NULL DACL"),
                    "diagnostic must explain itself, got: {message}"
                );
            }
        }
    }

    /// Mit Share-Overlay: NTFS-Trustees + Share-Trustees, beide
    /// Kategorien werden im Ergebnis getrennt sichtbar.
    /// With share overlay: NTFS trustees + share trustees, both
    /// categories visible separately.
    #[test]
    fn share_overlay_is_appended_to_ntfs_trustees() {
        let f = fso(vec![ace("S-1-5-32-544", AceKind::Allow, 0x001F01FF, true)]);
        let overlay = ShareTrusteeOverlay {
            trustees: vec![PathTrusteeEntry::Ace(PathTrustee {
                sid: Sid("S-1-1-0".to_owned()),
                display_name: Some("Everyone (share read)".to_owned()),
                kind: AceKind::Allow,
                mask: AccessMask(0x00120089),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
                category: TrusteeCategory::Share,
            })],
        };
        let trustees = build_path_trustees_with_share(&f, Some(&overlay));
        assert_eq!(trustees.len(), 2);
        assert_eq!(trustees[0].category(), TrusteeCategory::Ntfs);
        assert_eq!(trustees[1].category(), TrusteeCategory::Share);
        if let PathTrusteeEntry::Ace(ace) = &trustees[1] {
            assert_eq!(ace.sid.0, "S-1-1-0");
        } else {
            panic!("share overlay entry must be an Ace, got diagnostic");
        }
    }

    /// Round-10 Finding 2: die Caller-owned-Map-Variante setzt
    /// uebergebene Display-Namen UND macht keinen eigenen LSA-Aufruf.
    /// Plattform-unabhaengig testbar.
    /// Round-10 finding 2: the caller-owned-map variant applies the
    /// supplied display names AND performs no LSA lookup of its own.
    /// Platform-independent.
    #[test]
    fn caller_owned_map_sets_display_names() {
        use std::collections::BTreeMap;
        let f = fso(vec![
            ace("S-1-5-32-544", AceKind::Allow, 0x001F01FF, true),
            ace("S-1-5-21-1-2-3-1000", AceKind::Allow, 0x00120089, false),
        ]);
        let mut sid_names: BTreeMap<String, String> = BTreeMap::new();
        sid_names.insert(
            "S-1-5-32-544".to_owned(),
            "BUILTIN\\Administrators".to_owned(),
        );
        sid_names.insert(
            "S-1-5-21-1-2-3-1000".to_owned(),
            "TESTDOMAIN\\alice".to_owned(),
        );

        let trustees = build_path_trustees_with_share_and_names(&f, None, &sid_names);
        assert_eq!(trustees.len(), 2);
        if let PathTrusteeEntry::Ace(ace) = &trustees[0] {
            assert_eq!(ace.display_name.as_deref(), Some("BUILTIN\\Administrators"));
        } else {
            panic!("first entry must be Ace");
        }
        if let PathTrusteeEntry::Ace(ace) = &trustees[1] {
            assert_eq!(ace.display_name.as_deref(), Some("TESTDOMAIN\\alice"));
        } else {
            panic!("second entry must be Ace");
        }
    }

    /// Round-10 Finding 2: Diagnose-Eintraege haben keine SID und werden
    /// NICHT mit Display-Namen ueberschrieben.
    /// Round-10 finding 2: diagnostic entries have no SID and are NOT
    /// overwritten with display names.
    #[test]
    fn caller_owned_map_does_not_touch_diagnostics() {
        use std::collections::BTreeMap;
        let f = FileSystemObject {
            path: NormalizedPath(r"C:\Loose".to_owned()),
            is_directory: false,
            owner_sid: None,
            dacl: vec![],
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: Vec::new(),
            null_dacl: true,
        };
        let mut sid_names: BTreeMap<String, String> = BTreeMap::new();
        sid_names.insert("S-1-1-0".to_owned(), "Everyone".to_owned());

        let trustees = build_path_trustees_with_share_and_names(&f, None, &sid_names);
        assert_eq!(trustees.len(), 1);
        match &trustees[0] {
            PathTrusteeEntry::Diagnostic { message, .. } => {
                assert!(
                    message.contains("NULL DACL"),
                    "diagnostic message must remain untouched"
                );
            }
            PathTrusteeEntry::Ace(_) => panic!("NULL DACL must remain a diagnostic"),
        }
    }

    /// Round-10 Finding 2: die Helper-Funktion sammelt SIDs aus FSO-DACL
    /// UND Share-Overlay zusammen — das ist genau die Liste, die der
    /// Scan-Pfad an `build_sid_name_map` weitergibt.
    /// Round-10 finding 2: the helper collects SIDs from FSO DACL AND
    /// share overlay together — exactly the list the scan path hands
    /// to `build_sid_name_map`.
    #[test]
    fn collect_ace_sids_for_resolution_covers_ntfs_and_share() {
        let f = fso(vec![
            ace("S-1-5-32-544", AceKind::Allow, 0x001F01FF, true),
            ace("S-1-5-21-1-2-3-1000", AceKind::Allow, 0x00120089, false),
        ]);
        let overlay = ShareTrusteeOverlay {
            trustees: vec![
                PathTrusteeEntry::Ace(PathTrustee {
                    sid: Sid("S-1-1-0".to_owned()),
                    display_name: None,
                    kind: AceKind::Allow,
                    mask: AccessMask(0x001200A9),
                    inherited: false,
                    inheritance_flags: 0,
                    propagation_flags: 0,
                    category: TrusteeCategory::Share,
                }),
                PathTrusteeEntry::diagnostic(TrusteeCategory::Share, "noise"),
            ],
        };
        let sids = collect_ace_sids_for_resolution(&f, Some(&overlay));
        assert_eq!(
            sids.len(),
            3,
            "two NTFS + one Share ACE; diagnostic skipped"
        );
        assert!(sids.contains(&"S-1-5-32-544".to_owned()));
        assert!(sids.contains(&"S-1-5-21-1-2-3-1000".to_owned()));
        assert!(sids.contains(&"S-1-1-0".to_owned()));
    }

    /// Round-10 Finding 4: JSON-Serialisierung trennt eindeutig
    /// zwischen `kind: "ace"` und `kind: "diagnostic"`. Damit koennen
    /// JSON-Konsumenten das nicht mehr verwechseln.
    /// Round-10 finding 4: JSON serialization unambiguously separates
    /// `kind: "ace"` and `kind: "diagnostic"`. JSON consumers can no
    /// longer confuse the two.
    #[test]
    fn diagnostic_and_ace_have_distinct_json_tags() {
        let ace_entry = PathTrusteeEntry::Ace(PathTrustee {
            sid: Sid("S-1-5-32-544".to_owned()),
            display_name: None,
            kind: AceKind::Allow,
            mask: AccessMask(0x001F01FF),
            inherited: true,
            inheritance_flags: 0,
            propagation_flags: 0,
            category: TrusteeCategory::Ntfs,
        });
        let diag = PathTrusteeEntry::diagnostic(
            TrusteeCategory::Share,
            "Share-DACL nicht lesbar: timeout",
        );

        let ace_json = serde_json::to_string(&ace_entry).expect("serialize Ace");
        let diag_json = serde_json::to_string(&diag).expect("serialize Diagnostic");

        assert!(
            ace_json.contains("\"entry_kind\":\"ace\""),
            "Ace must carry entry_kind=ace, got: {ace_json}"
        );
        assert!(
            diag_json.contains("\"entry_kind\":\"diagnostic\""),
            "Diagnostic must carry entry_kind=diagnostic, got: {diag_json}"
        );
        assert!(
            diag_json.contains("Share-DACL nicht lesbar"),
            "Diagnostic message must be present"
        );
    }
}
