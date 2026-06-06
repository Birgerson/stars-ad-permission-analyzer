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

use adpa_core::model::{AccessMask, AceKind, PathTrustee, Sid, TrusteeCategory};
use share_scanner::get_share_dacl;

/// Optionaler Share-Overlay, der einmal pro Share gelesen und an alle
/// Pfade unterhalb dieses Shares angehaengt wird. Schliesst Review
/// Runde 3 Finding 3 (kein stiller Skip der Share-DACL).
///
/// Optional share overlay, read once per share and attached to every
/// path below that share. Closes round-3 finding 3 (no silent skips of
/// the share DACL).
#[derive(Debug, Clone, Default)]
pub struct ShareTrusteeOverlay {
    pub trustees: Vec<PathTrustee>,
}

/// Liest die Share-DACL einmal und produziert eine
/// [`ShareTrusteeOverlay`]. Bei NULL-DACL wird eine erklaerende
/// Pseudo-Zeile ("Everyone (Share NULL DACL)") angefuegt; bei einem
/// Lesefehler eine "Share-DACL nicht lesbar"-Pseudo-Zeile, damit der
/// Fehler im Bericht sichtbar bleibt statt still wegzufallen.
///
/// Reads the share DACL once and produces a [`ShareTrusteeOverlay`].
/// A NULL DACL yields an explanatory pseudo-row; a read failure
/// yields a visible "share DACL not readable" pseudo-row instead of
/// being silently dropped.
pub fn read_share_overlay(server: &str, share_name: &str) -> ShareTrusteeOverlay {
    let mut trustees: Vec<PathTrustee> = Vec::new();
    match get_share_dacl(server, share_name) {
        Ok(scan) => match scan.dacl {
            share_scanner::ShareDacl::NullDacl => {
                trustees.push(PathTrustee {
                    sid: Sid("S-1-1-0".to_owned()),
                    display_name: Some(
                        "Everyone (Share NULL DACL — no SMB restriction)".to_owned(),
                    ),
                    kind: AceKind::Allow,
                    mask: AccessMask(0x001F01FF),
                    inherited: false,
                    inheritance_flags: 0,
                    propagation_flags: 0,
                    category: TrusteeCategory::Share,
                });
            }
            share_scanner::ShareDacl::Acl(perms) => {
                for p in perms {
                    trustees.push(PathTrustee {
                        sid: p.sid.clone(),
                        display_name: None,
                        kind: p.kind.clone(),
                        mask: p.mask,
                        inherited: false,
                        inheritance_flags: 0,
                        propagation_flags: 0,
                        category: TrusteeCategory::Share,
                    });
                }
            }
        },
        Err(e) => {
            trustees.push(PathTrustee {
                sid: Sid(String::new()),
                display_name: Some(format!("Share-DACL nicht lesbar: {e}")),
                kind: AceKind::Allow,
                mask: AccessMask(0),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
                category: TrusteeCategory::Share,
            });
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
pub fn build_path_trustees(
    fso: &adpa_core::model::FileSystemObject,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Vec<PathTrustee> {
    let share_overlay = match (smb_server, share_name) {
        (Some(server), Some(name)) => Some(read_share_overlay(server, name)),
        _ => None,
    };
    build_path_trustees_with_share(fso, share_overlay.as_ref())
}

/// Wie [`build_path_trustees`], aber mit bereits gelesenem Share-
/// Overlay. Scan-Pfade rufen [`read_share_overlay`] einmal vor der
/// Schleife auf und uebergeben die Referenz an jeden Pfad-Aufruf.
///
/// Like [`build_path_trustees`] but with a pre-read share overlay.
pub fn build_path_trustees_with_share(
    fso: &adpa_core::model::FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrustee> {
    let mut out: Vec<PathTrustee> = Vec::new();

    // NTFS-DACL
    if fso.null_dacl {
        out.push(PathTrustee {
            sid: Sid("S-1-1-0".to_owned()),
            display_name: Some("Everyone (NULL DACL — no access restriction)".to_owned()),
            kind: AceKind::Allow,
            mask: AccessMask(0x001F01FF),
            inherited: false,
            inheritance_flags: 0x03, // OI | CI
            propagation_flags: 0,
            category: TrusteeCategory::Ntfs,
        });
    } else {
        for ace in &fso.dacl {
            out.push(PathTrustee {
                sid: ace.sid.clone(),
                display_name: None,
                kind: ace.kind.clone(),
                mask: ace.mask,
                inherited: ace.inherited,
                inheritance_flags: ace.inheritance_flags,
                propagation_flags: ace.propagation_flags,
                category: TrusteeCategory::Ntfs,
            });
        }
    }

    // Share-Overlay anhaengen — wenn der Aufrufer einen SMB-Kontext hat.
    if let Some(overlay) = share_overlay {
        out.extend(overlay.trustees.iter().cloned());
    }

    // SIDs in lesbare Namen aufloesen — eine Runde LSA pro eindeutiger SID.
    // Auf Nicht-Windows-Plattformen (Tests, CI) bleiben display_names None.
    // Resolve SIDs to readable names — one LSA round per unique SID.
    // On non-Windows platforms (tests, CI) display_names remain None.
    #[cfg(windows)]
    {
        let sids: Vec<String> = out
            .iter()
            .map(|r| r.sid.0.clone())
            .filter(|s| !s.is_empty())
            .collect();
        let map = ad_resolver::build_sid_name_map(&[], sids);
        for row in &mut out {
            if row.display_name.is_some() {
                // Erklaerende Pseudo-Zeilen (NULL DACL, Lesefehler) bleiben.
                // Keep explanatory pseudo-rows (NULL DACL, read error).
                continue;
            }
            if let Some(name) = map.get(&row.sid.0) {
                row.display_name = Some(name.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{AceEntry, FileSystemObject, NormalizedPath};

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
                .all(|t| matches!(t.category, TrusteeCategory::Ntfs)),
            "without overlay no Share-category entry must appear"
        );
        let sids: Vec<&str> = trustees.iter().map(|t| t.sid.0.as_str()).collect();
        assert_eq!(
            sids,
            vec!["S-1-5-32-544", "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001"]
        );
    }

    /// NULL-DACL muss als sichtbare Pseudo-Zeile aufgenommen werden —
    /// keine stillen Skips.
    /// NULL DACL must surface as an explicit pseudo-row.
    #[test]
    fn null_dacl_yields_explicit_pseudo_row() {
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
        assert_eq!(trustees.len(), 1, "exactly one pseudo-row for NULL DACL");
        let row = &trustees[0];
        assert_eq!(row.sid.0, "S-1-1-0", "Everyone is the sentinel");
        assert!(
            row.display_name
                .as_deref()
                .unwrap_or("")
                .contains("NULL DACL"),
            "pseudo-row must explain itself"
        );
        assert_eq!(row.category, TrusteeCategory::Ntfs);
    }

    /// Mit Share-Overlay: NTFS-Trustees + Share-Trustees, beide
    /// Kategorien werden im Ergebnis getrennt sichtbar.
    /// With share overlay: NTFS trustees + share trustees, both
    /// categories visible separately.
    #[test]
    fn share_overlay_is_appended_to_ntfs_trustees() {
        let f = fso(vec![ace("S-1-5-32-544", AceKind::Allow, 0x001F01FF, true)]);
        let overlay = ShareTrusteeOverlay {
            trustees: vec![PathTrustee {
                sid: Sid("S-1-1-0".to_owned()),
                display_name: Some("Everyone (share read)".to_owned()),
                kind: AceKind::Allow,
                mask: AccessMask(0x00120089),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
                category: TrusteeCategory::Share,
            }],
        };
        let trustees = build_path_trustees_with_share(&f, Some(&overlay));
        assert_eq!(trustees.len(), 2);
        assert_eq!(trustees[0].category, TrusteeCategory::Ntfs);
        assert_eq!(trustees[1].category, TrusteeCategory::Share);
        assert_eq!(trustees[1].sid.0, "S-1-1-0");
    }
}
