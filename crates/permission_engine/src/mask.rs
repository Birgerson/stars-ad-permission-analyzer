// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! NTFS-Zugriffsmasken-Normalisierung.
//! NTFS access mask normalization.
//!
//! Übersetzt rohe Windows-AccessMask-Werte (u32) in benannte NTFS-Rechte.
//! Translates raw Windows AccessMask values (u32) into named NTFS rights.
//!
//! Bit-Quellen / Bit sources: WinNT.h, MSDN "File Security and Access Rights"

use adpa_core::model::AccessMask;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Spezifische Dateirechte (Bits 0–8) — aus WinNT.h
// Specific file rights (bits 0–8) — from WinNT.h
// ---------------------------------------------------------------------------

/// Datei lesen / Verzeichnisinhalt auflisten
pub const FILE_READ_DATA: u32 = 0x0000_0001;
/// Datei schreiben / Datei in Verzeichnis anlegen
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// Datei anhängen / Unterverzeichnis anlegen
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// Erweiterte Attribute lesen
pub const FILE_READ_EA: u32 = 0x0000_0008;
/// Erweiterte Attribute schreiben
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
/// Datei ausführen / Verzeichnis durchqueren
pub const FILE_EXECUTE: u32 = 0x0000_0020;
/// Unterelemente löschen (nur Verzeichnisse / directories only)
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
/// Basis-Attribute lesen
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Basis-Attribute schreiben
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

// ---------------------------------------------------------------------------
// Standardrechte (Bits 16–20) — aus WinNT.h
// Standard rights (bits 16–20) — from WinNT.h
// ---------------------------------------------------------------------------

/// Objekt löschen
pub const FILE_DELETE: u32 = 0x0001_0000;
/// Security-Descriptor lesen (READ_CONTROL)
pub const FILE_READ_CONTROL: u32 = 0x0002_0000;
/// DACL ändern (WRITE_DAC)
pub const FILE_WRITE_DAC: u32 = 0x0004_0000;
/// Besitzer ändern (WRITE_OWNER)
pub const FILE_WRITE_OWNER: u32 = 0x0008_0000;
/// Synchronisationspunkt (SYNCHRONIZE)
pub const FILE_SYNCHRONIZE: u32 = 0x0010_0000;

// ---------------------------------------------------------------------------
// Generische Rechte (Bits 28–31) — Windows mapped sie auf spezifische Rechte
// Generic rights (bits 28–31) — Windows maps them to specific rights
// ---------------------------------------------------------------------------

pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

/// FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES
///                     | FILE_READ_EA | SYNCHRONIZE
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
///                      | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES
///                        | FILE_EXECUTE | SYNCHRONIZE
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;

// ---------------------------------------------------------------------------
// ACE-Flag-Bits (WinNT.h) — werden vom Scanner in inheritance_flags
// (OI|CI) bzw. propagation_flags (NP|IO) abgelegt.
// ACE flag bits (WinNT.h) — the scanner places them into inheritance_flags
// (OI|CI) and propagation_flags (NP|IO).
// ---------------------------------------------------------------------------

/// OI — Sub-Dateien erben diesen ACE.
pub const OBJECT_INHERIT_ACE: u32 = 0x01;
/// CI — Sub-Verzeichnisse erben diesen ACE.
pub const CONTAINER_INHERIT_ACE: u32 = 0x02;
/// NP — Vererbung wird nicht weiter propagiert (nur direkte Kinder).
pub const NO_PROPAGATE_INHERIT_ACE: u32 = 0x04;
/// IO — ACE gilt nur für Kinder, nicht für das aktuelle Objekt.
pub const INHERIT_ONLY_ACE: u32 = 0x08;
/// INHERITED — ACE wurde vom Parent geerbt (kennzeichnet die Herkunft).
pub const INHERITED_ACE: u32 = 0x10;

/// Bits, die zu `AceEntry::inheritance_flags` gehören (WHAT inherits).
pub const INHERITANCE_FLAGS_MASK: u32 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
/// Bits, die zu `AceEntry::propagation_flags` gehören (HOW it propagates).
pub const PROPAGATION_FLAGS_MASK: u32 = NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE;

/// Expandiert generische Rechtebits (GENERIC_READ/WRITE/EXECUTE/ALL) in die
/// spezifischen Datei-Bits. Muss vor jeder Allow-/Deny-Auswertung erfolgen,
/// sonst „verschwinden" generische ACEs aus der Berechnung (Bits 28–31 sind
/// nicht Teil der spezifischen Datei-Bits, mit denen die Engine arbeitet).
///
/// Expands generic rights bits (GENERIC_READ/WRITE/EXECUTE/ALL) into the
/// specific file bits. Must be applied before any allow/deny evaluation;
/// otherwise generic ACEs effectively vanish from the calculation (bits
/// 28–31 are not part of the specific file bits the engine reasons about).
pub fn expand_generic_rights(mask: u32) -> u32 {
    let mut out = mask;
    if mask & GENERIC_READ != 0 {
        out = (out & !GENERIC_READ) | FILE_GENERIC_READ;
    }
    if mask & GENERIC_WRITE != 0 {
        out = (out & !GENERIC_WRITE) | FILE_GENERIC_WRITE;
    }
    if mask & GENERIC_EXECUTE != 0 {
        out = (out & !GENERIC_EXECUTE) | FILE_GENERIC_EXECUTE;
    }
    if mask & GENERIC_ALL != 0 {
        out = (out & !GENERIC_ALL) | MASK_FULL_CONTROL;
    }
    out
}

// ---------------------------------------------------------------------------
// Bekannte zusammengesetzte Masken (Windows-Benutzeroberfläche / icacls)
// Well-known composite masks (Windows UI / icacls)
// ---------------------------------------------------------------------------

/// F — Full Control (FILE_ALL_ACCESS = STANDARD_RIGHTS_ALL | SYNCHRONIZE | 0x1FF)
pub const MASK_FULL_CONTROL: u32 = 0x001F_01FF;

/// M — Modify (alle Bits außer WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD)
pub const MASK_MODIFY: u32 = 0x0013_01BF;

/// RX — Read & Execute (FILE_GENERIC_READ + FILE_EXECUTE)
pub const MASK_READ_EXECUTE: u32 = 0x0012_00A9;

/// R — Read (FILE_GENERIC_READ)
pub const MASK_READ: u32 = 0x0012_0089;

/// W — Write (FILE_GENERIC_WRITE)
pub const MASK_WRITE: u32 = 0x0012_0116;

// ---------------------------------------------------------------------------
// NormalizedRights
// ---------------------------------------------------------------------------

/// Normalisierte Darstellung einer Windows-Zugriffsmaske für NTFS-Objekte.
/// Normalized representation of a Windows access mask for NTFS objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRights {
    raw: u32,
}

impl NormalizedRights {
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Gibt den Roh-u32-Wert zurück.
    /// Returns the raw u32 value.
    pub fn raw(&self) -> u32 {
        self.raw
    }

    // --- Spezifische Bits / specific bits ---

    pub fn read_data(&self) -> bool {
        self.has(FILE_READ_DATA)
    }
    pub fn write_data(&self) -> bool {
        self.has(FILE_WRITE_DATA)
    }
    pub fn append_data(&self) -> bool {
        self.has(FILE_APPEND_DATA)
    }
    pub fn read_ea(&self) -> bool {
        self.has(FILE_READ_EA)
    }
    pub fn write_ea(&self) -> bool {
        self.has(FILE_WRITE_EA)
    }
    pub fn execute(&self) -> bool {
        self.has(FILE_EXECUTE)
    }
    pub fn delete_child(&self) -> bool {
        self.has(FILE_DELETE_CHILD)
    }
    pub fn read_attributes(&self) -> bool {
        self.has(FILE_READ_ATTRIBUTES)
    }
    pub fn write_attributes(&self) -> bool {
        self.has(FILE_WRITE_ATTRIBUTES)
    }

    // --- Standardrechte / standard rights ---

    pub fn delete(&self) -> bool {
        self.has(FILE_DELETE)
    }
    pub fn read_control(&self) -> bool {
        self.has(FILE_READ_CONTROL)
    }
    pub fn write_dac(&self) -> bool {
        self.has(FILE_WRITE_DAC)
    }
    pub fn write_owner(&self) -> bool {
        self.has(FILE_WRITE_OWNER)
    }
    pub fn synchronize(&self) -> bool {
        self.has(FILE_SYNCHRONIZE)
    }

    // --- Zusammengesetzte Prüfungen / composite checks ---

    /// Prüft ob alle Full-Control-Bits gesetzt sind (icacls: F).
    /// Checks whether all Full Control bits are set (icacls: F).
    pub fn is_full_control(&self) -> bool {
        self.raw & MASK_FULL_CONTROL == MASK_FULL_CONTROL
    }

    /// Prüft ob mindestens alle Modify-Bits gesetzt sind (icacls: M).
    /// Checks whether at least all Modify bits are set (icacls: M).
    pub fn is_modify(&self) -> bool {
        self.raw & MASK_MODIFY == MASK_MODIFY
    }

    /// Prüft ob mindestens alle Read-&-Execute-Bits gesetzt sind (icacls: RX).
    /// Checks whether at least all Read & Execute bits are set (icacls: RX).
    pub fn is_read_execute(&self) -> bool {
        self.raw & MASK_READ_EXECUTE == MASK_READ_EXECUTE
    }

    /// Prüft ob mindestens alle Read-Bits gesetzt sind (icacls: R).
    /// Checks whether at least all Read bits are set (icacls: R).
    pub fn is_read(&self) -> bool {
        self.raw & MASK_READ == MASK_READ
    }

    /// Prüft ob mindestens alle Write-Bits gesetzt sind (icacls: W).
    /// Checks whether at least all Write bits are set (icacls: W).
    pub fn is_write(&self) -> bool {
        self.raw & MASK_WRITE == MASK_WRITE
    }

    /// Enthält generische Rechte (nicht auf spezifische Rechte abgebildet).
    /// Contains generic rights (not yet mapped to specific rights).
    pub fn has_generic(&self) -> bool {
        self.raw & (GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ) != 0
    }

    /// Gibt den höchsten zutreffenden icacls-Kurznamen zurück.
    /// Returns the highest matching icacls short name.
    ///
    /// Reihenfolge: F > M > RX > R, W > (special)
    /// Order: F > M > RX > R, W > (special)
    pub fn label(&self) -> &'static str {
        if self.is_full_control() {
            "F"
        } else if self.is_modify() {
            "M"
        } else if self.is_read_execute() {
            "RX"
        } else if self.is_read() && self.is_write() {
            "RW"
        } else if self.is_read() {
            "R"
        } else if self.is_write() {
            "W"
        } else {
            "(special)"
        }
    }

    /// Gibt eine lesbare Langform zurück (für Berichte / CLI).
    /// Returns a human-readable long form (for reports / CLI).
    pub fn display_name(&self) -> &'static str {
        if self.is_full_control() {
            "Full Control"
        } else if self.is_modify() {
            "Modify"
        } else if self.is_read_execute() {
            "Read & Execute"
        } else if self.is_read() && self.is_write() {
            "Read & Write"
        } else if self.is_read() {
            "Read"
        } else if self.is_write() {
            "Write"
        } else {
            "Special"
        }
    }

    /// Restriktivere Kombination zweier Masken (z. B. NTFS ∩ Share).
    /// More restrictive combination of two masks (e.g. NTFS ∩ Share).
    pub fn intersect(self, other: NormalizedRights) -> NormalizedRights {
        NormalizedRights::new(self.raw & other.raw)
    }

    #[inline]
    fn has(&self, flag: u32) -> bool {
        self.raw & flag != 0
    }
}

impl From<AccessMask> for NormalizedRights {
    fn from(m: AccessMask) -> Self {
        Self::new(m.0)
    }
}

impl From<NormalizedRights> for AccessMask {
    fn from(r: NormalizedRights) -> Self {
        AccessMask(r.raw)
    }
}

impl std::fmt::Display for NormalizedRights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:08X})", self.display_name(), self.raw)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rights(raw: u32) -> NormalizedRights {
        NormalizedRights::new(raw)
    }

    // --- Zusammengesetzte Masken / composite masks ---

    #[test]
    fn full_control_detected() {
        assert!(rights(MASK_FULL_CONTROL).is_full_control());
        assert_eq!(rights(MASK_FULL_CONTROL).label(), "F");
        assert_eq!(rights(MASK_FULL_CONTROL).display_name(), "Full Control");
    }

    #[test]
    fn modify_detected() {
        assert!(rights(MASK_MODIFY).is_modify());
        assert!(!rights(MASK_MODIFY).is_full_control());
        assert_eq!(rights(MASK_MODIFY).label(), "M");
    }

    #[test]
    fn read_execute_detected() {
        assert!(rights(MASK_READ_EXECUTE).is_read_execute());
        assert!(!rights(MASK_READ_EXECUTE).is_modify());
        assert_eq!(rights(MASK_READ_EXECUTE).label(), "RX");
    }

    #[test]
    fn read_detected() {
        assert!(rights(MASK_READ).is_read());
        assert!(!rights(MASK_READ).is_read_execute());
        assert_eq!(rights(MASK_READ).label(), "R");
    }

    #[test]
    fn write_detected() {
        assert!(rights(MASK_WRITE).is_write());
        assert!(!rights(MASK_WRITE).is_read());
        assert_eq!(rights(MASK_WRITE).label(), "W");
    }

    #[test]
    fn special_for_single_bit() {
        let r = rights(FILE_READ_DATA);
        assert!(!r.is_read());
        assert!(!r.is_full_control());
        assert_eq!(r.label(), "(special)");
    }

    #[test]
    fn zero_mask_is_special() {
        let r = rights(0);
        assert_eq!(r.label(), "(special)");
        assert!(!r.read_data());
        assert!(!r.delete());
    }

    // --- Einzelne Bits / individual bits ---

    #[test]
    fn full_control_sets_all_bits() {
        let r = rights(MASK_FULL_CONTROL);
        assert!(r.read_data());
        assert!(r.write_data());
        assert!(r.append_data());
        assert!(r.read_ea());
        assert!(r.write_ea());
        assert!(r.execute());
        assert!(r.delete_child());
        assert!(r.read_attributes());
        assert!(r.write_attributes());
        assert!(r.delete());
        assert!(r.read_control());
        assert!(r.write_dac());
        assert!(r.write_owner());
        assert!(r.synchronize());
    }

    #[test]
    fn modify_missing_write_dac_write_owner_delete_child() {
        let r = rights(MASK_MODIFY);
        assert!(!r.write_dac(), "Modify must not include WRITE_DAC");
        assert!(!r.write_owner(), "Modify must not include WRITE_OWNER");
        assert!(
            !r.delete_child(),
            "Modify must not include FILE_DELETE_CHILD"
        );
        assert!(r.delete(), "Modify must include DELETE");
        assert!(r.write_data(), "Modify must include FILE_WRITE_DATA");
    }

    #[test]
    fn read_missing_write_bits() {
        let r = rights(MASK_READ);
        assert!(!r.write_data());
        assert!(!r.write_ea());
        assert!(!r.write_attributes());
        assert!(!r.delete());
        assert!(r.read_data());
        assert!(r.read_ea());
        assert!(r.read_attributes());
        assert!(r.read_control());
        assert!(r.synchronize());
    }

    // --- Hierarchie / hierarchy ---

    #[test]
    fn full_control_implies_modify() {
        let r = rights(MASK_FULL_CONTROL);
        assert!(r.is_modify(), "Full Control implies Modify");
        assert!(r.is_read_execute(), "Full Control implies Read & Execute");
        assert!(r.is_read(), "Full Control implies Read");
        assert!(r.is_write(), "Full Control implies Write");
    }

    #[test]
    fn modify_implies_read_execute() {
        let r = rights(MASK_MODIFY);
        assert!(r.is_read_execute(), "Modify implies Read & Execute");
        assert!(r.is_read(), "Modify implies Read");
    }

    // --- From/Into ---

    #[test]
    fn from_access_mask_roundtrip() {
        let mask = AccessMask(MASK_FULL_CONTROL);
        let rights: NormalizedRights = mask.into();
        let back: AccessMask = rights.into();
        assert_eq!(back.0, MASK_FULL_CONTROL);
    }

    // --- Intersect (restriktivere Kombination / restrictive combination) ---

    #[test]
    fn intersect_share_read_ntfs_modify_yields_read() {
        // Share: R, NTFS: M → effektiv R (restriktiver / more restrictive)
        let share = rights(MASK_READ);
        let ntfs = rights(MASK_MODIFY);
        let effective = ntfs.intersect(share);
        assert!(effective.is_read());
        assert!(!effective.is_modify());
        assert_eq!(effective.label(), "R");
    }

    #[test]
    fn intersect_share_full_ntfs_read_yields_read() {
        // Share: F, NTFS: R → effektiv R
        let share = rights(MASK_FULL_CONTROL);
        let ntfs = rights(MASK_READ);
        let effective = ntfs.intersect(share);
        assert!(effective.is_read());
        assert!(!effective.is_full_control());
    }

    // --- Display ---

    #[test]
    fn display_includes_hex() {
        let r = rights(MASK_FULL_CONTROL);
        let s = r.to_string();
        assert!(s.contains("Full Control"));
        assert!(s.contains("0x001F01FF"));
    }

    // --- Generische Rechte / generic rights ---

    #[test]
    fn generic_all_detected() {
        let r = rights(GENERIC_ALL);
        assert!(r.has_generic());
        assert!(
            !r.is_full_control(),
            "GENERIC_ALL is not mapped to specific bits here"
        );
    }

    // --- expand_generic_rights ---

    #[test]
    fn expand_generic_all_yields_full_control() {
        // GENERIC_ALL → FILE_ALL_ACCESS (alle spezifischen Bits gesetzt).
        // GENERIC_ALL → FILE_ALL_ACCESS (all specific bits set).
        let expanded = expand_generic_rights(GENERIC_ALL);
        assert_eq!(expanded, MASK_FULL_CONTROL);
        assert!(NormalizedRights::new(expanded).is_full_control());
    }

    #[test]
    fn expand_generic_read_yields_file_generic_read() {
        let expanded = expand_generic_rights(GENERIC_READ);
        assert_eq!(expanded, FILE_GENERIC_READ);
        assert!(NormalizedRights::new(expanded).is_read());
    }

    #[test]
    fn expand_generic_write_yields_file_generic_write() {
        let expanded = expand_generic_rights(GENERIC_WRITE);
        assert_eq!(expanded, FILE_GENERIC_WRITE);
        assert!(NormalizedRights::new(expanded).is_write());
    }

    #[test]
    fn expand_combined_generic_bits_merge() {
        // GENERIC_READ | GENERIC_WRITE → FILE_GENERIC_READ | FILE_GENERIC_WRITE
        let expanded = expand_generic_rights(GENERIC_READ | GENERIC_WRITE);
        assert_eq!(expanded, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
        let r = NormalizedRights::new(expanded);
        assert!(r.is_read());
        assert!(r.is_write());
    }

    #[test]
    fn expand_preserves_specific_bits() {
        // Spezifische Bits dürfen durch die Expansion nicht verloren gehen.
        // Specific bits must not be lost when expansion runs.
        let mask = FILE_DELETE | GENERIC_READ;
        let expanded = expand_generic_rights(mask);
        assert_ne!(expanded & FILE_DELETE, 0, "DELETE bit must survive");
        assert_ne!(expanded & FILE_READ_DATA, 0, "GENERIC_READ must expand");
        assert_eq!(
            expanded & GENERIC_READ,
            0,
            "GENERIC_READ bit must be cleared"
        );
    }

    #[test]
    fn expand_noop_when_no_generic_bits() {
        let expanded = expand_generic_rights(MASK_MODIFY);
        assert_eq!(expanded, MASK_MODIFY);
    }
}
