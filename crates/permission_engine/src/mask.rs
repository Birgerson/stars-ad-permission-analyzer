// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! NTFS access-mask normalization.
//!
//! Translates raw Windows AccessMask values (u32) into named NTFS rights.
//!
//! Bit sources: WinNT.h, MSDN "File Security and Access Rights".

use adpa_core::model::AccessMask;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Specific file rights (bits 0-8) — from WinNT.h
// ---------------------------------------------------------------------------

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_EA: u32 = 0x0000_0008;
/// Write extended attributes.
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Write basic attributes.
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

// ---------------------------------------------------------------------------
// Standard rights (bits 16-20) — from WinNT.h
// ---------------------------------------------------------------------------

pub const FILE_DELETE: u32 = 0x0001_0000;
pub const FILE_READ_CONTROL: u32 = 0x0002_0000;
pub const FILE_WRITE_DAC: u32 = 0x0004_0000;
pub const FILE_WRITE_OWNER: u32 = 0x0008_0000;
/// Synchronization point (SYNCHRONIZE).
pub const FILE_SYNCHRONIZE: u32 = 0x0010_0000;

// ---------------------------------------------------------------------------
// Generic rights (bits 28-31) — Windows maps them to specific rights.
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
// ACE flag bits (WinNT.h) — the scanner places them into inheritance_flags
// (OI|CI) and propagation_flags (NP|IO).
// ---------------------------------------------------------------------------

pub const OBJECT_INHERIT_ACE: u32 = 0x01;
pub const CONTAINER_INHERIT_ACE: u32 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u32 = 0x04;
pub const INHERIT_ONLY_ACE: u32 = 0x08;
pub const INHERITED_ACE: u32 = 0x10;

pub const INHERITANCE_FLAGS_MASK: u32 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
pub const PROPAGATION_FLAGS_MASK: u32 = NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE;

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

// Author / AGPL attribution marker (see ENGINE_ATTRIBUTION in engine.rs).
// Embedded openly in the compiled binary via `#[used]` so attribution
// survives into the shipped artifact. Data only, never read by logic.
#[used]
static MASK_ATTRIBUTION: &str = "Stars permission mask layer - author: Birger Labinsch - AGPL-3.0; copies and derivative works must keep this attribution.";

// ---------------------------------------------------------------------------
// Well-known composite masks (Windows UI / icacls)
// ---------------------------------------------------------------------------

/// F — Full Control (FILE_ALL_ACCESS = STANDARD_RIGHTS_ALL | SYNCHRONIZE | 0x1FF)
pub const MASK_FULL_CONTROL: u32 = 0x001F_01FF;

pub const MASK_MODIFY: u32 = 0x0013_01BF;

/// RX — Read & Execute (FILE_GENERIC_READ + FILE_EXECUTE)
pub const MASK_READ_EXECUTE: u32 = 0x0012_00A9;

/// R — Read (FILE_GENERIC_READ)
pub const MASK_READ: u32 = 0x0012_0089;

/// W — Write (FILE_GENERIC_WRITE)
pub const MASK_WRITE: u32 = 0x0012_0116;

/// ACCESS_SYSTEM_SECURITY — read/write the SACL (WinNT.h).
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// MAXIMUM_ALLOWED — request bit, not a right (WinNT.h).
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The standard permission levels of the Windows basic-permissions dialog,
/// highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardLevel {
    FullControl,
    Modify,
    ReadExecute,
    ReadWrite,
    Read,
    Write,
}

/// Highest first — `base_level` takes the first fully contained one.
const STANDARD_LEVELS: [StandardLevel; 6] = [
    StandardLevel::FullControl,
    StandardLevel::Modify,
    StandardLevel::ReadExecute,
    StandardLevel::ReadWrite,
    StandardLevel::Read,
    StandardLevel::Write,
];

impl StandardLevel {
    /// The level's composite access mask.
    pub fn mask(self) -> u32 {
        match self {
            StandardLevel::FullControl => MASK_FULL_CONTROL,
            StandardLevel::Modify => MASK_MODIFY,
            StandardLevel::ReadExecute => MASK_READ_EXECUTE,
            StandardLevel::ReadWrite => MASK_READ | MASK_WRITE,
            StandardLevel::Read => MASK_READ,
            StandardLevel::Write => MASK_WRITE,
        }
    }

    /// Long name as shown by Windows.
    pub fn name(self) -> &'static str {
        match self {
            StandardLevel::FullControl => "Full Control",
            StandardLevel::Modify => "Modify",
            StandardLevel::ReadExecute => "Read & Execute",
            StandardLevel::ReadWrite => "Read & Write",
            StandardLevel::Read => "Read",
            StandardLevel::Write => "Write",
        }
    }

    /// `icacls` short name.
    pub fn short(self) -> &'static str {
        match self {
            StandardLevel::FullControl => "F",
            StandardLevel::Modify => "M",
            StandardLevel::ReadExecute => "RX",
            StandardLevel::ReadWrite => "RW",
            StandardLevel::Read => "R",
            StandardLevel::Write => "W",
        }
    }
}

/// One access-right bit with the wording of the Windows advanced security
/// dialog and its `icacls` abbreviation.
struct NamedBit {
    bit: u32,
    name: &'static str,
    short: &'static str,
}

/// Every bit a label may have to name, in the order of the Windows advanced
/// security dialog, followed by the bits that dialog does not show.
const NAMED_BITS: &[NamedBit] = &[
    NamedBit {
        bit: FILE_EXECUTE,
        name: "Traverse folder / execute file",
        short: "X",
    },
    NamedBit {
        bit: FILE_READ_DATA,
        name: "List folder / read data",
        short: "RD",
    },
    NamedBit {
        bit: FILE_READ_ATTRIBUTES,
        name: "Read attributes",
        short: "RA",
    },
    NamedBit {
        bit: FILE_READ_EA,
        name: "Read extended attributes",
        short: "REA",
    },
    NamedBit {
        bit: FILE_WRITE_DATA,
        name: "Create files / write data",
        short: "WD",
    },
    NamedBit {
        bit: FILE_APPEND_DATA,
        name: "Create folders / append data",
        short: "AD",
    },
    NamedBit {
        bit: FILE_WRITE_ATTRIBUTES,
        name: "Write attributes",
        short: "WA",
    },
    NamedBit {
        bit: FILE_WRITE_EA,
        name: "Write extended attributes",
        short: "WEA",
    },
    NamedBit {
        bit: FILE_DELETE_CHILD,
        name: "Delete subfolders and files",
        short: "DC",
    },
    NamedBit {
        bit: FILE_DELETE,
        name: "Delete",
        short: "DE",
    },
    NamedBit {
        bit: FILE_READ_CONTROL,
        name: "Read permissions",
        short: "RC",
    },
    NamedBit {
        bit: FILE_WRITE_DAC,
        name: "Change permissions",
        short: "WDAC",
    },
    NamedBit {
        bit: FILE_WRITE_OWNER,
        name: "Take ownership",
        short: "WO",
    },
    NamedBit {
        bit: FILE_SYNCHRONIZE,
        name: "Synchronize",
        short: "S",
    },
    NamedBit {
        bit: ACCESS_SYSTEM_SECURITY,
        name: "Access system security (SACL)",
        short: "AS",
    },
    NamedBit {
        bit: MAXIMUM_ALLOWED,
        name: "Maximum allowed",
        short: "MA",
    },
    NamedBit {
        bit: GENERIC_ALL,
        name: "Generic all",
        short: "GA",
    },
    NamedBit {
        bit: GENERIC_EXECUTE,
        name: "Generic execute",
        short: "GE",
    },
    NamedBit {
        bit: GENERIC_WRITE,
        name: "Generic write",
        short: "GW",
    },
    NamedBit {
        bit: GENERIC_READ,
        name: "Generic read",
        short: "GR",
    },
];

// ---------------------------------------------------------------------------
// NormalizedRights
// ---------------------------------------------------------------------------

/// Normalized representation of a Windows access mask for NTFS objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRights {
    raw: u32,
}

impl NormalizedRights {
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Returns the raw u32 value.
    pub fn raw(&self) -> u32 {
        self.raw
    }

    // --- specific bits ---

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

    /// Checks whether all Full Control bits are set (icacls: F).
    pub fn is_full_control(&self) -> bool {
        self.raw & MASK_FULL_CONTROL == MASK_FULL_CONTROL
    }

    /// Checks whether at least all Modify bits are set (icacls: M).
    pub fn is_modify(&self) -> bool {
        self.raw & MASK_MODIFY == MASK_MODIFY
    }

    /// Checks whether at least all Read & Execute bits are set (icacls: RX).
    pub fn is_read_execute(&self) -> bool {
        self.raw & MASK_READ_EXECUTE == MASK_READ_EXECUTE
    }

    /// Checks whether at least all Read bits are set (icacls: R).
    pub fn is_read(&self) -> bool {
        self.raw & MASK_READ == MASK_READ
    }

    /// Checks whether at least all Write bits are set (icacls: W).
    pub fn is_write(&self) -> bool {
        self.raw & MASK_WRITE == MASK_WRITE
    }

    /// Contains generic rights (not yet mapped to specific rights).
    pub fn has_generic(&self) -> bool {
        self.raw & (GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ) != 0
    }

    /// The highest standard level (Full Control > Modify > Read & Execute >
    /// Read & Write > Read > Write) whose bits are **all** contained in the
    /// mask, or `None` when no standard level is complete.
    pub fn base_level(&self) -> Option<StandardLevel> {
        STANDARD_LEVELS
            .iter()
            .copied()
            .find(|level| self.raw & level.mask() == level.mask())
    }

    /// Splits the mask into its base level and the **extra** rights beyond
    /// it, so a label never hides a bit (lab finding PE3-1): `0x001E0089`
    /// is Read **plus** Change permissions and Take ownership — not "Read".
    /// On top of Read & Execute, a complete Write set is named as "Write"
    /// (the Windows basic-permissions dialog shows both boxes); every other
    /// extra bit is named individually in the order of the Windows advanced
    /// security dialog; bits outside the named set are reported as "other
    /// bits" with their hex value.
    fn decompose(&self) -> (Option<StandardLevel>, Vec<(&'static str, String)>) {
        let base = self.base_level();
        let mut rest = self.raw & !base.map(StandardLevel::mask).unwrap_or(0);
        let mut extras: Vec<(&'static str, String)> = Vec::new();
        if base == Some(StandardLevel::ReadExecute) && self.raw & MASK_WRITE == MASK_WRITE {
            extras.push(("Write", "W".to_owned()));
            rest &= !MASK_WRITE;
        }
        for named in NAMED_BITS {
            if rest & named.bit != 0 {
                extras.push((named.name, named.short.to_owned()));
                rest &= !named.bit;
            }
        }
        if rest != 0 {
            extras.push(("other bits", format!("0x{rest:X}")));
        }
        (base, extras)
    }

    /// Exact short label in the style of `icacls`: the base level alone when
    /// the mask is exactly that level (`R`, `RX`, `M`, `F`, …), the base level
    /// plus the abbreviations of every extra right (`R+WDAC,WO`), the
    /// parenthesised bit list when no standard level is complete
    /// (`(RC,WDAC)`), and `none` for an empty mask.
    pub fn label(&self) -> String {
        if self.raw == 0 {
            return "none".to_owned();
        }
        let (base, extras) = self.decompose();
        let shorts: Vec<&str> = extras.iter().map(|(_, s)| s.as_str()).collect();
        match base {
            Some(level) if shorts.is_empty() => level.short().to_owned(),
            Some(level) => format!("{}+{}", level.short(), shorts.join(",")),
            None => format!("({})", shorts.join(",")),
        }
    }

    /// Exact human-readable long form (reports / CLI / GUI): the base level
    /// alone when the mask is exactly that level, otherwise the base level
    /// plus every extra right by name ("Read + Change permissions, Take
    /// ownership"), "Special: …" with the named rights when no standard
    /// level is complete, and "No access" for an empty mask. The previous
    /// form named only the highest complete level, so `0x001E0089` read as
    /// plain "Read" and an empty mask as "Special" (lab finding PE3-1).
    pub fn display_name(&self) -> String {
        if self.raw == 0 {
            return "No access".to_owned();
        }
        let (base, extras) = self.decompose();
        let names: Vec<String> = extras
            .iter()
            .map(|(name, short)| {
                if *name == "other bits" {
                    format!("other bits {short}")
                } else {
                    (*name).to_owned()
                }
            })
            .collect();
        match base {
            Some(level) if names.is_empty() => level.name().to_owned(),
            Some(level) => format!("{} + {}", level.name(), names.join(", ")),
            None => format!("Special: {}", names.join(", ")),
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
    fn single_bit_is_named_not_hidden_behind_special() {
        let r = rights(FILE_READ_DATA);
        assert!(!r.is_read());
        assert!(!r.is_full_control());
        assert_eq!(r.label(), "(RD)");
        assert_eq!(r.display_name(), "Special: List folder / read data");
    }

    #[test]
    fn zero_mask_is_no_access_not_special() {
        // Lab finding PE3-1: an empty mask used to read "Special", which
        // suggests some right exists.
        let r = rights(0);
        assert_eq!(r.label(), "none");
        assert_eq!(r.display_name(), "No access");
        assert!(!r.read_data());
        assert!(!r.delete());
    }

    #[test]
    fn exact_levels_keep_their_plain_names() {
        for (mask, name, short) in [
            (MASK_FULL_CONTROL, "Full Control", "F"),
            (MASK_MODIFY, "Modify", "M"),
            (MASK_READ_EXECUTE, "Read & Execute", "RX"),
            (MASK_READ | MASK_WRITE, "Read & Write", "RW"),
            (MASK_READ, "Read", "R"),
            (MASK_WRITE, "Write", "W"),
        ] {
            assert_eq!(rights(mask).display_name(), name, "{mask:#X}");
            assert_eq!(rights(mask).label(), short, "{mask:#X}");
        }
    }

    #[test]
    fn extra_rights_beyond_the_base_level_are_named() {
        // Lab case S7: Read + WRITE_DAC + WRITE_OWNER was labelled "Read".
        let s7 = rights(0x001E_0089);
        assert_eq!(
            s7.display_name(),
            "Read + Change permissions, Take ownership"
        );
        assert_eq!(s7.label(), "R+WDAC,WO");
        // Lab case A1: Full Control minus the write bits was labelled
        // "Read & Execute".
        let a1 = rights(0x001F_00E9);
        assert_eq!(
            a1.display_name(),
            "Read & Execute + Delete subfolders and files, Delete, Change permissions, \
             Take ownership"
        );
        assert_eq!(a1.label(), "RX+DC,DE,WDAC,WO");
        // Lab case S14: Read & Execute + Delete.
        assert_eq!(
            rights(0x0013_00A9).display_name(),
            "Read & Execute + Delete"
        );
        // Read & Execute with a complete Write set reads like the basic
        // dialog: both boxes.
        let rxw = rights(MASK_READ_EXECUTE | MASK_WRITE);
        assert_eq!(rxw.display_name(), "Read & Execute + Write");
        assert_eq!(rxw.label(), "RX+W");
        // Modify plus WRITE_DAC.
        assert_eq!(
            rights(MASK_MODIFY | FILE_WRITE_DAC).display_name(),
            "Modify + Change permissions"
        );
    }

    #[test]
    fn masks_without_a_standard_level_list_every_bit() {
        // Owner bits only (lab cases S1/S17): READ_CONTROL + WRITE_DAC.
        let owner = rights(FILE_READ_CONTROL | FILE_WRITE_DAC);
        assert_eq!(
            owner.display_name(),
            "Special: Read permissions, Change permissions"
        );
        assert_eq!(owner.label(), "(RC,WDAC)");
        // Lab case D3: Modify without the read bits (RD, REA, RA, RC) —
        // Traverse/execute stays, it is not a read bit.
        let d3 = rights(0x0011_0136);
        assert_eq!(
            d3.display_name(),
            "Special: Traverse folder / execute file, Create files / write data, \
             Create folders / append data, Write attributes, Write extended attributes, \
             Delete, Synchronize"
        );
        assert_eq!(d3.label(), "(X,WD,AD,WA,WEA,DE,S)");
    }

    #[test]
    fn unnamed_bits_are_reported_with_their_value() {
        // Windows grants the reserved specific bits 0xFE00 on a NULL DACL.
        let r = rights(MASK_FULL_CONTROL | 0x0000_FE00);
        assert_eq!(r.display_name(), "Full Control + other bits 0xFE00");
        assert_eq!(r.label(), "F+0xFE00");
        let generic = rights(GENERIC_READ);
        assert_eq!(generic.display_name(), "Special: Generic read");
        assert_eq!(rights(ACCESS_SYSTEM_SECURITY).label(), "(AS)");
    }

    #[test]
    fn base_level_is_the_highest_complete_level() {
        assert_eq!(
            rights(MASK_FULL_CONTROL).base_level(),
            Some(StandardLevel::FullControl)
        );
        assert_eq!(rights(0x001E_0089).base_level(), Some(StandardLevel::Read));
        assert_eq!(rights(FILE_READ_CONTROL).base_level(), None);
        assert_eq!(rights(0).base_level(), None);
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
        // Share: R, NTFS: M → effective R (the more restrictive)
        let share = rights(MASK_READ);
        let ntfs = rights(MASK_MODIFY);
        let effective = ntfs.intersect(share);
        assert!(effective.is_read());
        assert!(!effective.is_modify());
        assert_eq!(effective.label(), "R");
    }

    #[test]
    fn intersect_share_full_ntfs_read_yields_read() {
        // Share: F, NTFS: R → effective R
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

    // --- generic rights ---

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
