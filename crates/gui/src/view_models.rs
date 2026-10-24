// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Builders for the view models (`ui/models.slint`) that more than one tab
//! shows (ADR 0082).

use crate::worker::TrusteeRow;
use crate::TrusteeRowVm;

/// One ACE row of a trustee list — the Analyze tab's "Who has access?" and
/// the expanded rows of the Scan Tree: Allow green, Deny red, anything else
/// grey.
pub fn trustee_vm(r: TrusteeRow) -> TrusteeRowVm {
    let kind_color = match r.kind.as_str() {
        "Allow" => slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f),
        "Deny" => slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b),
        _ => slint::Color::from_rgb_u8(0x6c, 0x7a, 0x89),
    };
    TrusteeRowVm {
        display_name: r.display_name.into(),
        sid: r.sid.into(),
        kind: r.kind.into(),
        kind_color,
        rights_label: r.rights_label.into(),
        mask_hex: r.mask_hex.into(),
        source: r.source.into(),
        applies_to: r.applies_to.into(),
        category: r.category.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::trustee_vm;
    use crate::worker::TrusteeRow;

    fn row(kind: &str) -> TrusteeRow {
        TrusteeRow {
            sid: "S-1-5-21-1-2-3-1000".to_owned(),
            display_name: "CORP\\test.user".to_owned(),
            kind: kind.to_owned(),
            rights_label: "Modify (M)".to_owned(),
            mask_hex: "0x001301BF".to_owned(),
            source: "inherited".to_owned(),
            applies_to: "This folder, subfolders and files".to_owned(),
            category: "NTFS".to_owned(),
        }
    }

    /// Every field reaches the row unchanged, and Allow, Deny and anything
    /// else get three different colours — a Deny must never look like an
    /// Allow.
    #[test]
    fn trustee_vm_carries_every_field_and_colours_by_kind() {
        let vm = trustee_vm(row("Deny"));
        assert_eq!(vm.sid, "S-1-5-21-1-2-3-1000");
        assert_eq!(vm.display_name, "CORP\\test.user");
        assert_eq!(vm.kind, "Deny");
        assert_eq!(vm.rights_label, "Modify (M)");
        assert_eq!(vm.mask_hex, "0x001301BF");
        assert_eq!(vm.source, "inherited");
        assert_eq!(vm.applies_to, "This folder, subfolders and files");
        assert_eq!(vm.category, "NTFS");
        let allow = trustee_vm(row("Allow")).kind_color;
        let deny = vm.kind_color;
        let other = trustee_vm(row("Audit")).kind_color;
        assert_eq!(allow, slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f));
        assert_eq!(deny, slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b));
        assert_eq!(other, slint::Color::from_rgb_u8(0x6c, 0x7a, 0x89));
    }
}
