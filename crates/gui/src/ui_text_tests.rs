// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! ADR 0083: the GUI draws every text in one font, Arial, and uses no emoji
//! or symbol icons. A character Arial has no glyph for would be drawn from
//! another font (the Windows emoji or symbol font), so this test fails on
//! any character outside a set checked against Arial's glyph table.

use std::path::{Path, PathBuf};

/// Characters beyond ASCII that the GUI may use — each one checked against
/// Arial regular and bold (2026-10-24): all of Latin-1, the dashes and
/// quotes, the bullet and ellipsis, four arrows, the maths signs Stars
/// prints (∩ for NTFS ∩ Share) and the three triangles of the disclosure
/// toggles.
fn allowed(c: char) -> bool {
    c.is_ascii()
        || ('\u{00A0}'..='\u{00FF}').contains(&c)
        || matches!(
            c,
            '\u{2013}' // en dash
                | '\u{2014}' // em dash
                | '\u{2018}'
                | '\u{2019}'
                | '\u{201C}'
                | '\u{201D}' // quotes
                | '\u{2022}' // bullet
                | '\u{2026}' // ellipsis
                | '\u{2190}'
                ..='\u{2193}' // arrows
                | '\u{2212}' // minus
                | '\u{2229}' // intersection
                | '\u{2260}'
                | '\u{2264}'
                | '\u{2265}'
                | '\u{25B2}' // up triangle
                | '\u{25BA}' // right pointer
                | '\u{25BC}' // down triangle
        )
}

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// Every line of the UI files and of the GUI's Rust code that is not a
/// comment — comments are never drawn.
#[test]
fn gui_texts_use_only_characters_arial_can_draw() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    files(&root.join("ui"), "slint", &mut paths);
    files(&root.join("src"), "rs", &mut paths);
    assert!(paths.len() > 20, "found only {} files", paths.len());
    let mut bad = Vec::new();
    for path in &paths {
        let text = std::fs::read_to_string(path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for c in code.chars().filter(|c| !allowed(*c)) {
                bad.push(format!(
                    "{}:{}: U+{:04X}",
                    path.strip_prefix(root).unwrap_or(path).display(),
                    n + 1,
                    c as u32
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "characters Arial cannot draw:\n{}",
        bad.join("\n")
    );
}

/// The check itself: an emoji and a warning sign are refused, the
/// characters the GUI does use are accepted.
#[test]
fn allowed_set_refuses_emoji_and_symbol_icons() {
    for c in [
        '\u{1F50D}',
        '\u{26A0}',
        '\u{2139}',
        '\u{2713}',
        '\u{25B6}',
        '\u{2605}',
    ] {
        assert!(!allowed(c), "U+{:04X}", c as u32);
    }
    for c in [
        '\u{2014}', '\u{00B7}', '\u{2026}', '\u{2192}', '\u{2229}', '\u{25BC}', '\u{00E4}',
    ] {
        assert!(allowed(c), "U+{:04X}", c as u32);
    }
}
