// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! adpa-gui — Graphical interface for the AD Permission Analyzer (Slint).
//!
//! Logfile, panic hook and MessageBox fallback are kept from the eframe
//! predecessors — they are independent of the GUI toolkit and reliably
//! surface startup problems on a bare server.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod worker;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use adpa_core::model::{EffectivePermission, RiskFinding, RiskSeverity, ShareEvalStatus};
use fs_scanner::CancellationToken;
use permission_engine::NormalizedRights;

use crate::worker::{
    spawn_worker, DeltaRow, IdentitySuggestion, LdapParams, NotifyFn, ScanRow, ScanRunSummary,
    TrusteeRow, WorkerEvent, WorkerRequest,
};

// drei voll funktionalen Tabs (Analyze, Scan Tree, Delta).
// Slint UI inline. Defines view models for scan rows, scan errors, risk
// findings, scan runs and delta rows, plus the MainWindow with three
// fully functional tabs (Analyze, Scan Tree, Delta).
slint::slint! {
    import {
        TabWidget, VerticalBox, HorizontalBox, GridBox, GroupBox,
        LineEdit, Button, CheckBox, ScrollView, SpinBox, ComboBox,
        Palette,
    } from "std-widgets.slint";

    // ============================================================
    // Theme — global design tokens with light/dark switching.
    // Theme — global design language with light/dark toggle.
    // ============================================================
    // gepflegt. Komponenten referenzieren `Theme.bg-app`, `Theme.accent`,
    // `Theme.spacing-md` usw. statt Hardcoded-Hex-Werten.
    // All colors, spacings and font sizes live here. Components
    // reference `Theme.bg-app`, `Theme.accent`, `Theme.spacing-md`, …
    // instead of hardcoded hex values.
    export global Theme {
        // Toggle: false = Light (Default), true = Dark.
        in-out property <bool> dark: false;

        // --- Backgrounds ---
        // Neutral, only slightly off-white app background so Slint
        // default widgets stay legible with their system-default text.
        out property <color> bg-app:    dark ? #1a1a24 : #eef0f5;
        out property <color> bg-card:   dark ? #25252f : #ffffff;
        out property <color> bg-header: dark ? #1f1f29 : #ffffff;
        out property <color> bg-input:  dark ? #1a1a26 : #ffffff;
        out property <color> bg-hover:  dark ? #2f2f3c : #e4e8f0;
        out property <color> bg-active: dark ? #34344a : #d4d9e4;

        // --- Text ---
        out property <color> text-primary:   dark ? #e8e8ec : #1f2937;
        out property <color> text-secondary: dark ? #a5a5b5 : #4b5563;
        out property <color> text-muted:     dark ? #707080 : #6b7280;
        out property <color> text-inverse:   #ffffff;

        // --- Borders ---
        // Slightly darker default border so cards and inputs stand out
        // clearly against the light background.
        out property <color> border:        dark ? #3a3a4a : #a8b1c2;
        out property <color> border-strong: dark ? #4a4a5c : #7a8499;

        // --- Accent (Stars warm orange) ---
        // A dark, warm orange reads more comfortably than blue for many
        // eyes and gives Stars a distinct identity. On the light app
        // background a deep orange keeps strong contrast; on dark mode a
        // slightly muted warm tone is used for the soft accent.
        // Hex values deliberately avoid "digit(s) directly followed by
        // e/E", which Rust's tokenizer parses as a float exponent.
        out property <color> accent:         #C2410C;
        out property <color> accent-hover:   #9A3412;
        out property <color> accent-soft:    dark ? #7C3A12 : #FFEDD5;
        out property <color> accent-text:    #ffffff;

        // --- Semantic ramp (diagnostic & severity), light + dark ---
        // correct = Microsoft blue (calm "all good"); info = teal; warning =
        // amber; danger = orange-red (under-report); error = red; ok = green.
        // Hex values avoid "digit directly followed by e/E" (Rust tokenizer).
        out property <color> correct:  dark ? #4DA3FF : #0067C0;
        out property <color> info:     dark ? #45C2D6 : #0891B2;
        out property <color> warning:  dark ? #F5A623 : #D97706;
        out property <color> danger:   dark ? #FB7335 : #EA580C;
        out property <color> error:    dark ? #F05252 : #DC2626;
        out property <color> success:  dark ? #34C759 : #16A34A;

        // --- Spacing (6er-Skala) ---
        out property <length> spacing-xs: 4px;
        out property <length> spacing-sm: 6px;
        out property <length> spacing-md: 10px;
        out property <length> spacing-lg: 14px;
        out property <length> spacing-xl: 20px;

        // --- Radius ---
        out property <length> radius-sm: 4px;
        out property <length> radius-md: 6px;
        out property <length> radius-lg: 10px;

        // --- Fonts ---
        out property <length> font-xs:  11px;
        out property <length> font-sm:  12px;
        out property <length> font-md:  13px;
        out property <length> font-lg:  14px;
        out property <length> font-xl:  16px;
        out property <length> font-xxl: 20px;
    }

    // Haupt-Aktionen wie Analyze, Scan starten, Vergleichen.
    // PrimaryButton — accent background, white text. For main actions.
    //
    // Wichtig: `horizontal-stretch: 0; vertical-stretch: 0` plus
    // Important: pinning stretch + max-height keeps the parent layout
    // from inflating the button to fill the available space.
    component PrimaryButton inherits Rectangle {
        in property <string> text;
        in property <bool> enabled: true;
        callback clicked;

        background: !enabled
            ? Theme.border
            : (ta.has-hover ? Theme.accent-hover : Theme.accent);
        border-radius: Theme.radius-sm;
        horizontal-stretch: 0;
        vertical-stretch: 0;
        preferred-height: 30px;
        max-height: 30px;
        preferred-width: label.preferred-width + 2 * Theme.spacing-lg;
        min-width: 96px;

        animate background { duration: 80ms; }

        label := Text {
            x: Theme.spacing-md;
            y: 0;
            height: parent.height;
            width: parent.width - 2 * Theme.spacing-md;
            text: root.text;
            color: Theme.text-inverse;
            font-size: Theme.font-md;
            font-weight: 600;
            vertical-alignment: center;
            horizontal-alignment: center;
        }

        ta := TouchArea {
            enabled: root.enabled;
            mouse-cursor: enabled ? pointer : default;
            clicked => { root.clicked(); }
        }
    }

    // DangerButton — destruktive Aktionen wie Cancel/Delete.
    // DangerButton — destructive actions like Cancel/Delete.
    component DangerButton inherits Rectangle {
        in property <string> text;
        in property <bool> enabled: true;
        callback clicked;

        background: !enabled
            ? Theme.border
            : (ta.has-hover ? #b91c1c : Theme.error);
        border-radius: Theme.radius-sm;
        horizontal-stretch: 0;
        vertical-stretch: 0;
        preferred-height: 30px;
        max-height: 30px;
        preferred-width: dlabel.preferred-width + 2 * Theme.spacing-lg;
        min-width: 96px;

        animate background { duration: 80ms; }

        dlabel := Text {
            x: Theme.spacing-md;
            y: 0;
            height: parent.height;
            width: parent.width - 2 * Theme.spacing-md;
            text: root.text;
            color: Theme.text-inverse;
            font-size: Theme.font-md;
            font-weight: 600;
            vertical-alignment: center;
            horizontal-alignment: center;
        }

        ta := TouchArea {
            enabled: root.enabled;
            mouse-cursor: enabled ? pointer : default;
            clicked => { root.clicked(); }
        }
    }

    // ThemeToggle — sun/moon switcher for light/dark.
    // klickbare Schaltflaeche.
    // Theme toggle — deliberately uses a text label instead of a sole
    // Unicode glyph, because Slint's software backend on Windows Server
    // (default font) does not reliably render U+263E (☾) / U+2600 (☀).
    // With border + background + text the toggle is clearly visible.
    component ThemeToggle inherits Rectangle {
        height: 32px;
        width: 110px;
        border-radius: Theme.radius-sm;
        border-width: 1px;
        border-color: ta.has-hover ? Theme.accent : Theme.border;
        background: ta.has-hover ? Theme.bg-hover : Theme.bg-card;

        animate background, border-color { duration: 80ms; }

        HorizontalLayout {
            padding-left: 8px;
            padding-right: 8px;
            spacing: 6px;
            alignment: center;
            Text {
                text: Theme.dark ? "☀" : "☾";
                font-size: 14px;
                color: Theme.text-primary;
                vertical-alignment: center;
            }
            Text {
                text: Theme.dark ? "Light" : "Dark";
                font-size: Theme.font-sm;
                color: Theme.text-primary;
                vertical-alignment: center;
            }
        }

        ta := TouchArea {
            mouse-cursor: pointer;
            clicked => { Theme.dark = !Theme.dark; }
        }
    }

    // HeaderBar — Brand-Block links, Status-/Theme-Controls rechts.
    // HeaderBar — brand block left, status/theme controls right.
    component HeaderBar inherits Rectangle {
        in property <string> app-title: "Stars";
        in property <string> app-subtitle: "AD Permission Analyzer";
        in property <string> version-text;
        height: 48px;
        background: Theme.bg-header;
        // Dezente untere Trennlinie
        // Subtle bottom separator
        Rectangle {
            x: 0;
            y: parent.height - 1px;
            width: parent.width;
            height: 1px;
            background: Theme.border;
        }

        HorizontalLayout {
            padding-left: Theme.spacing-lg;
            padding-right: Theme.spacing-md;
            padding-top: Theme.spacing-sm;
            padding-bottom: Theme.spacing-sm;
            spacing: Theme.spacing-md;

            // Brand block: star + title (incl. version) + subtitle
            HorizontalLayout {
                spacing: Theme.spacing-sm;
                Text {
                    text: "★";
                    font-size: Theme.font-xxl;
                    color: Theme.accent;
                    vertical-alignment: center;
                }
                VerticalLayout {
                    HorizontalLayout {
                        spacing: Theme.spacing-sm;
                        alignment: start;
                        Text {
                            text: root.app-title;
                            font-size: Theme.font-xl;
                            font-weight: 700;
                            color: Theme.text-primary;
                            vertical-alignment: center;
                        }
                        if root.version-text != "": Text {
                            text: root.version-text;
                            font-size: Theme.font-sm;
                            font-weight: 500;
                            color: Theme.text-secondary;
                            vertical-alignment: center;
                        }
                    }
                    Text {
                        text: root.app-subtitle;
                        font-size: Theme.font-xs;
                        color: Theme.text-muted;
                    }
                }
            }

            // Spacer
            Rectangle { horizontal-stretch: 1; }

            ThemeToggle {}
        }
    }

    // Wiederverwendbares ⓘ-Help-Icon. Bei Hover erscheint ein kleiner
    // Reusable ⓘ help icon. On hover a small dark tooltip box appears
    // right next to the icon. The tooltip is only shown while hovered,
    // overlays its neighbors (Slint renders children over siblings)
    // and disappears as soon as the mouse leaves.
    component HelpTip inherits Rectangle {
        in property <string> tip;
        width: 20px;
        height: 20px;

        Text {
            text: "ⓘ";
            font-size: Theme.font-lg;
            color: Theme.accent;
            horizontal-alignment: center;
            vertical-alignment: center;
        }

        ta := TouchArea {
            mouse-cursor: help;
        }

        if ta.has-hover: Rectangle {
            x: parent.width + 6px;
            y: parent.height / 2;
            background: Theme.dark ? #15151c : #1f2937;
            border-radius: Theme.radius-sm;
            border-color: Theme.border-strong;
            border-width: 1px;
            width: 320px;
            height: tip-text.preferred-height + 14px;

            tip-text := Text {
                x: 8px;
                y: 6px;
                width: parent.width - 16px;
                text: root.tip;
                color: white;
                font-size: Theme.font-xs;
                wrap: word-wrap;
            }
        }
    }

    // One row in the trustee view — declared ahead of ScanRowVm because
    // ScanRowVm carries the model as a field and Slint's parser requires
    // forward declarations.
    export struct TrusteeRowVm {
        display_name: string,
        sid: string,
        kind: string,
        kind_color: color,
        rights_label: string,
        mask_hex: string,
        source: string,
        applies_to: string,
        category: string,
    }

    // One diagnostic marker — its reason plus whether it is a warning
    // (evaluation may be incomplete) or only informational. Declared ahead of
    // ScanRowVm because that struct carries the model as a field.
    export struct DiagnosticVm {
        text: string,
        // 0 = info, 1 = warning, 2 = high (PermissionDiagnostic::severity).
        level: int,
    }

    // A row in the scan result.
    export struct ScanRowVm {
        path: string,
        rights_label: string,
        mask_hex: string,
        steps: [string],
        // Path-centric trustee list (every ACE resolved). Shown in the
        // expanded state alongside the identity-based explanation path.
        trustees: [TrusteeRowVm],
        expanded: bool,
        has_diagnostic: bool,
        // Row presentation level: 0 = correct/complete, 1 = info-only,
        // 2 = warning (incomplete), 3 = high (under-report marker present).
        row_severity: int,
        // Per-diagnostic reasons for this row (engine review 2026-06-13
        // finding 2), each with its severity. Shown in the expanded detail so
        // the GUI surfaces *why* a row is flagged, warnings apart from info.
        diagnostics: [DiagnosticVm],
    }

    // A scan error (a path could not be evaluated).
    export struct ScanErrorVm {
        path: string,
        message: string,
    }

    // A risk finding.
    // A risk finding.
    export struct RiskItemVm {
        severity_label: string,
        severity_color: color,
        rule_id: string,
        description: string,
        affected_path: string,
        incomplete: bool,
    }

    // A persisted scan run in the Delta tab's list.
    export struct ScanRunVm {
        id: string,
        label: string,
        selected_as_old: bool,
        selected_as_new: bool,
    }

    // A delta row (Added / Removed / Changed).
    export struct DeltaRowVm {
        path: string,
        kind_label: string,
        kind_color: color,
        old_rights: string,
        new_rights: string,
    }

    // A suggestion in the live search below the name field.
    export struct IdentitySuggestionVm {
        name: string,
        qualified: string,
        kind_icon: string,
        description: string,
    }

    export component MainWindow inherits Window {
        title: "Stars — AD Permission Analyzer";
        preferred-width: 1100px;
        preferred-height: 720px;
        min-width: 800px;
        min-height: 560px;
        background: Theme.bg-app;
        // Stars only runs on Windows Server hosts (see AGENTS.md).
        // Arial is guaranteed and renders consistently across editions.
        default-font-family: "Arial";

        // Pin Slint widget palette to our explicit toggle so the
        // host theme cannot override readability. Reactive binding via
        // a tracking property + `changed` callback (Slint 1.6+).
        property <ColorScheme> _palette-scheme: Theme.dark ? ColorScheme.dark : ColorScheme.light;
        init => {
            Palette.color-scheme = self._palette-scheme;
        }
        changed _palette-scheme => {
            Palette.color-scheme = self._palette-scheme;
        }

        // Version / branding text for the HeaderBar — set by main.rs at
        // setup so the UI does not need to decide what to render.
        in property <string> app-version: "";

        // ============================================================
        // Analyze-Tab Properties / Analyze tab properties
        // ============================================================
        // Pre-fill the SYSVOL directory: exists on every default
        // Windows Server DC install, is audit-relevant (Group Policy
        // templates, login scripts) and saves the first keystroke. The
        // user can overwrite the path at any time — the property is
        // `in-out`.
        in-out property <string> a-path: "C:\\Windows\\SYSVOL\\sysvol";
        // User/group name as a convenient alternative to typing a SID
        // directly. `resolve-name-clicked` translates the name via LSA
        // into the SID and writes it to the SID field. The user can
        // still type a SID into the SID field directly.
        in-out property <string> a-name;
        in property <string> a-name-error;
        in property <[IdentitySuggestionVm]> a-suggestions;
        in-out property <string> a-sid;

        // LDAP mode: 0 = off (SAM/LSA, recommended on DC),
        //            1 = LDAPS (encrypted, port 636),
        //            2 = plain LDAP (port 389, test only).
        in-out property <int>    a-ldap-mode: 0;
        in-out property <string> a-ldap-server;
        in-out property <string> a-ldap-base-dn;
        in-out property <string> a-ldap-bind-dn;
        in-out property <string> a-ldap-password;

        in-out property <bool>   a-smb-enabled;
        in-out property <string> a-smb-server;
        in-out property <string> a-smb-share;

        in property <bool>   a-is-running;
        in property <string> a-status;
        in property <bool>   a-status-is-error;
        in property <string> a-rights-label;
        in property <string> a-mask-hex;
        in property <string> a-share-line;
        in property <[string]> a-explanation;
        // Trustee view: path-centric listing of all ACEs without a fixed
        // identity.
        in property <[TrusteeRowVm]> a-trustees;
        in property <bool>           a-has-trustees;
        in property <bool>           a-trustees-running;

        callback analyze-clicked();
        callback analyze-trustees-clicked();
        callback resolve-name-clicked();
        callback analyze-name-edited(string);
        callback pick-analyze-suggestion(string);

        // ============================================================
        // Scan-Tab Properties / Scan tab properties
        // ============================================================
        // Root path pre-filled to SYSVOL, analogous to the Analyze tab.
        in-out property <string> s-root: "C:\\Windows\\SYSVOL\\sysvol";
        // Analogous to the Analyze tab: name → SID helper.
        in-out property <string> s-name;
        in property <string> s-name-error;
        in property <[IdentitySuggestionVm]> s-suggestions;
        in-out property <string> s-sid;

        in-out property <bool>   s-limit-depth;
        in-out property <int>    s-max-depth: 5;

        // LDAP mode analogous to the Analyze tab. 0 = off (SAM/LSA),
        // 1 = LDAPS, 2 = plain LDAP.
        in-out property <int>    s-ldap-mode: 0;
        in-out property <string> s-ldap-server;
        in-out property <string> s-ldap-base-dn;
        in-out property <string> s-ldap-bind-dn;
        in-out property <string> s-ldap-password;

        in-out property <bool>   s-smb-enabled;
        in-out property <string> s-smb-server;
        in-out property <string> s-smb-share;

        in property <bool>   s-is-running;
        in property <bool>   s-done;
        in property <string> s-status;
        in property <bool>   s-status-is-error;
        in property <int>    s-total;
        in property <int>    s-error-count;
        in property <string> s-scan-run-id;

        in-out property <string> s-filter;
        in property <[ScanRowVm]>    s-rows;
        in property <[ScanErrorVm]>  s-errors;
        in property <[RiskItemVm]>   s-risks;

        in-out property <string> s-export-path;
        in property <string> s-export-message;
        in property <bool>   s-export-is-error;

        callback scan-clicked();
        callback scan-cancel-clicked();
        callback scan-row-toggle(int);
        callback scan-filter-changed();
        callback export-clicked();
        callback resolve-scan-name-clicked();
        callback scan-name-edited(string);
        callback pick-scan-suggestion(string);

        // ============================================================
        // Delta-Tab Properties / Delta tab properties
        // ============================================================
        in property <bool>   d-is-loading;
        in property <string> d-status;
        in property <bool>   d-status-is-error;
        in property <[ScanRunVm]>  d-scan-runs;
        in property <[DeltaRowVm]> d-rows;
        in property <bool>   d-has-result;
        in property <int>    d-added-count;
        in property <int>    d-removed-count;
        in property <int>    d-changed-count;

        callback delta-load-runs-clicked();
        callback delta-pick-old(string);
        callback delta-pick-new(string);
        callback delta-compare-clicked();
        // Request to delete a scan run. The GUI prompts via the
        // d-pending-delete dialog first; the worker only sees the request
        // after confirmation.
        callback delta-delete-confirmed(string);

        // ID of the scan run for which the confirmation dialog should be
        // visible. Empty = no dialog open.
        in-out property <string> d-pending-delete-id;
        in-out property <string> d-pending-delete-label;

        VerticalLayout {
            spacing: 0;

            HeaderBar {
                app-title: "Stars";
                app-subtitle: "AD Permission Analyzer";
                version-text: root.app-version;
            }

            // Content area with consistent padding around the TabWidget;
            // the TabWidget keeps its Slint default look but gets some air.
            Rectangle {
                background: Theme.bg-app;

                VerticalLayout {
                    padding-left: Theme.spacing-md;
                    padding-right: Theme.spacing-md;
                    padding-top: Theme.spacing-md;
                    padding-bottom: Theme.spacing-md;

                    TabWidget {
                // ============================================================
                // Tab: Analyze
                // ============================================================
                Tab {
                    title: "Analyze";

                    ScrollView {
                        VerticalBox {
                            padding: Theme.spacing-md;
                            spacing: Theme.spacing-sm;

                            GroupBox {
                                title: "Target";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Path:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "C:\\Folder  or  \\\\server\\share\\Folder";
                                                text <=> root.a-path;
                                            }
                                        }
                                        Row {
                                            Text { text: "Identity:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "local name · DOMAIN\\user · user@domain.lab · S-1-5-21-…";
                                                text <=> root.a-name;
                                                edited(s) => { root.analyze-name-edited(s); }
                                                accepted(s) => { root.resolve-name-clicked(); }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            Text {
                                                text: "One field for any identity — a local name, DOMAIN\\user, UPN, or a raw SID. Stars resolves it when you run; the suggestion list covers local accounts, and 'Resolve SID' is an optional preview.";
                                                color: Theme.text-muted;
                                                font-size: 11px;
                                                wrap: word-wrap;
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            HorizontalBox {
                                                alignment: start;
                                                spacing: Theme.spacing-sm;
                                                padding: 0px;
                                                Button {
                                                    text: "🔍 Resolve SID";
                                                    clicked => { root.resolve-name-clicked(); }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            if root.a-suggestions.length > 0: Rectangle {
                                                background: Theme.bg-card;
                                                border-color: Theme.border;
                                                border-width: 1px;
                                                border-radius: 4px;
                                                VerticalLayout {
                                                    padding: 4px;
                                                    spacing: 0px;
                                                    Text {
                                                        text: "[L] = local identity of this machine";
                                                        color: Theme.text-muted;
                                                        font-size: 11px;
                                                    }
                                                    for sug[i] in root.a-suggestions: TouchArea {
                                                        height: 24px;
                                                        clicked => { root.pick-analyze-suggestion(sug.name); }
                                                        HorizontalLayout {
                                                            padding-left: 6px;
                                                            padding-right: 6px;
                                                            spacing: Theme.spacing-sm;
                                                            Text {
                                                                text: "[" + sug.kind_icon + "]";
                                                                color: Theme.text-secondary;
                                                                width: 28px;
                                                                vertical-alignment: center;
                                                            }
                                                            Text {
                                                                text: sug.qualified;
                                                                color: Theme.text-primary;
                                                                vertical-alignment: center;
                                                                width: 320px;
                                                                overflow: elide;
                                                            }
                                                            Text {
                                                                text: sug.description;
                                                                color: Theme.text-muted;
                                                                horizontal-stretch: 1;
                                                                overflow: elide;
                                                                vertical-alignment: center;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: "Resolved SID:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "auto-filled when you run · or paste a SID directly";
                                                text <=> root.a-sid;
                                            }
                                        }
                                    }
                                    if root.a-name-error != "": Text {
                                        text: root.a-name-error;
                                        color: Theme.error;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Identity resolution";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        padding: 0px;
                                        Text {
                                            text: "Mode:";
                                            vertical-alignment: center;
                                            width: 110px;
                                        }
                                        ComboBox {
                                            model: [
                                                "Off — use SAM/LSA (recommended on a DC)",
                                                "LDAPS — encrypted, port 636",
                                                "Plain LDAP — port 389 (test only)",
                                                "Global Catalog — forest-wide, port 3269 (LDAPS)",
                                                "Signed LDAP — Kerberos sign & seal, port 389",
                                            ];
                                            current-index <=> root.a-ldap-mode;
                                            horizontal-stretch: 1;
                                        }
                                        HelpTip {
                                            tip: "How should identity and groups be resolved?\n\n• Off (recommended): uses the local Windows LSA/SAM. On a domain controller this returns complete data (users, global groups, local groups). No configuration, no certificate needed.\n\n• LDAPS: encrypted LDAP connection on port 636. Requires the DC to have a valid LDAPS certificate that this machine trusts (AD CS enterprise CA); a self-signed certificate is rejected. Connect by FQDN, not IP.\n\n• Plain LDAP: port 389, no TLS. For test environments only — transmits the password in cleartext, and is refused by hardened Windows Server 2022/2025 DCs (LDAP signing).\n\n• Global Catalog: forest-wide bind over LDAPS (port 3269). Base DN may be left empty. Same certificate requirement as LDAPS. Only universal groups replicate fully to the GC, so memberships are flagged potentially incomplete.\n\n• Signed LDAP: port 389 with Kerberos sign & seal — no certificate needed. The cert-free way to query a hardened DC that enforces LDAP signing. Uses the current Windows logon (no bind DN / password); Server must be the DC's FQDN. Run Stars as the domain account whose context you want.";
                                        }
                                    }

                                    if root.a-ldap-mode > 0: GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "dc01.domain.local";
                                                text <=> root.a-ldap-server;
                                            }
                                            HelpTip {
                                                tip: "Fully qualified hostname (FQDN) of the domain controller.\n\nExample: dc01.company.local\n\nDo not enter a scheme prefix (no ldap:// or ldaps://) — the mode determines it.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Base DN:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "DC=domain,DC=local";
                                                text <=> root.a-ldap-base-dn;
                                            }
                                            HelpTip {
                                                tip: "Distinguished Name of the domain root.\n\nExample: DC=company,DC=local\n\nComma-separated, no spaces after the commas. Derivable from the DNS domain: 'company.local' becomes 'DC=company,DC=local'.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Bind DN:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "CN=SvcScan,CN=Users,DC=domain,DC=local";
                                                text <=> root.a-ldap-bind-dn;
                                            }
                                            HelpTip {
                                                tip: "Full DN of the service or auditor account used to bind against LDAP.\n\nNot just the username — the full path to the object:\nCN=Max Muster,OU=Users,DC=company,DC=local\n\nA dedicated read-only service account is recommended, not the domain admin.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Passwort:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                input-type: password;
                                                text <=> root.a-ldap-password;
                                            }
                                            HelpTip {
                                                tip: "Password for the bind-DN account.\n\nNot persisted, only held in memory for the running session. With 'Plain LDAP' it crosses the wire in cleartext — use only in test environments.";
                                            }
                                        }
                                    }
                                }
                            }

                            GroupBox {
                                title: "SMB share (optional, combines NTFS ∩ share)";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    CheckBox {
                                        text: "Include share mask";
                                        checked <=> root.a-smb-enabled;
                                    }
                                    if root.a-smb-enabled: GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "fileserver";
                                                text <=> root.a-smb-server;
                                            }
                                        }
                                        Row {
                                            Text { text: "Share:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "data";
                                                text <=> root.a-smb-share;
                                            }
                                        }
                                    }
                                }
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: Theme.spacing-sm;
                                PrimaryButton {
                                    text: root.a-is-running ? "Running..." : "▶  Analyze";
                                    enabled: !root.a-is-running;
                                    clicked => { root.analyze-clicked(); }
                                }
                                // Zweite Audit-Frage: pfadzentrierte
                                // Second audit question: path-centric
                                // trustee view. Needs no identity because
                                // it lists every ACE on the path.
                                Button {
                                    text: root.a-trustees-running ? "Running..." : "Who has access?";
                                    enabled: !root.a-trustees-running;
                                    clicked => { root.analyze-trustees-clicked(); }
                                }
                            }

                            if root.a-status != "": Text {
                                text: root.a-status;
                                color: root.a-status-is-error ? Theme.error : Theme.text-primary;
                                wrap: word-wrap;
                            }

                            Text {
                                text: "Note: every analysis is stored automatically in the scan history and becomes comparable in the Delta tab.";
                                color: Theme.text-muted;
                                font-size: 12px;
                                wrap: word-wrap;
                            }

                            if root.a-rights-label != "": GroupBox {
                                title: "Result";
                                VerticalBox {
                                    spacing: 4px;
                                    Text {
                                        text: "Effective rights: " + root.a-rights-label;
                                        font-size: 16px;
                                    }
                                    Text {
                                        text: "Access-Mask: " + root.a-mask-hex;
                                        color: Theme.text-secondary;
                                    }
                                    if root.a-share-line != "": Text {
                                        text: root.a-share-line;
                                        color: Theme.text-secondary;
                                    }
                                    Text {
                                        text: "Permission path:";
                                        font-size: 14px;
                                    }
                                    for step[i] in root.a-explanation: Text {
                                        text: (i + 1) + ". " + step;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            // Trustee view: shows every ACE on the path,
                            // independent of any identity token. Complement
                            // to the identity-based effective analysis above.
                            if root.a-has-trustees: GroupBox {
                                title: "Who has access (" + root.a-trustees.length + " ACE entries)";
                                VerticalBox {
                                    spacing: 4px;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text { text: "Trustee"; font-weight: 700; horizontal-stretch: 2; }
                                        Text { text: "Kind"; font-weight: 700; width: 70px; }
                                        Text { text: "Rights"; font-weight: 700; width: 220px; }
                                        Text { text: "Source"; font-weight: 700; width: 80px; }
                                        Text { text: "Applies to"; font-weight: 700; width: 220px; }
                                        Text { text: "Layer"; font-weight: 700; width: 70px; }
                                    }
                                    for t[i] in root.a-trustees: HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text {
                                            text: t.display_name;
                                            color: Theme.text-primary;
                                            horizontal-stretch: 2;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: t.kind;
                                            color: t.kind_color;
                                            width: 70px;
                                        }
                                        Text {
                                            text: t.rights_label;
                                            color: Theme.text-secondary;
                                            width: 220px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: t.source;
                                            color: Theme.text-secondary;
                                            width: 80px;
                                        }
                                        Text {
                                            text: t.applies_to;
                                            color: Theme.text-secondary;
                                            width: 220px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: t.category;
                                            color: Theme.text-secondary;
                                            width: 70px;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ============================================================
                // Tab: Scan Tree
                // ============================================================
                Tab {
                    title: "Scan Tree";

                    ScrollView {
                        VerticalBox {
                            padding: Theme.spacing-md;
                            spacing: Theme.spacing-sm;

                            GroupBox {
                                title: "Target";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Root path:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "C:\\Data  or  \\\\server\\share\\Data";
                                                text <=> root.s-root;
                                            }
                                        }
                                        Row {
                                            Text { text: "Identity:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "local name · DOMAIN\\user · user@domain.lab · S-1-5-21-…";
                                                text <=> root.s-name;
                                                edited(s) => { root.scan-name-edited(s); }
                                                accepted(s) => { root.resolve-scan-name-clicked(); }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            Text {
                                                text: "One field for any identity — a local name, DOMAIN\\user, UPN, or a raw SID. Stars resolves it when you run; the suggestion list covers local accounts, and 'Resolve SID' is an optional preview.";
                                                color: Theme.text-muted;
                                                font-size: 11px;
                                                wrap: word-wrap;
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            HorizontalBox {
                                                alignment: start;
                                                spacing: Theme.spacing-sm;
                                                padding: 0px;
                                                Button {
                                                    text: "🔍 Resolve SID";
                                                    clicked => { root.resolve-scan-name-clicked(); }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            if root.s-suggestions.length > 0: Rectangle {
                                                background: Theme.bg-card;
                                                border-color: Theme.border;
                                                border-width: 1px;
                                                border-radius: 4px;
                                                VerticalLayout {
                                                    padding: 4px;
                                                    spacing: 0px;
                                                    Text {
                                                        text: "[L] = local identity of this machine";
                                                        color: Theme.text-muted;
                                                        font-size: 11px;
                                                    }
                                                    for sug[i] in root.s-suggestions: TouchArea {
                                                        height: 24px;
                                                        clicked => { root.pick-scan-suggestion(sug.name); }
                                                        HorizontalLayout {
                                                            padding-left: 6px;
                                                            padding-right: 6px;
                                                            spacing: Theme.spacing-sm;
                                                            Text {
                                                                text: "[" + sug.kind_icon + "]";
                                                                color: Theme.text-secondary;
                                                                width: 28px;
                                                                vertical-alignment: center;
                                                            }
                                                            Text {
                                                                text: sug.qualified;
                                                                color: Theme.text-primary;
                                                                vertical-alignment: center;
                                                                width: 320px;
                                                                overflow: elide;
                                                            }
                                                            Text {
                                                                text: sug.description;
                                                                color: Theme.text-muted;
                                                                horizontal-stretch: 1;
                                                                overflow: elide;
                                                                vertical-alignment: center;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: "Resolved SID:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "auto-filled when you run · or paste a SID directly";
                                                text <=> root.s-sid;
                                            }
                                        }
                                        // Depth limit row stretches its
                                        // second-column container so the
                                        // label column stays aligned with
                                        // the rows above.
                                        Row {
                                            Text { text: "Depth:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            HorizontalLayout {
                                                spacing: Theme.spacing-md;
                                                alignment: start;
                                                horizontal-stretch: 1;
                                                VerticalLayout {
                                                    alignment: center;
                                                    horizontal-stretch: 0;
                                                    CheckBox {
                                                        text: "Limit depth";
                                                        checked <=> root.s-limit-depth;
                                                    }
                                                }
                                                if root.s-limit-depth: VerticalLayout {
                                                    alignment: center;
                                                    horizontal-stretch: 0;
                                                    SpinBox {
                                                        minimum: 1;
                                                        maximum: 100;
                                                        value <=> root.s-max-depth;
                                                        width: 120px;
                                                        height: 30px;
                                                    }
                                                }
                                                // verbreitern.
                                                // Spacer to keep contents left-
                                                // aligned without inflating.
                                                Rectangle { horizontal-stretch: 1; }
                                            }
                                        }
                                    }
                                    if root.s-name-error != "": Text {
                                        text: root.s-name-error;
                                        color: Theme.error;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Identity resolution";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        padding: 0px;
                                        Text {
                                            text: "Mode:";
                                            vertical-alignment: center;
                                            width: 110px;
                                        }
                                        ComboBox {
                                            model: [
                                                "Off — use SAM/LSA (recommended on a DC)",
                                                "LDAPS — encrypted, port 636",
                                                "Plain LDAP — port 389 (test only)",
                                                "Global Catalog — forest-wide, port 3269 (LDAPS)",
                                                "Signed LDAP — Kerberos sign & seal, port 389",
                                            ];
                                            current-index <=> root.s-ldap-mode;
                                            horizontal-stretch: 1;
                                        }
                                        HelpTip {
                                            tip: "How should identity and groups be resolved?\n\n• Off (recommended): uses the local Windows LSA/SAM. On a domain controller this returns complete data (users, global groups, local groups). No configuration, no certificate needed.\n\n• LDAPS: encrypted LDAP connection on port 636. Requires the DC to have a valid LDAPS certificate that this machine trusts (AD CS enterprise CA); a self-signed certificate is rejected. Connect by FQDN, not IP.\n\n• Plain LDAP: port 389, no TLS. For test environments only — transmits the password in cleartext, and is refused by hardened Windows Server 2022/2025 DCs (LDAP signing).\n\n• Global Catalog: forest-wide bind over LDAPS (port 3269). Base DN may be left empty. Same certificate requirement as LDAPS. Only universal groups replicate fully to the GC, so memberships are flagged potentially incomplete.\n\n• Signed LDAP: port 389 with Kerberos sign & seal — no certificate needed. The cert-free way to query a hardened DC that enforces LDAP signing. Uses the current Windows logon (no bind DN / password); Server must be the DC's FQDN. Run Stars as the domain account whose context you want.";
                                        }
                                    }

                                    if root.s-ldap-mode > 0: GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "dc01.domain.local";
                                                text <=> root.s-ldap-server;
                                            }
                                            HelpTip {
                                                tip: "Fully qualified hostname (FQDN) of the domain controller.\n\nExample: dc01.company.local\n\nDo not enter a scheme prefix (no ldap:// or ldaps://) — the mode determines it.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Base DN:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "DC=domain,DC=local";
                                                text <=> root.s-ldap-base-dn;
                                            }
                                            HelpTip {
                                                tip: "Distinguished Name of the domain root.\n\nExample: DC=company,DC=local\n\nComma-separated, no spaces after the commas. Derivable from the DNS domain: 'company.local' becomes 'DC=company,DC=local'.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Bind DN:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "CN=SvcScan,CN=Users,DC=domain,DC=local";
                                                text <=> root.s-ldap-bind-dn;
                                            }
                                            HelpTip {
                                                tip: "Full DN of the service or auditor account used to bind against LDAP.\n\nNot just the username — the full path to the object:\nCN=Max Muster,OU=Users,DC=company,DC=local\n\nA dedicated read-only service account is recommended, not the domain admin.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Passwort:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                input-type: password;
                                                text <=> root.s-ldap-password;
                                            }
                                            HelpTip {
                                                tip: "Password for the bind-DN account.\n\nNot persisted, only held in memory for the running session. With 'Plain LDAP' it crosses the wire in cleartext — use only in test environments.";
                                            }
                                        }
                                    }
                                }
                            }

                            GroupBox {
                                title: "SMB share (optional)";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    CheckBox {
                                        text: "Include share mask";
                                        checked <=> root.s-smb-enabled;
                                    }
                                    if root.s-smb-enabled: GridBox {
                                        spacing: Theme.spacing-sm;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "fileserver";
                                                text <=> root.s-smb-server;
                                            }
                                        }
                                        Row {
                                            Text { text: "Share:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                            LineEdit {
                                                placeholder-text: "data";
                                                text <=> root.s-smb-share;
                                            }
                                        }
                                    }
                                }
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: Theme.spacing-sm;
                                PrimaryButton {
                                    text: root.s-is-running ? "Running..." : "▶  Start scan";
                                    enabled: !root.s-is-running;
                                    clicked => { root.scan-clicked(); }
                                }
                                DangerButton {
                                    text: "■  Cancel";
                                    enabled: root.s-is-running;
                                    clicked => { root.scan-cancel-clicked(); }
                                }
                            }

                            if root.s-status != "": Text {
                                text: root.s-status;
                                color: root.s-status-is-error ? Theme.error : Theme.text-primary;
                                wrap: word-wrap;
                            }

                            if root.s-done || root.s-is-running: GroupBox {
                                title: "Results (" + root.s-total + " paths, "
                                    + root.s-error-count + " errors)";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text { text: "Filter:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                        LineEdit {
                                            placeholder-text: "Path substring filter";
                                            text <=> root.s-filter;
                                            edited(s) => { root.scan-filter-changed(); }
                                        }
                                    }

                                    for row[i] in root.s-rows: VerticalBox {
                                        spacing: 2px;
                                        TouchArea {
                                            clicked => { root.scan-row-toggle(i); }
                                            HorizontalBox {
                                                spacing: Theme.spacing-sm;
                                                alignment: start;
                                                Text {
                                                    text: row.expanded ? "▼" : "▶";
                                                    width: 16px;
                                                }
                                                Text {
                                                    text: row.path;
                                                    // Attention ramp: concern → orange-red,
                                                    // notice → amber, neutral (correct or expected
                                                    // caveat) → plain text. Only real problems pop.
                                                    color: row.row-severity == 2 ? Theme.danger
                                                         : row.row-severity == 1 ? Theme.warning
                                                         : Theme.text-primary;
                                                    overflow: elide;
                                                    horizontal-stretch: 1;
                                                }
                                                Text {
                                                    text: row.rights_label;
                                                    color: Theme.text-primary;
                                                    width: 200px;
                                                }
                                                Text {
                                                    text: row.mask_hex;
                                                    color: #777;
                                                    width: 120px;
                                                }
                                            }
                                        }
                                        if row.expanded: VerticalBox {
                                            padding-left: 24px;
                                            spacing: Theme.spacing-sm;
                                            VerticalBox {
                                                spacing: 1px;
                                                for step[j] in row.steps: Text {
                                                    text: (j + 1) + ". " + step;
                                                    color: #444;
                                                    wrap: word-wrap;
                                                }
                                            }

                                            // Diagnostic reasons — surface
                                            // *why* this row is flagged
                                            // (incompleteness / informational
                                            // markers), not just the colored
                                            // path. Mirrors the CLI/HTML/CSV
                                            // diagnostics so uncertainty is
                                            // visible in the GUI scan tree
                                            // (review 2026-06-13 finding 2).
                                            if row.diagnostics.length > 0: VerticalBox {
                                                spacing: 1px;
                                                Text {
                                                    text: "Diagnostics (" + row.diagnostics.length + "):";
                                                    color: Theme.text-secondary;
                                                    font-weight: 700;
                                                }
                                                // neutral (ℹ, grey) · notice (⚠, amber) · concern (⚠, orange-red).
                                                for diag[d] in row.diagnostics: Text {
                                                    text: (diag.level == 0 ? "ℹ " : "⚠ ") + diag.text;
                                                    color: diag.level == 2 ? Theme.danger
                                                         : diag.level == 1 ? Theme.warning
                                                         : Theme.text-secondary;
                                                    wrap: word-wrap;
                                                }
                                            }

                                            // Path-centric trustee table —
                                            // the second audit question "who
                                            // can access this path at all?"
                                            // directly in the scan row.
                                            if row.trustees.length > 0: VerticalBox {
                                                spacing: 1px;
                                                Text {
                                                    text: "Who has access (" + row.trustees.length + " ACE entries):";
                                                    color: Theme.text-primary;
                                                    font-weight: 700;
                                                }
                                                HorizontalBox {
                                                    spacing: Theme.spacing-sm;
                                                    Text { text: "Trustee"; font-weight: 700; horizontal-stretch: 2; color: Theme.text-secondary; }
                                                    Text { text: "Kind"; font-weight: 700; width: 60px; color: Theme.text-secondary; }
                                                    Text { text: "Rights"; font-weight: 700; width: 180px; color: Theme.text-secondary; }
                                                    Text { text: "Source"; font-weight: 700; width: 70px; color: Theme.text-secondary; }
                                                    Text { text: "Applies to"; font-weight: 700; width: 200px; color: Theme.text-secondary; }
                                                    Text { text: "Layer"; font-weight: 700; width: 60px; color: Theme.text-secondary; }
                                                }
                                                for t[k] in row.trustees: HorizontalBox {
                                                    spacing: Theme.spacing-sm;
                                                    Text { text: t.display_name; color: #444; horizontal-stretch: 2; overflow: elide; }
                                                    Text { text: t.kind; color: t.kind_color; width: 60px; }
                                                    Text { text: t.rights_label; color: Theme.text-secondary; width: 180px; overflow: elide; }
                                                    Text { text: t.source; color: Theme.text-secondary; width: 70px; }
                                                    Text { text: t.applies_to; color: Theme.text-secondary; width: 200px; overflow: elide; }
                                                    Text { text: t.category; color: Theme.text-secondary; width: 60px; }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if root.s-errors.length > 0: GroupBox {
                                title: "Scan errors";
                                VerticalBox {
                                    spacing: 2px;
                                    for err[i] in root.s-errors: HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text {
                                            text: err.path != "" ? err.path : "(no path)";
                                            color: Theme.error;
                                            width: 320px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: err.message;
                                            wrap: word-wrap;
                                            horizontal-stretch: 1;
                                        }
                                    }
                                }
                            }

                            if root.s-risks.length > 0: GroupBox {
                                title: "Risk Findings";
                                VerticalBox {
                                    spacing: 4px;
                                    for risk[i] in root.s-risks: VerticalBox {
                                        spacing: 1px;
                                        HorizontalBox {
                                            spacing: Theme.spacing-sm;
                                            alignment: start;
                                            Text {
                                                text: "[" + risk.severity_label + "]";
                                                color: risk.severity_color;
                                                width: 100px;
                                            }
                                            Text {
                                                text: risk.rule_id;
                                                color: Theme.text-primary;
                                                width: 220px;
                                            }
                                            Text {
                                                text: risk.affected_path;
                                                color: Theme.text-secondary;
                                                overflow: elide;
                                                horizontal-stretch: 1;
                                            }
                                        }
                                        Text {
                                            text: risk.incomplete
                                                ? "⚠ incomplete — " + risk.description
                                                : risk.description;
                                            color: #444;
                                            wrap: word-wrap;
                                        }
                                    }
                                }
                            }

                            if root.s-done: GroupBox {
                                title: "Export HTML report";
                                VerticalBox {
                                    spacing: Theme.spacing-sm;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text { text: "Target file:"; vertical-alignment: center; horizontal-stretch: 0; width: 140px; }
                                        LineEdit {
                                            placeholder-text: "C:\\Reports\\scan.html";
                                            text <=> root.s-export-path;
                                        }
                                        PrimaryButton {
                                            text: "💾  Export";
                                            clicked => { root.export-clicked(); }
                                        }
                                    }
                                    if root.s-export-message != "": Text {
                                        text: root.s-export-message;
                                        color: root.s-export-is-error ? #c0392b : #16a085;
                                        wrap: word-wrap;
                                    }
                                }
                            }
                        }
                    }
                }

                // ============================================================
                // Tab: Delta
                // ============================================================
                Tab {
                    title: "Delta";

                    ScrollView {
                        VerticalBox {
                            padding: Theme.spacing-md;
                            spacing: Theme.spacing-sm;

                            Text {
                                text: "Compare two scan runs — show paths "
                                    + "that were added, removed, or saved with different "
                                    + "rights.";
                                wrap: word-wrap;
                                color: Theme.text-secondary;
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: Theme.spacing-sm;
                                PrimaryButton {
                                    text: root.d-is-loading ? "Loading..." : "📂  Load scan history";
                                    enabled: !root.d-is-loading;
                                    clicked => { root.delta-load-runs-clicked(); }
                                }
                            }

                            if root.d-status != "": Text {
                                text: root.d-status;
                                color: root.d-status-is-error ? Theme.error : Theme.text-primary;
                                wrap: word-wrap;
                            }

                            if root.d-scan-runs.length > 0: GroupBox {
                                title: "Available scan runs (select the older one as 'Old')";
                                VerticalBox {
                                    spacing: 4px;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text {
                                            text: "Old";
                                            width: 60px;
                                            font-weight: 700;
                                        }
                                        Text {
                                            text: "New";
                                            width: 60px;
                                            font-weight: 700;
                                        }
                                        Text {
                                            text: "Scan run";
                                            horizontal-stretch: 1;
                                            font-weight: 700;
                                        }
                                    }
                                    for run[i] in root.d-scan-runs: HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        CheckBox {
                                            text: "";
                                            width: 60px;
                                            checked: run.selected_as_old;
                                            toggled => { root.delta-pick-old(run.id); }
                                        }
                                        CheckBox {
                                            text: "";
                                            width: 60px;
                                            checked: run.selected_as_new;
                                            toggled => { root.delta-pick-new(run.id); }
                                        }
                                        Text {
                                            text: run.label;
                                            horizontal-stretch: 1;
                                            overflow: elide;
                                            wrap: no-wrap;
                                        }
                                        // Trash button — opens the
                                        // confirmation dialog, no instant
                                        // delete. The actual action runs
                                        // only after confirmation.
                                        Button {
                                            text: "🗑";
                                            width: 36px;
                                            clicked => {
                                                root.d-pending-delete-id = run.id;
                                                root.d-pending-delete-label = run.label;
                                            }
                                        }
                                    }
                                }
                            }

                            if root.d-scan-runs.length > 0: HorizontalBox {
                                alignment: start;
                                spacing: Theme.spacing-sm;
                                PrimaryButton {
                                    text: "⟳  Compare";
                                    clicked => { root.delta-compare-clicked(); }
                                }
                            }

                            // Confirmation dialog — not a separate popup but an
                            // inline visible box so a stray trash click does
                            // not delete immediately.
                            if root.d-pending-delete-id != "": Rectangle {
                                background: #fff3cd;
                                border-color: #c69210;
                                border-width: 1px;
                                border-radius: 4px;
                                VerticalBox {
                                    padding: Theme.spacing-md;
                                    spacing: Theme.spacing-sm;
                                    Text {
                                        text: "Really remove this scan run?";
                                        font-weight: 700;
                                        color: #5c4500;
                                    }
                                    Text {
                                        text: root.d-pending-delete-label;
                                        color: #5c4500;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "This action cannot be undone. All permissions and scan errors stored for this run will be deleted along with it.";
                                        color: #5c4500;
                                        wrap: word-wrap;
                                        font-size: 12px;
                                    }
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        alignment: end;
                                        Button {
                                            text: "Cancel";
                                            clicked => {
                                                root.d-pending-delete-id = "";
                                                root.d-pending-delete-label = "";
                                            }
                                        }
                                        Button {
                                            text: "Delete permanently";
                                            clicked => {
                                                root.delta-delete-confirmed(root.d-pending-delete-id);
                                                root.d-pending-delete-id = "";
                                                root.d-pending-delete-label = "";
                                            }
                                        }
                                    }
                                }
                            }

                            if root.d-has-result: GroupBox {
                                title: "Delta (" + root.d-added-count + " added, "
                                    + root.d-removed-count + " removed, "
                                    + root.d-changed-count + " changed)";
                                VerticalBox {
                                    spacing: 2px;
                                    HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text {
                                            text: "Path";
                                            font-weight: 700;
                                            horizontal-stretch: 1;
                                        }
                                        Text {
                                            text: "Kind";
                                            font-weight: 700;
                                            width: 110px;
                                        }
                                        Text {
                                            text: "Old";
                                            font-weight: 700;
                                            width: 180px;
                                        }
                                        Text {
                                            text: "New";
                                            font-weight: 700;
                                            width: 180px;
                                        }
                                    }
                                    // Empty delta: explicitly state that the comparison ran and
                                    // found nothing — otherwise the user sees an empty table and
                                    // thinks the click was lost.
                                    if root.d-rows.length == 0: Text {
                                        text: "No differences found between the two scans. Both runs contain the same paths with identical effective permissions.";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                    for entry[i] in root.d-rows: HorizontalBox {
                                        spacing: Theme.spacing-sm;
                                        Text {
                                            text: entry.path;
                                            color: Theme.text-primary;
                                            overflow: elide;
                                            horizontal-stretch: 1;
                                        }
                                        Text {
                                            text: entry.kind_label;
                                            color: entry.kind_color;
                                            width: 110px;
                                        }
                                        Text {
                                            text: entry.old_rights;
                                            color: Theme.text-secondary;
                                            width: 180px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: entry.new_rights;
                                            color: Theme.text-secondary;
                                            width: 180px;
                                            overflow: elide;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ============================================================
                // Tab: Info / Pflichtangaben
                // ============================================================
                Tab {
                    title: "Info";

                    ScrollView {
                        VerticalBox {
                            padding: Theme.spacing-md;
                            spacing: Theme.spacing-md;

                            Text {
                                text: "Stars — AD Permission Analyzer";
                                font-size: Theme.font-xl;
                                font-weight: 700;
                                color: Theme.text-primary;
                            }
                            Text {
                                text: root.app-version;
                                font-size: Theme.font-md;
                                color: Theme.text-secondary;
                            }

                            GroupBox {
                                title: "Author and license";
                                VerticalLayout {
                                    spacing: Theme.spacing-sm;
                                    padding: Theme.spacing-sm;
                                    Text {
                                        text: "Copyright (c) 2026 Birger Labinsch";
                                        color: Theme.text-primary;
                                    }
                                    Text {
                                        text: "License: GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "License text: https://www.gnu.org/licenses/agpl-3.0.html";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "Source code (required by AGPL): https://github.com/Birgerson/stars-ad-permission-analyzer";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "This software was largely implemented with AI assistance: Code with Anthropic Claude Opus. Birger Labinsch is the prompt engineer, not the code author.";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Read-only principle — three hard limits";
                                VerticalLayout {
                                    spacing: Theme.spacing-sm;
                                    padding: Theme.spacing-sm;
                                    Text {
                                        text: "1. Read-only. Stars never writes to NTFS, SMB shares, or Active Directory. No future release will ship write functions either.";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "2. No agent on target systems. Stars runs on an audit workstation or an audit DC. It installs nothing on file servers or other DCs.";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "3. No backdoor authentication. Stars binds via LDAP (LDAPS preferred), nothing else. No hidden telemetry, no update beacons without signature verification.";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Backup duty and disclaimer";
                                VerticalLayout {
                                    spacing: Theme.spacing-sm;
                                    padding: Theme.spacing-sm;
                                    Text {
                                        text: "Before any production use, a full and tested backup of the affected systems is mandatory — even though Stars is architecturally read-only. Driver bugs, antivirus interventions, or load spikes can cause incidents even with a pure read-only tool.";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "Use at your own risk. Birger Labinsch assumes no liability for damages, data loss, incorrect audit results, or consequences arising from the use of this software. Full disclaimer in README.md (section 'Disclaimer').";
                                        color: Theme.text-primary;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Contact and further documentation";
                                VerticalLayout {
                                    spacing: Theme.spacing-sm;
                                    padding: Theme.spacing-sm;
                                    Text {
                                        text: "E-mail: birger@labinsch.de";
                                        color: Theme.text-primary;
                                    }
                                    Text {
                                        text: "Issues / bugs: https://github.com/Birgerson/stars-ad-permission-analyzer/issues";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "Decision guide before use: docs/can-stars-help-you.md in the repo.";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "Build verified against Windows Server 2022 Standard and Windows Server 2025 Standard (3-forest lab smoke test, 2026-06-07).";
                                        color: Theme.text-secondary;
                                        font-size: Theme.font-sm;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                        }
                    }
                }
            }
                }
            }
        }
    }
}

/// Returns the log directory (`%LOCALAPPDATA%\Stars\logs`).
fn log_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Stars").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn main() {
    let dir = log_dir();
    let file_appender = tracing_appender::rolling::never(&dir, "stars-gui.log");
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .init();

    let log_path = dir.join("stars-gui.log");
    std::panic::set_hook(Box::new({
        let log_path = log_path.clone();
        move |info| {
            let payload = info
                .payload()
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown>".to_string());
            tracing::error!(target: "stars-gui", "panic at {location}: {payload}");
            show_fatal_dialog(
                "Stars — crash at startup",
                &format!(
                    "The application has crashed.\n\nLocation: {location}\nReason: {payload}\n\nDetails: {}",
                    log_path.display()
                ),
            );
        }
    }));

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %dir.display(),
        "starting adpa-gui (slint software backend)"
    );

    std::env::set_var("SLINT_BACKEND", "winit-software");
    // Default je nach System-Theme blasse Standard-Texte produzieren.
    // Force fluent style so default widget text colors stay legible
    // regardless of the host system theme.
    std::env::set_var("SLINT_STYLE", "fluent");
    // Slint normally derives the std-widget color scheme from the OS
    // theme. On Windows Server hosts that yields a dark palette and
    // light grey text disappears on our light background. Pin it.
    std::env::set_var("SLINT_COLOR_SCHEME", "light");

    if let Err(e) = run_ui(&log_path) {
        tracing::error!(error = %e, "Slint UI failed");
        show_fatal_dialog(
            "Stars — startup failed",
            &format!(
                "The GUI backend could not be initialized.\n\nReason: {e}\n\nDetails: {}",
                log_path.display()
            ),
        );
    }
}

/// Aggregates all scan intermediates that don't fit directly into a Slint
/// property — the unfiltered raw rows (for the filter) and the expanded
/// row state, both pure UI-side bookkeeping.
#[derive(Default)]
struct ScanUiState {
    all_rows: Vec<ScanRowVm>,
    all_errors: Vec<ScanErrorVm>,
    all_risks: Vec<RiskItemVm>,
}

/// Backing store for the Delta tab. Slint properties hold the view; the
/// "source of truth" for selection lives here so the exclusive checkbox
/// behaviour (exactly one "old" and one "new" pick) does not need
/// Slint-side bookkeeping.
#[derive(Default)]
struct DeltaUiState {
    runs: Vec<ScanRunSummaryUi>,
    selected_old: Option<String>,
    selected_new: Option<String>,
}

#[derive(Clone)]
struct ScanRunSummaryUi {
    id: String,
    label: String,
}

thread_local! {
    static EVENT_RX: RefCell<Option<Receiver<WorkerEvent>>> = const { RefCell::new(None) };
    /// Worker sender for follow-up actions inside event handlers (e.g.
    /// re-load the scan history after a deletion). Populated in `run_ui`
    /// right after `spawn_worker`.
    static REQ_TX: RefCell<Option<Sender<WorkerRequest>>> = const { RefCell::new(None) };
    static SCAN_STATE: RefCell<ScanUiState> = RefCell::new(ScanUiState::default());
    static DELTA_STATE: RefCell<DeltaUiState> = RefCell::new(DeltaUiState::default());
    /// Pre-loaded identity list for the live search. Filled once after
    /// app start; keystroke filtering runs purely locally against this
    /// cache without a worker round-trip.
    static IDENTITY_CACHE: RefCell<Vec<IdentitySuggestion>> = const { RefCell::new(Vec::new()) };
}

fn run_ui(_log_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;

    // App version from Cargo metadata into the GUI. Without this the
    // HeaderBar version badge stays hidden behind its `if != ""` guard.
    ui.set_app_version(format!("v{}", env!("CARGO_PKG_VERSION")).into());

    // notify callback: wakes the GUI thread once the worker has sent an
    // event. Slint's `invoke_from_event_loop` is callable from any thread
    // and runs the closure on the UI thread.
    let weak = ui.as_weak();
    let notify: NotifyFn = Arc::new({
        let weak = weak.clone();
        move || {
            let weak = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(handle) = weak.upgrade() {
                    pump_worker_events(&handle);
                }
            });
        }
    });

    let (req_tx, evt_rx, cancel) = spawn_worker(notify);
    EVENT_RX.with(|cell| *cell.borrow_mut() = Some(evt_rx));
    REQ_TX.with(|cell| *cell.borrow_mut() = Some(req_tx.clone()));

    wire_analyze_tab(&ui, req_tx.clone());
    wire_scan_tab(&ui, req_tx.clone(), cancel);
    wire_delta_tab(&ui, req_tx.clone());

    // ohne Cache.
    // Pre-load the identity list once so the live search can show
    // suggestions from the first keystroke. If the call fails the GUI
    // keeps running without suggestions — SID input and the
    let _ = req_tx.send(WorkerRequest::ListIdentities);

    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyze tab wiring
// ---------------------------------------------------------------------------

fn wire_analyze_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // Name → SID: LSA lookup directly on the UI thread (LookupAccountNameW
    // is sub-millisecond, no worker round-trip needed).
    {
        let weak = ui.as_weak();
        ui.on_resolve_name_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let name = ui.get_a_name().to_string();
            resolve_name_to_sid(
                &name,
                |sid| ui.set_a_sid(sid.into()),
                |err| ui.set_a_name_error(err.into()),
            );
        });
    }

    // Live search: filter the cache on every keystroke and push the result
    // to the Slint property. An empty query auto-hides the suggestion
    // list (length == 0).
    {
        let weak = ui.as_weak();
        ui.on_analyze_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_a_suggestions(filter_suggestions_model(query.as_str()));
        });
    }

    // Click on a suggestion: take the name, close the list, immediately
    // resolve the SID — saves the user a second click.
    {
        let weak = ui.as_weak();
        ui.on_pick_analyze_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_a_name(name.clone());
            ui.set_a_suggestions(empty_suggestion_model());
            let name_str = name.to_string();
            resolve_name_to_sid(
                &name_str,
                |sid| ui.set_a_sid(sid.into()),
                |err| ui.set_a_name_error(err.into()),
            );
        });
    }

    let analyze_tx = req_tx.clone();
    let weak = ui.as_weak();
    ui.on_analyze_clicked(move || {
        let req_tx = &analyze_tx;
        let Some(ui) = weak.upgrade() else { return };
        let path = ui.get_a_path().to_string();
        if path.trim().is_empty() {
            ui.set_a_status("Path is required.".into());
            ui.set_a_status_is_error(true);
            return;
        }

        // Identity: use the SID field if set, otherwise take what was typed in
        // the identity field — a raw SID is used directly, a name / UPN is
        // resolved to a SID via LSA. This lets the user just type an identity
        // and click Analyze; the separate "Resolve SID" step is now optional.
        let mut sid = ui.get_a_sid().to_string();
        if sid.trim().is_empty() {
            let identity = ui.get_a_name().to_string();
            let identity = identity.trim();
            if identity.is_empty() {
                ui.set_a_status("Path and identity are required.".into());
                ui.set_a_status_is_error(true);
                return;
            }
            if identity.starts_with("S-1-") {
                sid = identity.to_string();
            } else {
                let mut resolved = String::new();
                let mut resolve_err = String::new();
                resolve_name_to_sid(identity, |s| resolved = s, |e| resolve_err = e);
                if resolved.trim().is_empty() {
                    let msg = if resolve_err.is_empty() {
                        "Identity could not be resolved to a SID.".to_string()
                    } else {
                        resolve_err
                    };
                    ui.set_a_name_error(msg.clone().into());
                    ui.set_a_status(msg.into());
                    ui.set_a_status_is_error(true);
                    return;
                }
                ui.set_a_name_error("".into());
                sid = resolved;
            }
            ui.set_a_sid(sid.clone().into());
        }

        // LDAP mode: 0 = off (SAM/LSA), 1 = LDAPS, 2 = plain LDAP,
        // 3 = Global Catalog (LDAPS 3269). Mapping lives in
        // LdapParams::from_mode so it is unit-tested without the UI.
        let ldap = LdapParams::from_mode(
            ui.get_a_ldap_mode(),
            ui.get_a_ldap_server().to_string(),
            ui.get_a_ldap_base_dn().to_string(),
            ui.get_a_ldap_bind_dn().to_string(),
            ui.get_a_ldap_password().to_string(),
        );

        let (smb_server, share_name) = if ui.get_a_smb_enabled() {
            (
                Some(ui.get_a_smb_server().to_string()),
                Some(ui.get_a_smb_share().to_string()),
            )
        } else {
            (None, None)
        };

        ui.set_a_is_running(true);
        ui.set_a_status("Analysis running...".into());
        ui.set_a_status_is_error(false);
        ui.set_a_rights_label("".into());
        ui.set_a_mask_hex("".into());
        ui.set_a_share_line("".into());
        ui.set_a_explanation(empty_string_model());

        if let Err(e) = req_tx.send(WorkerRequest::Analyze {
            path,
            sid,
            ldap,
            smb_server,
            share_name,
        }) {
            ui.set_a_is_running(false);
            ui.set_a_status(format!("Worker not reachable: {e}").into());
            ui.set_a_status_is_error(true);
        }
    });

    // "Who has access?" — path-centric trustee view. Needs no SID.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_analyze_trustees_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let path = ui.get_a_path().to_string();
            if path.trim().is_empty() {
                ui.set_a_status("Path is required.".into());
                ui.set_a_status_is_error(true);
                return;
            }
            let (smb_server, share_name) = if ui.get_a_smb_enabled() {
                (
                    Some(ui.get_a_smb_server().to_string()),
                    Some(ui.get_a_smb_share().to_string()),
                )
            } else {
                (None, None)
            };
            ui.set_a_trustees_running(true);
            ui.set_a_has_trustees(false);
            ui.set_a_status("Lese DACL...".into());
            ui.set_a_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::AnalyzeTrustees {
                path,
                smb_server,
                share_name,
            }) {
                ui.set_a_trustees_running(false);
                ui.set_a_status(format!("Worker not reachable: {e}").into());
                ui.set_a_status_is_error(true);
            }
        });
    }
}

fn handle_trustees_done(ui: &MainWindow, result: Result<Vec<TrusteeRow>, String>) {
    ui.set_a_trustees_running(false);
    match result {
        Ok(rows) => {
            let vms: Vec<TrusteeRowVm> = rows
                .into_iter()
                .map(|r| {
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
                })
                .collect();
            let len = vms.len();
            ui.set_a_trustees(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.set_a_has_trustees(true);
            ui.set_a_status(format!("{} ACE entries found on this path.", len).into());
            ui.set_a_status_is_error(false);
        }
        Err(e) => {
            ui.set_a_has_trustees(false);
            ui.set_a_status(format!("Trustee evaluation failed: {e}").into());
            ui.set_a_status_is_error(true);
        }
    }
}

fn apply_analyze_result(
    ui: &MainWindow,
    result: Result<EffectivePermission, String>,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
) {
    ui.set_a_is_running(false);
    match result {
        Ok(perm) => {
            let effective_raw = perm.effective_mask.0;
            let rights = NormalizedRights::new(effective_raw);
            ui.set_a_rights_label(format!("{} ({})", rights.display_name(), rights.label()).into());
            ui.set_a_mask_hex(format!("0x{effective_raw:08X}").into());
            ui.set_a_share_line(format_share_line(&perm).into());
            let steps: Vec<slint::SharedString> = perm
                .path_explanation
                .steps
                .iter()
                .map(|s| slint::SharedString::from(s.as_str()))
                .collect();
            ui.set_a_explanation(slint::ModelRc::new(slint::VecModel::from(steps)));
            // the scan history — required for it to be comparable in the
            // Delta tab.
            let (status, is_error) = match (scan_run_id, persistence_error) {
                (Some(_), _) => (
                    "Analysis complete — saved to scan history.".to_string(),
                    false,
                ),
                (None, Some(reason)) => (
                    format!("Analysis complete, but persistence failed: {reason}"),
                    true,
                ),
                (None, None) => ("Analysis complete.".to_string(), false),
            };
            ui.set_a_status(status.into());
            ui.set_a_status_is_error(is_error);
        }
        Err(e) => {
            ui.set_a_status(format!("Analysis failed: {e}").into());
            ui.set_a_status_is_error(true);
        }
    }
}

fn format_share_line(perm: &EffectivePermission) -> String {
    let ntfs_label = NormalizedRights::new(perm.ntfs_mask.0).label();
    match &perm.share_status {
        ShareEvalStatus::NotApplicable => String::new(),
        ShareEvalStatus::Applied => {
            let share_label = perm
                .share_mask
                .as_ref()
                .map(|m| NormalizedRights::new(m.0).label())
                .unwrap_or("—");
            format!(
                "Share restriction applied: NTFS = {ntfs_label}, Share = {share_label}, effective = NTFS ∩ Share."
            )
        }
        ShareEvalStatus::Unrestricted => {
            format!(
                "Share has NULL DACL (no SMB restriction) — effective follows NTFS = {ntfs_label}."
            )
        }
        ShareEvalStatus::ReadFailed(reason) => {
            format!("Share DACL read failed: {reason} — result may be incomplete.")
        }
    }
}

// ---------------------------------------------------------------------------
// Scan tab wiring
// ---------------------------------------------------------------------------

fn wire_scan_tab(
    ui: &MainWindow,
    req_tx: std::sync::mpsc::Sender<WorkerRequest>,
    cancel: CancellationToken,
) {
    // Name → SID helper (analogous to the Analyze tab).
    {
        let weak = ui.as_weak();
        ui.on_resolve_scan_name_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let name = ui.get_s_name().to_string();
            resolve_name_to_sid(
                &name,
                |sid| ui.set_s_sid(sid.into()),
                |err| ui.set_s_name_error(err.into()),
            );
        });
    }

    // Live search analogous to the Analyze tab.
    {
        let weak = ui.as_weak();
        ui.on_scan_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_s_suggestions(filter_suggestions_model(query.as_str()));
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_pick_scan_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_s_name(name.clone());
            ui.set_s_suggestions(empty_suggestion_model());
            let name_str = name.to_string();
            resolve_name_to_sid(
                &name_str,
                |sid| ui.set_s_sid(sid.into()),
                |err| ui.set_s_name_error(err.into()),
            );
        });
    }

    // scan-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        let cancel = cancel.clone();
        ui.on_scan_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let root = ui.get_s_root().to_string();
            if root.trim().is_empty() {
                ui.set_s_status("Root path is required.".into());
                ui.set_s_status_is_error(true);
                return;
            }

            // Identity: SID field if set, else resolve the typed identity (a raw
            // SID is used directly, a name / UPN is resolved via LSA) — same as
            // the Analyze tab, so the user can just type an identity and Scan.
            let mut sid = ui.get_s_sid().to_string();
            if sid.trim().is_empty() {
                let identity = ui.get_s_name().to_string();
                let identity = identity.trim();
                if identity.is_empty() {
                    ui.set_s_status("Root path and identity are required.".into());
                    ui.set_s_status_is_error(true);
                    return;
                }
                if identity.starts_with("S-1-") {
                    sid = identity.to_string();
                } else {
                    let mut resolved = String::new();
                    let mut resolve_err = String::new();
                    resolve_name_to_sid(identity, |s| resolved = s, |e| resolve_err = e);
                    if resolved.trim().is_empty() {
                        let msg = if resolve_err.is_empty() {
                            "Identity could not be resolved to a SID.".to_string()
                        } else {
                            resolve_err
                        };
                        ui.set_s_name_error(msg.clone().into());
                        ui.set_s_status(msg.into());
                        ui.set_s_status_is_error(true);
                        return;
                    }
                    ui.set_s_name_error("".into());
                    sid = resolved;
                }
                ui.set_s_sid(sid.clone().into());
            }

            let max_depth = if ui.get_s_limit_depth() {
                let d = ui.get_s_max_depth();
                if d > 0 {
                    Some(d as u32)
                } else {
                    None
                }
            } else {
                None
            };

            // LDAP mode analogous to the Analyze tab (0=off, 1=LDAPS,
            // 2=plain, 3=Global Catalog). Mapping in LdapParams::from_mode.
            let ldap = LdapParams::from_mode(
                ui.get_s_ldap_mode(),
                ui.get_s_ldap_server().to_string(),
                ui.get_s_ldap_base_dn().to_string(),
                ui.get_s_ldap_bind_dn().to_string(),
                ui.get_s_ldap_password().to_string(),
            );

            let (smb_server, share_name) = if ui.get_s_smb_enabled() {
                (
                    Some(ui.get_s_smb_server().to_string()),
                    Some(ui.get_s_smb_share().to_string()),
                )
            } else {
                (None, None)
            };

            // Reset state for a fresh run.
            SCAN_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.all_rows.clear();
                s.all_errors.clear();
                s.all_risks.clear();
            });
            cancel.reset();

            ui.set_s_is_running(true);
            ui.set_s_done(false);
            ui.set_s_status("Scan running...".into());
            ui.set_s_status_is_error(false);
            ui.set_s_total(0);
            ui.set_s_error_count(0);
            ui.set_s_scan_run_id("".into());
            ui.set_s_export_message("".into());
            ui.set_s_export_is_error(false);
            ui.set_s_rows(empty_row_model());
            ui.set_s_errors(empty_error_model());
            ui.set_s_risks(empty_risk_model());

            if let Err(e) = req_tx.send(WorkerRequest::Scan {
                root,
                sid,
                max_depth,
                smb_server,
                share_name,
                ldap,
            }) {
                ui.set_s_is_running(false);
                ui.set_s_status(format!("Worker not reachable: {e}").into());
                ui.set_s_status_is_error(true);
            }
        });
    }

    // scan-cancel-clicked
    {
        let cancel = cancel.clone();
        ui.on_scan_cancel_clicked(move || {
            cancel.cancel();
        });
    }

    // gefilterten View neu.
    // scan-row-toggle: flips the expanded column of a row. The master
    // list lives in SCAN_STATE; we re-render the filtered view
    // afterwards.
    {
        let weak = ui.as_weak();
        ui.on_scan_row_toggle(move |index| {
            let Some(ui) = weak.upgrade() else { return };
            let filter = ui.get_s_filter().to_string();
            SCAN_STATE.with(|s| {
                let mut s = s.borrow_mut();
                if let Some(real_index) = nth_matching_index(&s.all_rows, &filter, index as usize) {
                    s.all_rows[real_index].expanded = !s.all_rows[real_index].expanded;
                }
            });
            refresh_rows(&ui);
        });
    }

    // scan-filter-changed
    {
        let weak = ui.as_weak();
        ui.on_scan_filter_changed(move || {
            let Some(ui) = weak.upgrade() else { return };
            refresh_rows(&ui);
        });
    }

    // export-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_export_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let output_path = ui.get_s_export_path().to_string();
            if output_path.trim().is_empty() {
                ui.set_s_export_message("Please specify a target file.".into());
                ui.set_s_export_is_error(true);
                return;
            }
            ui.set_s_export_message("Export running...".into());
            ui.set_s_export_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ExportHtml { output_path }) {
                ui.set_s_export_message(format!("Worker not reachable: {e}").into());
                ui.set_s_export_is_error(true);
            }
        });
    }
}

/// Translates an index from the filtered view back to the index in the
/// unfiltered master list by walking to the `nth` match.
fn nth_matching_index(all: &[ScanRowVm], filter: &str, n: usize) -> Option<usize> {
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return if n < all.len() { Some(n) } else { None };
    }
    all.iter()
        .enumerate()
        .filter(|(_, r)| r.path.to_lowercase().contains(&filter))
        .nth(n)
        .map(|(i, _)| i)
}

/// Re-renders the rows property from the master state + current filter.
fn refresh_rows(ui: &MainWindow) {
    let filter = ui.get_s_filter().to_string().trim().to_lowercase();
    let filtered: Vec<ScanRowVm> = SCAN_STATE.with(|s| {
        let s = s.borrow();
        if filter.is_empty() {
            s.all_rows.clone()
        } else {
            s.all_rows
                .iter()
                .filter(|r| r.path.to_lowercase().contains(&filter))
                .cloned()
                .collect()
        }
    });
    ui.set_s_rows(slint::ModelRc::new(slint::VecModel::from(filtered)));
}

fn handle_scan_item(ui: &MainWindow, row: ScanRow) {
    let mask_hex = format!("0x{:08X}", row.mask_raw);
    // Convert the trustee list to the slint model — same colour logic as the
    // Analyze tab (Allow green, Deny red, anything else grey).
    let trustee_vms: Vec<TrusteeRowVm> = row
        .trustees
        .into_iter()
        .map(|t| {
            let kind_color = match t.kind.as_str() {
                "Allow" => slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f),
                "Deny" => slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b),
                _ => slint::Color::from_rgb_u8(0x6c, 0x7a, 0x89),
            };
            TrusteeRowVm {
                display_name: t.display_name.into(),
                sid: t.sid.into(),
                kind: t.kind.into(),
                kind_color,
                rights_label: t.rights_label.into(),
                mask_hex: t.mask_hex.into(),
                source: t.source.into(),
                applies_to: t.applies_to.into(),
                category: t.category.into(),
            }
        })
        .collect();
    let vm = ScanRowVm {
        path: row.path.clone().into(),
        rights_label: row.rights_label.clone().into(),
        mask_hex: mask_hex.into(),
        steps: slint::ModelRc::new(slint::VecModel::from(
            row.steps
                .iter()
                .map(|s| slint::SharedString::from(s.as_str()))
                .collect::<Vec<_>>(),
        )),
        trustees: slint::ModelRc::new(slint::VecModel::from(trustee_vms)),
        expanded: false,
        has_diagnostic: row.diagnostic_count > 0 || row.unsupported_ace_count > 0,
        row_severity: row.row_severity,
        diagnostics: slint::ModelRc::new(slint::VecModel::from(
            row.diagnostics
                .iter()
                .map(|d| DiagnosticVm {
                    text: slint::SharedString::from(d.text.as_str()),
                    level: d.level,
                })
                .collect::<Vec<_>>(),
        )),
    };
    SCAN_STATE.with(|s| s.borrow_mut().all_rows.push(vm));
    let total = SCAN_STATE.with(|s| s.borrow().all_rows.len()) as i32;
    ui.set_s_total(total);
    refresh_rows(ui);
}

fn handle_scan_error(ui: &MainWindow, path: String, message: String) {
    let vm = ScanErrorVm {
        path: path.into(),
        message: message.into(),
    };
    SCAN_STATE.with(|s| s.borrow_mut().all_errors.push(vm));
    let errors = SCAN_STATE.with(|s| {
        let s = s.borrow();
        s.all_errors.clone()
    });
    let count = errors.len() as i32;
    ui.set_s_error_count(count);
    ui.set_s_errors(slint::ModelRc::new(slint::VecModel::from(errors)));
}

fn handle_scan_done(
    ui: &MainWindow,
    total: usize,
    errors: usize,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
    cancelled: bool,
) {
    ui.set_s_is_running(false);
    ui.set_s_done(true);
    ui.set_s_total(total as i32);
    ui.set_s_error_count(errors as i32);
    ui.set_s_scan_run_id(scan_run_id.unwrap_or_default().into());

    let mut parts: Vec<String> = Vec::new();
    if cancelled {
        parts.push("Scan cancelled — results are incomplete.".to_string());
    } else {
        parts.push("Scan complete.".to_string());
    }
    let had_persistence_error = persistence_error.is_some();
    if let Some(err) = persistence_error {
        parts.push(format!("Persistence failed: {err}"));
    }
    let is_error = cancelled || had_persistence_error;
    ui.set_s_status(parts.join(" ").into());
    ui.set_s_status_is_error(is_error);
}

fn handle_risk_findings(ui: &MainWindow, findings: Vec<RiskFinding>) {
    let vms: Vec<RiskItemVm> = findings
        .into_iter()
        .map(|f| {
            let (label, color) = severity_visual(&f.severity);
            RiskItemVm {
                severity_label: label.into(),
                severity_color: color,
                rule_id: f.rule_id.into(),
                description: f.description.into(),
                affected_path: f.affected_path.map(|p| p.0).unwrap_or_default().into(),
                incomplete: f.incomplete,
            }
        })
        .collect();
    SCAN_STATE.with(|s| s.borrow_mut().all_risks = vms.clone());
    ui.set_s_risks(slint::ModelRc::new(slint::VecModel::from(vms)));
}

fn handle_export_done(ui: &MainWindow, result: Result<(), String>) {
    match result {
        Ok(()) => {
            ui.set_s_export_message("✓ Export successful.".into());
            ui.set_s_export_is_error(false);
        }
        Err(e) => {
            ui.set_s_export_message(format!("✗ Export failed: {e}").into());
            ui.set_s_export_is_error(true);
        }
    }
}

fn severity_visual(severity: &RiskSeverity) -> (&'static str, slint::Color) {
    match severity {
        RiskSeverity::Info => ("Info", slint::Color::from_rgb_u8(0x55, 0x77, 0x99)),
        // Same saturated ramp as the diagnostics: green · amber · orange-red · red.
        RiskSeverity::Low => ("Low", slint::Color::from_rgb_u8(0x16, 0xA3, 0x4A)),
        RiskSeverity::Medium => ("Medium", slint::Color::from_rgb_u8(0xD9, 0x77, 0x06)),
        RiskSeverity::High => ("High", slint::Color::from_rgb_u8(0xEA, 0x58, 0x0C)),
        RiskSeverity::Critical => ("Critical", slint::Color::from_rgb_u8(0xDC, 0x26, 0x26)),
    }
}

// ---------------------------------------------------------------------------
// Delta tab wiring
// ---------------------------------------------------------------------------

fn wire_delta_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // delta-load-runs-clicked: asks the worker for the scan history. The
    // answer arrives asynchronously as WorkerEvent::ScanRunsLoaded.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_load_runs_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_d_is_loading(true);
            ui.set_d_status("Loading scan history...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListScanRuns) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-pick-old / delta-pick-new: exclusive toggle — clicking a row
    // sets that run as "old" or "new" and clears the corresponding flag
    // on every other row. Clicking the same row again clears the
    // selection.
    {
        let weak = ui.as_weak();
        ui.on_delta_pick_old(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                let id_owned = id.to_string();
                if s.selected_old.as_deref() == Some(id_owned.as_str()) {
                    s.selected_old = None;
                } else {
                    s.selected_old = Some(id_owned);
                }
            });
            refresh_delta_runs(&ui);
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_delta_pick_new(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                let id_owned = id.to_string();
                if s.selected_new.as_deref() == Some(id_owned.as_str()) {
                    s.selected_new = None;
                } else {
                    s.selected_new = Some(id_owned);
                }
            });
            refresh_delta_runs(&ui);
        });
    }

    // delta-compare-clicked: read the two ids and dispatch to the worker.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_compare_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (old_id, new_id) = DELTA_STATE.with(|s| {
                let s = s.borrow();
                (s.selected_old.clone(), s.selected_new.clone())
            });
            let (Some(old_id), Some(new_id)) = (old_id, new_id) else {
                ui.set_d_status("Please select one scan run for 'Old' and one for 'New'.".into());
                ui.set_d_status_is_error(true);
                return;
            };
            if old_id == new_id {
                ui.set_d_status("'Old' and 'New' must be different runs.".into());
                ui.set_d_status_is_error(true);
                return;
            }
            ui.set_d_is_loading(true);
            ui.set_d_status("Comparing runs...".into());
            ui.set_d_status_is_error(false);
            ui.set_d_has_result(false);
            if let Err(e) = req_tx.send(WorkerRequest::ComputeDelta {
                old_run_id: old_id,
                new_run_id: new_id,
            }) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-delete-confirmed: fired by the confirmation dialog after the
    // follow-up actions (clearing selection, reloading the list) are
    // handled by the event handler on WorkerEvent::ScanRunDeleted.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_delete_confirmed(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let id_str = id.to_string();
            if id_str.is_empty() {
                return;
            }
            ui.set_d_status("Deleting scan run...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::DeleteScanRun { run_id: id_str }) {
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }
}

fn refresh_delta_runs(ui: &MainWindow) {
    let vms: Vec<ScanRunVm> = DELTA_STATE.with(|s| {
        let s = s.borrow();
        s.runs
            .iter()
            .map(|r| ScanRunVm {
                id: r.id.clone().into(),
                label: r.label.clone().into(),
                selected_as_old: s.selected_old.as_deref() == Some(r.id.as_str()),
                selected_as_new: s.selected_new.as_deref() == Some(r.id.as_str()),
            })
            .collect()
    });
    ui.set_d_scan_runs(slint::ModelRc::new(slint::VecModel::from(vms)));
}

fn handle_scan_runs_loaded(ui: &MainWindow, result: Result<Vec<ScanRunSummary>, String>) {
    ui.set_d_is_loading(false);
    match result {
        Ok(runs) if runs.is_empty() => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs.clear();
                s.selected_old = None;
                s.selected_new = None;
            });
            refresh_delta_runs(ui);
            ui.set_d_status("No scan runs stored — run a scan first.".into());
            ui.set_d_status_is_error(false);
        }
        Ok(runs) => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs = runs
                    .into_iter()
                    .map(|r| ScanRunSummaryUi {
                        id: r.id,
                        label: format!(
                            "{}  —  {}  ({} errors)",
                            r.started_at, r.target, r.error_count
                        ),
                    })
                    .collect();
                // Drop selections that point at runs which no longer exist.
                let ids: std::collections::HashSet<String> =
                    s.runs.iter().map(|r| r.id.clone()).collect();
                if s.selected_old.as_ref().is_some_and(|id| !ids.contains(id)) {
                    s.selected_old = None;
                }
                if s.selected_new.as_ref().is_some_and(|id| !ids.contains(id)) {
                    s.selected_new = None;
                }
            });
            refresh_delta_runs(ui);
            ui.set_d_status(
                "Scan runs loaded. Check one for 'Old' and one for 'New', then compare.".into(),
            );
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_status(format!("Loading failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

/// Reacts to a worker-completed scan-run deletion. Updates the status line,
/// clears local selection state and triggers a fresh history reload so the
/// list is up-to-date without requiring another click on "Load scan history
fn handle_scan_run_deleted(ui: &MainWindow, run_id: &str, result: Result<(), String>) {
    match result {
        Ok(()) => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs.retain(|r| r.id != run_id);
                if s.selected_old.as_deref() == Some(run_id) {
                    s.selected_old = None;
                }
                if s.selected_new.as_deref() == Some(run_id) {
                    s.selected_new = None;
                }
            });
            refresh_delta_runs(ui);
            ui.set_d_status("Scan run removed.".into());
            ui.set_d_status_is_error(false);
            // ausblenden.
            // If a delta result was still visible in the frame, it might
            // refer to the just-deleted run — hide it to be safe.
            ui.set_d_has_result(false);
            // Reload the list in background so the GUI state is guaranteed
            // to match the DB.
            REQ_TX.with(|cell| {
                if let Some(tx) = cell.borrow().as_ref() {
                    let _ = tx.send(WorkerRequest::ListScanRuns);
                }
            });
        }
        Err(e) => {
            ui.set_d_status(format!("Delete failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

fn handle_delta_computed(ui: &MainWindow, result: Result<Vec<DeltaRow>, String>) {
    ui.set_d_is_loading(false);
    match result {
        Ok(rows) => {
            let mut added = 0;
            let mut removed = 0;
            let mut changed = 0;
            let vms: Vec<DeltaRowVm> = rows
                .into_iter()
                .map(|r| {
                    let color = match r.kind_label.as_str() {
                        "Added" => {
                            added += 1;
                            slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f)
                        }
                        "Removed" => {
                            removed += 1;
                            slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b)
                        }
                        _ => {
                            changed += 1;
                            slint::Color::from_rgb_u8(0xc6, 0x89, 0x10)
                        }
                    };
                    DeltaRowVm {
                        path: r.path.into(),
                        kind_label: r.kind_label.into(),
                        kind_color: color,
                        old_rights: r.old_rights.into(),
                        new_rights: r.new_rights.into(),
                    }
                })
                .collect();
            ui.set_d_added_count(added);
            ui.set_d_removed_count(removed);
            ui.set_d_changed_count(changed);
            ui.set_d_rows(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.set_d_has_result(true);
            ui.set_d_status("Comparison complete.".into());
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_has_result(false);
            ui.set_d_status(format!("Comparison failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

// ---------------------------------------------------------------------------
// Event pump
// ---------------------------------------------------------------------------

fn pump_worker_events(ui: &MainWindow) {
    EVENT_RX.with(|cell| {
        let borrow = cell.borrow();
        let Some(rx) = borrow.as_ref() else { return };
        while let Ok(event) = rx.try_recv() {
            match event {
                WorkerEvent::AnalyzeDone {
                    result,
                    scan_run_id,
                    persistence_error,
                } => apply_analyze_result(ui, *result, scan_run_id, persistence_error),
                WorkerEvent::ScanItem(row) => handle_scan_item(ui, row),
                WorkerEvent::ScanError { path, message } => handle_scan_error(ui, path, message),
                WorkerEvent::ScanDone {
                    total,
                    errors,
                    scan_run_id,
                    persistence_error,
                    cancelled,
                } => handle_scan_done(ui, total, errors, scan_run_id, persistence_error, cancelled),
                WorkerEvent::RiskFindings(findings) => handle_risk_findings(ui, findings),
                WorkerEvent::ExportDone(result) => handle_export_done(ui, result),
                WorkerEvent::ScanRunsLoaded(result) => handle_scan_runs_loaded(ui, result),
                WorkerEvent::DeltaComputed(result) => handle_delta_computed(ui, result),
                WorkerEvent::ScanRunDeleted { run_id, result } => {
                    handle_scan_run_deleted(ui, &run_id, result)
                }
                WorkerEvent::IdentitiesLoaded(result) => handle_identities_loaded(ui, result),
                WorkerEvent::TrusteesDone(result) => handle_trustees_done(ui, result),
                // Phase reserviert.
                // SearchResults (identity picker) stays reserved for a
                // later phase.
                WorkerEvent::SearchResults(_) => {}
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_string_model() -> slint::ModelRc<slint::SharedString> {
    slint::ModelRc::new(slint::VecModel::<slint::SharedString>::from(Vec::<
        slint::SharedString,
    >::new()))
}

fn empty_row_model() -> slint::ModelRc<ScanRowVm> {
    slint::ModelRc::new(slint::VecModel::<ScanRowVm>::from(Vec::<ScanRowVm>::new()))
}

fn empty_error_model() -> slint::ModelRc<ScanErrorVm> {
    slint::ModelRc::new(slint::VecModel::<ScanErrorVm>::from(
        Vec::<ScanErrorVm>::new(),
    ))
}

fn empty_risk_model() -> slint::ModelRc<RiskItemVm> {
    slint::ModelRc::new(slint::VecModel::<RiskItemVm>::from(Vec::<RiskItemVm>::new()))
}

fn empty_suggestion_model() -> slint::ModelRc<IdentitySuggestionVm> {
    slint::ModelRc::new(slint::VecModel::<IdentitySuggestionVm>::from(Vec::<
        IdentitySuggestionVm,
    >::new()))
}

/// Filters the list cached in `IDENTITY_CACHE` against the query string
/// and returns a Slint ModelRc that can be assigned directly to a
/// `[IdentitySuggestionVm]` property. At most `MAX_SUGGESTIONS` entries so
/// the list stays scannable — typing more specifically narrows the
/// results.
const MAX_SUGGESTIONS: usize = 15;

fn filter_suggestions_model(query: &str) -> slint::ModelRc<IdentitySuggestionVm> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return empty_suggestion_model();
    }
    let suggestions: Vec<IdentitySuggestionVm> = IDENTITY_CACHE.with(|c| {
        c.borrow()
            .iter()
            .filter(|s| {
                s.qualified.to_lowercase().contains(&q) || s.name.to_lowercase().contains(&q)
            })
            .take(MAX_SUGGESTIONS)
            .map(|s| IdentitySuggestionVm {
                name: s.name.clone().into(),
                qualified: s.qualified.clone().into(),
                kind_icon: s.kind_icon.clone().into(),
                description: s.description.clone().into(),
            })
            .collect()
    });
    slint::ModelRc::new(slint::VecModel::from(suggestions))
}

fn handle_identities_loaded(_ui: &MainWindow, result: Result<Vec<IdentitySuggestion>, String>) {
    match result {
        Ok(list) => {
            let count = list.len();
            IDENTITY_CACHE.with(|c| *c.borrow_mut() = list);
            tracing::info!(target: "stars-gui", count, "identity cache populated");
        }
        Err(e) => {
            // Cache stays empty; the live search just shows no
            // because it only uses LookupAccountNameW.
            tracing::warn!(target: "stars-gui", error = %e, "identity enumeration failed — live search disabled");
        }
    }
}

/// Windows-only.
/// Translates a user/group name to a SID via the local LSA
/// (`LookupAccountNameW`). Success calls `on_sid` with the resolved SID,
/// failure calls `on_error` with a short localized message. Empty input
/// is treated as an error ("Bitte Namen eingeben"). On non-Windows the
/// function deliberately does not exist — the entire SAM path is
/// Windows-only.
#[cfg(windows)]
fn resolve_name_to_sid(
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
fn resolve_name_to_sid(
    _name: &str,
    mut _on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    on_error("Name → SID resolution needs Windows (LSA API).".to_string());
}

/// Modal error dialog (Windows) or stderr output (other platforms).
#[cfg(windows)]
fn show_fatal_dialog(title: &str, message: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let title_w = to_wide(title);
    let msg_w = to_wide(message);
    // SAFETY: Both pointers reference valid, null-terminated UTF-16 buffers
    // that live until the call returns. `hwnd` = 0 is allowed.
    unsafe {
        MessageBoxW(
            0 as _,
            msg_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(windows))]
fn show_fatal_dialog(title: &str, message: &str) {
    eprintln!("{title}\n\n{message}");
}
