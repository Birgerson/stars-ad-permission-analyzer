//! adpa-gui — Grafische Oberfläche für den AD Permission Analyzer (Slint).
//! adpa-gui — Graphical interface for the AD Permission Analyzer (Slint).
//!
//! Logfile, Panic-Hook und MessageBox-Fallback bleiben aus den eframe-
//! Vorgängern erhalten — sie sind unabhängig vom GUI-Toolkit und decken
//! Startprobleme auf einem nackten Server zuverlässig auf.
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

// Slint-UI inline. Definiert ViewModels für Scan-Zeilen, Scan-Fehler,
// Risikobefunde, Scan-Läufe und Delta-Zeilen sowie das MainWindow mit
// drei voll funktionalen Tabs (Analyze, Scan Tree, Delta).
// Slint UI inline. Defines view models for scan rows, scan errors, risk
// findings, scan runs and delta rows, plus the MainWindow with three
// fully functional tabs (Analyze, Scan Tree, Delta).
slint::slint! {
    import {
        TabWidget, VerticalBox, HorizontalBox, GridBox, GroupBox,
        LineEdit, Button, CheckBox, ScrollView, SpinBox, ComboBox,
    } from "std-widgets.slint";

    // Wiederverwendbares ⓘ-Help-Icon. Bei Hover erscheint ein kleiner
    // dunkler Tooltip-Kasten mit Erklaerungstext direkt rechts neben
    // dem Icon. Tooltip wird nur eingeblendet, ueberlappt Nachbarn
    // (Slint zeichnet Kinder ueber Geschwister) und verschwindet, sobald
    // die Maus weg ist.
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
            font-size: 14px;
            color: #4f7cad;
            horizontal-alignment: center;
            vertical-alignment: center;
        }

        ta := TouchArea {
            mouse-cursor: help;
        }

        if ta.has-hover: Rectangle {
            x: parent.width + 6px;
            y: parent.height / 2;
            background: #2c2c2c;
            border-radius: 4px;
            border-color: #6c8eaf;
            border-width: 1px;
            width: 320px;
            height: tip-text.preferred-height + 14px;

            tip-text := Text {
                x: 8px;
                y: 6px;
                width: parent.width - 16px;
                text: root.tip;
                color: white;
                font-size: 11px;
                wrap: word-wrap;
            }
        }
    }

    // Eine Zeile im Scan-Ergebnis.
    // A row in the scan result.
    export struct ScanRowVm {
        path: string,
        rights_label: string,
        mask_hex: string,
        steps: [string],
        expanded: bool,
        has_diagnostic: bool,
    }

    // Ein Scan-Fehler (Pfad konnte nicht ausgewertet werden).
    // A scan error (a path could not be evaluated).
    export struct ScanErrorVm {
        path: string,
        message: string,
    }

    // Ein Risikobefund.
    // A risk finding.
    export struct RiskItemVm {
        severity_label: string,
        severity_color: color,
        rule_id: string,
        description: string,
        affected_path: string,
        incomplete: bool,
    }

    // Ein persistierter Scan-Lauf in der Delta-Tab-Liste.
    // A persisted scan run in the Delta tab's list.
    export struct ScanRunVm {
        id: string,
        label: string,
        selected_as_old: bool,
        selected_as_new: bool,
    }

    // Eine Zeile in der Trustee-Sicht des Analyze-Tabs.
    // One row in the trustee view of the Analyze tab.
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

    // Eine Delta-Zeile (Hinzugefügt / Entfernt / Geändert).
    // A delta row (Added / Removed / Changed).
    export struct DeltaRowVm {
        path: string,
        kind_label: string,
        kind_color: color,
        old_rights: string,
        new_rights: string,
    }

    // Ein Vorschlag in der Live-Suche unter dem Namensfeld.
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

        // ============================================================
        // Analyze-Tab Properties / Analyze tab properties
        // ============================================================
        // Vorauswahl auf das SYSVOL-Verzeichnis: existiert auf jeder
        // standardmäßig installierten Windows-Server-DC, ist
        // audit-relevant (Group Policy Templates, Login-Skripte) und
        // erspart den ersten Tippvorgang. Der User kann den Pfad
        // jederzeit überschreiben — die Property ist `in-out`.
        // Pre-fill the SYSVOL directory: exists on every default
        // Windows Server DC install, is audit-relevant (Group Policy
        // templates, login scripts) and saves the first keystroke. The
        // user can overwrite the path at any time — the property is
        // `in-out`.
        in-out property <string> a-path: "C:\\Windows\\SYSVOL\\sysvol";
        // Benutzer-/Gruppen-Name als komfortable Alternative zur SID-
        // Eingabe. Über `resolve-name-clicked` wird der Name via LSA in
        // die SID übersetzt, die dann im SID-Feld landet. Der User kann
        // weiterhin direkt eine SID in das SID-Feld eintippen.
        // User/group name as a convenient alternative to typing a SID
        // directly. `resolve-name-clicked` translates the name via LSA
        // into the SID and writes it to the SID field. The user can
        // still type a SID into the SID field directly.
        in-out property <string> a-name;
        in property <string> a-name-error;
        in property <[IdentitySuggestionVm]> a-suggestions;
        in-out property <string> a-sid;

        // LDAP-Modus: 0 = Aus (SAM/LSA, empfohlen auf DC),
        //              1 = LDAPS (verschluesselt, Port 636),
        //              2 = LDAP unverschluesselt (Port 389, nur Test).
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
        // Trustee-Sicht: pfadzentrierte Auflistung aller ACEs ohne
        // vorgegebene Identität.
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
        // Wurzelpfad analog zum Analyze-Tab auf SYSVOL vorbelegt.
        // Root path pre-filled to SYSVOL, analogous to the Analyze tab.
        in-out property <string> s-root: "C:\\Windows\\SYSVOL\\sysvol";
        // Analog zum Analyze-Tab: Name → SID-Hilfe.
        // Analogous to the Analyze tab: name → SID helper.
        in-out property <string> s-name;
        in property <string> s-name-error;
        in property <[IdentitySuggestionVm]> s-suggestions;
        in-out property <string> s-sid;

        in-out property <bool>   s-limit-depth;
        in-out property <int>    s-max-depth: 5;

        // LDAP-Modus analog zum Analyze-Tab. 0 = Aus (SAM/LSA),
        // 1 = LDAPS, 2 = LDAP unverschluesselt.
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
        // Anfrage zum Löschen eines Scan-Laufs. Die GUI fragt erst über den
        // d-pending-delete-Dialog nach, der Worker bekommt die Anfrage erst
        // nach Bestätigung.
        // Request to delete a scan run. The GUI prompts via the
        // d-pending-delete dialog first; the worker only sees the request
        // after confirmation.
        callback delta-delete-confirmed(string);

        // ID des Scan-Laufs, für den der Bestätigungsdialog gerade
        // sichtbar sein soll. Leer = kein Dialog offen.
        // ID of the scan run for which the confirmation dialog should be
        // visible. Empty = no dialog open.
        in-out property <string> d-pending-delete-id;
        in-out property <string> d-pending-delete-label;

        VerticalBox {
            padding: 8px;
            spacing: 6px;

            Text {
                text: "Stars — AD Permission Analyzer";
                font-size: 18px;
                horizontal-alignment: left;
            }

            TabWidget {
                // ============================================================
                // Tab: Analyze
                // ============================================================
                Tab {
                    title: "Analyze";

                    ScrollView {
                        VerticalBox {
                            padding: 8px;
                            spacing: 8px;

                            GroupBox {
                                title: "Ziel / Target";
                                VerticalBox {
                                    spacing: 6px;
                                    GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Pfad:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "C:\\Ordner  oder  \\\\server\\share\\Ordner";
                                                text <=> root.a-path;
                                            }
                                        }
                                        Row {
                                            Text { text: "Benutzer/Gruppe:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "ad  →  Administrator, Domain Admins, BUILTIN\\Administrators, …";
                                                text <=> root.a-name;
                                                edited(s) => { root.analyze-name-edited(s); }
                                                accepted(s) => { root.resolve-name-clicked(); }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            HorizontalBox {
                                                alignment: start;
                                                spacing: 6px;
                                                padding: 0px;
                                                Button {
                                                    text: "🔍 SID auflösen";
                                                    clicked => { root.resolve-name-clicked(); }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            if root.a-suggestions.length > 0: Rectangle {
                                                background: #ffffff;
                                                border-color: #c0c0c0;
                                                border-width: 1px;
                                                border-radius: 4px;
                                                VerticalLayout {
                                                    padding: 4px;
                                                    spacing: 0px;
                                                    for sug[i] in root.a-suggestions: TouchArea {
                                                        height: 24px;
                                                        clicked => { root.pick-analyze-suggestion(sug.name); }
                                                        HorizontalLayout {
                                                            padding-left: 6px;
                                                            padding-right: 6px;
                                                            spacing: 8px;
                                                            Text {
                                                                text: "[" + sug.kind_icon + "]";
                                                                color: #666;
                                                                width: 28px;
                                                                vertical-alignment: center;
                                                            }
                                                            Text {
                                                                text: sug.qualified;
                                                                color: #2c3e50;
                                                                vertical-alignment: center;
                                                                width: 320px;
                                                                overflow: elide;
                                                            }
                                                            Text {
                                                                text: sug.description;
                                                                color: #999;
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
                                            Text { text: "Benutzer-SID:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "S-1-5-21-...   (entweder direkt eintippen oder oben auflösen lassen)";
                                                text <=> root.a-sid;
                                            }
                                        }
                                    }
                                    if root.a-name-error != "": Text {
                                        text: root.a-name-error;
                                        color: #c0392b;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Identitätsauflösung";
                                VerticalBox {
                                    spacing: 6px;
                                    HorizontalBox {
                                        spacing: 8px;
                                        padding: 0px;
                                        Text {
                                            text: "Modus:";
                                            vertical-alignment: center;
                                            width: 110px;
                                        }
                                        ComboBox {
                                            model: [
                                                "Aus — SAM/LSA nutzen (empfohlen auf DC)",
                                                "LDAPS — verschlüsselt, Port 636",
                                                "LDAP unverschlüsselt — Port 389 (nur Test)",
                                            ];
                                            current-index <=> root.a-ldap-mode;
                                            horizontal-stretch: 1;
                                        }
                                        HelpTip {
                                            tip: "Wie sollen Identität und Gruppen aufgelöst werden?\n\n• Aus (empfohlen): nutzt die lokale Windows-LSA/SAM. Auf einem Domain Controller liefert das vollständige Daten (User, globale Gruppen, lokale Gruppen). Keine Konfiguration, kein Zertifikat nötig.\n\n• LDAPS: verschlüsselte LDAP-Verbindung über Port 636. Setzt voraus, dass der DC ein gültiges LDAPS-Zertifikat hat (AD Certificate Services oder manuell installiert).\n\n• LDAP unverschlüsselt: Port 389, ohne TLS. Nur für Testumgebungen — überträgt Passwort im Klartext.";
                                        }
                                    }

                                    if root.a-ldap-mode > 0: GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "dc01.domain.local";
                                                text <=> root.a-ldap-server;
                                            }
                                            HelpTip {
                                                tip: "Vollqualifizierter Hostname (FQDN) des Domain Controllers.\n\nBeispiel: dc01.firma.local\n\nKein Schema-Präfix (kein ldap:// oder ldaps://) eintragen — das ergibt sich aus dem Modus.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Base DN:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "DC=domain,DC=local";
                                                text <=> root.a-ldap-base-dn;
                                            }
                                            HelpTip {
                                                tip: "Distinguished Name der Domänenwurzel.\n\nBeispiel: DC=firma,DC=local\n\nKomma-getrennt, keine Leerzeichen nach den Kommas. Aus der DNS-Domäne ableitbar: aus 'firma.local' wird 'DC=firma,DC=local'.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Bind DN:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "CN=SvcScan,CN=Users,DC=domain,DC=local";
                                                text <=> root.a-ldap-bind-dn;
                                            }
                                            HelpTip {
                                                tip: "Vollständiger DN des Service- oder Auditor-Kontos zum Anmelden gegen LDAP.\n\nNicht nur der Benutzername — der ganze Pfad bis zum Objekt:\nCN=Max Muster,OU=Benutzer,DC=firma,DC=local\n\nFür ein dediziertes Read-only-Service-Konto empfohlen, nicht der Domain-Admin.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Passwort:"; vertical-alignment: center; }
                                            LineEdit {
                                                input-type: password;
                                                text <=> root.a-ldap-password;
                                            }
                                            HelpTip {
                                                tip: "Passwort des Bind-DN-Kontos.\n\nWird nicht gespeichert, nur für die laufende Sitzung im Speicher gehalten. Bei 'Unverschlüsseltes LDAP' geht es im Klartext über das Netz — deshalb nur in Testumgebungen verwenden.";
                                            }
                                        }
                                    }
                                }
                            }

                            GroupBox {
                                title: "SMB-Freigabe (optional, kombiniert NTFS ∩ Share)";
                                VerticalBox {
                                    spacing: 6px;
                                    CheckBox {
                                        text: "Share-Maske berücksichtigen";
                                        checked <=> root.a-smb-enabled;
                                    }
                                    if root.a-smb-enabled: GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "fileserver";
                                                text <=> root.a-smb-server;
                                            }
                                        }
                                        Row {
                                            Text { text: "Share:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "Daten";
                                                text <=> root.a-smb-share;
                                            }
                                        }
                                    }
                                }
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: 8px;
                                Button {
                                    text: root.a-is-running ? "Läuft..." : "Analysieren";
                                    enabled: !root.a-is-running;
                                    clicked => { root.analyze-clicked(); }
                                }
                                // Zweite Audit-Frage: pfadzentrierte
                                // Trustee-Sicht. Benötigt keine Identität,
                                // weil sie alle ACEs des Pfads zeigt.
                                // Second audit question: path-centric
                                // trustee view. Needs no identity because
                                // it lists every ACE on the path.
                                Button {
                                    text: root.a-trustees-running ? "Läuft..." : "Wer hat Zugriff?";
                                    enabled: !root.a-trustees-running;
                                    clicked => { root.analyze-trustees-clicked(); }
                                }
                            }

                            if root.a-status != "": Text {
                                text: root.a-status;
                                color: root.a-status-is-error ? #c0392b : #2c3e50;
                                wrap: word-wrap;
                            }

                            Text {
                                text: "Hinweis: jede Analyse wird automatisch in der Scan-Historie gespeichert und ist anschließend im Delta-Tab vergleichbar.";
                                color: #6c7a89;
                                font-size: 12px;
                                wrap: word-wrap;
                            }

                            if root.a-rights-label != "": GroupBox {
                                title: "Ergebnis";
                                VerticalBox {
                                    spacing: 4px;
                                    Text {
                                        text: "Effektive Rechte: " + root.a-rights-label;
                                        font-size: 16px;
                                    }
                                    Text {
                                        text: "Access-Mask: " + root.a-mask-hex;
                                        color: #555;
                                    }
                                    if root.a-share-line != "": Text {
                                        text: root.a-share-line;
                                        color: #555;
                                    }
                                    Text {
                                        text: "Berechtigungspfad:";
                                        font-size: 14px;
                                    }
                                    for step[i] in root.a-explanation: Text {
                                        text: (i + 1) + ". " + step;
                                        wrap: word-wrap;
                                    }
                                }
                            }

                            // Trustee-Sicht: zeigt alle ACEs auf dem Pfad,
                            // unabhängig vom Identitäts-Token. Komplement zur
                            // identitätsbasierten Effektiv-Analyse oben.
                            // Trustee view: shows every ACE on the path,
                            // independent of any identity token. Complement
                            // to the identity-based effective analysis above.
                            if root.a-has-trustees: GroupBox {
                                title: "Wer hat Zugriff (" + root.a-trustees.length + " ACE-Einträge)";
                                VerticalBox {
                                    spacing: 4px;
                                    HorizontalBox {
                                        spacing: 8px;
                                        Text { text: "Trustee"; font-weight: 700; horizontal-stretch: 2; }
                                        Text { text: "Art"; font-weight: 700; width: 70px; }
                                        Text { text: "Rechte"; font-weight: 700; width: 220px; }
                                        Text { text: "Quelle"; font-weight: 700; width: 80px; }
                                        Text { text: "Anwendung"; font-weight: 700; width: 220px; }
                                        Text { text: "Schicht"; font-weight: 700; width: 70px; }
                                    }
                                    for t[i] in root.a-trustees: HorizontalBox {
                                        spacing: 8px;
                                        Text {
                                            text: t.display_name;
                                            color: #2c3e50;
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
                                            color: #555;
                                            width: 220px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: t.source;
                                            color: #555;
                                            width: 80px;
                                        }
                                        Text {
                                            text: t.applies_to;
                                            color: #555;
                                            width: 220px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: t.category;
                                            color: #555;
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
                            padding: 8px;
                            spacing: 8px;

                            GroupBox {
                                title: "Ziel / Target";
                                VerticalBox {
                                    spacing: 6px;
                                    GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Wurzelpfad:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "C:\\Daten  oder  \\\\server\\share\\Daten";
                                                text <=> root.s-root;
                                            }
                                        }
                                        Row {
                                            Text { text: "Benutzer/Gruppe:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "ad  →  Administrator, Domain Admins, BUILTIN\\Administrators, …";
                                                text <=> root.s-name;
                                                edited(s) => { root.scan-name-edited(s); }
                                                accepted(s) => { root.resolve-scan-name-clicked(); }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            HorizontalBox {
                                                alignment: start;
                                                spacing: 6px;
                                                padding: 0px;
                                                Button {
                                                    text: "🔍 SID auflösen";
                                                    clicked => { root.resolve-scan-name-clicked(); }
                                                }
                                            }
                                        }
                                        Row {
                                            Text { text: ""; }
                                            if root.s-suggestions.length > 0: Rectangle {
                                                background: #ffffff;
                                                border-color: #c0c0c0;
                                                border-width: 1px;
                                                border-radius: 4px;
                                                VerticalLayout {
                                                    padding: 4px;
                                                    spacing: 0px;
                                                    for sug[i] in root.s-suggestions: TouchArea {
                                                        height: 24px;
                                                        clicked => { root.pick-scan-suggestion(sug.name); }
                                                        HorizontalLayout {
                                                            padding-left: 6px;
                                                            padding-right: 6px;
                                                            spacing: 8px;
                                                            Text {
                                                                text: "[" + sug.kind_icon + "]";
                                                                color: #666;
                                                                width: 28px;
                                                                vertical-alignment: center;
                                                            }
                                                            Text {
                                                                text: sug.qualified;
                                                                color: #2c3e50;
                                                                vertical-alignment: center;
                                                                width: 320px;
                                                                overflow: elide;
                                                            }
                                                            Text {
                                                                text: sug.description;
                                                                color: #999;
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
                                            Text { text: "Benutzer-SID:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "S-1-5-21-...   (entweder direkt eintippen oder oben auflösen lassen)";
                                                text <=> root.s-sid;
                                            }
                                        }
                                    }
                                    if root.s-name-error != "": Text {
                                        text: root.s-name-error;
                                        color: #c0392b;
                                        wrap: word-wrap;
                                    }
                                }
                                HorizontalBox {
                                    spacing: 8px;
                                    alignment: start;
                                    CheckBox {
                                        text: "Tiefe begrenzen";
                                        checked <=> root.s-limit-depth;
                                    }
                                    if root.s-limit-depth: SpinBox {
                                        minimum: 1;
                                        maximum: 100;
                                        value <=> root.s-max-depth;
                                        width: 120px;
                                    }
                                }
                            }

                            GroupBox {
                                title: "Identitätsauflösung";
                                VerticalBox {
                                    spacing: 6px;
                                    HorizontalBox {
                                        spacing: 8px;
                                        padding: 0px;
                                        Text {
                                            text: "Modus:";
                                            vertical-alignment: center;
                                            width: 110px;
                                        }
                                        ComboBox {
                                            model: [
                                                "Aus — SAM/LSA nutzen (empfohlen auf DC)",
                                                "LDAPS — verschlüsselt, Port 636",
                                                "LDAP unverschlüsselt — Port 389 (nur Test)",
                                            ];
                                            current-index <=> root.s-ldap-mode;
                                            horizontal-stretch: 1;
                                        }
                                        HelpTip {
                                            tip: "Wie sollen Identität und Gruppen aufgelöst werden?\n\n• Aus (empfohlen): nutzt die lokale Windows-LSA/SAM. Auf einem Domain Controller liefert das vollständige Daten (User, globale Gruppen, lokale Gruppen). Keine Konfiguration, kein Zertifikat nötig.\n\n• LDAPS: verschlüsselte LDAP-Verbindung über Port 636. Setzt voraus, dass der DC ein gültiges LDAPS-Zertifikat hat (AD Certificate Services oder manuell installiert).\n\n• LDAP unverschlüsselt: Port 389, ohne TLS. Nur für Testumgebungen — überträgt Passwort im Klartext.";
                                        }
                                    }

                                    if root.s-ldap-mode > 0: GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "dc01.domain.local";
                                                text <=> root.s-ldap-server;
                                            }
                                            HelpTip {
                                                tip: "Vollqualifizierter Hostname (FQDN) des Domain Controllers.\n\nBeispiel: dc01.firma.local\n\nKein Schema-Präfix (kein ldap:// oder ldaps://) eintragen — das ergibt sich aus dem Modus.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Base DN:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "DC=domain,DC=local";
                                                text <=> root.s-ldap-base-dn;
                                            }
                                            HelpTip {
                                                tip: "Distinguished Name der Domänenwurzel.\n\nBeispiel: DC=firma,DC=local\n\nKomma-getrennt, keine Leerzeichen nach den Kommas. Aus der DNS-Domäne ableitbar: aus 'firma.local' wird 'DC=firma,DC=local'.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Bind DN:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "CN=SvcScan,CN=Users,DC=domain,DC=local";
                                                text <=> root.s-ldap-bind-dn;
                                            }
                                            HelpTip {
                                                tip: "Vollständiger DN des Service- oder Auditor-Kontos zum Anmelden gegen LDAP.\n\nNicht nur der Benutzername — der ganze Pfad bis zum Objekt:\nCN=Max Muster,OU=Benutzer,DC=firma,DC=local\n\nFür ein dediziertes Read-only-Service-Konto empfohlen, nicht der Domain-Admin.";
                                            }
                                        }
                                        Row {
                                            Text { text: "Passwort:"; vertical-alignment: center; }
                                            LineEdit {
                                                input-type: password;
                                                text <=> root.s-ldap-password;
                                            }
                                            HelpTip {
                                                tip: "Passwort des Bind-DN-Kontos.\n\nWird nicht gespeichert, nur für die laufende Sitzung im Speicher gehalten. Bei 'Unverschlüsseltes LDAP' geht es im Klartext über das Netz — deshalb nur in Testumgebungen verwenden.";
                                            }
                                        }
                                    }
                                }
                            }

                            GroupBox {
                                title: "SMB-Freigabe (optional)";
                                VerticalBox {
                                    spacing: 6px;
                                    CheckBox {
                                        text: "Share-Maske berücksichtigen";
                                        checked <=> root.s-smb-enabled;
                                    }
                                    if root.s-smb-enabled: GridBox {
                                        spacing: 6px;
                                        Row {
                                            Text { text: "Server:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "fileserver";
                                                text <=> root.s-smb-server;
                                            }
                                        }
                                        Row {
                                            Text { text: "Share:"; vertical-alignment: center; }
                                            LineEdit {
                                                placeholder-text: "Daten";
                                                text <=> root.s-smb-share;
                                            }
                                        }
                                    }
                                }
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: 8px;
                                Button {
                                    text: root.s-is-running ? "Läuft..." : "Scan starten";
                                    enabled: !root.s-is-running;
                                    clicked => { root.scan-clicked(); }
                                }
                                Button {
                                    text: "Abbrechen";
                                    enabled: root.s-is-running;
                                    clicked => { root.scan-cancel-clicked(); }
                                }
                            }

                            if root.s-status != "": Text {
                                text: root.s-status;
                                color: root.s-status-is-error ? #c0392b : #2c3e50;
                                wrap: word-wrap;
                            }

                            if root.s-done || root.s-is-running: GroupBox {
                                title: "Ergebnisse (" + root.s-total + " Pfade, "
                                    + root.s-error-count + " Fehler)";
                                VerticalBox {
                                    spacing: 6px;
                                    HorizontalBox {
                                        spacing: 6px;
                                        Text { text: "Filter:"; vertical-alignment: center; }
                                        LineEdit {
                                            placeholder-text: "Teilstring im Pfad";
                                            text <=> root.s-filter;
                                            edited(s) => { root.scan-filter-changed(); }
                                        }
                                    }

                                    for row[i] in root.s-rows: VerticalBox {
                                        spacing: 2px;
                                        TouchArea {
                                            clicked => { root.scan-row-toggle(i); }
                                            HorizontalBox {
                                                spacing: 8px;
                                                alignment: start;
                                                Text {
                                                    text: row.expanded ? "▼" : "▶";
                                                    width: 16px;
                                                }
                                                Text {
                                                    text: row.path;
                                                    color: row.has_diagnostic ? #c0392b : #2c3e50;
                                                    overflow: elide;
                                                    horizontal-stretch: 1;
                                                }
                                                Text {
                                                    text: row.rights_label;
                                                    color: #2c3e50;
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
                                            spacing: 1px;
                                            for step[j] in row.steps: Text {
                                                text: (j + 1) + ". " + step;
                                                color: #444;
                                                wrap: word-wrap;
                                            }
                                        }
                                    }
                                }
                            }

                            if root.s-errors.length > 0: GroupBox {
                                title: "Fehler beim Scan";
                                VerticalBox {
                                    spacing: 2px;
                                    for err[i] in root.s-errors: HorizontalBox {
                                        spacing: 8px;
                                        Text {
                                            text: err.path != "" ? err.path : "(ohne Pfad)";
                                            color: #c0392b;
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
                                title: "Risikobefunde";
                                VerticalBox {
                                    spacing: 4px;
                                    for risk[i] in root.s-risks: VerticalBox {
                                        spacing: 1px;
                                        HorizontalBox {
                                            spacing: 8px;
                                            alignment: start;
                                            Text {
                                                text: "[" + risk.severity_label + "]";
                                                color: risk.severity_color;
                                                width: 100px;
                                            }
                                            Text {
                                                text: risk.rule_id;
                                                color: #2c3e50;
                                                width: 220px;
                                            }
                                            Text {
                                                text: risk.affected_path;
                                                color: #555;
                                                overflow: elide;
                                                horizontal-stretch: 1;
                                            }
                                        }
                                        Text {
                                            text: risk.incomplete
                                                ? "⚠ unvollständig — " + risk.description
                                                : risk.description;
                                            color: #444;
                                            wrap: word-wrap;
                                        }
                                    }
                                }
                            }

                            if root.s-done: GroupBox {
                                title: "HTML-Bericht exportieren";
                                VerticalBox {
                                    spacing: 6px;
                                    HorizontalBox {
                                        spacing: 6px;
                                        Text { text: "Zieldatei:"; vertical-alignment: center; }
                                        LineEdit {
                                            placeholder-text: "C:\\Berichte\\scan.html";
                                            text <=> root.s-export-path;
                                        }
                                        Button {
                                            text: "Exportieren";
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
                            padding: 8px;
                            spacing: 8px;

                            Text {
                                text: "Vergleich zweier Scan-Läufe — zeige Pfade, "
                                    + "die hinzugekommen, entfernt oder mit anderen "
                                    + "Rechten gespeichert sind.";
                                wrap: word-wrap;
                                color: #555;
                            }

                            HorizontalBox {
                                alignment: start;
                                spacing: 8px;
                                Button {
                                    text: root.d-is-loading ? "Lädt..." : "📂 Scan-Historie laden";
                                    enabled: !root.d-is-loading;
                                    clicked => { root.delta-load-runs-clicked(); }
                                }
                            }

                            if root.d-status != "": Text {
                                text: root.d-status;
                                color: root.d-status-is-error ? #c0392b : #2c3e50;
                                wrap: word-wrap;
                            }

                            if root.d-scan-runs.length > 0: GroupBox {
                                title: "Verfügbare Scan-Läufe (älteste zuerst auswählen für 'Alt')";
                                VerticalBox {
                                    spacing: 4px;
                                    HorizontalBox {
                                        spacing: 8px;
                                        Text {
                                            text: "Alt";
                                            width: 60px;
                                            font-weight: 700;
                                        }
                                        Text {
                                            text: "Neu";
                                            width: 60px;
                                            font-weight: 700;
                                        }
                                        Text {
                                            text: "Scan-Lauf";
                                            horizontal-stretch: 1;
                                            font-weight: 700;
                                        }
                                    }
                                    for run[i] in root.d-scan-runs: HorizontalBox {
                                        spacing: 8px;
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
                                        // Mülleimer-Button — öffnet den
                                        // Bestätigungsdialog, ohne sofort zu
                                        // löschen. Die eigentliche Aktion
                                        // läuft erst über die Bestätigung.
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
                                spacing: 8px;
                                Button {
                                    text: "⟳ Vergleichen";
                                    clicked => { root.delta-compare-clicked(); }
                                }
                            }

                            // Bestätigungsdialog — keine separates Popup-Fenster
                            // sondern eine sichtbare Inline-Box, damit ein
                            // unbeabsichtigter Klick auf den Mülleimer nicht
                            // bereits löscht.
                            // Confirmation dialog — not a separate popup but an
                            // inline visible box so a stray trash click does
                            // not delete immediately.
                            if root.d-pending-delete-id != "": Rectangle {
                                background: #fff3cd;
                                border-color: #c69210;
                                border-width: 1px;
                                border-radius: 4px;
                                VerticalBox {
                                    padding: 8px;
                                    spacing: 6px;
                                    Text {
                                        text: "Scan-Lauf wirklich entfernen?";
                                        font-weight: 700;
                                        color: #5c4500;
                                    }
                                    Text {
                                        text: root.d-pending-delete-label;
                                        color: #5c4500;
                                        wrap: word-wrap;
                                    }
                                    Text {
                                        text: "Diese Aktion kann nicht rückgängig gemacht werden. Alle in diesem Lauf gespeicherten Berechtigungen und Scan-Fehler werden mit gelöscht.";
                                        color: #5c4500;
                                        wrap: word-wrap;
                                        font-size: 12px;
                                    }
                                    HorizontalBox {
                                        spacing: 8px;
                                        alignment: end;
                                        Button {
                                            text: "Abbrechen";
                                            clicked => {
                                                root.d-pending-delete-id = "";
                                                root.d-pending-delete-label = "";
                                            }
                                        }
                                        Button {
                                            text: "Endgültig löschen";
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
                                title: "Delta (" + root.d-added-count + " hinzugefügt, "
                                    + root.d-removed-count + " entfernt, "
                                    + root.d-changed-count + " geändert)";
                                VerticalBox {
                                    spacing: 2px;
                                    HorizontalBox {
                                        spacing: 8px;
                                        Text {
                                            text: "Pfad";
                                            font-weight: 700;
                                            horizontal-stretch: 1;
                                        }
                                        Text {
                                            text: "Art";
                                            font-weight: 700;
                                            width: 110px;
                                        }
                                        Text {
                                            text: "Alt";
                                            font-weight: 700;
                                            width: 180px;
                                        }
                                        Text {
                                            text: "Neu";
                                            font-weight: 700;
                                            width: 180px;
                                        }
                                    }
                                    // Leeres Delta: ausdrücklich sagen, dass der Vergleich
                                    // gelaufen ist und nichts gefunden hat — sonst sieht der
                                    // Nutzer eine leere Tabelle und denkt, der Klick sei verloren.
                                    // Empty delta: explicitly state that the comparison ran and
                                    // found nothing — otherwise the user sees an empty table and
                                    // thinks the click was lost.
                                    if root.d-rows.length == 0: Text {
                                        text: "Keine Unterschiede zwischen den beiden Scans gefunden. Beide Läufe enthalten dieselben Pfade mit identischen effektiven Berechtigungen.";
                                        color: #2c3e50;
                                        wrap: word-wrap;
                                    }
                                    for entry[i] in root.d-rows: HorizontalBox {
                                        spacing: 8px;
                                        Text {
                                            text: entry.path;
                                            color: #2c3e50;
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
                                            color: #555;
                                            width: 180px;
                                            overflow: elide;
                                        }
                                        Text {
                                            text: entry.new_rights;
                                            color: #555;
                                            width: 180px;
                                            overflow: elide;
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

/// Liefert das Log-Verzeichnis (`%LOCALAPPDATA%\Stars\logs`).
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
                "Stars — Absturz beim Start",
                &format!(
                    "Die Anwendung ist abgestürzt.\n\nOrt: {location}\nGrund: {payload}\n\nDetails: {}",
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

    if let Err(e) = run_ui(&log_path) {
        tracing::error!(error = %e, "Slint UI failed");
        show_fatal_dialog(
            "Stars — Start fehlgeschlagen",
            &format!(
                "Das GUI-Backend konnte nicht initialisiert werden.\n\nGrund: {e}\n\nDetails: {}",
                log_path.display()
            ),
        );
    }
}

/// Sammelt alle Scan-Zwischenstände, die nicht direkt in eine Slint-Property
/// passen — der ungefilterte Originalbestand der Zeilen (für den Filter)
/// und die ausgeklappten Zeilen, beides reine UI-Hilfsdaten.
/// Aggregates all scan intermediates that don't fit directly into a Slint
/// property — the unfiltered raw rows (for the filter) and the expanded
/// row state, both pure UI-side bookkeeping.
#[derive(Default)]
struct ScanUiState {
    all_rows: Vec<ScanRowVm>,
    all_errors: Vec<ScanErrorVm>,
    all_risks: Vec<RiskItemVm>,
}

/// Backing-Store für den Delta-Tab. Die Slint-Properties sind die
/// View-Darstellung; den „Wahrheits"-Stand der Auswahl halten wir hier,
/// damit das exklusive Anhaken („Alt" und „Neu" sind je genau einer der
/// Läufe) ohne Slint-Bookkeeping läuft.
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
    /// Worker-Sender für Folge-Aktionen aus Event-Handlern (z. B. nach einer
    /// Löschung erneut die Scan-Historie laden). Wird in `run_ui` direkt nach
    /// `spawn_worker` befüllt.
    /// Worker sender for follow-up actions inside event handlers (e.g.
    /// re-load the scan history after a deletion). Populated in `run_ui`
    /// right after `spawn_worker`.
    static REQ_TX: RefCell<Option<Sender<WorkerRequest>>> = const { RefCell::new(None) };
    static SCAN_STATE: RefCell<ScanUiState> = RefCell::new(ScanUiState::default());
    static DELTA_STATE: RefCell<DeltaUiState> = RefCell::new(DeltaUiState::default());
    /// Vorab geladene Identitäts­liste für die Live-Suche. Wird einmalig
    /// nach App-Start gefüllt; die Tastendruck-Filter läuft rein lokal
    /// gegen diesen Cache und braucht keinen Worker-Roundtrip.
    /// Pre-loaded identity list for the live search. Filled once after
    /// app start; keystroke filtering runs purely locally against this
    /// cache without a worker round-trip.
    static IDENTITY_CACHE: RefCell<Vec<IdentitySuggestion>> = const { RefCell::new(Vec::new()) };
}

fn run_ui(_log_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;

    // notify-Callback: weckt den GUI-Thread, sobald der Worker ein Event
    // gesendet hat. Slints `invoke_from_event_loop` darf aus jedem Thread
    // gerufen werden und führt die Closure im UI-Thread aus.
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

    // Identitäts­liste einmal vorab anfordern, damit die Live-Suche im
    // Namensfeld ab dem ersten Tastendruck Vorschläge zeigen kann. Wenn
    // der Aufruf fehlschlägt, läuft das GUI ohne Vorschläge weiter — die
    // SID-Eingabe und der „🔍 SID auflösen"-Button funktionieren auch
    // ohne Cache.
    // Pre-load the identity list once so the live search can show
    // suggestions from the first keystroke. If the call fails the GUI
    // keeps running without suggestions — SID input and the
    // "🔍 SID auflösen" button work without the cache too.
    let _ = req_tx.send(WorkerRequest::ListIdentities);

    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyze tab wiring
// ---------------------------------------------------------------------------

fn wire_analyze_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // Name → SID: LSA-Lookup direkt im UI-Thread (LookupAccountNameW ist
    // sub-millisekunden­schnell, kein Worker-Roundtrip nötig).
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

    // Live-Suche: bei jedem Tastendruck im Namensfeld die Cache-Liste
    // filtern und an die Slint-Property weiterreichen. Bei leerer Eingabe
    // verschwindet die Vorschlagsliste automatisch (length == 0).
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

    // Klick auf einen Vorschlag: Name übernehmen, Liste schließen, SID
    // direkt mit auflösen — so muss der User nicht zweimal klicken.
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
        let sid = ui.get_a_sid().to_string();

        if path.trim().is_empty() || sid.trim().is_empty() {
            ui.set_a_status("Pfad und SID müssen angegeben werden.".into());
            ui.set_a_status_is_error(true);
            return;
        }

        // LDAP-Modus: 0 = Aus (SAM/LSA), 1 = LDAPS, 2 = LDAP unverschluesselt.
        // LDAP mode: 0 = off (SAM/LSA), 1 = LDAPS, 2 = plain LDAP.
        let ldap = match ui.get_a_ldap_mode() {
            1 | 2 => Some(LdapParams {
                server: ui.get_a_ldap_server().to_string(),
                base_dn: ui.get_a_ldap_base_dn().to_string(),
                bind_dn: ui.get_a_ldap_bind_dn().to_string(),
                password: ui.get_a_ldap_password().to_string(),
                insecure: ui.get_a_ldap_mode() == 2,
            }),
            _ => None,
        };

        let (smb_server, share_name) = if ui.get_a_smb_enabled() {
            (
                Some(ui.get_a_smb_server().to_string()),
                Some(ui.get_a_smb_share().to_string()),
            )
        } else {
            (None, None)
        };

        ui.set_a_is_running(true);
        ui.set_a_status("Analyse läuft...".into());
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
            ui.set_a_status(format!("Worker nicht erreichbar: {e}").into());
            ui.set_a_status_is_error(true);
        }
    });

    // „Wer hat Zugriff?" — pfadzentrierte Trustee-Sicht. Braucht keine SID.
    // "Wer hat Zugriff?" — path-centric trustee view. Needs no SID.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_analyze_trustees_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let path = ui.get_a_path().to_string();
            if path.trim().is_empty() {
                ui.set_a_status("Pfad muss angegeben werden.".into());
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
                ui.set_a_status(format!("Worker nicht erreichbar: {e}").into());
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
            ui.set_a_status(format!("{} ACE-Einträge auf diesem Pfad gefunden.", len).into());
            ui.set_a_status_is_error(false);
        }
        Err(e) => {
            ui.set_a_has_trustees(false);
            ui.set_a_status(format!("Trustee-Auswertung fehlgeschlagen: {e}").into());
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
            // Status spiegelt jetzt auch wider, ob die Auswertung in die
            // Scan-Historie geschrieben wurde — Voraussetzung dafür, dass
            // sie im Delta-Tab vergleichbar ist.
            // Status now also reflects whether the evaluation was written to
            // the scan history — required for it to be comparable in the
            // Delta tab.
            let (status, is_error) = match (scan_run_id, persistence_error) {
                (Some(_), _) => (
                    "Analyse abgeschlossen — in der Scan-Historie gespeichert.".to_string(),
                    false,
                ),
                (None, Some(reason)) => (
                    format!("Analyse abgeschlossen, aber Persistenz fehlgeschlagen: {reason}"),
                    true,
                ),
                (None, None) => ("Analyse abgeschlossen.".to_string(), false),
            };
            ui.set_a_status(status.into());
            ui.set_a_status_is_error(is_error);
        }
        Err(e) => {
            ui.set_a_status(format!("Analyse fehlgeschlagen: {e}").into());
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
                "Share-Beschränkung angewendet: NTFS = {ntfs_label}, Share = {share_label}, effektiv = NTFS ∩ Share."
            )
        }
        ShareEvalStatus::Unrestricted => {
            format!("Share hat NULL-DACL (keine Beschränkung über SMB) — effektiv folgt NTFS = {ntfs_label}.")
        }
        ShareEvalStatus::ReadFailed(reason) => {
            format!("Share-DACL-Lesen fehlgeschlagen: {reason} — Ergebnis kann unvollständig sein.")
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
    // Name → SID Hilfsfunktion (analog zum Analyze-Tab).
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

    // Live-Suche analog zum Analyze-Tab.
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
            let sid = ui.get_s_sid().to_string();

            if root.trim().is_empty() || sid.trim().is_empty() {
                ui.set_s_status("Wurzelpfad und SID müssen angegeben werden.".into());
                ui.set_s_status_is_error(true);
                return;
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

            // LDAP-Modus analog zum Analyze-Tab.
            // LDAP mode analogous to the Analyze tab.
            let ldap = match ui.get_s_ldap_mode() {
                1 | 2 => Some(LdapParams {
                    server: ui.get_s_ldap_server().to_string(),
                    base_dn: ui.get_s_ldap_base_dn().to_string(),
                    bind_dn: ui.get_s_ldap_bind_dn().to_string(),
                    password: ui.get_s_ldap_password().to_string(),
                    insecure: ui.get_s_ldap_mode() == 2,
                }),
                _ => None,
            };

            let (smb_server, share_name) = if ui.get_s_smb_enabled() {
                (
                    Some(ui.get_s_smb_server().to_string()),
                    Some(ui.get_s_smb_share().to_string()),
                )
            } else {
                (None, None)
            };

            // Zustand für einen neuen Lauf zurücksetzen.
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
            ui.set_s_status("Scan läuft...".into());
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
                ui.set_s_status(format!("Worker nicht erreichbar: {e}").into());
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

    // scan-row-toggle: schaltet die expanded-Spalte einer Zeile um. Wir
    // halten die Master-Liste in SCAN_STATE und rendern danach den
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
                ui.set_s_export_message("Bitte Zieldatei angeben.".into());
                ui.set_s_export_is_error(true);
                return;
            }
            ui.set_s_export_message("Export läuft...".into());
            ui.set_s_export_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ExportHtml { output_path }) {
                ui.set_s_export_message(format!("Worker nicht erreichbar: {e}").into());
                ui.set_s_export_is_error(true);
            }
        });
    }
}

/// Übersetzt einen Index aus dem gefilterten View zurück in den Index der
/// ungefilterten Master-Liste, indem der `nth` Treffer gesucht wird.
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

/// Rendert die Zeilen-Property neu aus dem Master-Stand + aktuellem Filter.
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
        expanded: false,
        has_diagnostic: row.diagnostic_count > 0 || row.unsupported_ace_count > 0,
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
        parts.push("Scan abgebrochen — Ergebnisse sind unvollständig.".to_string());
    } else {
        parts.push("Scan abgeschlossen.".to_string());
    }
    if let Some(err) = persistence_error {
        parts.push(format!("Persistenz fehlgeschlagen: {err}"));
    }
    let is_error = cancelled || parts.iter().any(|p| p.starts_with("Persistenz"));
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
            ui.set_s_export_message("✓ Export erfolgreich.".into());
            ui.set_s_export_is_error(false);
        }
        Err(e) => {
            ui.set_s_export_message(format!("✗ Export fehlgeschlagen: {e}").into());
            ui.set_s_export_is_error(true);
        }
    }
}

fn severity_visual(severity: &RiskSeverity) -> (&'static str, slint::Color) {
    match severity {
        RiskSeverity::Info => ("Info", slint::Color::from_rgb_u8(0x55, 0x77, 0x99)),
        RiskSeverity::Low => ("Low", slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f)),
        RiskSeverity::Medium => ("Medium", slint::Color::from_rgb_u8(0xc6, 0x89, 0x10)),
        RiskSeverity::High => ("High", slint::Color::from_rgb_u8(0xd3, 0x55, 0x1c)),
        RiskSeverity::Critical => ("Critical", slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b)),
    }
}

// ---------------------------------------------------------------------------
// Delta tab wiring
// ---------------------------------------------------------------------------

fn wire_delta_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // delta-load-runs-clicked: bittet den Worker die Scan-Historie zu
    // liefern. Antwort kommt asynchron als WorkerEvent::ScanRunsLoaded.
    // delta-load-runs-clicked: asks the worker for the scan history. The
    // answer arrives asynchronously as WorkerEvent::ScanRunsLoaded.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_load_runs_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_d_is_loading(true);
            ui.set_d_status("Lade Scan-Historie...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListScanRuns) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker nicht erreichbar: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-pick-old / delta-pick-new: exklusiv toggeln — Klick auf eine
    // Zeile setzt diesen Lauf als „Alt" bzw. „Neu" und löscht die
    // entsprechende Markierung auf allen anderen Zeilen. Wenn dieselbe
    // Zeile erneut geklickt wird, wird die Auswahl entfernt.
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

    // delta-compare-clicked: zwei IDs lesen, Worker beauftragen.
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
                ui.set_d_status("Bitte je einen Scan-Lauf für 'Alt' und 'Neu' auswählen.".into());
                ui.set_d_status_is_error(true);
                return;
            };
            if old_id == new_id {
                ui.set_d_status("'Alt' und 'Neu' müssen unterschiedliche Läufe sein.".into());
                ui.set_d_status_is_error(true);
                return;
            }
            ui.set_d_is_loading(true);
            ui.set_d_status("Vergleiche Läufe...".into());
            ui.set_d_status_is_error(false);
            ui.set_d_has_result(false);
            if let Err(e) = req_tx.send(WorkerRequest::ComputeDelta {
                old_run_id: old_id,
                new_run_id: new_id,
            }) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker nicht erreichbar: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-delete-confirmed: vom Bestätigungsdialog ausgelöst, nachdem der
    // Anwender „Endgültig löschen" geklickt hat. Schickt die Anfrage an den
    // Worker — die Folge­aktionen (Selektion bereinigen, Liste neu laden)
    // übernimmt der Event-Handler nach Empfang von WorkerEvent::ScanRunDeleted.
    // delta-delete-confirmed: fired by the confirmation dialog after the
    // user clicked "Endgültig löschen". Sends the request to the worker —
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
            ui.set_d_status("Lösche Scan-Lauf...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::DeleteScanRun { run_id: id_str }) {
                ui.set_d_status(format!("Worker nicht erreichbar: {e}").into());
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
            ui.set_d_status("Keine Scan-Läufe gespeichert — erst einen Scan ausführen.".into());
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
                            "{}  —  {}  ({} Fehler)",
                            r.started_at, r.target, r.error_count
                        ),
                    })
                    .collect();
                // Selektionen, die auf nicht mehr existierende Läufe zeigen,
                // ausräumen.
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
                "Scan-Läufe geladen. Je einen für 'Alt' und 'Neu' anhaken, dann vergleichen."
                    .into(),
            );
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_status(format!("Laden fehlgeschlagen: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

/// Reagiert auf eine vom Worker abgeschlossene Scan-Lauf-Löschung. Aktualisiert
/// die Statuszeile, räumt lokale Selektionen auf und triggert ein erneutes
/// Laden der Historie — damit ist die Liste sofort frisch ohne Klick auf
/// „Scan-Historie laden".
/// Reacts to a worker-completed scan-run deletion. Updates the status line,
/// clears local selection state and triggers a fresh history reload so the
/// list is up-to-date without requiring another click on "Scan-Historie
/// laden".
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
            ui.set_d_status("Scan-Lauf entfernt.".into());
            ui.set_d_status_is_error(false);
            // Wenn das Delta-Ergebnis im Frame noch sichtbar war, kann es
            // sich auf den eben gelöschten Lauf beziehen — vorsichtshalber
            // ausblenden.
            // If a delta result was still visible in the frame, it might
            // refer to the just-deleted run — hide it to be safe.
            ui.set_d_has_result(false);
            // Liste frisch nachladen (Background), damit der GUI-State
            // garantiert mit der DB übereinstimmt.
            // Reload the list in background so the GUI state is guaranteed
            // to match the DB.
            REQ_TX.with(|cell| {
                if let Some(tx) = cell.borrow().as_ref() {
                    let _ = tx.send(WorkerRequest::ListScanRuns);
                }
            });
        }
        Err(e) => {
            ui.set_d_status(format!("Löschen fehlgeschlagen: {e}").into());
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
                        "Hinzugefügt" => {
                            added += 1;
                            slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f)
                        }
                        "Entfernt" => {
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
            ui.set_d_status("Vergleich abgeschlossen.".into());
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_has_result(false);
            ui.set_d_status(format!("Vergleich fehlgeschlagen: {e}").into());
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
                // SearchResults (Identitäts-Picker) bleibt für eine spätere
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

/// Filtert die im `IDENTITY_CACHE` liegende Liste gegen den Suchstring
/// und liefert ein Slint-ModelRc zurück, das direkt in eine
/// `[IdentitySuggestionVm]`-Property fließen kann. Maximal `MAX_SUGGESTIONS`
/// Einträge, damit die Liste übersichtlich bleibt — wer mehr will, tippt
/// präziser.
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
            // Cache bleibt leer; Live-Suche zeigt einfach keine
            // Vorschläge. Der „🔍 SID auflösen"-Button funktioniert
            // weiterhin, weil er nur LookupAccountNameW braucht.
            // Cache stays empty; the live search just shows no
            // suggestions. The "🔍 SID auflösen" button keeps working
            // because it only uses LookupAccountNameW.
            tracing::warn!(target: "stars-gui", error = %e, "identity enumeration failed — live search disabled");
        }
    }
}

/// Übersetzt einen Benutzer-/Gruppennamen in eine SID über die lokale LSA
/// (`LookupAccountNameW`). Erfolg ruft `on_sid` mit der aufgelösten SID,
/// Fehler ruft `on_error` mit einer kurzen lokalisierten Meldung. Leere
/// Eingaben gelten als Fehler („Bitte Namen eingeben"). Auf nicht-Windows
/// existiert die Funktion bewusst nicht — der gesamte SAM-Pfad ist
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
        on_error("Bitte einen Benutzer- oder Gruppennamen eingeben.".to_string());
        return;
    }
    match ad_resolver::lookup_sid_for_account(None, trimmed) {
        Ok(sid) => {
            on_sid(sid.0);
            on_error(String::new());
        }
        Err(e) => on_error(format!("'{trimmed}' konnte nicht aufgelöst werden: {e}")),
    }
}

#[cfg(not(windows))]
fn resolve_name_to_sid(
    _name: &str,
    mut _on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    on_error("Name → SID-Auflösung benötigt Windows (LSA-API).".to_string());
}

/// Modaler Fehler-Dialog (Windows) bzw. stderr-Ausgabe (andere Plattformen).
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
    // SAFETY: Beide Zeiger zeigen auf gültige, null-terminierte UTF-16-Puffer,
    // die bis zum Ende des Aufrufs leben. `hwnd` = 0 ist erlaubt.
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
