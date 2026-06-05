# Stars — Technische Dokumentation

**Version:** v1.5.11 (2026-06-05)
**Zielgruppe:** Entwickler, Code-Reviewer, Security-Engineers, die
verstehen wollen, *wie* Stars intern funktioniert — nicht *wie es zu
bedienen* ist (das deckt das [Anwender-Handbuch](anwender-handbuch.md)
ab).

Dieses Dokument beschreibt Architektur, Datenflüsse und die zentralen
Algorithmen. Es ersetzt nicht den Code (die Wahrheit liegt im Quelltext)
und nicht die [ADRs](adr/) (die Entscheidungsbegründungen liegen dort) —
es liefert die Brücke dazwischen.

---

## Inhaltsverzeichnis

1. [Architekturprinzipien](#1-architekturprinzipien)
2. [Workspace und Crate-Layering](#2-workspace-und-crate-layering)
3. [Das fachliche Datenmodell](#3-das-fachliche-datenmodell)
4. [Der Gesamt-Datenfluss](#4-der-gesamt-datenfluss)
5. [Identitätsauflösung — die Principal-Pipeline](#5-identitätsauflösung--die-principal-pipeline)
6. [Permission-Engine — die AccessCheck-Nachbildung](#6-permission-engine--die-accesscheck-nachbildung)
7. [Share-DACL ∩ NTFS-DACL](#7-share-dacl--ntfs-dacl)
8. [Lokale Server-Gruppen und die Kandidatenliste](#8-lokale-server-gruppen-und-die-kandidatenliste)
9. [Das Diagnose-Marker-System](#9-das-diagnose-marker-system)
10. [Risk-Engine — von der Permission zum Audit-Befund](#10-risk-engine--von-der-permission-zum-audit-befund)
11. [Threading-Modell — GUI/CLI/Engine](#11-threading-modell--guiclienginge)
12. [Persistenz und Export](#12-persistenz-und-export)
13. [Validierung an Systemgrenzen](#13-validierung-an-systemgrenzen)
14. [Test-Architektur](#14-test-architektur)
15. [Update-Manager](#15-update-manager)
16. [Weiterführende Dokumente](#16-weiterführende-dokumente)

---

## 1. Architekturprinzipien

Vier Regeln, die jede Designentscheidung in Stars geprägt haben:

### 1.1 Read-only

Stars liest aus AD, NTFS, SMB. Stars schreibt **nichts** an diese
Systeme zurück. Es gibt **keinen Code-Pfad**, der eine ACL ändert,
eine AD-Gruppenmitgliedschaft setzt, eine Datei verschiebt oder einen
Owner ändert — auch nicht als „Reparaturvorschlag", auch nicht im
GUI-Komfortmodus. Diese Regel ist als
[`AGENTS.md`](../AGENTS.md)-Projektgrenze festgeschrieben und in jeder
Crate durch die Abwesenheit entsprechender API-Aufrufe gewährleistet.

Schreibvorgänge nur an Stars-eigene Daten:
- SQLite-Scan-Historie (`%APPDATA%\Stars\stars_data.db`).
- Anwendungs-Logs.
- Vom User gewählte Export-Dateien.

### 1.2 Sichtbarkeit von Unsicherheit

Stars *zeigt* nicht nur die Antwort, sondern auch, was es *nicht wusste*.
Realisiert über strukturierte
[`PermissionDiagnostic`](#9-das-diagnose-marker-system)-Marker, die durch
die gesamte Pipeline (Engine → Risk → Renderer → Export) als
variant-tagged Daten geleitet werden. Risk-Findings tragen
`incomplete = true`, sobald die Berechnungsgrundlage strukturell
unvollständig war. **Keine stillen Skips.**

### 1.3 Modulare Trennung

Die fachliche Engine ist **unabhängig von GUI und CLI** lauffähig.
Dieses Prinzip ist im Crate-Layering verankert: `permission_engine`
und `risk_engine` kennen weder `gui` noch `cli`. Adapter-Traits
(`IdentityResolver`, `IdentityBackend`, `LsaBackend`,
`PermissionEvaluator`, `RiskRule`, `Exporter`) bilden Schnittstellen,
keine Implementierungs-Abhängigkeiten.

### 1.4 Erklärbarkeit

Jeder Berechtigungsbefund trägt einen `PermissionPath` mit den
Zwischenschritten:

```text
User → Group A → Group B (over LDAP_MATCHING_RULE_IN_CHAIN)
     → ACE (Allow, Modify, inherited from C:\)
     → normalized right: Modify
```

Bedeutet: Nicht „Stars hat berechnet", sondern „Stars hat berechnet,
**warum**". Das ist auditierbar und falsifizierbar.

---

## 2. Workspace und Crate-Layering

Stars ist ein Rust-Workspace mit 12 Crates. Das Layering ist strikt
gerichtet — höhere Schichten kennen niedrigere, nie umgekehrt:

```text
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  cli (adpa.exe)        gui (adpa-gui.exe, Slint)         │
│                                                          │
└──────────────┬───────────────────────┬───────────────────┘
               │                       │
               ▼                       ▼
┌──────────────────────────────────────────────────────────┐
│  exporter (CSV/JSON/HTML)   persistence (SQLite)         │
│  update_manager                                          │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  risk_engine (6 Regeln + is_incomplete)                  │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  permission_engine (AccessCheck-Nachbildung)             │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  fs_scanner       share_scanner     ad_resolver          │
│  (NTFS-Walk +     (Share-DACL,      (LDAP, LSA,          │
│   DACL-Read)       NetShareEnum)     SAM, Principal-     │
│                                      Pipeline)           │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  core (Datenmodell, Traits, CoreError)                   │
│  validation (Wrapper-Typen für alle User-Inputs)         │
└──────────────────────────────────────────────────────────┘
```

### Verantwortlichkeiten pro Crate

| Crate | Rolle | Wichtige Module |
| --- | --- | --- |
| `core` | Fachliche Datentypen (`Identity`, `Sid`, `FileSystemObject`, `EffectivePermission`, `PermissionDiagnostic`) + Traits + `CoreError` | `model.rs`, `traits.rs`, `error.rs` |
| `validation` | Typisierte Wrapper für jeden User-Input (`ValidatedSid`, `ValidatedDn`, `ValidatedServerName`, …) plus die Validate-Funktionen | `sid.rs`, `net.rs`, `path.rs`, `numbers.rs`, `export_path.rs`, `db_path.rs` |
| `ad_resolver` | AD-/LSA-/SAM-Zugriff; **zentrale Principal-Pipeline** ist hier | `principal.rs`, `resolver.rs`, `sam.rs`, `local_groups.rs`, `ldap_client.rs` |
| `fs_scanner` | NTFS-DACL-Read + Walker mit Reparse-Point-Schleifen-Erkennung | `walker.rs`, `dacl.rs` |
| `share_scanner` | SMB-Enumeration + Share-DACL-Read über Windows-API | `scanner.rs`, `dacl.rs` |
| `permission_engine` | AccessCheck-Nachbildung, Token-SID-Bau, Berechtigungspfad-Generierung | `engine.rs`, `token.rs`, `mask.rs`, `normalized.rs` |
| `risk_engine` | Sechs Risk-Regeln + `is_incomplete()` | `rules.rs` |
| `persistence` | SQLite-Schema + Migrationen + `ScanStore` | `scan_store.rs`, `migrations.rs` |
| `exporter` | CSV/JSON/HTML-Renderer | `csv.rs`, `json.rs`, `html.rs` |
| `update_manager` | Skelett für signaturgeprüfte Updates | `lib.rs` |
| `cli` | Kommandozeilen-Frontend (`adpa.exe`) | `main.rs`, `output.rs` |
| `gui` | Slint-basiertes GUI (`adpa-gui.exe`) | `main.rs`, `worker.rs`, `ui.slint` |

### Workspace-Konfiguration

Versionen werden zentral in [`Cargo.toml`](../Cargo.toml) gepflegt
(`workspace.package.version`); jede Crate erbt mit
`version.workspace = true`. Dependencies kommen aus
`workspace.dependencies`, sodass Versions-Drift zwischen Crates
ausgeschlossen ist.

---

## 3. Das fachliche Datenmodell

`adpa_core::model` definiert die zentralen Typen, mit denen alle Crates
arbeiten. Hier die wichtigsten:

### Identität

```rust
struct Sid(String);              // canonical "S-1-5-..."

enum IdentityKind { User, Group, Computer, WellKnown, Orphaned, Unknown }

struct Identity {
    sid: Sid,
    name: Option<String>,             // sAMAccountName / LSA-Name
    domain: Option<String>,           // NetBIOS oder DNS, je nach Quelle
    kind: IdentityKind,
    disabled: bool,                   // userAccountControl/UF_ACCOUNTDISABLE
    user_principal_name: Option<String>,
}
```

`Sid` ist ein typisierter String-Wrapper, der ohne Validierungs-
versprechen zwischen Modulen wandert. **Validierung von Roh-SIDs an
Systemgrenzen** geschieht in `validation::sid::validate_sid`, das
einen `ValidatedSid` liefert.

### Dateisystem-Objekt

```rust
struct FileSystemObject {
    path: NormalizedPath,
    is_directory: bool,
    owner_sid: Option<Sid>,
    dacl: Vec<AceEntry>,
    inheritance_disabled: bool,
    is_reparse_point: bool,
    unsupported_aces: Vec<UnsupportedAce>,
    null_dacl: bool,                   // NULL DACL ≠ leere DACL!
}

struct AceEntry {
    kind: AceKind,                     // Allow | Deny
    sid: Sid,
    mask: AccessMask,
    inherited: bool,
    inheritance_flags: u32,            // OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, …
    propagation_flags: u32,            // INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE
}
```

Wichtig:

- `null_dacl: bool` unterscheidet **NULL DACL** (kein Zugriffsschutz =
  Vollzugriff für alle) von einer **leeren DACL** (kein Zugriff für
  niemanden). Die zwei Fälle haben gegensätzliche Bedeutung und müssen
  in jeder Berechnung getrennt behandelt werden.
- `unsupported_aces` sammelt Object-/Callback-/Conditional-/vendor-
  spezifische ACEs, die der Parser nicht versteht — gezählt für den
  `UnsupportedShareAces`-Marker.

### Berechtigungsergebnis

```rust
struct EffectivePermission {
    identity: Identity,
    path: NormalizedPath,
    ntfs_mask: AccessMask,
    share_mask: Option<AccessMask>,
    effective_mask: AccessMask,         // = ntfs ∩ share (restriktiver)
    path_explanation: PermissionPath,
    share_status: ShareEvalStatus,
    local_group_status: LocalGroupEvalStatus,
    contributing_sids: Vec<Sid>,        // welche Token-SIDs trafen ACEs?
    unsupported_ace_count: usize,
    diagnostics: Vec<PermissionDiagnostic>,
}
```

`PermissionPath::steps` ist eine `Vec<String>` mit den Erklärungs-
zeilen — der menschenlesbare Beweis, *warum* das effektive Recht
zustande kam.

### Diagnose-Marker

```rust
enum PermissionDiagnostic {
    NonCanonicalDaclOrder { at_index: usize },
    UnsupportedShareAces { count: usize },
    DomainGroupRecursionIncomplete,
    IdentityDisabled,
    IdentityNotInConfiguredLdapBase,
    IdentityDisabledStatusUnknown,
    IdentityLookupFailed { reason: String },
    GroupResolutionFailed { reason: String },
}
```

Variant-tagged — bei der JSON-Serialisierung erscheint
`{ "kind": "IdentityLookupFailed", "reason": "..." }`. Das macht den
Export vorwärtskompatibel: neue Varianten können hinzugefügt werden,
ohne bestehende JSON-Konsumenten zu brechen.

### Status-Enums vs. Optional-Bools

Wo eine Bool-Entscheidung mehr als zwei Zustände hat, nutzt Stars
Enum-Statuswerte. Beispiele:

```rust
enum ShareMaskStatus {
    NotApplicable,         // kein SMB-Kontext (lokaler Pfad)
    Applied(AccessMask),   // Share-DACL gelesen, Maske berechnet
    Unrestricted,          // NULL DACL — Vollzugriff per Share
    ReadFailed(String),    // Read schlug fehl — incomplete trigger
}

enum LocalGroupEvalStatus {
    NotQueried,                // bewusst nicht angefragt
    Applied,                   // erfolgreich aufgelöst (0 oder mehr Gruppen)
    NotAvailable(String),      // Resolution scheiterte → incomplete
}
```

Diese Trennung ist die Voraussetzung für die Risk-Engine, "wir haben
**nicht** geprüft" von "wir haben geprüft und **nichts** gefunden" zu
unterscheiden — ohne sie wären stille Skips zwangsläufig.

---

## 4. Der Gesamt-Datenfluss

```text
                      ┌─────────────────────────┐
   User-Eingaben ─►   │  Validation             │
   (CLI args, GUI,    │  validation::*          │
    Slint-Events)     │  (trimming, typing)     │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   AD/LDAP, LSA, ─►   │  Principal Pipeline     │
   SAM/NetAPI         │  ad_resolver::principal │  ───► PrincipalResolution
                      │  (Backend-Traits)       │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   NTFS-Walker ──►    │  FileSystemObjects     │
   fs_scanner         │  (path + DACL + owner)  │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   Share-DACL ───►    │  ShareMaskStatus        │
   share_scanner      │  + ShareTrusteeOverlay  │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Permission Engine      │
                      │  permission_engine      │  ───► EffectivePermission
                      │  (Token-Bau + ACE-Walk) │       (+ diagnostics)
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Risk Engine            │
                      │  risk_engine            │  ───► RiskFinding
                      │  (6 Regeln + incomplete)│       (+ severity)
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Persistence + Export   │
                      │  (SQLite, CSV, JSON,    │
                      │   HTML; CLI/GUI-Anzeige)│
                      └─────────────────────────┘
```

Jede Stufe konsumiert das Ergebnis der vorigen — keine Stufe greift
„rückwärts" auf eine spätere zu. Das macht die Pipeline testbar (jede
Stufe einzeln) und parallelisierbar (eine `EffectivePermission` pro
Pfad ist unabhängig von der nächsten).

---

## 5. Identitätsauflösung — die Principal-Pipeline

**Quelle:** [`crates/ad_resolver/src/principal.rs`](../crates/ad_resolver/src/principal.rs).
**Architektur-Begründung:** [ADR 0036](adr/0036-unified-principal-resolution-pipeline.md).

Die Principal-Pipeline ist der **einzige Eintrittspunkt** für jede
Identitätsauflösung in Stars. Sie ersetzt fünf frühere
Sonderpfade durch eine gemeinsame Logik.

### 5.1 Eingaben

```rust
enum PrincipalInput {
    Auto(String),             // Klassifikation per Syntax
    DomainQualified(String),  // "DOMAIN\\user"
    Upn(String),              // "user@domain.tld"
    SamAccount(String),       // "user"
    Sid(Sid),
    DisplayName(String),      // GUI-Identitäts-Picker
}
```

`PrincipalInput::Auto(...).classify()` trimmt und dispatcht nach
Syntax — `\` → DomainQualified, `@` → Upn, `S-1-…` → Sid, sonst SAM.

### 5.2 Backend-Traits

Der Resolver konsumiert zwei abstrakte Backends:

```rust
#[async_trait]
trait IdentityBackend: Send + Sync {
    async fn lookup_identity_by_sid(&self, sid: &Sid)
        -> Result<Option<Identity>, CoreError>;
    async fn lookup_identity_by_upn(&self, upn: &str)
        -> Result<Option<(Sid, Identity)>, CoreError>;
    async fn lookup_identities_by_sam(&self, sam: &str)
        -> Result<Vec<(Sid, Identity)>, CoreError>;
    async fn resolve_memberships(&self, sid: &Sid)
        -> Result<Vec<GroupMembership>, CoreError>;
}

trait LsaBackend: Send + Sync {
    fn lookup_sid_for_name(&self, name: &str) -> Result<Sid, CoreError>;
    fn lookup_account_for_sid(&self, sid: &Sid) -> Result<LsaAccountInfo, CoreError>;
}
```

**Produktion:** `LdapIdentityBackend` (delegiert an `LdapResolver`) +
`WindowsLsaBackend` (Windows) bzw. `NoLsaBackend` (Non-Windows).

**Tests:** `FakeLdapBackend` + `FakeLsaBackend` mit HashMap-Backing
— erlauben strukturelle Tests aller Eingabe/Ausgabe-Kombinationen
ohne echten DC.

### 5.3 Resolution-Status

```rust
enum IdentityScopeStatus {
    InsideConfiguredLdapBase,           // LDAP-Hit
    OutsideConfiguredLdapBase,          // LDAP-Miss + LSA-Hit (Trust)
    OrphanedSid,                        // LDAP-Miss + LSA-Miss
    LookupFailed { reason: String },    // LDAP-Connection-Fehler
}

enum GroupResolutionStatus {
    LdapRecursive,                      // LDAP_MATCHING_RULE_IN_CHAIN
    SamFlat,                            // NetUserGetGroups (DC-Mode)
    Failed { reason: String },
    NotAttempted,
}

enum DisabledStatus {
    Known(bool),                        // userAccountControl gelesen
    Unknown,                            // SAM-Pfad ohne NetUserGetInfo
}
```

### 5.4 Die Routing-Tabelle

| Eingabe | Pfad |
| --- | --- |
| `DomainQualified` / `DisplayName` | LSA → SID → `resolve_by_sid(sid)` |
| `Sid` | LDAP-by-SID → falls Miss + LSA verfügbar: LSA-Crosscheck → Outside-Identity bauen |
| `Upn` | LDAP-by-UPN → falls Miss: **expliziter Fehler mit GC-Hinweis** (kein stiller Fallback!) |
| `SamAccount` | LDAP-by-SAM → Eindeutigkeitsprüfung (>1 Treffer = Fehler) |

Das `Sid`-Routing ist der zentrale Knoten — alle Eingangsformen
führen am Ende dorthin und teilen sich denselben LDAP-/LSA-Crosscheck.

### 5.5 Engine-Flags-Ableitung

```rust
impl PrincipalResolution {
    fn engine_flags(&self) -> EngineFlags {
        EngineFlags {
            identity_not_in_configured_ldap_base:
                matches!(self.scope_status, OutsideConfiguredLdapBase),
            identity_disabled_status_unknown:
                matches!(self.disabled_status, DisabledStatus::Unknown),
            group_resolution_via_sam_fallback:
                matches!(self.group_resolution_status, SamFlat),
            identity_lookup_failure_reason:
                match &self.scope_status {
                    LookupFailed { reason } => Some(reason.clone()),
                    _ => None,
                },
            group_resolution_failure_reason:
                match &self.group_resolution_status {
                    Failed { reason } => Some(reason.clone()),
                    NotAttempted if Outside-Pfad => Some("group resolution skipped..."),
                    _ => None,
                },
        }
    }
}
```

`engine_flags()` ist die **einzige offizielle Quelle** für die fünf
Flags, die in `PermissionEvaluationInput` fließen. Aufrufer (CLI +
GUI) leiten ihre `PermissionEvaluationInput` direkt aus dem Ergebnis
dieser Methode ab — sie kommen nicht auf die Idee, die Flags aus den
Status-Feldern selbst zu rekonstruieren.

### 5.6 Cache-Verhalten

`LdapResolver::resolve_identity_internal` cached LDAP-Treffer, **cached
aber explizit keine `Orphaned`-Identities**
(`crates/ad_resolver/src/resolver.rs` — Fix aus
[ADR 0036](adr/0036-unified-principal-resolution-pipeline.md)).
Sonst hätte ein erster LDAP-Miss eine spätere LSA-Reklassifikation
unmöglich gemacht.

### 5.7 Identitäts-Vorschlagsliste in der GUI — bewusst kein LDAP-Live-Lookup

Die Vorschlagsliste unter dem GUI-Feld „Benutzer/Gruppe" füllt der
Worker über die Funktion
[`collect_identity_suggestions`](../crates/gui/src/worker.rs).
Diese Funktion enumeriert **ausschließlich lokale Identitäten**:

- lokale Benutzer und lokale Gruppen via LSA (`LsaEnumerateAccountsWithUserRight`,
  `NetUserEnum`, `NetLocalGroupEnum`)
- statisch bekannte Well-Knowns (Builtin-Container)

**Domain-Konten und Domain-Gruppen werden bewusst nicht** während
des Tippens aus LDAP gesucht. Der `[L]`-Tag links neben jeder Zeile
in der GUI markiert die Liste konsequent als *Local*.

**Begründung der Entwurfsentscheidung:**

1. **Latenz pro Tastenanschlag.** Ein LDAP-Search-Roundtrip kostet je
   nach DC, Netzwerk und Filter-Selektivität typisch 20–200 ms. In
   einem Suggester, der nach jedem Tastenanschlag triggert, wird
   das schnell zur spürbaren Eingabe-Verzögerung — besonders, wenn
   während eines parallelen Scans LDAP ohnehin belastet ist.
2. **DC-Last bei Massen-Eingabe.** In einem Forest mit 100 000
   Identitäten erzeugt jeder unvollständige Suchbegriff (`m`, `ma`,
   `mar`, …) eine eigene LDAP-`(objectClass=user)`-Substring-Suche.
   Das ist eine N+1-Multiplikation pro Tastenanschlag und steht im
   direkten Widerspruch zu ADR 0036, das LDAP-Suchen pro Identität auf
   einmal pro Lauf begrenzt.
3. **Stars ist read-only und audit-fokussiert, nicht
   Identity-Picker-fokussiert.** Der Hauptanwendungsfall ist
   „Auditor weiß die Zielidentität bereits" — entweder als
   `DOMAIN\name`, UPN oder SID. Eine LDAP-getriebene Auto-Suggestion
   ist Komfort, kein Audit-Wert.
4. **Trennung Suggestion ↔ Resolution.** Der GUI-Workflow ist bewusst
   zweistufig: tippen (lokale Suggester-Liste, billig), dann
   `Resolve SID` klicken (einmaliger LDAP-Lookup, teuer, aber
   bewusst angefordert). Die Trennung macht den teuren Pfad sichtbar.

**Workaround für den Anwender** (siehe auch
[`anwender-handbuch.md`](anwender-handbuch.md#vorschlagsliste-im-gui-identitätspicker--was-zeigt-sie-was-nicht)):

| Eingabeform | Verhalten |
|---|---|
| `DOMAIN\user`, UPN, SID | Direkt eintippen → `Resolve SID`-Button → einmaliger LDAP-Lookup |
| Reiner `sAMAccountName` | Funktioniert ebenfalls, sofern AD-Server konfiguriert |

**Folgekonsequenz für die Doku.** Die User-Doku
([`anwender-handbuch.md`](anwender-handbuch.md) /
[`user-guide.md`](user-guide.md)) erklärt diesen Effekt für
Endanwender. Wer als Entwickler den GUI-Worker erweitert, sollte ein
neues Feature wie „LDAP-Suchen on demand" als **eigenen Button mit
Spinner** umsetzen, nicht als Keystroke-Trigger.

---

## 6. Permission-Engine — die AccessCheck-Nachbildung

**Quelle:** [`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs).

Die Permission-Engine bildet die Windows-`AccessCheck`-Logik nach, mit
der Stars-spezifischen Erweiterung von strukturierten Diagnose-Markern.

### 6.1 Eingabe

```rust
struct PermissionEvaluationInput {
    identity: Identity,
    group_memberships: Vec<GroupMembership>,
    file_system_object: FileSystemObject,
    share_status: ShareMaskStatus,
    local_group_sids: Vec<Sid>,
    local_group_status: LocalGroupEvalStatus,
    access_context: AccessContext,        // RemoteSmb / LocalInteractive / Unspecified
    unsupported_share_ace_count: usize,
    sid_names: BTreeMap<String, String>,  // SID → Display-Name für Erklärungspfad
    group_resolution_via_sam_fallback: bool,
    identity_not_in_configured_ldap_base: bool,
    identity_disabled_status_unknown: bool,
    identity_lookup_failure_reason: Option<String>,
    group_resolution_failure_reason: Option<String>,
}
```

Beachte: das Eingabemodell **konsumiert** den FSO, weil die Engine
ihn nicht nach der Auswertung mehr braucht — der Bericht hängt am
Ergebnis.

### 6.2 Schritt 1: Token-SID-Satz aufbauen

`build_token_sids_with_context(sid, memberships, local_group_sids, access_context)`
baut die Liste der SIDs, die Windows beim Login in den Access Token
schreiben würde:

1. Die User-SID selbst.
2. Alle Domain-Gruppen-SIDs aus `memberships`.
3. Alle lokalen Server-Gruppen-SIDs aus `local_group_sids`.
4. Universal-Well-Knowns: `Everyone` (S-1-1-0),
   `Authenticated Users` (S-1-5-11).
5. **Kontextspezifische Well-Knowns** aus `access_context`:
   - `RemoteSmb` → `NETWORK` (S-1-5-2).
   - `LocalInteractive` → `INTERACTIVE` (S-1-5-4), `LOCAL` (S-1-2-0).
   - `Unspecified` → keine zusätzlichen.

Dieser Unterschied ist entscheidend: eine ACE auf `NETWORK` matcht nur
bei SMB-Auswertung, nicht bei lokaler. Stars muss den Kontext kennen,
um korrekt zu sein.

### 6.3 Schritt 2: DACL durchwalken (Allow vor Deny)

Windows wertet DACLs in **gespeicherter Reihenfolge** aus — nicht in
einer kanonisierten. Stars tut dasselbe:

```rust
let mut allow_mask = 0u32;
let mut deny_mask = 0u32;

for ace in dacl_iter {
    if !token_sids.contains(&ace.sid) { continue; }
    if !ace_applies_to_this_object(ace, is_dir) { continue; }
    match ace.kind {
        Allow => allow_mask |= ace.mask & !deny_mask,  // schon-denied bleibt denied
        Deny  => deny_mask  |= ace.mask & !allow_mask, // schon-allowed bleibt allowed
    }
}
let effective = allow_mask & !deny_mask;
```

Wichtig: `Allow & !deny_mask` und `Deny & !allow_mask` implementieren
die Windows-Regel **„first match wins per bit"**. Wenn die DACL ein
explizites Allow vor einem geerbten Deny enthält, gewinnt das Allow
für die spezifischen Bits — Stars produziert dasselbe Ergebnis wie
AccessCheck.

`ace_applies_to_this_object()` prüft die Inheritance- und Propagation-
Flags:
- `OBJECT_INHERIT_ACE` (0x1) auf Files, `CONTAINER_INHERIT_ACE` (0x2)
  auf Dirs.
- `INHERIT_ONLY_ACE` (0x8) — gilt nicht für das aktuelle Objekt,
  nur für Kinder.
- `NO_PROPAGATE_INHERIT_ACE` (0x4) — stoppt weitere Vererbung
  (Stars merkt das in der Erklärung, nicht für die aktuelle Maske).

### 6.4 Schritt 3: Non-canonical-DACL-Erkennung

`first_non_canonical_position(dacl)` prüft, ob die ACE-Reihenfolge
der Windows-Canonical-Order entspricht (Deny-explicit, Allow-explicit,
Deny-inherited, Allow-inherited). Bei Abweichung wird
`PermissionDiagnostic::NonCanonicalDaclOrder { at_index }` gepusht.

Das ist nicht `incomplete = true` — die Berechnung stimmt mit Windows
überein, aber der Auditor sollte wissen, dass die ACL „ungewöhnlich"
sortiert ist (häufig Sign eines manuellen Eingriffs).

### 6.5 Schritt 4: Owner-Rechte

Wenn `identity.sid == owner_sid`, addiert die Engine implizit
`READ_CONTROL` und `WRITE_DAC` zum effektiven Recht — Owner haben in
Windows immer das Recht, die DACL zu sehen und zu ändern, unabhängig
von der DACL selbst.

### 6.6 Schritt 5: Share-Maske intersect

Wenn `share_status = Applied(share_mask)`, ist das effektive Recht
**die restriktivere** der beiden Masken (`effective & share_mask`).
Bei `Unrestricted` (NULL share DACL) wird die Share-Seite ignoriert
(= Vollzugriff per Share). Bei `ReadFailed` bleibt die NTFS-Maske
unverändert und der `incomplete`-Marker greift.

### 6.7 Schritt 6: Marker pushen

```rust
if input.unsupported_share_ace_count > 0 {
    diagnostics.push(UnsupportedShareAces { count: ... });
}
if input.group_resolution_via_sam_fallback {
    diagnostics.push(DomainGroupRecursionIncomplete);
}
if input.identity.disabled {
    diagnostics.push(IdentityDisabled);
}
if input.identity_not_in_configured_ldap_base {
    diagnostics.push(IdentityNotInConfiguredLdapBase);
}
if input.identity_disabled_status_unknown {
    diagnostics.push(IdentityDisabledStatusUnknown);
}
if let Some(reason) = input.identity_lookup_failure_reason {
    diagnostics.push(IdentityLookupFailed { reason });
}
if let Some(reason) = input.group_resolution_failure_reason {
    diagnostics.push(GroupResolutionFailed { reason });
}
```

Plus der Non-canonical-Marker aus Schritt 4. Jeder Marker, der
`incomplete`-Trigger ist, wird von der Risk-Engine später matched
(siehe Kapitel 10).

### 6.8 Schritt 7: Erklärungspfad bauen

`PermissionPath::steps` wird parallel zur Maskenberechnung gefüllt:

```text
- User S-1-5-21-...-1001 (CORP\alice)
- Member of S-1-5-21-...-1100 (CORP\Domain Users) [direct, source: LDAP_MATCHING_RULE_IN_CHAIN]
- Member of S-1-5-32-545 (BUILTIN\Users) [via local server group chain]
- Allow ACE for S-1-5-32-545 → Read,Execute (inherited from C:\)
- Effective: Read,Execute (0x001200A9)
```

`sid_names` wird vorab aus den Membership-Namen und den DACL-Trustee-
SIDs zusammengebaut — eine LSA-Anfrage pro unique SID, dedupliziert
über den ganzen Scan.

---

## 7. Share-DACL ∩ NTFS-DACL

**Quelle:** [`crates/share_scanner/src/scanner.rs`](../crates/share_scanner/src/scanner.rs)
und [`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs).

SMB-Zugriff ist **restriktiv**: ein User darf nur, was **beide** —
Share-DACL und NTFS-DACL — gleichzeitig erlauben. Stars baut diese
Schnittmenge in drei Schritten:

### 7.1 Share-DACL lesen

`share_scanner::get_share_dacl(server, share_name)`:

1. Verbindet sich zum `server` (`NetShareGetInfo` Level 502).
2. Liest den Security-Descriptor der Freigabe.
3. Parsiert die DACL in `ShareDacl::Acl(Vec<SharePermission>)` oder
   `ShareDacl::NullDacl`.
4. Zählt nicht-unterstützte ACE-Typen (`unsupported_count`).

Rückgabe: `ShareDaclScan { dacl, unsupported_count }`.

### 7.2 Share-Maske berechnen

`effective_share_mask(share_dacl, token_sids)`:

- Bei `NullDacl`: `None` (= Vollzugriff per Share, signalisiert über
  `ShareMaskStatus::Unrestricted`).
- Bei `Acl`: dieselbe Allow/Deny-Logik wie für NTFS, aber mit den
  Token-SIDs des Users.

### 7.3 ShareMaskStatus weitergeben

Die Maske wird als `ShareMaskStatus` an die Engine übergeben:

```rust
enum ShareMaskStatus {
    NotApplicable,         // lokaler Pfad, kein UNC, kein --smb-server
    Applied(AccessMask),   // erfolgreich gelesen + berechnet
    Unrestricted,          // NULL DACL — Share gewährt alles
    ReadFailed(String),    // get_share_dacl scheiterte → incomplete trigger
}
```

Die Engine setzt das effektive Recht entsprechend:
- `NotApplicable` → `share_mask = None`, kein Intersect.
- `Applied(m)` → `effective = ntfs & m`.
- `Unrestricted` → `effective = ntfs` (Share ist breiter als NTFS).
- `ReadFailed` → `effective = ntfs`, plus `incomplete`-Marker; der
  echte Wert könnte restriktiver sein, aber Stars kann es nicht
  wissen.

### 7.4 Share-Trustees im Bericht

Für die „Wer hat Zugriff?"-Trustee-Ansicht baut der GUI-Worker
**vor dem Scan** einmalig pro Share das `ShareTrusteeOverlay`
([ADR 0038](adr/0038-share-trustees-in-scan-output.md)):

```rust
struct ShareTrusteeOverlay {
    trustees: Vec<PathTrustee>,  // alle TrusteeCategory::Share
}

// Pro Pfad:
let raw_trustees = build_path_trustees_with_share(&fso, share_overlay.as_ref());
```

Damit hat jeder Pfad die NTFS-Trustees aus seiner DACL **plus** die
Share-Trustees aus der Share-DACL der Freigabe, getrennt über die
`TrusteeCategory::{Ntfs, Share}`-Spalte.

---

## 8. Lokale Server-Gruppen und die Kandidatenliste

**Quelle:** [`crates/ad_resolver/src/local_groups.rs`](../crates/ad_resolver/src/local_groups.rs).
**Architektur-Begründung:** [ADR 0040](adr/0040-local-group-candidate-name-list.md).

Lokale Server-Gruppen (`BUILTIN\Administrators`, lokale benutzer-
definierte Gruppen) sind essentiell für korrekte Token-Bildung — und
historisch eine der häufigsten stillen Lücken in Permission-Tools.

### 8.1 Das Problem

`NetUserGetLocalGroups` erwartet einen Account-Namen. Welche Form
ist die richtige?

- Für domain-joined User mit UPN: `user@dns.suffix` funktioniert.
- Für NetBIOS-Domain-Trust-Identities: `user@TRUSTED` schlägt fehl
  (kein gültiger UPN-Suffix). `TRUSTED\user` funktioniert.
- Für lokale Konten: `user` allein.

Bis v1.5.2 baute Stars blind `name@domain` — bei NetBIOS-Domains aus
dem LSA-/Trust-Pfad führte das regelmäßig zu `NERR_USER_NOT_FOUND`,
das **stillschweigend** als `Ok(Vec::new())` interpretiert wurde.
Ergebnis: ACEs auf lokale Server-Gruppen unsichtbar, kein
`incomplete`-Marker.

### 8.2 Die Kandidatenliste

`format_account_candidates_for_local_groups(identity)` liefert eine
Liste in Präferenzreihenfolge:

```rust
1. identity.user_principal_name              // echter UPN (wenn AD ihn hat)
2. format!("{domain}\\{name}")                // funktioniert für alle Domain-Typen
3. format!("{name}@{domain}")                 // NUR wenn looks_like_dns_domain(domain)
4. name                                       // lokale Konten
```

`looks_like_dns_domain(domain)` ist die Heuristik:

```rust
fn looks_like_dns_domain(domain: &str) -> bool {
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}
```

Ein NetBIOS-Name wie `TRUSTED` enthält keinen Punkt → die UPN-Form
wird **nicht** in die Liste aufgenommen → kein irreführender
`alice@TRUSTED`-Versuch.

### 8.3 Strict-Variante + Outcome-Typ

```rust
enum LocalGroupLookupOutcome {
    WithGroups(Vec<Sid>),     // Account gefunden, hier sind die Gruppen
    UserNotFoundOnServer,     // NERR_USER_NOT_FOUND
}

fn resolve_local_group_sids_strict(server, account)
    -> Result<LocalGroupLookupOutcome, CoreError>
```

Diese Trennung ist die Voraussetzung für den Kandidaten-Loop: nur so
kann der Aufrufer „Account gefunden mit 0 Gruppen" (= valides
Ergebnis) von „Account nicht erkannt" (= nächsten Kandidaten
probieren) unterscheiden.

### 8.4 Der Identity-Wrapper

`resolve_local_group_sids_for_identity(server, identity)` ist die
**ehrliche** Funktion, die CLI und GUI aufrufen:

```rust
for candidate in candidates {
    match resolve_local_group_sids_strict(server, &candidate)? {
        WithGroups(sids) => return Ok(sids),       // erster Treffer
        UserNotFoundOnServer => continue,          // nächster
    }
}
// Wenn ALLE NotFound:
Err(CoreError::Validation(format!(
    "NetUserGetLocalGroups: account for identity {} not known on {server:?} \
     (tried forms: {:?}). Local server group memberships are not available; \
     the result is marked incomplete.",
    identity.sid.0, tried
)))
```

Aufrufer setzen das `Err` als
`LocalGroupEvalStatus::NotAvailable(reason)` → Risk-Engine markiert
`incomplete = true`. **Keine stillen Skips.**

### 8.5 Backward Compatibility

Die alte API `resolve_local_group_sids()` bleibt erhalten — sie
behandelt `NERR_USER_NOT_FOUND` weiterhin als `Ok(Vec::new())`, aber
das wird nur noch von externen Konsumenten genutzt. Intern gehen
alle Aufrufer durch den Identity-Wrapper.

---

## 9. Das Diagnose-Marker-System

**Quelle:** [`crates/core/src/model.rs`](../crates/core/src/model.rs)
(Enum) +
[`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs)
(Push) +
[`crates/risk_engine/src/rules.rs`](../crates/risk_engine/src/rules.rs)
(Matching).

Das Marker-System ist die zentrale Architektur, die Stars überhaupt
auditierbar macht. Es funktioniert in drei Schichten:

### 9.1 Datenebene — variant-tagged Enum

```rust
#[serde(tag = "kind")]
enum PermissionDiagnostic {
    NonCanonicalDaclOrder { at_index: usize },
    UnsupportedShareAces { count: usize },
    DomainGroupRecursionIncomplete,
    IdentityDisabled,
    IdentityNotInConfiguredLdapBase,
    IdentityDisabledStatusUnknown,
    IdentityLookupFailed { reason: String },
    GroupResolutionFailed { reason: String },
}
```

Das `tag = "kind"`-Attribut serdialisiert als:

```json
{ "kind": "IdentityLookupFailed", "reason": "LDAP bind failed: connection refused" }
```

Neue Varianten können hinzugefügt werden, ohne JSON-Konsumenten zu
brechen — sie sehen einfach ein neues `kind` und können es ignorieren
oder behandeln.

### 9.2 Engine-Schicht — Push aus Flags

`PermissionEvaluationInput` enthält **die Flags**, die `engine_flags()`
aus dem `PrincipalResolution`-Status abgeleitet hat. Die Engine pusht
pro Flag den passenden Marker (siehe Kapitel 6.7).

Hier ist die Strikt-Regel: **kein Marker entsteht im Engine-Code
ohne entsprechende Eingabe.** Wenn ein Marker fehlt, muss man nicht
die Engine debuggen, sondern den Aufrufer (CLI/GUI), der die Flags
nicht korrekt aus `engine_flags()` übernommen hat.

### 9.3 Risk-Schicht — Incomplete-Klassifikation

`risk_engine::is_incomplete(p: &EffectivePermission)` ist die
**authoritative Quelle** dafür, ob ein Befund als `incomplete = true`
markiert wird:

```rust
fn is_incomplete(p: &EffectivePermission) -> bool {
    matches!(p.share_status, ShareEvalStatus::ReadFailed(_))
        || p.unsupported_ace_count > 0
        || matches!(p.local_group_status, LocalGroupEvalStatus::NotAvailable(_))
        || p.diagnostics.iter().any(|d| matches!(d,
            PermissionDiagnostic::UnsupportedShareAces { .. }
            | PermissionDiagnostic::DomainGroupRecursionIncomplete
            | PermissionDiagnostic::IdentityNotInConfiguredLdapBase
            | PermissionDiagnostic::IdentityLookupFailed { .. }
            | PermissionDiagnostic::GroupResolutionFailed { .. }
        ))
}
```

Bewusst **nicht** matched:

- `IdentityDisabled` — die ACL-Auswertung ist vollständig; nur die
  Authentifizierungsfähigkeit ist eingeschränkt. Das ist eine
  **informationelle** Aussage, kein Vollständigkeitsmangel.
- `IdentityDisabledStatusUnknown` — orthogonal zur Permission-
  Berechnung.
- `NonCanonicalDaclOrder` — Windows AccessCheck arbeitet korrekt
  auf der gespeicherten Reihenfolge; Stars reproduziert das exakt.

Diese Trennung ist die produktive Substanz des Marker-Systems —
ein Auditor unterscheidet, was Stars *nicht wusste* (= bitte
nachsehen) von was Stars *gewusst und gemeldet* hat (= Stars-Befund
ist final).

### 9.4 Renderer-Schicht

CLI (`crates/cli/src/output.rs`), HTML
(`crates/exporter/src/html.rs`) und JSON
(`crates/exporter/src/json.rs`) rendern jeden Marker mit eigener
Beschreibung. Bei Markern mit `reason`-Feld wird der Text mit
gerendert (HTML-escaped im HTML-Pfad).

### 9.5 Konsistenz-Pflicht

Wenn `PermissionDiagnostic` um eine Variante erweitert wird, müssen
**gleichzeitig** angepasst werden:

- `risk_engine::is_incomplete()` (wenn incomplete-Trigger).
- Renderer in `cli::output`, `exporter::html`, `exporter::json`.
- Marker-Tabelle in `docs/features-and-limitations.md`.
- Marker-Tabelle in `docs/anwender-handbuch.md` und
  `docs/user-guide.md`.
- `docs/audit-kriterien.md` (DE + EN incomplete-Sektion).

Diese Liste steht als Beitragspolitik in
`docs/audit-kriterien.md` und in jedem ADR, der einen neuen Marker
einführt.

---

## 10. Risk-Engine — von der Permission zum Audit-Befund

**Quelle:** [`crates/risk_engine/src/rules.rs`](../crates/risk_engine/src/rules.rs).
**Fachliche Begründung:** [`docs/audit-kriterien.md`](audit-kriterien.md).

Die Risk-Engine konsumiert `Vec<EffectivePermission>` und produziert
`Vec<RiskFinding>`.

### 10.1 Architektur

```rust
trait RiskRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding>;
}

struct RuleRegistry {
    rules: Vec<Box<dyn RiskRule>>,
}

impl RuleRegistry {
    fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Box::new(FullControlRule));
        r.register(Box::new(WriteAccessRule));
        r.register(Box::new(AdminRightsRule));
        r.register(Box::new(BroadGroupWriteRule));
        r.register(Box::new(DirectUserAceRule));
        r.register(Box::new(SensitivePathRule));
        r
    }
}
```

Eine Rule liest `context.findings`, filtert nach ihrem Kriterium und
produziert pro Treffer ein `RiskFinding`:

```rust
struct RiskFinding {
    severity: RiskSeverity,    // Critical | High | Medium | Low | Info
    rule_id: String,           // "FULL_CONTROL", "BROAD_GROUP_WRITE", …
    identity: Identity,
    path: NormalizedPath,
    rights: AccessMask,
    explanation: String,
    incomplete: bool,          // aus is_incomplete(p)
}
```

### 10.2 Die sechs Regeln

| Regel | Severity | Trigger |
| --- | --- | --- |
| `FullControlRule` | Critical | Effektive Maske enthält `MASK_FULL_CONTROL`-Bits |
| `WriteAccessRule` | High | Effektive Maske hat Write-spezifische Bits (`MASK_WRITE & !MASK_READ`) |
| `AdminRightsRule` | High | `FILE_WRITE_DAC`, `FILE_WRITE_OWNER` einzeln vorhanden |
| `BroadGroupWriteRule` | Critical | Write-Recht über `Everyone`, `Authenticated Users`, `Anonymous Logon` |
| `DirectUserAceRule` | Low | ACE direkt auf User-SID (nicht über Gruppe) |
| `SensitivePathRule` | Critical/High/Medium | Pfad enthält sensitive Schlüsselwörter (`password`, `credentials`, …) |

`SensitivePathRule` ist die einzige, die ihre Severity *dynamisch*
aus dem effektiven Recht ableitet — Full Control auf eine
`passwords.txt` ist Critical, Read auf das gleiche File ist Medium.

### 10.3 `incomplete = true`

Jede Rule ruft `is_incomplete(&p)` und schreibt das Ergebnis ins
`RiskFinding`. CLI, HTML und JSON sortieren und rendern Findings
unterschiedlich, wenn `incomplete` gesetzt ist — typischerweise mit
einem zusätzlichen Hinweis am Befund.

### 10.4 Audit-Kriterien

Das Dokument [`docs/audit-kriterien.md`](audit-kriterien.md) hält die
fachliche Logik fest:
- Wer welche Rechte auf welchem Pfad-Typ haben *darf*.
- Wer welche Rechte auf welchem Pfad-Typ *nicht* haben sollte.
- Wie Severities zustande kommen.

Die Risk-Regeln implementieren das, was dort steht — bei
Inkonsistenz zwischen Dokument und Code gewinnt das Dokument
(es ist die fachliche Spezifikation).

---

## 11. Threading-Modell — GUI/CLI/Engine

### 11.1 CLI

Die CLI nutzt `tokio` als Runtime:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> { ... }
```

Der **Walker** (`fs_scanner::walk_tree`) ist blockierend (Windows-
APIs sind sync), läuft deshalb auf einem `tokio::task::spawn_blocking`-
Thread. Ein `tokio::spawn` fängt `Ctrl-C` ab und setzt einen
`CancellationToken`, den der Walker periodisch prüft.

LDAP-Aufrufe (`ldap3`) sind echt async — sie laufen direkt im Main-
Tokio-Pool.

### 11.2 GUI

Die GUI nutzt **Slint** für die Oberfläche und **`std::sync::mpsc`-
Channels** für die Worker-Kommunikation:

```rust
// GUI-Thread (Slint event loop):
let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<WorkerCommand>();
let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WorkerEvent>();

// Worker-Thread:
std::thread::spawn(move || {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        loop {
            match cmd_rx.recv() {
                Ok(WorkerCommand::Analyze { ... }) => { ... }
                Ok(WorkerCommand::Scan { ... }) => { ... }
                ...
            }
        }
    });
});
```

Die GUI **blockiert nie** auf einem laufenden Scan — sie empfängt
`WorkerEvent::ScanItem`-Events vom Worker und aktualisiert die
Slint-Modelle.

`CancellationToken` aus `fs_scanner` wird in den Worker geteilt und
über einen `WorkerCommand::Cancel` ausgelöst.

### 11.3 Engine

Die Engine selbst ist **sync und einzelthreaded** pro Aufruf — eine
`EffectivePermission` pro Pfad. Parallelisierung passiert auf der
Ebene des Aufrufers: jeder Pfad ist unabhängig, der Walker könnte
sie theoretisch parallel an die Engine geben (tut er aktuell nicht,
weil der LSA-Lookup für `sid_names` global gecacht wird).

---

## 12. Persistenz und Export

### 12.1 SQLite-Scan-Historie

**Quelle:** [`crates/persistence/src/scan_store.rs`](../crates/persistence/src/scan_store.rs)
und [`crates/persistence/src/migrations.rs`](../crates/persistence/src/migrations.rs).

Schema (vereinfacht):

```sql
CREATE TABLE scan_runs (
    run_id TEXT PRIMARY KEY,         -- UUID
    timestamp TEXT NOT NULL,
    root_path TEXT NOT NULL,
    cancelled INTEGER NOT NULL
);

CREATE TABLE scan_permissions (
    run_id TEXT NOT NULL,
    path TEXT NOT NULL,
    identity_sid TEXT NOT NULL,
    effective_mask INTEGER NOT NULL,
    ntfs_mask INTEGER NOT NULL,
    share_mask INTEGER,
    diagnostics_json TEXT NOT NULL,  -- variant-tagged JSON
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE scan_errors (
    run_id TEXT NOT NULL,
    path TEXT,
    message TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);
```

Migrationen sind versioniert und transaktional. Bei jedem Start
prüft `Database::open` die Schema-Version und führt die nötigen
Migrations-Schritte aus.

### 12.2 Delta-Vergleich

`ScanStore::compute_delta(run_a, run_b)` joint zwei Läufe per Pfad
und liefert pro Pfad die effektiven Masken vorher/nachher. Die GUI
filtert clientseitig Pfade ohne Änderung heraus.

### 12.3 Export-Formate

**CSV** (`crates/exporter/src/csv.rs`):
- Pfad pro Zeile.
- Diagnose-Marker als Komma-separierte Variantennamen
  (`"IdentityDisabled,IdentityLookupFailed"`).
- Geeignet für Excel/Pivot.

**JSON** (`crates/exporter/src/json.rs`):
- Vollständiges variant-tagged Output.
- `reason`-Texte erhalten.
- Geeignet für SIEM, Skripts, Custom-Tooling.

**HTML** (`crates/exporter/src/html.rs`):
- Vollformatierter Bericht mit Tabs:
  - Risk Findings (sortiert nach Severity).
  - Trustee-Tabelle pro Pfad (NTFS + Share getrennt).
  - Scan-Fehler in eigener Sektion.
- Diagnose-Marker als farbige Badges (`badge-high`, `badge-medium`,
  `badge-info`) mit Tooltip-Text.

---

## 13. Validierung an Systemgrenzen

**Quelle:** [`crates/validation/`](../crates/validation/).

Jeder User-Input — CLI-Arg, GUI-Feld, Config-Datei-Wert — wird an
der Systemgrenze in einen typisierten Wrapper überführt:

```rust
struct ValidatedSid(pub String);              // matched S-1-...
struct ValidatedServerName(pub String);       // hostname check
struct ValidatedShareName(pub String);        // SMB-share-name check
struct ValidatedDn(pub String);               // LDAP DN check
struct ValidatedIdentityQuery(pub String);    // GUI-search-input
struct ValidatedExportPath(pub PathBuf);      // path safety
struct ValidatedDbPath(pub PathBuf);
struct ScanDepth(pub u32);
```

Alle `validate_*`-Funktionen **trimmen Whitespace** und prüfen das
Format. Die Wrapper-Typen werden dann an LDAP/NetAPI/SQLite/Datei-
APIs weitergereicht — **nie die Roh-Strings**.

### 13.1 Die Paar-Pflicht

`gui::worker::normalize_smb_pair(smb_server, share_name)` und sein
CLI-Pendant erzwingen, dass die zwei SMB-Felder **als Paar** gesetzt
sind. Einzelne Werte ergeben einen Validation-Fehler — nicht ein
stilles „nur eines verwenden" ([ADR-Vorgeschichte: ChatGPT-Review
Runde 2 Finding 2 und Runde 4 Finding 3](../review.md)).

### 13.2 Pfadnormalisierung

`validate_path(path)` liefert einen `NormalizedPath` mit:
- getrimmten Whitespace,
- kanonisierter Long-Path-Form (`\\?\C:\…`, `\\?\UNC\…`),
- ungültige Zeichen rejected.

Der `NormalizedPath` wird durch die ganze Pipeline geleitet — der
Walker, die Engine und die Persistierung sehen alle denselben Wert.
Stars hat lange unter dem Anti-Pattern „validieren, dann den Rohwert
weiterverwenden" gelitten — siehe ADR 0037 für die Konsolidierung.

---

## 14. Test-Architektur

### 14.1 Drei Test-Ebenen

1. **Unit-Tests** in jedem Modul (`#[cfg(test)] mod tests`).
   Decken die Engine-Logik, die Validierungen, das Marker-System ab.
   Laufen in `cargo test --workspace` — derzeit ~485 Tests, alle grün.

2. **Fake-basierte Integration** in
   [`crates/ad_resolver/src/principal.rs`](../crates/ad_resolver/src/principal.rs).
   `FakeLdapBackend` + `FakeLsaBackend` mit HashMap-Backing erlauben
   strukturelle Tests der Principal-Pipeline:
   - DOMAIN\user → LDAP-Hit
   - DOMAIN\user → LDAP-Miss + LSA-Hit (Multi-Domain)
   - Direkte SID → LDAP-Miss + LSA-Hit
   - GUI-Name → SID → LDAP-Miss + LSA-Hit
   - UPN → outside configured base
   - Unknown SID → LDAP-Miss + LSA-Miss
   - LDAP-Bind-Fehler → LookupFailed
   - Group-Resolution-Fehler nach Identity-Hit
   - Outside-Pfad + skipped Groups
   - Ambiguous SAM → Eindeutigkeits-Fehler

3. **Live-Integration** als `#[ignore]`-Tests.
   Laufen mit `cargo test -- --ignored` auf einer realen
   Windows-/AD-Umgebung. Decken `NetUserGetLocalGroups`,
   `NetLocalGroupGetMembers` und echte LDAP-Bindings ab.

### 14.2 Engine-Test-Pattern

Engine-Tests konstruieren synthetische `FileSystemObject`s und
`PermissionEvaluationInput`s direkt:

```rust
#[test]
fn deny_before_allow_wins() {
    let fso = fso(None, vec![
        deny_ace(USER, MASK_WRITE, false),
        allow_ace(USER, MASK_READ | MASK_WRITE, false),
    ]);
    let result = DefaultPermissionEngine
        .evaluate(input_for(user(USER), fso))
        .unwrap();
    assert_eq!(result.effective_mask.0, MASK_READ);  // Write denied
}
```

Diese Tests decken die AccessCheck-Reproduktion ab — auch
non-canonical DACLs, NULL DACLs, Inherit-Only-ACEs,
Owner-Rechte-Implikation.

### 14.3 Marker-Konsistenz-Tests

Pro Engine-Marker existiert ein Test, der die `Some(reason)` /
`true`-Eingabe direkt setzt und prüft, dass der Marker im
Diagnostics-Vector landet. Pro Risk-Engine-Marker existiert ein
Test, der das `incomplete = true`-Verhalten asserted. Negative
Tests (informationelle Marker dürfen **nicht** als incomplete
gelten) sind explizit:

```rust
#[test]
fn full_control_does_not_mark_incomplete_on_disabled_status_unknown_alone() {
    let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
    p.diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
    let r = FullControlRule.evaluate(&ctx(vec![p]));
    assert!(!r[0].incomplete);
}
```

---

## 15. Update-Manager

**Quelle:** [`crates/update_manager/`](../crates/update_manager/).
**Architektur-Begründung:** ADR 0028, ADR 0030.

Der Update-Manager ist als **Skelett** vorhanden — die Pfad-
Validierung, das Signature-Schema und die Migration-Hooks sind
implementiert, die automatische Update-Logik selbst nicht.

Aktuell:
- Installer-Updates manuell durch den Anwender.
- SQLite-Schema-Migrationen werden bei `Database::open` automatisch
  ausgeführt — versioniert, transaktional, mit Rollback bei Fehler.
- Update-Pfade werden validiert (`validation::path::*`), damit ein
  Angreifer kein UNC-Path-Substitution machen kann.

Geplant für künftige Versionen:
- Signature-Verification an signierten Update-Paketen.
- Konfigurierbare Update-Quelle (lokale Datei, interne HTTPS-URL).
- Rollback-Mechanismus bei fehlgeschlagener Installation.

---

## 16. Weiterführende Dokumente

- **[Anwender-Handbuch](anwender-handbuch.md)** — GUI/CLI-Anleitung.
- **[Features und Grenzen](features-and-limitations.md)** —
  vollständige Liste, was Stars zuverlässig kann.
- **[Bekannte Grenzen und Roadmap](known-limitations.md)** —
  strukturelle Lücken, die Stars markiert aber nicht löst.
- **[Audit-Kriterien](audit-kriterien.md)** — fachliche
  Bewertungsregeln, Severities, optimale Rechte pro Rolle.
- **[ADRs](adr/)** — Architektur-Entscheidungen mit Begründung
  und Konsequenzen.
- **[review.md](../review.md)** (gitignored) — Aufzeichnung der
  ChatGPT-Code-Review-Runden 1–5 mit Status-Tabellen.

## English version

An English version of this technical documentation is available at
**[technical-documentation.md](technical-documentation.md)**.
