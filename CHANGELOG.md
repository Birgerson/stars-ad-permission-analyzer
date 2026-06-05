# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format orientiert sich an [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) und das Projekt folgt [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Stand vor `v0.2.0-rc1` wird zusammenfassend abgehandelt, weil dort noch keine echten Release Notes geführt wurden. Ab `v0.2.0-rc1` ist jede Version einzeln aufgeschlüsselt.

---

## [Unreleased]

---

## [1.5.7] — 2026-06-05

**Bugfix-/Verifikations-Release.** Zwei Themen:

1. **Deny-Aggregation explizit im Erklärungspfad** (ADR 0042). Wenn eine
   Deny-ACE im Spiel ist und Bits einer Allow-ACE blockiert, taucht jetzt
   ein eigener Pfad-Schritt auf, der genau das benennt:

   ```text
   Deny aggregation: Special (0x000301BF) blocked by Deny ACEs — those
   bits were removed from the effective NTFS mask
   NTFS effective: Special (0x00100000)
   ```

   Damit muss der Auditor nicht mehr aus der Differenz der Hex-Werte
   schließen, dass Deny Allow-Bits zermalmt hat. Ohne Deny ändert sich
   nichts — der Step erscheint nur bei real existierenden Deny-Effekten.

2. **Lab-Verifikations-Block A** durchgeführt und in
   [`docs/lab/verification.md`](docs/lab/verification.md) festgehalten.
   Stars wurde gegen drei weitere Edge-Cases gestellt:
   - E1: Deny Modify vs. inherited Allow Modify → korrekt
   - E2: Vererbung unterbrochen (`Protect`), nur Admins+SYSTEM → korrekt
   - E3: UNC-Pfad, Share=Read + NTFS=Modify → Result=Read (Share dominiert)

   Zusätzlich ein GUI-Boot-Smoke auf tier0 — `adpa-gui.exe` startet
   unter VirtIO-GPU + Slint-software-Backend ohne Crash, hält 15 s
   stabil, terminiert sauber.

### Engine

- `evaluate_dacl_ordered` gibt jetzt `(granted, denied)` zurück, sodass
  die Deny-Maske in den Erklärungspfad fließen kann.
- `build_explanation` rendert bei `denied != 0` einen
  `Deny aggregation`-Step vor dem `NTFS effective`-Step.
- Zwei neue Engine-Tests (`deny_aggregation_step_surfaces_blocked_bits`,
  `deny_aggregation_step_absent_when_no_deny`).

### Dokumentation

- ADR 0042 — Deny-Aggregation als eigener Erklärungspfad-Schritt.
- `docs/lab/verification.md` erweitert um Block A (E1–E3) und Block B
  (GUI-Boot-Smoke).
- `docs/lab/scripts/09-blockA-edge-cases.sh` und `10-blockB-gui-smoke.sh`
  als sanitisierte Reproduktionsskripte.

Installer-Versionshinweise in den User-Dokus auf `v1.5.7` aktualisiert.

---

## [1.5.6] — 2026-06-05

**Bugfix-Release.** Lokale Server-Gruppen erscheinen jetzt **vollständig
im Erklärungspfad**, nicht mehr nur als unsichtbarer Token-Eintrag.

Bisher konnte Stars zwar das richtige effektive Recht ausrechnen,
wenn die Berechtigung über eine lokale Server-Gruppe wie
`BUILTIN\Administrators` kam — die Erklärung blieb aber stumm. Der
Auditor sah „Modify" und einen ACE, aber keinen Mediator-Schritt,
der erklärt, *warum* der User Mitglied dieser lokalen Gruppe ist.

Mit v1.5.6 baut `ad_resolver` für jeden Account-Kandidaten echte
`GroupMembership`-Einträge mit `MembershipPathSource::LocalGroup`,
CLI und GUI mergen sie in die Gruppen-Liste, und die Engine rendert
daraus die Mediator-Kette samt `[via … → …, source: LocalGroup]`-Step.
Unvollständige Member-Lookups erscheinen als
`[exact chain unknown, source: LocalGroup]` statt stillschweigend zu
fehlen.

Außerdem: ein bewusst komplexes 3-Forest-Test-Lab (`docs/lab/`) ist
neu im Repo dokumentiert — inklusive Reproduktionsskripten und
Stars-Smoke-Test-Ergebnis, die das neue Verhalten live an einem
echten Cross-Forest-Setup beweisen (`tier0.lab ↔ tier1.lab ↔ tier2.lab`,
bidirektionale Forest-Trusts).

Installer-Versionshinweise in `README.md`, `docs/anwender-handbuch.md`,
`docs/user-guide.md`, `docs/technische-dokumentation.md`,
`docs/technical-documentation.md` und `docs/known-limitations.md` auf
`v1.5.6` aktualisiert (Review Runde 6 Finding 2).

### Engine

- Lokale Gruppen-SIDs fließen jetzt nicht mehr nur in das ACE-Match-Token,
  sondern auch in `group_memberships`. Die Erklärungspfad-Schritte für
  diese Mitgliedschaften tragen `source: LocalGroup` und — sofern
  bekannt — die vollständige Mediator-Kette.
- Bei `complete: false`-Member-Lookups erscheint der Step explizit als
  `[exact chain unknown, source: LocalGroup]`, damit die Lücke sichtbar
  bleibt.
- Zwei neue Engine-Tests (`local_group_membership_renders_in_explanation_path`,
  `local_group_membership_with_incomplete_path_renders_unknown_chain`)
  decken beide Pfade ab.

### Resolver

- Neue Funktion `ad_resolver::resolve_local_group_chains_for_identity`,
  die zusätzlich zur SID-Liste die Member-Chain als `Vec<GroupMembership>`
  liefert. Wiederverwendet `format_account_candidates_for_local_groups`
  aus ADR 0040.

### CLI / GUI

- `collect_local_group_sids_for_path` nimmt jetzt die AD-Memberships
  entgegen und gibt zusätzlich zur SID-Liste die LocalGroup-Memberships
  zurück. Beide Call-Sites (`analyze` und `scan`) mergen sie in den
  Engine-Input.

### Dokumentation

- ADR 0041 — Lokale-Gruppen-Mitgliedschaften im Erklärungspfad.
- `docs/lab/README.md`, `forest-topology.md`, `setup-procedure.md`,
  `verification.md` plus acht Bash-Skripte (`docs/lab/scripts/01..08`)
  für die Reproduktion.

---

## [1.5.5] — 2026-06-05

**Doku-Release.** Erweitert den Haftungs-Abschnitt um die explizite
**Backup-Pflicht vor jeder produktiven Nutzung**, auch wenn Stars
architektonisch ausschließlich lesend arbeitet. Plus die schon
vorhandene Prompt-Engineer-/KI-Implementations-Klarstellung wurde
zusätzlich oben im Disclaimer-Quote sichtbar gemacht.

Hintergrund: Auch read-only-Software kann durch Inkompatibilitäten,
Treiberbugs, Antivirus-Eingriffe, Sperrkonflikte oder unbedachte
Last auf Zielsystemen zu Betriebsstörungen führen. Eine getestete
Backup-Wiederherstellung schützt vor unerwarteten Nebeneffekten —
unabhängig von der Architekturzusicherung des Tools selbst.

Keine Funktions- oder Code-Änderungen am Audit-Tool. Setup.exe für
v1.5.5 wird vom CI-Workflow erstellt, damit Nutzer der Setup-Datei
denselben rechtlichen Stand erhalten wie der main-Branch.

### Hinzugefügt
- **Disclaimer-Sektion „Pflicht zur Datensicherung vor Nutzung"** (DE
  + EN) — vollständiger Unterabschnitt mit:
  - Klarstellung, dass Stars per Architektur read-only ist, aber
    Nebenwirkungen nicht ausgeschlossen sind,
  - Pflicht zu vollständigem, getestetem Backup aller betroffenen
    Systeme (DC, Fileserver, NTFS-Volumes, SMB-Shares) vor
    produktiver Nutzung,
  - explizite Haftungsausschluss-Klausel für fehlende oder
    untestete Backups,
  - drei verpflichtende Vorab-Verifikationen: isolierte Test-
    Restore, Pilot-Evaluation, Stakeholder-Information.
- **Top-Warnung** im einleitenden Haftungs-Quote (DE + EN, jeweils
  am Anfang des README): Backup-Pflicht ist sofort sichtbar, nicht
  erst am Ende des Dokuments.

---

## [1.5.4] — 2026-06-05

**Patch-Release.** Reine UI-Politur. Keine Funktionsänderungen am
Audit-Tool, keine neuen Findings, keine Modell-/Engine-/Risk-Änderungen
— alle 488 Tests grün, Architektur und Diagnostik bleiben identisch
zu v1.5.3.

### Hinzugefügt
- **Light/Dark-Theme-System mit Toggle** im HeaderBar (Sonne/Mond
  oben rechts). Zentrale `Theme`-Global-Komponente hält Farben,
  Spacings, Schriftgrößen und Radien — vorher verteilt auf
  Hardcoded-Hex-Werte (`#2c3e50`, `#555`, `#6c7a89`, `#c0392b`,
  `#c0c0c0`, `#ffffff`, …). Theme synchronisiert sich reaktiv mit der
  Slint-Standard-Widget-Palette via `init` + `changed`-Callback;
  Dunkler Hintergrund ⇒ helle Schrift, hell ⇒ dunkel — unabhängig
  vom OS-Theme des Hosts.
- **HeaderBar** mit Brand-Block (★ Stars + Subtitle), Versions-Badge,
  Theme-Toggle.
- **PrimaryButton + DangerButton** als eigene Slint-Komponenten;
  ausgerollt für die Haupt-Aktionen: Analyze, Scan starten/Abbrechen,
  Exportieren, Compare, Historie laden.
- **Arial** als Default-Schrift (`default-font-family`) — Stars läuft
  ausschließlich auf Windows-Server, Arial ist dort garantiert
  verfügbar und liefert ein konsistentes Schriftbild.

### Behoben
- **Aufgeblähte Buttons**: PrimaryButton, DangerButton, SpinBox haben
  `vertical-stretch: 0` und `max-height` / `height`-Constraints;
  vorher konnten umgebende Layouts sie auf die volle Container-Höhe
  aufblähen (z. B. fast bildschirmhohe „Scan-Historie laden"-
  Schaltfläche im Delta-Tab).
- **Versetzte CheckBox + SpinBox** in der Tiefe-Begrenzen-Reihe: jedes
  Element jetzt in einem eigenen `VerticalLayout { alignment: center }`,
  damit beide unabhängig von ihren intrinsischen Höhen auf derselben
  Y-Linie sitzen. Die Reihe selbst sitzt jetzt als reguläre GridBox-
  Row unter „Benutzer-SID:" statt in einer separaten Layout-Schicht
  oberhalb.
- **Aufgeblähte Label-Spalte**: GridBox-Spalten dehnen sich in Slint
  per Default. Labels haben jetzt `width: 140px;
  horizontal-stretch: 0;` — Eingabefelder sitzen direkt daneben statt
  weit nach rechts gerückt.
- **README**: „Wie wird Stars gestartet?"-Sektion (DE + EN) auf den
  signierten Installer (`Stars-vX.Y.Z-Setup.exe`) umgestellt. Vorher
  stand dort „erfordert keine Installation", was seit Existenz des
  Setup-Installers veraltet war. CLI-Beispiele zusätzlich: `analyze`
  für Einzelpfad, `scan` für rekursiven Baum-Scan.

---

## [1.5.3] — 2026-06-04

**Patch-Release.** Schließt beide Findings aus ChatGPT-Code-Review
2026-06-04 **Runde 5** — eines High, eines Medium. Eines davon ist der
gefährlichste Bug-Typ, der bisher gefunden wurde: **stille
Rechteunterbewertung** im lokalen Gruppen-Pfad bei Trust-/LSA-Identities.

### Behoben
- **High — Lokale Servergruppen konnten bei LSA-/Trust-Identitäten
  still fehlen.** `format_account_for_local_groups()` baute den
  Accountnamen blind als `name@domain`. Bei NetBIOS-Domains aus dem
  LSA-/Trust-Pfad (`alice@TRUSTED` statt `TRUSTED\alice`) lieferte
  `NetUserGetLocalGroups` regelmäßig `NERR_USER_NOT_FOUND` — und der
  alte Code interpretierte das als `Ok(Vec::new())` →
  `LocalGroupEvalStatus::Applied`. ACEs auf lokale Server-Gruppen
  (z. B. `BUILTIN\Administrators`) blieben dadurch unsichtbar **ohne
  `incomplete`-Signal**. Fix in drei Stufen:
  - Neue Funktion `format_account_candidates_for_local_groups()` liefert
    eine Kandidatenliste in Präferenzreihenfolge: UPN → `DOMAIN\name` →
    `name@dns-domain` (nur wenn DNS-artig) → `name`. `looks_like_dns_domain()`
    erkennt DNS-Suffixe heuristisch über das `.`-Vorkommen.
  - Neue strict-Variante `resolve_local_group_sids_strict()` mit
    explizitem `LocalGroupLookupOutcome { WithGroups(Vec<Sid>),
    UserNotFoundOnServer }`-Typ — trennt "User gefunden, leere Liste"
    von "User auf Server nicht bekannt".
  - Neue Identity-Wrapper-Funktion
    `resolve_local_group_sids_for_identity()` probiert die Kandidaten
    durch; erster `WithGroups`-Treffer gewinnt; wenn **alle**
    `UserNotFoundOnServer` liefern, gibt sie einen Validation-Fehler
    mit `tried`-Liste zurück → Aufrufer setzen
    `LocalGroupEvalStatus::NotAvailable(reason)` → Risk-Finding ist
    `incomplete = true`.
  - CLI- und GUI-`collect_local_group_sids_for_path` rufen jetzt
    `resolve_local_group_sids_for_identity` direkt mit der `&Identity`
    auf. Die alten Public-APIs bleiben backward-compatible erhalten.
  - **5 neue Tests** plus zwei angepasste bestehende Tests:
    `format_falls_back_to_domain_backslash_name_for_dns_domain`,
    `format_netbios_domain_only_emits_domain_backslash_form`,
    `format_returns_plain_name_without_domain`,
    `looks_like_dns_domain_distinguishes_netbios_and_dns`,
    `format_upn_wins_over_domain_form`.
  - ADR 0040 (ChatGPT-Code-Review 2026-06-04 Runde 5, **Finding 1**).

- **Medium — `docs/audit-kriterien.md` beschrieb `incomplete` noch mit
  veralteter Vier-Ursachen-Liste.** Beide Sprachsektionen (DE und EN)
  des `incomplete`-Abschnitts wurden auf die tatsächlichen Trigger
  aus `risk_engine::is_incomplete()` aktualisiert: jetzt acht
  durchnummerierte Ursachen plus separate Liste der **informationellen**
  Marker, die explizit **nicht** als incomplete gelten
  (`IdentityDisabled`, `IdentityDisabledStatusUnknown`,
  `NonCanonicalDaclOrder`). Verweise auf ADR 0033, 0034, 0036, 0039.
  Zusätzlich: **Doku-Konsistenz-Checkliste** als Blockquote am Ende,
  die festhält, welche Dateien bei einem neuen
  `PermissionDiagnostic`-Incomplete-Trigger gleichzeitig aktualisiert
  werden müssen (ChatGPT-Code-Review 2026-06-04 Runde 5, **Finding 2**).

### Hinzugefügt
- **ADR 0040** (Kandidatenliste für lokale Gruppen-Auflösung) inkl.
  Selbstkritik zu dem stillen NERR_USER_NOT_FOUND-Pfad seit v1.0.

---

## [1.5.2] — 2026-06-04

**Patch-Release.** Schließt alle drei Findings aus ChatGPT-Code-Review
2026-06-04 **Runde 4** — eines High, zwei Medium/Low. Plus den
symmetrischen Whitespace-Bug, den ChatGPT nur im GUI-Pfad nannte, auch
in der CLI.

### Behoben
- **High — `LookupFailed` und `GroupResolutionFailed` schlugen nicht
  bis zur Diagnose durch.** Die in ADR 0036 eingeführten neuen
  Status-Werte `IdentityScopeStatus::LookupFailed { reason }` und
  `GroupResolutionStatus::Failed { reason }` hatten keine Diagnose-
  Marker — wenn LDAP-Bind oder Gruppenrekursion crashte, lief die
  Analyse mit leerem Token weiter, ohne dass der Befund als
  `incomplete` markiert wurde. **Zwei neue strukturierte Marker:**
  `PermissionDiagnostic::IdentityLookupFailed { reason }` und
  `PermissionDiagnostic::GroupResolutionFailed { reason }`. Beide
  tragen den ursprünglichen Fehlertext mit, sind
  Incompleteness-Trigger, werden von CLI und HTML mit
  Reason-Beschreibung gerendert. `EngineFlags` und
  `PermissionEvaluationInput` wurden um die zwei `Option<String>`-
  Felder erweitert. **Außerdem**: `OutsideConfiguredLdapBase +
  NotAttempted` (Cross-Domain-Pfad ohne GC-Crawl) produziert jetzt
  auch einen `group_resolution_failure_reason` — vorher rechnete
  dieser Pfad still ohne Gruppen. ADR 0039 (ChatGPT-Code-Review
  2026-06-04 Runde 4, **Finding 1**).
- **Medium — Whitespace-umrahmte SID landete in CLI und GUI im
  Name-Zweig.** `if sid.starts_with("S-1-")` lief auf dem **Rohwert**,
  bevor `validate_sid` trimmen konnte. `"  S-1-5-21-...  "` wurde
  deshalb nicht als SID erkannt und ging als Roh-Eingabe an den
  Resolver — produktiv: `OrphanedSid` statt korrekter Auflösung. Fix
  in beiden Pfaden: `let sid_trimmed = sid.trim();` vor der
  Klassifikation, dann `validate_sid(sid_trimmed)`. CLI hatte denselben
  symmetrischen Bug in `run_analyze` und `run_scan` — wird mitgefixt
  (ChatGPT-Code-Review 2026-06-04 Runde 4, **Finding 2**).
- **Low — `analyze_trustees` akzeptierte halben SMB-Kontext.** Die
  Paar-Pflicht aus `validate_connection_inputs` (Runde 2 Finding 2)
  war im Trustee-Pfad nicht aktiv — `Some(server), None` konnte
  durchgehen und führte zu stillem NTFS-only-Output. Neuer
  wiederverwendbarer Helper `normalize_smb_pair(smb_server, share_name)`
  erzwingt die Paarbildung und wird jetzt von beiden Pfaden geteilt
  (ChatGPT-Code-Review 2026-06-04 Runde 4, **Finding 3**).

### Hinzugefügt
- **ADR 0039** (Diagnostik für gescheiterte Identity- und Group-
  Auflösung).
- **Test-Erweiterungen**: 3 Principal-Tests
  (`group_resolution_error_after_identity_hit_carries_reason`,
  `outside_base_with_skipped_groups_yields_group_failure_reason`, plus
  erweiterte `ldap_error_yields_lookup_failed_not_orphaned`-Assertion);
  2 Engine-Tests; 2 Risk-Engine-Tests; je 1 Worker-Test für
  Whitespace-SID-Klassifikation und `normalize_smb_pair`-Pair-Pflicht.
- **CLI- und HTML-Renderer** für die zwei neuen Marker mit Reason-
  Text (HTML-escaped).

---

## [1.5.1] — 2026-06-04

**Patch-Release.** Schließt zwei in v1.5.0 übersehene Wrapper-Stellen
(Finding-2-Regress) und ergänzt die in den Test Gaps der Review
geforderten Regressionstests, die v1.5.0 nur indirekt deckte.

### Behoben
- **`handle_search` (GUI-Identity-Picker) verwarf die getrimmten
  Wrapper-Werte.** Die Validierungen liefen, aber `LdapConfig::new`
  und `search_by_query` bekamen weiterhin die Rohwerte aus
  `ldap.server` / `ldap.base_dn` / `ldap.bind_dn` / `query`. Whitespace
  im Identity-Search-Feld der GUI hätte produktiv zu „User not found"
  geführt, obwohl die Eingabe gültig war. Jetzt fließen konsistent die
  getrimmten Werte in beide Aufrufe.
- **`analyze_trustees` (GUI-Trustee-Ansicht) verwarf
  `validate_smb_server` und `validate_share_name`.** Symmetrisch zum
  obigen Befund: die Validierung lief, der Aufruf von
  `build_trustee_rows` bekam aber den Rohstring. Jetzt durchgereicht.

### Hinzugefügt
- **Regressionstest `validate_connection_inputs_returns_trimmed_
  normalized_values`** in der CLI: prüft explizit, dass alle fünf
  Felder (server, base_dn, bind_dn, smb_server, share_name) getrimmt
  und als Strings im Result auftauchen.
- **`validate_connection_inputs_rejects_half_set_smb_pair`**: hält die
  Paar-Pflicht aus Review Runde 2 Finding 2 als Regressionstest fest.
- **`validate_connection_inputs_treats_empty_smb_strings_as_unset`**:
  whitespace-only / leerer String für SMB-Felder zählt wie nicht
  gesetzt — verhindert, dass leere UI-Felder durchschlagen.
- **`build_path_trustees_with_share_includes_overlay`** im
  `gui::worker`: sichert ab, dass der Scan-Pfad-Helper Share-ACEs
  tatsächlich an die NTFS-ACEs anhängt und beide Kategorien sichtbar
  bleiben. Direkter Regressionstest für Review Runde 3 Finding 3.
- **`build_path_trustees_with_share_falls_back_to_ntfs_only_without_overlay`**:
  hält das Verhalten ohne SMB-Kontext explizit fest.

---

## [1.5.0] — 2026-06-04

**Minor-Release.** Schließt alle drei Findings aus der dritten Runde
des ChatGPT-Code-Reviews 2026-06-04 — eines High, zwei Medium. Bricht
keine öffentliche API; intern verschmelzen `LookupResult`,
`SamResolution`, `ResolvedIdentity` und `IdentityResolution` zu einem
gemeinsamen `PrincipalResolution`-Modell.

### Behoben
- **High — Multi-Domain-/Trust-Fallback griff nur für `DOMAIN\user`.**
  Der in v1.4.1 eingeführte LSA-only-Fallback war eine Punktlösung im
  `lookup_via_lsa`-Pfad. GUI Name → SID, CLI direkte SID und UPN
  liefen weiterhin an der Logik vorbei: ein realer Trust-Principal
  wurde je nach Eingabeform mal korrekt als
  `IdentityNotInConfiguredLdapBase` markiert, mal still als
  `IdentityKind::Orphaned` klassifiziert. Plus: ein
  Cache-Vergiftungsbug in `resolve_identity_internal` cached
  `Orphaned` schon bevor `lookup_via_lsa` eine LSA-only-Identity bauen
  konnte. Beide Defekte sind jetzt geschlossen über eine **zentrale
  Principal-Pipeline** im neuen `ad_resolver::principal`-Modul mit den
  Backend-Traits `IdentityBackend` / `LsaBackend` und den
  Status-Enums `IdentityScopeStatus` / `GroupResolutionStatus` /
  `DisabledStatus`. CLI und GUI nutzen dieselbe Pipeline; alle vier
  Eingabeformen führen durch denselben LDAP-/LSA-Crosscheck. UPN-Miss
  liefert einen expliziten Fehler mit GC-Hinweis, statt einer stillen
  Misklassifikation. ADR 0036 (ChatGPT-Code-Review 2026-06-04 Runde 3,
  **Finding 1**).
- **Medium — Validierte Wrapper wurden an mehreren API-Grenzen
  verworfen.** `validate_sid`, `validate_ldap_endpoint`, `validate_dn`,
  `validate_smb_server`, `validate_share_name` lieferten getrimmte
  Werte; CLI/GUI prüften und verbrauchten aber teilweise weiter den
  Rohstring. `validate_connection_inputs` liefert jetzt eine
  `NormalizedConnectionInputs`-Struktur mit den getrimmten Feldern;
  alle SID- und Identity-Eingaben in CLI/GUI verwenden ab der
  Validierung den Wrapper-Wert. ADR 0037 (ChatGPT-Code-Review
  2026-06-04 Runde 3, **Finding 2**).
- **Medium — Scan-Trustee-Ansicht zeigte nur NTFS-Trustees.** Der
  Scan-Pfad rief `build_path_trustees(&fso, None, None)` und liess die
  Share-Trustees komplett weg, obwohl die HTML-Tabelle als
  „who can access this path at all" beschriftet ist und eine eigene
  Share-Spalte besitzt. Neuer `ShareTrusteeOverlay`-Helper liest die
  Share-DACL einmal pro Share und hängt sie als Overlay an jeden Pfad
  unter diesem Share an (`build_path_trustees_with_share`).
  Lese-Fehler bleiben als sichtbare Pseudo-Zeile drin — keine stillen
  Skips. ADR 0038 (ChatGPT-Code-Review 2026-06-04 Runde 3,
  **Finding 3**).

### Hinzugefügt
- **`ad_resolver::principal`-Modul** mit `PrincipalResolver`,
  `PrincipalInput`, `PrincipalResolution`, `IdentityScopeStatus`,
  `GroupResolutionStatus`, `DisabledStatus`, `EngineFlags`,
  Backend-Traits `IdentityBackend` / `LsaBackend`, Production-Adapter
  `LdapIdentityBackend` / `WindowsLsaBackend` / `NoLsaBackend`.
- **11-Fälle-Test-Matrix** im `principal`-Modul mit In-Memory-LDAP-
  und LSA-Fakes (`FakeLdapBackend`, `FakeLsaBackend`). Deckt alle
  sechs in der Review geforderten Eingabe/Output-Kombinationen ab
  plus disabled-Account-, no-LSA-, LDAP-Error-, ambiguous-SAM- und
  Auto-Dispatcher-Sonderfälle.
- **ADR 0036** (Unified Principal-Resolution-Pipeline), **ADR 0037**
  (Validated wrappers propagated), **ADR 0038** (Share-Trustees im
  Scan-Output).
- **docs/features-and-limitations.md** Abschnitt „Multi-Domain-Forest
  / Trusted Domains" aktualisiert: gilt jetzt für **alle**
  Eingabeformen, plus UPN-Sonderfall mit GC-Workaround-Hinweis.

### Entfernt
- `LookupResult`-Struct und die Public-Methode
  `LdapResolver::lookup_by_samaccount` (intern durch `PrincipalResolver`
  ersetzt; externe Konsumenten gibt es nicht).
- Private Helfer `lookup_via_lsa`, `lookup_via_upn`,
  `lookup_via_samaccount_strict`, `build_identity_from_lsa` —
  konsolidiert im neuen `principal`-Modul.

---

## [1.4.1] — 2026-06-04

**Patch-Release.** Schließt sechs Follow-up-Findings aus der zweiten
Runde des ChatGPT-Code-Reviews 2026-06-04 — vier in Block D (Risk-
Engine-Konsistenz, GUI-Timeout, SMB-Override-Validierung,
`NormalizedPath`-Propagation), zwei in Block E (Multi-Domain-LSA-
Fallback, SAM disabled-Status). Plus umfangreiche User-Doku
„Was geht / Was nicht geht" (`docs/features-and-limitations.md`).
Reines Lese-Tool — keine Schreibvorgänge auf Zielsystemen.

### Behoben
- **Risk-Engine `is_incomplete()` prüfte den `DomainGroupRecursionIncomplete`-Marker nicht.** ADR 0033 schrieb explizit fest, dass Risk-Findings für Berechtigungen mit SAM-Fallback-Diagnose als `incomplete = true` markiert werden müssen — der Code übernahm das aber nicht. Ein `FULL_CONTROL`- oder `WRITE_ACCESS`-Befund konnte dadurch als confirmed erscheinen, obwohl die Domain-Gruppen-Rekursion lückenhaft war. **Inkonsistenz zwischen ADR und Code** ist jetzt geschlossen, plus Regressionstest `full_control_marks_finding_incomplete_on_sam_fallback_diagnostic` (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 4**).
- **GUI-Identitätssuche umging den LDAP-Timeout.** `handle_search` baute selbst eine LDAP-Verbindung auf und rief `search_by_query` direkt — der `connect()`-interne Timeout-Wrapper war hier wirkungslos. Der interaktive Benutzer-Picker blockierte bei langsamen oder hängenden DCs länger als `LdapConfig::timeout_secs` versprach. Connect + Search + Disconnect sind jetzt gemeinsam in einen `with_timeout("identity_search", …)` gewickelt (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 3**).
- **Unvollständige SMB-Override-Kombinationen wurden stillschweigend akzeptiert.** Lokaler Pfad + nur `--smb-server` (ohne `--share-name`): lokale Gruppen wurden vom Remote-Server gelesen, gleichzeitig stand der Share-Status auf `NotApplicable` — Token-Verunreinigung mit fremden Server-SIDs ohne sichtbare Wirkung. `validate_connection_inputs` in CLI und GUI verlangt jetzt explizit `smb_server` und `share_name` als Paar; halb-gesetzte Eingaben liefern einen klaren Validierungsfehler (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 2**).
- **`validate_path`-Rückgabewert wurde an mehreren API-Grenzen verworfen.** Die Funktion lieferte eine `NormalizedPath` mit getrimmten Whitespaces und kanonisierter Long-Path-Form, CLI und GUI gaben aber weiterhin den Rohstring an `read_fso`, `walk_tree`, `AccessContext::for_path` und die Share-Helfer weiter. Die fünf betroffenen Stellen reichen jetzt konsequent die Normalform durch (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 6**).
- **Multi-Domain-Identitäten erschienen fälschlich als `IdentityKind::Orphaned`.** `DOMAIN\user` mit LSA-Treffer und LDAP-Miss (typisch in Forests mit Trusts, weil `base_dn` nur eine Domain indexiert) klassifizierte einen realen User als „verwaiste SID". Der Resolver fällt jetzt auf eine LSA-only-Identity (`build_identity_from_lsa`) zurück und setzt zwei strukturierte Diagnose-Marker am Befund: `IdentityNotInConfiguredLdapBase` (medium, `incomplete = true`) und `IdentityDisabledStatusUnknown` (info). Beide Flags fließen durch `LookupResult` → `ResolvedIdentity` / `IdentityResolution` → `PermissionEvaluationInput`. CLI und HTML rendern die neuen Marker mit eigener Beschreibung. ADR 0034 (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 1**).
- **`disabled`-Status im SAM-Pfad war pauschal `false`.** `ad_resolver::sam::resolve_identity_via_sam` baute `Identity` nur aus `LookupAccountSidW` + `NetUserGetGroups`; das `userAccountControl/UF_ACCOUNTDISABLE`-Bit blieb ungelesen. Ein deaktivierter Account wurde im Report still als aktiv ausgewiesen. Neue Helper-Funktion `user_account_disabled` ruft jetzt `NetUserGetInfo` Level 1 auf und prüft `UF_ACCOUNTDISABLE`. Die Rückgabe von `resolve_identity_via_sam` ist jetzt das additive Struct `SamResolution { identity, memberships, disabled_known }`; bei `disabled_known = false` (User-not-found, Access Denied o. ä.) setzt der Aufrufer den Marker `IdentityDisabledStatusUnknown`. ADR 0035 (ChatGPT-Code-Review 2026-06-04 Runde 2, **Finding 5**).

### Hinzugefügt
- **`docs/features-and-limitations.md`** — umfangreiche User-Doku „Was Stars zuverlässig kann / Was Stars nicht macht / Bekannte Einschränkungen und ihre Lesart". Enthält die vollständige Diagnose-Marker-Tabelle (inkl. `incomplete`-Spalte) und Schritt-für-Schritt-Lesart unerwarteter Befunde. README (de + en) verweist als Eingangsdoku darauf.
- **ADR 0034 (Multi-Domain-LSA-Fallback)** und **ADR 0035 (SAM disabled-Status per `NetUserGetInfo`)** dokumentieren die Architekturentscheidungen hinter den zwei neuen Diagnose-Markern.

---

## [1.4.0] — 2026-06-04

**Minor-Release.** Schliesst alle sieben Findings aus dem ChatGPT-Code-Review 2026-06-04 — drei High, drei Medium, eins Low. Reines Lese-Tool — keine Schreibvorgänge auf Zielsystemen.

### Behoben
- **CLI hielt lokale Pfade fälschlich für UNC-Pfade.** `unc_components` in `crates/cli/src/main.rs` prüfte das doppelte Präfix nicht und lieferte für `C:\Windows\SYSVOL` `Some(("C:", "Windows"))`. Folge: `collect_local_group_sids_for_path` fragte lokale Gruppen gegen den Server `C:` ab und `resolve_scan_share_status` startete einen Share-DACL-Lookup `NetShareGetInfo("C:", "Windows")` — beides ohne dass der Aufrufer SMB angefragt hatte. Auf einem Domain Controller ist genau `C:\Windows\SYSVOL` ein Kernpfad; das Ergebnis konnte fälschlich als unvollständig markiert werden und Token-SIDs konnten fehlen (ChatGPT-Code-Review 2026-06-04, **Finding 1**).
- **Long-Path-UNC wurde in Server- und Share-Lookup falsch zerlegt.** Sowohl die CLI- als auch die GUI-Variante arbeiteten am unnormalisierten Pfad-String — `\\?\UNC\server\share\folder` wurde dadurch als Server=`?`, Share=`UNC` interpretiert. Betraf Share-DACL-Auflösung und lokale Gruppen des Zielservers auf grossen Fileservern mit langen Pfaden (ChatGPT-Code-Review 2026-06-04, **Finding 4**).
- **Lokale Gruppen kamen vom Pfad-Server, nicht vom manuell gesetzten `--smb-server`.** Wenn der Anwender für einen lokalen NTFS-Pfad zusätzlich `--smb-server` / `--share-name` setzte, wurde die Share-DACL vom Override-Server gelesen, die lokalen Gruppen aber vom Pfad-Server (bei lokalem Pfad: lokaler Rechner). Token-SID-Satz für die Share-Auswertung konnte andere lokale Gruppen enthalten als der echte Zugriff auf den angegebenen Fileserver — kritisch bei ACEs auf `SERVER\Administrators`, `BUILTIN\Users` oder Fileserver-lokale Applikations­gruppen (ChatGPT-Code-Review 2026-06-04, **Finding 2**).

### Geändert
- Neue zentrale Helper `validation::path::parse_unc_components` und `validation::path::effective_smb_target` — **eine** Quelle der Wahrheit für CLI und GUI. Lokale Pfade, Long-Path-UNC und der `\\?\C:\…`-Sonderfall werden konsistent behandelt.
- `effective_smb_target` priorisiert den explizit gesetzten `smb_server` vor dem aus dem Pfad abgeleiteten UNC-Server.
- `collect_local_group_sids_for_path` (CLI + GUI) nimmt jetzt zusätzlich `explicit_smb_server` entgegen und nutzt `effective_smb_target` für die Server-Wahl.
- `resolve_scan_share_status` (CLI) und `resolve_share_status` (GUI) leiten Server und Share über die zentralen Helper ab.

### Hinzugefügt
- Neun Regressionstests in `validation::path`: `parse_unc_components` mit lokalen Pfaden (`C:\Windows\SYSVOL`, `D:\Daten`, `\singlebackslash\foo`), klassischem UNC, Long-Path-UNC mit Hostname und mit IP-Adresse, lokaler Long-Path-Form `\\?\C:\…` (muss als NICHT-UNC erkannt werden), unvollständigem UNC ohne Share, sowie `effective_smb_target`: expliziter Override auf lokalem und UNC-Pfad, Fallback auf UNC-Server, kein Override und kein UNC.
- GUI-Smoke-Test `share_status_does_not_treat_local_path_as_unc`, der genau die Sentinel-Konstellation aus Befund 1 prüft: `C:\Windows\SYSVOL` ohne Override muss `NotApplicable` liefern, keinen Share-Lookup.
- `ldap_client::with_timeout(operation, duration, future)` und `ldap_client::ldap_timeout(&config)` als zentrale Timeout-Wrapper für LDAP-Operationen. Schliesst **ChatGPT-Code-Review 2026-06-04 Finding 5** (`LdapConfig::timeout_secs` war konfiguriert, wurde aber nirgends angewendet — produktiv konnte ein unerreichbarer DC die Analyse beliebig lange blockieren). `LdapResolver::lookup_by_samaccount`, `resolve_identity_internal` und `resolve_memberships_internal` umklammern jetzt ihre vollständige LDAP-Logik mit dem konfigurierten Timeout; `connect()` selbst klammert TCP/TLS-Aufbau und Bind separat ein.
- `ldap_client::search_all_by_samaccount` (liefert **alle** Treffer für eine spätere Eindeutigkeits-Prüfung) und `ldap_client::search_by_upn` (Suche über `userPrincipalName`).
- `LdapResolver::lookup_via_lsa`, `lookup_via_upn` und `lookup_via_samaccount_strict` als interne Helfer für die jeweilige Eingabeform.

### Geändert
- **`LdapResolver::lookup_by_samaccount`** wurde komplett überarbeitet — Schliesst **ChatGPT-Code-Review 2026-06-04 Finding 3** (`DOMAIN\user` wurde akzeptiert, der Domainteil aber stillschweigend abgeschnitten; in Multi-Domain-Forests konnte das die SID des **falschen** Benutzers zurück­liefern). Der neue Dispatcher unterscheidet drei Eingabeformen:
  - `DOMAIN\user` → Auflösung über die Windows-LSA (`LookupAccountNameW`); die LSA ist domain-aware und garantiert die richtige Domain.
  - `user@domain.tld` (UPN) → LDAP-Suche über `userPrincipalName` (forestweit eindeutig).
  - `username` (ohne Qualifier) → LDAP-Suche über `sAMAccountName`, **Mehrfachtreffer liefern jetzt einen Eindeutigkeitsfehler** statt stillschweigend den ersten Treffer zu nehmen.
- Leere Eingabe (`""`) liefert jetzt einen `CoreError::Validation` statt eines stummen No-Op.

### Hinzugefügt
- Zwei neue `PermissionDiagnostic`-Varianten in `adpa_core::model`:
  - **`DomainGroupRecursionIncomplete`** — wird gesetzt, sobald die Gruppen­auflösung über den SAM/LSA-Fallback statt LDAP läuft (`NetUserGetGroups` liefert nur direkte globale Gruppen, verschachtelte Domain-Gruppen werden ohne LDAP nicht rekursiv aufgelöst, der Token-SID-Satz kann unvollständig sein). Schliesst **ChatGPT-Code-Review 2026-06-04 Finding 6**.
  - **`IdentityDisabled`** — wird gesetzt, sobald die analysierte Identität im AD als deaktiviert markiert ist (`userAccountControl` ACCOUNTDISABLE). Die berechneten Rechte sind ACL-theoretisch korrekt, aber das Konto kann sich normalerweise nicht authentifizieren / über SMB nicht zugreifen. Schliesst **ChatGPT-Code-Review 2026-06-04 Finding 7**.
- `PermissionEvaluationInput.group_resolution_via_sam_fallback: bool` (Default `false`) — der Aufrufer setzt das Flag, wenn er den SAM-Pfad nutzt. Die Engine pusht dann automatisch den passenden Diagnostic-Marker in das Ergebnis.

### Geändert
- `resolve_identity_sids` in der GUI liefert jetzt zusätzlich ein `used_sam_fallback`-Flag (3-Tupel). CLI nutzt das schon vorhandene `ResolvedIdentity::ad_connected`. Beide leiten den Wert in `PermissionEvaluationInput.group_resolution_via_sam_fallback` weiter.
- HTML-Bericht zeigt für `DomainGroupRecursionIncomplete` eine gelbe „⚠ SAM fallback — nested groups not resolved"-Badge mit Tooltip-Erklärung; für `IdentityDisabled` einen blauen „ℹ disabled account"-Hinweis.
- CLI-Output (`output::print_report`) fügt zwei zusätzliche Diagnose-Blöcke aus: `[!] Group resolution ran through the SAM/LSA fallback…` und `[i] Identity is flagged as disabled in AD…`.

### Versionsbump
- Workspace-Version: `1.3.0` → `1.4.0`.

---

## [1.3.0] — 2026-06-04

**Minor-Release.** Schließt die drei wesentlichen Audit-Lücken aus der Selbstkritik in v1.2.0: rekursive Trustee-Sicht im Scan-Tree-Tab, Trustee-Tabelle im HTML-Bericht, konkrete lokale Gruppen-Ketten via `NetLocalGroupGetMembers`. Reines Lese-Tool — keine Schreibvorgänge auf Zielsystemen.

### Hinzugefügt
- **Rekursive Trustee-Sicht im Scan-Tree-Tab.** Jede gescannte Pfad-Zeile zeigt auf Klick nicht nur den identitätsbasierten Berechtigungspfad, sondern zusätzlich die komplette DACL-Trustee-Tabelle des Pfads (alle ACEs mit aufgelöstem `DOMAIN\Name`, Allow/Deny, normalisierten Rechten + Roh-Maske, „explicit/inherited"-Quelle, Windows-typischer „Applies to"-Bezeichnung und NTFS/Share-Schicht). Damit beantwortet jeder Scan zwei Audit-Fragen gleichzeitig: „was darf X auf Y" und „wer hat überhaupt Zugriff auf Y".
- **Trustee-Tabelle im HTML-Bericht.** Neue Sektion „Wer hat Zugriff (Trustees pro Pfad)" als ausklappbare `<details>`-Liste je Pfad — gleiche Spaltenstruktur wie in der GUI, mit Hover-Tooltip für die SID.
- **Lokale Gruppen-Ketten konkret rekonstruiert.** `NetLocalGroupGetMembers` wird pro lokaler Gruppe aufgerufen; die zurückgelieferten Member werden gegen die schon bekannten Token-SIDs (Eigene SID + Domain-Gruppen) abgeglichen. Resultierende Kette ist jetzt z. B. `max.mustermann → Domain Admins → BUILTIN\Administrators` statt nur `BUILTIN\Administrators [transitive, exact chain unknown]`. Nicht rekonstruierbare Pfade (verschachtelt über eine weitere lokale Gruppe) bleiben ehrlich als `complete = false` markiert.
- **Neue `adpa_core`-Datentypen** `PathTrustee` (raw ACE-Eintrag mit aufgelöstem Namen) und `PathTrustees` (Pfad → Liste). `AnalysisResult` trägt jetzt ein zusätzliches `path_trustees`-Feld mit `Default`-Wert — alle bestehenden Konstruktions­sites bleiben kompatibel.
- **Worker-Helper** `build_path_trustees` (raw model) und `trustee_row_for_display` (display) — Trennung zwischen Datenmodell und Anzeige. `build_trustee_rows` ist jetzt ein dünner Wrapper, der aus dem rohen Modell die Display-Form ableitet.
- **`ad_resolver::local_groups`** bekommt drei neue öffentliche Funktionen: `resolve_local_groups` (Name + SID parallel statt nur SID), `get_local_group_members` (NetLocalGroupGetMembers Level 2, liefert PSID + DOMAIN\Name pro Mitglied), `resolve_local_group_chains` (rekonstruiert konkrete Ketten unter Nutzung der bekannten Token-SIDs).

### Geändert
- **SAM-Resolver** nutzt jetzt `resolve_local_group_chains` statt der flachen `resolve_local_group_sids`-Variante. Die alte Public-API bleibt für externe Aufrufer (z. B. GUI-Worker) erhalten.
- **GUI Scan-Tree-Renderer**: aufgeklappte Zeile zeigt jetzt zwei Blöcke gestapelt — Berechtigungspfad oben, Trustee-Tabelle unten.
- **HTML-Exporter** rendert `path_trustees` nur, wenn das Feld nicht leer ist; CLI-Aufrufe bleiben unverändert.

### Tests
- Alle bestehenden Tests laufen weiter grün (Workspace: 451 Tests). Neue Trustee-Pipeline ist über die schon vorhandene `analyze_trustees`-Logik abgedeckt; lokale Gruppen-Ketten brauchen für End-to-End-Verifikation eine echte DC-Umgebung und sind über die ignorierten Integrations­tests adressierbar.

### Versionsbump
- Workspace-Version: `1.2.0` → `1.3.0`.

---

## [1.2.0] — 2026-06-02

**Minor-Release.** Drei vom Bediener konkret angesprochene GUI-Lücken geschlossen: pfadzentrierte Trustee-Sicht im Analyze-Tab, Löschen einzelner Scan-Läufe aus der Historie, sichtbarer Hinweis bei leerem Delta-Ergebnis. Reines Lese-Tool — keine Schreibvorgänge auf Zielsystemen, keine Berechtigungs­änderungen.

### Hinzugefügt
- **Trustee-Sicht im Analyze-Tab** („Wer hat Zugriff?"-Button). Listet alle ACEs eines Pfads pfadzentriert auf — eine Zeile pro ACE mit aufgelöstem `DOMAIN\Name`, Allow/Deny, normalisierten Rechten + Roh-Maske, explicit/inherited-Quelle, Windows-typischer „Applies to"-Bezeichnung und Schicht (NTFS / Share). Beantwortet die Audit-Frage „wer kann überhaupt auf X zugreifen?" als Komplement zur identitätsbasierten Effektiv-Analyse. SMB-Kontext optional — wenn aktiv, wird zusätzlich die Share-DACL mit angezeigt. NULL-DACL erscheint als sichtbare Auditor-Zeile statt einer leeren Tabelle.
- **Worker-Request `AnalyzeTrustees`** + Event `TrusteesDone` + `TrusteeRow`-Struct. Auflösung der SIDs erfolgt batched per `ad_resolver::build_sid_name_map` — eine LSA-Runde pro eindeutiger SID.
- **`Database::delete_scan_run(id)`** und **`ScanStore::delete_scan_run(id)`** in `persistence`. Löscht einen Scan-Lauf samt aller `effective_permissions`- und `scan_errors`-Zeilen in einer expliziten Transaktion (BEGIN IMMEDIATE / COMMIT / ROLLBACK). SQLite-Foreign-Keys sind im Schema nicht über `PRAGMA foreign_keys = ON` aktiv, deshalb explizite Kaskade. Liefert die Anzahl entfernter Scan-Lauf-Zeilen (0 bei unbekannter ID, 1 bei Erfolg).
- **Mülleimer-Button pro Scan-Lauf im Delta-Tab** plus inline-Bestätigungsdialog. Ein versehentlicher Klick löscht nichts — die Aktion startet erst nach „Endgültig löschen". Nach Abschluss wird die Selektion bereinigt, ein eventuell sichtbares Delta-Ergebnis ausgeblendet und die Liste frisch aus der DB nachgeladen, damit GUI-State und DB nicht auseinanderlaufen.
- **`WorkerRequest::DeleteScanRun`** + Event `ScanRunDeleted { run_id, result }`. Triggert auf Erfolg automatisch ein `ListScanRuns`, damit der Bediener nicht erneut auf „Scan-Historie laden" klicken muss.
- **`REQ_TX`-Thread-Local** in der GUI für Folge­aktionen aus Event-Handlern (analog zum bestehenden `EVENT_RX`).
- **Sichtbarer Hinweis im Delta-Tab bei leerem Ergebnis**: „Keine Unterschiede zwischen den beiden Scans gefunden. Beide Läufe enthalten dieselben Pfade mit identischen effektiven Berechtigungen." Vorher sah der Bediener nur die `0 / 0 / 0`-Zähler über einer leeren Tabelle und konnte nicht zwischen „Vergleich gelaufen, nichts gefunden" und „Aktion verloren gegangen" unterscheiden.

### Tests
- Drei neue `persistence`-Tests für `delete_scan_run`: vollständiges Cascade-Delete (Run + Permissions + Errors), unbekannte UUID liefert `0` und kein Fehler, andere Scan-Läufe bleiben unangetastet.

### Versionsbump
- Workspace-Version: `1.1.2` → `1.2.0`.

---

## [1.1.2] — 2026-06-01

**Patch-Release.** Behebt einen vertrauenskritischen Fehler im Verzeichnis-Walker, der Reparse Points (Junctions, Symlinks) bisher still übersprungen hat — Inhalt hinter einer Junction war im Scan-Ergebnis stumm fehlend, ohne dass die GUI das angezeigt hat. Tritt produktiv vor allem bei SYSVOL-Scans auf (`C:\Windows\SYSVOL\sysvol\<domain>` ist standardmäßig eine Junction auf `C:\Windows\SYSVOL\domain`).

### Geändert
- `fs_scanner::walker::walk_tree` verfolgt Reparse Points jetzt standardmäßig und entdeckt Schleifen über das kanonisierte Ziel. Ein `HashSet` der schon besuchten kanonischen Pfade wird beim Eintritt in jeden Reparse Point geprüft; bei Treffer wird die Rekursion gestoppt und ein sichtbarer `WalkError` mit erklärendem Text ins Ergebnis geschrieben. Die alte „still überspringen"-Logik fällt damit ersatzlos weg.
- Schlägt die Auflösung des Reparse-Ziels fehl (z. B. defekter Link), wird ebenfalls ein sichtbarer `WalkError` ausgegeben statt im `debug!`-Log zu verschwinden.

### Hinzugefügt
- Walker-Test `walker_follows_directory_junction_into_target` — verifiziert mit einer per `mklink /J` erzeugten Junction, dass Objekte hinter dem Link tatsächlich enumeriert werden.
- Walker-Test `walker_detects_junction_loop_and_emits_visible_error` — erzeugt eine zirkuläre Junction-Struktur (`a\b → root`) und stellt sicher, dass die Schleife sauber erkannt und als Fehler im Ergebnis sichtbar wird (kein Stack-Overflow, kein stilles Drop).

### Versionsbump
- Workspace-Version: `1.1.1` → `1.1.2`.

---

## [1.1.1] — 2026-06-01

**Patch-Release.** Beseitigt eine UX-Falle im Analyze-Tab: bisher wurden Analyse-Ergebnisse nicht persistiert und tauchten deshalb im Delta-Tab nie auf.

### Geändert
- Analyze-Tab persistiert das Ergebnis jetzt automatisch in die Scan-Historie — eine `EffectivePermission` landet als Scan-Lauf mit genau einer Permission. Damit sind Analyze-Auswertungen im Delta-Tab vergleichbar; vorher schrieb nur der Scan-Tree-Tab in die DB, was sich für Endnutzer als „Liste lädt meine Auswertung nicht" bemerkbar machte.
- Statuszeile des Analyze-Tabs spiegelt das Persistenz-Ergebnis: „Analyse abgeschlossen — in der Scan-Historie gespeichert." bei Erfolg, sichtbarer Fehler­text bei Persistenz-Problemen.
- `WorkerEvent::AnalyzeDone` ist von Tuple- auf Struct-Variante umgestellt und trägt zusätzlich `scan_run_id` und `persistence_error`. `result` ist geboxt, weil `EffectivePermission` deutlich größer ist als die übrigen Event-Varianten (sonst greift `clippy::large_enum_variant`).

### Hinzugefügt
- Hinweistext direkt unter dem „Analysieren"-Button: „Hinweis: jede Analyse wird automatisch in der Scan-Historie gespeichert und ist anschließend im Delta-Tab vergleichbar." — macht die Semantik vor dem Klick sichtbar.

### Versionsbump
- Workspace-Version: `1.1.0` → `1.1.1`.

---

## [1.1.0] — 2026-06-01

**Audit-Beweiskraft und sicherheits­relevante Vorlauf­arbeiten am Update-Manager.** Schließt alle offenen Befunde aus dem ChatGPT-Code-Review 2026-05-31 (Findings 1, 2, 6, 7); Findings 3–5 wurden bereits in v1.0.0 adressiert.

### Hinzugefügt
- `MembershipPath` als neues Datenmodell in `adpa_core`: trägt pro `GroupMembership` die konkrete SID-Kette vom Benutzer zur Zielgruppe, indexweise zugeordnete Anzeigenamen, eine Herkunfts­quelle (`PrimaryGroup`, `DomainGroup`, `LocalGroup`, `LdapMatchingRule`) und ein `complete`-Flag. Der LDAP-Resolver rekonstruiert die Ketten per BFS über die `memberOf`-Edges der schon geladenen Gruppen-Entries; ist die Rekonstruktion nicht möglich (z. B. wegen trunkiertem `memberOf` einer Zwischengruppe), bleibt der Pfad zwei SIDs lang und wird als `complete = false` markiert (ChatGPT-Code-Review Finding 1).
- `validate_manifest_relative_path` als zentrale Windows-sichere Pfadprüfung im Update-Manifest. Lehnt Laufwerksbuchstaben (`C:\…`, `C:x`), UNC- und Long-Path-Präfixe (`\\…`, `\\?\…`), `.`/`..`-Segmente, leere Segmente, reservierte Geräte­namen (`NUL`, `CON`, `COM1`, …), ADS-Notation (`file.txt:ads`), verbotene Zeichen und Steuerzeichen ab. Schließt einen Sicherheits-Vorlauf für die spätere Installationslogik (ChatGPT-Code-Review Finding 6).
- `verify_update_policy` + `UpdatePolicyContext` als getrennte Policy-Schicht zur Manifest-Freigabe. Prüft Plattform, freigegebenen Kanal, dotted-numerische Versions-Reihenfolge (mit optionalem `allow_downgrade`), ISO-8601-Parsebarkeit von `issued_at`, sowie Future-Skew- und Max-Age-Toleranz (ChatGPT-Code-Review Finding 7).

### Geändert
- `validate_path` akzeptiert jetzt zusätzlich die Windows-Long-Path-Schreibweise (`\\?\C:\…` und `\\?\UNC\server\share\…`) und normalisiert sie auf die kanonische Anzeigeform. CLI- und GUI-Eingaben verhalten sich damit nicht mehr strenger als die darunterliegende Scanner-API (ChatGPT-Code-Review Finding 2).
- Erklärungstext der `PermissionPath`-Steps zeigt für jede Mitgliedschaft mit konkretem Pfad die geordnete Kette `User → Group A → Group B` plus Quellen-Label statt nur `Member of X [transitive]`. Direkte Mitgliedschaften erhalten `[direct, source: …]`, unvollständige transitive Ketten werden mit `exact chain unknown — source: LdapMatchingRule, possibly truncated memberOf` markiert. Cache-Lesepfade ohne `MembershipPath` fallen auf das alte Format zurück.
- `verify_manifest` aus `update_manager` umbenannt in `verify_manifest_integrity`, da der Name die tatsächliche Funktion (Schema + Signatur + Datei-Hashes) sauber abgrenzt von der neuen Policy-Schicht. Ältere Aufrufer existieren nicht außerhalb des Crates; der alte Name wird nicht beibehalten, weil das Risiko größer wäre, als die Schicht­trennung verlässlich zu erzwingen (ChatGPT-Code-Review Finding 7).
- `UpdateManifest::validate_schema` ruft jetzt `validate_manifest_relative_path` pro Datei-Eintrag — die alte Substring-Prüfung auf `..` und führende Separatoren ist abgelöst (ChatGPT-Code-Review Finding 6).

### Tests
- Zehn neue Tests für `validate_path` mit Long-Path-Eingaben: lokale und UNC-Long-Path-Form, Überlänge > MAX_PATH, Roundtrip mit `to_windows_api_path`, Ablehnung für fehlende Drive-/Share-Komponente, leeres Präfix und nach Strip noch verbotene Zeichen.
- Vier neue Engine-Tests für das Membership-Pfad-Rendering: verschachtelte Kette in geordneter Reihenfolge (`User → A → B`), direkte Kante mit Quellen-Label, unvollständige transitive Kette mit explizitem Hinweis, Rückfall auf Legacy-Format bei `path = None` (Cache-Reads).
- Vierzehn neue Tests für `validate_manifest_relative_path`: akzeptierte relative Pfade (auch mit `/`-Separator), Ablehnung von absoluten Drive-Pfaden, drive-relativen Pfaden (`C:foo`), `..`- und `.`-Segmenten, reservierten Geräte­namen, ADS-Notation, UNC- und Long-Path-Präfix, führenden Separatoren, leeren Segmenten, verbotenen Zeichen, Steuerzeichen und Null-Bytes.
- Elf neue Tests für `verify_update_policy` und `compare_dotted_versions`: passende Plattform/Kanal/Version, falsche Plattform, falscher Kanal, Downgrade ohne Freigabe, gleiche Version (kein Re-Install), Downgrade mit Freigabe, `issued_at` weit in der Zukunft vs. innerhalb der Skew-Toleranz, abgelaufenes `issued_at`, nicht parsbares `issued_at`, dotted-numerische Ordnung (`1.10.0` vs `1.9.5`) und Strip von Pre-Release-Suffixen.

### Dokumentation
- ADR 0029 — Konkreter Mitgliedschafts-Pfad in der Erklärung.
- ADR 0030 — Update-Manager: Pfadvalidierung und Policy-Schicht.
- README ergänzt um den Mitgliedschafts-Pfad in der AD-Sektion (DE + EN).

### Versionsbump
- Workspace-Version: `1.0.0` → `1.1.0`.

---

## [1.0.0] — 2026-05-31

**Erstes stabiles Release. Repository ab hier öffentlich, neuer Repo-Name.**

### Hinzugefügt
- Stabile Veröffentlichung des AD-Permission-Analyzers mit allen Funktionen aus rc1–rc17:
  - Effektive-NTFS- und Share-Berechtigungs­berechnung mit erklärbarem Pfad
  - Sechs Risikoregeln (Full Control, Write Access, Admin Rights, Broad Group Write, Direct User ACE, Sensitive Path)
  - Slint-GUI mit Analyze-, Scan- und Delta-Tab
  - SAM-/LSA-basierte Identitätsauflösung auf einem DC (kein LDAP-Bind nötig)
  - Live-Suche im Namensfeld (NetUserEnum + NetGroupEnum + NetLocalGroupEnum + Well-Known-Tabelle)
  - HTML-/CSV-/JSON-Export
  - SQLite-Scan-Historie mit Delta-Vergleich
  - Sauberer NSIS-Uninstaller mit optionaler Daten-Bereinigung

### Geändert
- Workspace-Version: `0.2.0-rc17` → `1.0.0`
- Repository: umgezogen von `Birgerson/Stars.Rocks` (private, gelöscht) nach `Birgerson/Stars` mit frischer Git-History — saubere Trennung zwischen Entwicklungs­phase und stabilen Releases.
- `SensitivePathRule` und `DirectUserAceRule` melden Befunde jetzt als `incomplete = is_incomplete(p)` statt fix `false`, konsistent zu allen anderen Risikoregeln (ChatGPT-Code-Review 2026-05-31 Findings 3 und 4).
- `scripts/test-env/02-setup-ad-objects.ps1`: Beispiel-Block enthält jetzt einen Platzhalter (`<dein-Testpasswort>`) statt eines konkreten Passworts (ChatGPT-Review Finding 5).

### Tests
- Zwei neue Regressionstests für die `incomplete`-Markierung bei `ShareEvalStatus::ReadFailed` (`SensitivePathRule`, `DirectUserAceRule`).

### Bekannte Punkte für spätere Versionen
- ChatGPT-Review Finding 1 (konkrete Gruppen-Kette im Erklärungspfad): geplant für v1.1.
- Finding 2 (Long-Path-Präfixe in `validate_path`): geplant für v1.1.
- Findings 6 und 7 (Update-Manager-Pfadvalidierung, `verify_manifest`-Naming): werden mit der Installations­logik des `update_manager` zusammen umgesetzt.

---

## [0.2.0-rc17] — 2026-05-31

**LDAP-Modus als Dropdown + Tooltip-Hinweise auf den wichtigen Feldern.**

### Hinzugefügt
- **ComboBox „Modus"** statt zweier Checkboxen im LDAP-Bereich von Analyze- und Scan-Tab. Drei klar getrennte Optionen:
  - „Aus — SAM/LSA nutzen (empfohlen auf DC)"
  - „LDAPS — verschlüsselt, Port 636"
  - „LDAP unverschlüsselt — Port 389 (nur Test)"
- **HelpTip-Component** (ⓘ-Icon) mit Hover-Tooltip auf den LDAP-Modus-Wähler und allen LDAP-Eingabefeldern (Server, Base DN, Bind DN, Passwort). Jeder Tooltip erklärt Zweck, Format und typische Stolperfallen — Anwender muss nicht erst die Doku lesen, um zu verstehen, was wohin gehört.

### Geändert
- LDAP-Properties auf Slint-Seite konsolidiert: `a-ldap-enabled` + `a-ldap-insecure` → eine `a-ldap-mode` Integer-Property (0/1/2). Analog für den Scan-Tab. Rust-Callbacks lesen die Mode-Property direkt und bauen `LdapParams` mit `insecure` daraus ab.

---

## [0.2.0-rc16] — 2026-05-31

**Sauberer Uninstaller: Process-Check, dynamische Version, optionale Audit-Historie-Bereinigung.**

### Hinzugefügt
- `setup.nsi` baut beim Deinstallieren jetzt eine **Components-Seite** mit zwei Sektionen:
  1. **„Stars"** (Pflicht) — Programmdateien, Verknüpfungen, Registry-Eintrag.
  2. **„Audit-Historie und Logs entfernen"** (standardmäßig **aus**) — entfernt `%APPDATA%\Stars\` (SQLite-DB) und `%LOCALAPPDATA%\Stars\logs\` mit. Die Standardvorgabe schützt die Audit-Historie als Beweismittel, der Anwender muss bewusst opt-in.
- **Process-Check** vor der eigentlichen Deinstallation: läuft `Stars.exe` noch, erscheint eine Meldung „Stars läuft noch — bitte schließen und Deinstallation neu starten" und der Vorgang bricht ab, statt teilweise zu scheitern.
- **APP_VERSION** wird vom Release-Workflow dynamisch via `/DAPP_VERSION=<tag-ohne-v>` an `makensis` übergeben. Damit zeigt der „Programme und Features"-Eintrag jetzt die echte Release-Version (`0.2.0-rc16`) statt des bisher hartkodierten `1.0`.

### Dokumentation
- README: neue Sektion „Deinstallation" mit Pfaden und Hinweis auf die Opt-in-Checkbox.
- `docs/audit-kriterien.md` Kapitel 11 (Persistierte Daten): Hinweis ergänzt, dass die Audit-Historie standardmäßig auch eine Deinstallation überlebt — und wie man sie bewusst entfernen kann.

---

## [0.2.0-rc15] — 2026-05-31

**Live-Suche im Namensfeld — Auditor muss SIDs nicht mehr auswendig wissen.**

### Hinzugefügt
- Neues Modul `ad_resolver::enumerate` mit `IdentitySnapshot` und `enumerate_all()`. Sammelt Domänen-User (`NetUserEnum` Level 10), globale Domänen­gruppen (`NetGroupEnum` Level 1), lokale Gruppen (`NetLocalGroupEnum` Level 1) und eine hartcodierte Tabelle audit-relevanter Well-Known-Identitäten (`Everyone`, `Authenticated Users`, `SYSTEM`, `NETWORK`, `CREATOR OWNER` …). Alle Aufrufe `NetApiBufferFree`-sauber, alle `unsafe`-Blöcke mit SAFETY-Begründung.
- Neue Worker-Variante `WorkerRequest::ListIdentities` + Event `IdentitiesLoaded`. Wird einmalig beim App-Start gefeuert, das Ergebnis liegt in einem thread-lokalen Cache in der GUI.
- Live-Suche unter dem Namensfeld in Analyze- und Scan-Tab: User tippt `ad`, eine kleine Vorschlags­liste erscheint mit Klartextnamen (`[U] Administrator`, `[G] Domain Admins`, `[L] BUILTIN\Administrators`, `[W] Authenticated Users` …). Klick übernimmt den Namen und löst die SID automatisch auf.
- Maximal 15 Treffer angezeigt — wer mehr braucht, tippt präziser.

### Technisches
- Filterung läuft rein lokal gegen den Cache, kein Worker-Roundtrip pro Tastendruck.
- Bei leerer Eingabe verschwindet die Vorschlags­liste automatisch.
- Fällt die Enumeration fehl (z.B. fehlende Rechte für `NetUserEnum`), läuft die GUI ohne Vorschläge weiter — Direkt-Eingabe und `🔍 SID auflösen`-Button funktionieren unabhängig vom Cache.

---

## [0.2.0-rc14] — 2026-05-31

**UX: Benutzername → SID-Auflösung direkt in der Maske.**

### Hinzugefügt
- Analyze- und Scan-Tab haben jetzt ein zusätzliches Feld „Benutzer/Gruppe" mit einem „🔍 SID auflösen"-Button (und Enter-Taste). Der Name wird per `LookupAccountNameW` über die lokale LSA in die SID übersetzt und ins SID-Feld geschrieben. Funktioniert ohne LDAP, für User UND Gruppen, mit oder ohne Domänen­präfix (`Administrator`, `DOMÄNE\\max.muster`, `BUILTIN\\Administrators`). Nicht aufgelöste Namen erscheinen als rote Fehlermeldung unter den Feldern.
- Neue Hilfsfunktion `resolve_name_to_sid` im GUI-Crate, `#[cfg(windows)]`-gegated, mit einer No-Op-Variante für nicht-Windows-Builds.

---

## [0.2.0-rc13] — 2026-05-31

**UX-Politur + nachgepflegte Dokumentation.**

### Hinzugefügt
- Analyze- und Scan-Tab haben jetzt `C:\Windows\SYSVOL\sysvol` als Pfad-Vorauswahl. Erspart auf einer Standard-DC-Installation den ersten Tippvorgang; bleibt überschreibbar.

### Dokumentation
- README „Entwicklungsstand"-Tabelle korrigiert (Risikoanalyse, HTML-Bericht, Delta-Vergleich nicht mehr „geplant").
- README: neue Sektion „Datenbank und gespeicherte Daten" beschreibt Standort und Schutz­charakter der SQLite-Historie.
- `docs/audit-kriterien.md`: neues Kapitel 11 „Persistierte Daten und Scan-Historie" + Workflow-Empfehlung um Delta-Tab erweitert + Anhang B um Persistence-Verweise ergänzt.

---

## [0.2.0-rc12] — 2026-05-30

**Phase 2c: Delta-Tab funktional — Feature-Parität mit der eframe-Vorgängerversion.**

### Hinzugefügt
- Vergleich zweier persistierter Scan-Läufe direkt in der GUI: historische Scans laden, je einen Lauf für „Alt" und „Neu" anhaken, mit einem Klick die Differenz lesen.
- Zwei neue ViewModels in der Slint-Definition: `ScanRunVm` (id, label, selected_as_old, selected_as_new) und `DeltaRowVm` (path, kind_label, kind_color, old_rights, new_rights).
- Zwei neue `WorkerRequest`-Varianten (`ListScanRuns`, `ComputeDelta`) mit den passenden Antwort-Events (`ScanRunsLoaded`, `DeltaComputed`).
- Delta-Tabelle mit farbcodierten Markern (grün = Hinzugefügt, rot = Entfernt, gelb = Geändert) und Zähl-Headline.

### Dokumentation
- README: „Entwicklungsstand"-Tabelle korrigiert — Risikoanalyse, HTML-Bericht und Delta-Vergleich stehen nicht mehr auf „geplant", sondern auf „✓".
- README: neue Sektion „Datenbank und gespeicherte Daten" beschreibt Standort (`%APPDATA%\Stars\stars_data.db`), Tabellenstruktur, Lebensdauer (überlebt Deinstallation) und Schutz­charakter (kein Passwort, kein Verschlüsselung — Profilpfad selbst absichern).
- Audit-Doku und CHANGELOG entsprechend nachgepflegt.

---

## [Unveröffentlicht in v0.2.0-rc11] — Dokumentations-Konsolidierung
- Audit-Kriterien und Bewertungsprinzipien als eigene, ausführliche Lektüre (`docs/audit-kriterien.md`).
- Urheberschaft transparent ausgewiesen: Birger Labinsch als Prompt Engineer, Implementierung durch Claude Opus 4.7.
- Plattformstatus (Server 2022 getestet, 2025 ungeprüft) und Haftungsausschluss in README und Audit-Doku.
- Repo-Topics und gekürzte Repo-Description direkt am GitHub-Repository gesetzt.

---

## [0.2.0-rc11] — 2026-05-30

**Klartext statt SID-Wüste im Berechtigungspfad.**

### Hinzugefügt
- `GroupMembership.group_name` und `PermissionEvaluationInput.sid_names` — Gruppen- und ACE-Trustee-SIDs erscheinen jetzt mit Namen im Erklärungstext (z. B. `Member of Domain Admins (S-1-5-…-512) [direct]` statt nur der SID).
- `ad_resolver::sam::build_sid_name_map` als zentraler Aufbau für die SID→Name-Tabelle; CLI und GUI bauen die Tabelle einmal pro Lauf, Trustees werden über alle DACLs unique gesammelt.

### Geändert
- SAM-Resolver setzt `group_name` direkt aus `NetUserGetGroups` und löst lokale Gruppen-SIDs (z. B. `BUILTIN\Administrators`) per `LookupAccountSidW` zurück in den Klartextnamen auf.
- LDAP-Resolver schreibt `sAMAccountName` (Fallback `cn`) der Gruppe in die Membership.
- Persistence-Cache liest weiterhin nur die Mitgliedschaftstopologie, `group_name` bleibt beim Cache-Hit `None` — der Live-Resolver liefert den Namen bei der nächsten Auswertung. Keine DB-Migration nötig.

### Tests
- Vier neue Engine-Tests für die SID-Name-Auflösung (Membership-Name, sid_names-Fallback, ACE-Trustee, voller Fallback ohne Namen).

---

## [0.2.0-rc10] — 2026-05-30

**Phase 2b: Scan-Tab in Slint funktional + Klartext-Rechte.**

### Hinzugefügt
- Scan-Tab in Slint vollständig verdrahtet: Live-Tabelle, klickbare Zeilen mit Aufklappen des Berechtigungspfads, Filter, Fehlerliste, farbcodierte Risikobefunde, HTML-Export-Sektion.
- Drei neue Slint-ViewModels (`ScanRowVm`, `ScanErrorVm`, `RiskItemVm`).
- Cancel-Token aus `spawn_worker` wird jetzt tatsächlich gehalten und an den Abbrechen-Button gebunden — der vorherige `_cancel` wurde verworfen.

### Geändert
- Analyze-Tab zeigt die effektiven Rechte als Langform mit icacls-Kürzel (`Modify (M)` statt nur `M`), damit Auditor und icacls 1:1 abgleichbar sind.

---

## [0.2.0-rc9] — 2026-05-30

**SAM-Pfad: Identitäten und Gruppen ohne LDAP auflösen, plus echter UNC-Test.**

### Hinzugefügt
- Neues Modul `ad_resolver::sam` mit `lookup_account_for_sid`, `user_global_group_names`, `lookup_sid_for_account`, `resolve_identity_via_sam`. Auf einem Domain Controller liefert das die vollständige Token-SID-Liste ohne LDAP-Bind, ganz so wie Windows beim Login.

### Behoben
- `unc_components` zerlegte lokale Pfade als UNC — `C:\Windows` landete als `NetShareGetInfo("C:", "Windows")` im share_scanner und scheiterte mit Status 53, obwohl SMB gar nicht angefragt war.
- Worker fällt jetzt ohne LDAP-Haken auf den SAM-Pfad zurück; Administrator zeigt damit korrekte effektive Rechte (vorher 0x00000000, weil das nackte SID-Token keine Gruppen-SIDs trug).

### Tests
- Vier locale-unabhängige Smoke-Tests gegen `S-1-5-32-544` und `S-1-5-18` (funktionieren auch auf deutsch lokalisierten Systemen, wo `BUILTIN` zu `VORDEFINIERT` wird).
- Zwei Negativtests und ein `#[ignore]`-Integrationstest gegen einen lokalen Administrator.

---

## [0.2.0-rc8] — 2026-05-30

**Phase 2a: Analyze-Tab in Slint funktional.**

### Hinzugefügt
- TabWidget mit drei Tabs (Analyze gefüllt, Scan + Delta als Platzhalter).
- Analyze-Eingaben mit Pfad, SID, optionaler LDAP-Sektion (inkl. Password-Input-Type und insecure-Flag) und optionaler SMB-Sektion.
- Analyze-Ergebnis: Rechte-Label, Access-Mask als Hex, Share-Status-Erläuterung, vollständiger Berechtigungspfad nummeriert.
- Worker-Anbindung über `NotifyFn` (Arc-Callback) statt egui-Context; Slints `invoke_from_event_loop` pumpt die Events im UI-Thread.

---

## [0.2.0-rc7] — 2026-05-30

**Phase 1: Wechsel von eframe/wgpu auf Slint mit Software-Renderer.**

### Geändert
- GUI-Crate von eframe/wgpu auf Slint 1.x mit `renderer-software` umgestellt. Slint schreibt direkt in eine GDI-Bitmap und läuft damit auf einem Windows-Server-Domain-Controller unter Proxmox mit VirtIO-GPU, wo eframe/wgpu mangels D3D12-/modernem-OpenGL-Pfad scheiterte.
- `SLINT_BACKEND=winit-software` hart gesetzt, damit kein Szenario auf einen GPU-Pfad zurückfällt.

### Entfernt
- Alle bisherigen eframe-basierten View-Dateien (`analyze_view.rs`, `scan_view.rs`, `delta_view.rs`, `identity_picker.rs`, `app.rs`, `worker.rs` mit egui-Kopplung) — konsequent gelöscht, kein Frankenstein-Stack.

---

## [0.2.0-rc4 — rc6] — 2026-05-30 (zurückgezogene wgpu-Versuche)

Drei kurzlebige Releases, die das wgpu-Backend auf einem Server ohne GPU lauffähig zu machen versuchten. Die Quintessenz: ein GPU-basiertes Toolkit ist auf einem DC mit VirtIO-GPU der falsche Stack. Inhaltlich Zwischenstationen, die mit `rc7` (Wechsel zu Slint Software-Renderer) obsolet wurden — aber lehrreich als Dokumentation des Sackgassen-Pfads.

### rc6
- wgpu-Instance und Adapter selbst vorab via `force_fallback_adapter: true` erstellen (WARP), an eframe als `WgpuSetup::Existing` übergeben.

### rc5
- `native_adapter_selector` mit Adapter-Logging und Reihenfolge echte GPU → WARP → letzter Ausweg. Auf dem DC lieferte `enumerate_adapters` weiterhin null — der Selector half nicht.

### rc4
- Logfile (`%LOCALAPPDATA%\Stars\logs\stars-gui.log`), Panic-Hook und MessageBox-Fallback eingeführt, damit Startfehler auf einem nackten Server überhaupt sichtbar werden.
- eframe von glow (OpenGL) auf wgpu (DX12) umgestellt, weil OpenGL in RDP-Sessions stillschweigend scheitert.

---

## [0.2.0-rc3] — 2026-05-25

### Behoben
- MSVC-CRT statisch linken, damit `Stars.exe` ohne installiertes VC-Redist startet.

### Dokumentation
- README-Download-Sektion mit Release-Badge auf die Startseite.

---

## [0.2.0-rc2] — 2026-05-25

**Großer Audit-Pass mit vielen Review-Findings.**

### Hinzugefügt
- `update_manager` mit Manifest-Schema, pluggable Signaturprüfung und Migrations-Logik.
- HTML-Summary trägt eine Diagnostics-Karte für unvollständige Pfade.
- CLI zeigt strukturierte `PermissionDiagnostic`-Marker pro Pfad.
- GitHub Actions Workflow für fmt + clippy + test bei jedem Push.
- Test-Umgebungsdaten (7 Abteilungen, 10 Test-Benutzer, Abteilungs-Fileserver) als Skripte.

### Behoben
- `share_scanner` wertet Share-DACL in Stored Order aus.
- Share-Token nutzt `AccessContext`.
- `matched_aces` filtert INHERIT_ONLY-Einträge.
- NULL-DACL-Klassifikation korrigiert.
- `SensitivePathRule` setzt effektiven Zugriff voraus (vorher Falschmeldung bei deny-all).
- Unsupported Share-ACEs werden als strukturierte Diagnose durchgereicht.
- `max_depth` wird durch den Validator am Boundary geprüft.
- Persistence: v1-Daten überleben Migration auf v6.

### Architekturentscheidung
- ADR 0026 — `ShareScanResult.share_dacls` trägt `ShareDaclScan`.

---

## [0.2.0-rc1] — 2026-05-24

**Erste Release-Candidate-Reihe mit kompletter Re-Review-Welle.**

### Hinzugefügt
- `JsonExporter`-Implementierung.
- `ShareMaskStatus::Unrestricted` für NULL-Share-DACLs (statt erfundener `0xFFFFFFFF`-Maske).
- `LocalGroupEvalStatus` als strukturierter Status der lokalen Gruppenauflösung.
- `AccessContext` für token-SIDs (`NETWORK` bei SMB, `INTERACTIVE`/`LOCAL` bei lokalem Zugriff).
- Strukturierte Diagnose-Marker pro Berechtigung in Core, Engine, Persistence, Exporter, GUI.
- Risikoauswertung im CLI-Pfad samt Export.
- Abbrechbare lange Scans (`CancellationToken`).
- `DirectUserAceRule` stützt sich auf strukturierte ACE-Daten (`matched_aces`) statt auf den Erklärungstext — lokalisierungssicher.
- `AdminRightsRule` erfasst destruktive und administrative Einzelrechte (`WRITE_DAC`, `WRITE_OWNER`, `DELETE`, `DELETE_CHILD`).
- AD-Identitäts-Picker in der GUI.
- LDAPS-Default (plain LDAP nur mit explizitem `--insecure-ldap`).
- Setup-Anleitung und Skripte für die AD-Integrationstest-Umgebung.

### Behoben
- NULL-DACL wird im kombinierten Scan korrekt erhalten.
- GUI-Scans persistieren Walk- und Eval-Fehler.
- Long-Path-Normalisierung für Win32 (`\\?\` / `\\?\UNC\…`).
- Paged LDAP-Search und transitive Gruppen via `LDAP_MATCHING_RULE_IN_CHAIN`.
- `Debug`-Impl von `LdapParams` maskiert das Bind-Passwort, damit `{params:?}` keine Secrets in Logs schreibt.
- Windows-Pfade werden strenger validiert; CSV trägt jetzt auch `local_group_status`, `matched_aces`, `contributing_sids`.
- Share-DACL-Lesefehler werden als Warnung im Risiko-View sichtbar (`Incomplete`-Marker).
- Exportdatei nur mit `--force` überschreiben.
- `share_scanner` mit Level-502-Enumeration, lokalem Pfad und Localhost-UNC-Behandlung.
- `BroadGroupWriteRule`: False-Positive behoben — meldet jetzt nur, wenn der breite Principal tatsächlich Write-Bits beigetragen hat.

---

## [0.1.0] — 2026-05-21

**Erste lauffähige Version: CLI, GUI-Prototyp, alle Kern-Crates.**

### Hinzugefügt
- Workspace-Setup mit `adpa_core` und `ad_resolver`.
- NTFS-DACL-Lesen via `GetNamedSecurityInfoW` (`fs_scanner`).
- ACE-Normalisierung über `NormalizedRights`.
- Effektive-NTFS-Berechtigungs-Berechnung in `permission_engine`.
- CLI-Prototyp mit formatierter Ausgabe (Steps 8 + 9).
- CSV-Export mit CLI-`--output`-Flag (Step 10).
- SQLite-Cache und Scan-Historie (`persistence`, Step 11).
- Mehr-Ordner-Tree-Scan mit DB-Persistenz (Step 12).
- SMB-Share-Scanner (`share_scanner`, Step 13).
- NTFS ∩ Share-Kombination im CLI-Scan (Step 14).
- GUI-Prototyp mit `egui`/`eframe`, Analyze- und Scan-Tab (Step 15).
- Risk-Engine, HTML-Export, Delta-Vergleich, Installer-Skript (Steps 16-19).
- README mit Projektbeschreibung, Nutzung und Entwicklungsstand.
- GitHub-Actions-Release-Pipeline.

---

## Urheberschaft

**Konzeption, Spezifikation, Steuerung und Review:** Birger Labinsch — Fachinformatiker Anwendungs­entwicklung / Prompt Engineer.
**Implementierung:** Claude Opus 4.7 (Anthropic) als KI-Modell, unter direkter Anleitung von Birger Labinsch.

Jeder Commit dieses Repositories trägt eine `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`-Zeile, die den KI-Anteil pro Änderung sichtbar macht.
