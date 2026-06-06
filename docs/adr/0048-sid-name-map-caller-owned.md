# ADR 0048 — SID→Name-Map als Caller-Verantwortung im Trustee-Modul

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-06

## Kontext / Context

Das `exporter::trustees`-Modul (ADR 0044) baut für jeden Pfad eine Liste von Trustee-Einträgen. Damit der Auditor lesbare Identitäten statt nackter SIDs sieht, löst das Modul jede ACE-SID per LSA (`LookupAccountSidLocal`) in einen Namen wie `BUILTIN\Administrators` auf.

Bisher passierte dieser Lookup **inside** der Build-Funktion, einmal pro Aufruf:

```rust
pub fn build_path_trustees_with_share(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrusteeEntry> {
    // ... baue out ...
    #[cfg(windows)]
    {
        let sids: Vec<String> = out.iter().filter_map(...).collect();
        let map = ad_resolver::build_sid_name_map(&[], sids);
        for entry in &mut out {
            // setze display_name aus map
        }
    }
    out
}
```

Im Analyze-Pfad (genau ein Pfad) ist das semantisch OK. Im **Scan-Pfad** (potenziell zehntausende Pfade unter einem Wurzel-Verzeichnis) ist es ein Performance-Problem:

- Stars-Projektregel: „große Umgebungen sind der Standardfall, nicht die Ausnahme".
- 50.000 Pfade × ~5 distinct SIDs in der DACL = 250.000 LSA-Lookups, davon ~99 % Wiederholungen derselben Standard-SIDs (`S-1-5-32-544` = BUILTIN\Administrators, `S-1-5-18` = SYSTEM, `S-1-5-11` = Authenticated Users, Domain-Gruppen).
- LSA-Lookups sind nicht trivial — sie können remote sein, RPC-Overhead haben, in Multi-Domain-Wäldern fehlschlagen.

Beide Konsumenten — `cli::main::run_scan` und `gui::worker::sweep_one_root` — bauten zusätzlich **eine scanweite SID→Name-Map für die Engine-Erklärungspfade**:

```rust
// CLI scan
let scan_sid_names = {
    let trustees: Vec<String> = walk.objects.iter()
        .flat_map(|fso| fso.dacl.iter())
        .filter_map(|ace| { /* unique SID */ })
        .collect();
    ad_resolver::build_sid_name_map(&memberships, trustees)
};
```

Diese Map wurde an `PermissionEvaluationInput.sid_names` weitergereicht — damit der Engine-Erklärungspfad (`EffectivePermission.path_explanation`) lesbare Namen hat. Sie war aber **für `path_trustees` nicht zugänglich**. Konsequenz:

| Komponente | Nutzte Scan-Map? |
|---|---|
| `EffectivePermission.path_explanation` | ✅ ja (über `PermissionEvaluationInput.sid_names`) |
| `path_trustees` Display-Namen | ❌ nein (machte LSA pro Pfad) |

Review-Runde 10 Finding 2 hat das als Medium klassifiziert.

## Entscheidung / Decision

Wir trennen die Build-Funktion von der SID-Name-Auflösung. Die Map wird **vom Aufrufer** befüllt und an die Build-Funktion übergeben — Layering wird damit ehrlich: Trustee-Bau ist Datentransformation, LSA-Lookup ist eine externe Abhängigkeit, und die wird sichtbar im Aufrufer.

### Neue Schnittstelle

```rust
// crates/exporter/src/trustees.rs

/// Sammelt alle ACE-SIDs aus FSO-DACL und Share-Overlay, die einer
/// LSA-Aufloesung beduerfen. Diagnose-Eintraege haben keine SID und
/// werden uebersprungen.
pub fn collect_ace_sids_for_resolution(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<String>;

/// Trustee-Build OHNE eingebauten LSA-Lookup. Der Aufrufer liefert die
/// vorab gebaute SID→Name-Map.
pub fn build_path_trustees_with_share_and_names(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
    sid_names: &BTreeMap<String, String>,
) -> Vec<PathTrusteeEntry>;
```

Die beiden bestehenden Funktionen `build_path_trustees` und `build_path_trustees_with_share` bleiben für den Analyze-Pfad erhalten und delegieren intern an die Map-Variante — **mit einer per-Aufruf gebauten Map**. Damit:

- **Analyze-Pfad** (CLI `run_analyze`, GUI Analyze-Tab): API unverändert, Verhalten unverändert.
- **Scan-Pfad** (CLI `run_scan`, GUI Scan-Tab): nutzt explizit die Map-Variante mit der scanweiten Map.

Keine Code-Duplikation — die Map-Variante ist die Implementierung, alle anderen sind Wrapper.

### Was der Scan-Caller jetzt tut

```rust
// 1. Share-Overlay einmal pro Scan lesen (ADR 0044).
let share_overlay = SmbAuditContext::resolve(...).map(|c| read_share_overlay(...));

// 2. SIDs SAMMELN (NTFS-DACL + Share-Overlay).
let unique_sids = {
    let mut seen = HashSet::new();
    let mut sids = Vec::new();
    for fso in &walk.objects {
        for sid in collect_ace_sids_for_resolution(fso, share_overlay.as_ref()) {
            if seen.insert(sid.clone()) { sids.push(sid); }
        }
    }
    sids
};

// 3. Eine LSA-Runde fuer den ganzen Scan.
let scan_sid_names = ad_resolver::build_sid_name_map(&memberships, unique_sids);

// 4. Pro Pfad: keine LSA mehr, nur Map-Lookup.
for fso in &walk.objects {
    let trustees = build_path_trustees_with_share_and_names(
        fso, share_overlay.as_ref(), &scan_sid_names,
    );
    // ...
}
```

### Wo die Map verwendet wird

| Aufrufstelle | Map-Quelle | LSA pro Pfad? |
|---|---|---|
| CLI `run_analyze` (Trustees) | per-Aufruf in `build_path_trustees` (intern, da nur 1 Pfad) | ja, aber n=1 |
| CLI `run_scan` (Trustees) | scanweite `scan_sid_names`, jetzt inkl. Share-Overlay-SIDs | **nein** |
| CLI `run_scan` (Engine-Erklärungspfad) | dieselbe Map über `PermissionEvaluationInput.sid_names` | unverändert |
| GUI Analyze (Trustees) | per-Aufruf, n=1 | ja, aber n=1 |
| GUI Scan (Trustees) | scanweite `scan_sid_names`, jetzt inkl. Share-Overlay-SIDs | **nein** |

Die scanweite Map deckt jetzt **drei Konsumenten** ab statt zwei: Engine-Erklärungspfad, GUI-/HTML-Render der Trustees, JSON-Export der Trustees.

### Tests

Drei neue Unit-Tests sichern die Invarianten:

| Test | Was er garantiert |
|---|---|
| `caller_owned_map_sets_display_names` | ACE-Display-Namen werden aus der uebergebenen Map gesetzt. |
| `caller_owned_map_does_not_touch_diagnostics` | Diagnose-Eintraege (NULL DACL, Share-Read-Fehler) werden NICHT mit einem fremden Display-Name ueberschrieben. |
| `collect_ace_sids_for_resolution_covers_ntfs_and_share` | Helper sammelt NTFS-ACE-SIDs UND Share-Overlay-ACE-SIDs; Diagnose-Eintraege werden uebersprungen. |

## Konsequenzen / Consequences

### Positiv

- **Performance bei großen Scans.** Statt N × M LSA-Lookups (N Pfade × M SIDs pro Pfad) jetzt M_unique LSA-Lookups pro Scan. Für die Stars-Standardfälle (großer Dateibaum, wenige unique SIDs) bedeutet das eine drei- bis vierstellige Reduktion des LSA-Round-Trips.
- **Konsistenz zwischen Engine-Erklärungspfad und Trustee-Display.** Beide Konsumenten teilen jetzt dieselbe Map — eine Identität, ein Display-Name, kein Aliasing-Risiko.
- **Sichtbare Abhängigkeit.** Der Scan-Caller sieht im Code, dass er einen LSA-Lookup macht. Das ist semantisch ehrlicher: das Trustee-Modul ist datentransformierend, der LSA-Aufruf ist Infrastruktur.
- **Share-Overlay-SIDs werden jetzt mit aufgelöst.** Vorher waren Share-Overlay-SIDs in der scanweiten Map nicht enthalten (sie kam nur aus `fso.dacl`). Jetzt sammelt der Helper aus beiden Quellen.
- **Plattform-unabhängige Tests.** `caller_owned_map_*`-Tests laufen auf CI-Linux durch, weil sie keine echte LSA brauchen — sie übergeben eine BTreeMap und prüfen die Map-Anwendung.

### Negativ / Trade-offs

- **API-Erweiterung.** Eine zusätzliche Funktion (`build_path_trustees_with_share_and_names`) und ein zusätzlicher Helper (`collect_ace_sids_for_resolution`). Im Workspace sauber gekapselt, Re-Export aus `exporter::lib` und `gui::worker`.
- **Per-Aufruf-Map bleibt für die einfache Form.** `build_path_trustees_with_share` baut intern eine eigene per-Aufruf-Map auf — für den Analyze-Pfad (n=1) ist das exakt der frühere Aufwand, kein Regress, aber auch keine Verbesserung. Die Map-Variante ist die Optimierung für die N-Pfad-Fälle.
- **Scan-Loop-Initialisierung etwas mehr Code.** Der Scan-Caller muss SIDs sammeln und die Map aufbauen, bevor er die Pfade verarbeitet. Das ist explizit so gewollt — die Sichtbarkeit der Abhängigkeit ist ein Ziel, nicht ein Trade-off.

### Beziehung zu anderen ADRs

- **ADR 0036** (Unified Principal Resolution Pipeline): „eine Datenquelle, beide Konsumenten" — diese ADR setzt dasselbe Prinzip für die Trustee-SID-Auflösung um.
- **ADR 0044** (Pfadzentrische Trustees als shared module): das Modul wird hier erweitert, nicht verändert. Die Schnittstelle bleibt für Analyze-Konsumenten kompatibel.
- **ADR 0047** (SmbAuditContext): die Share-Overlay-SIDs, die jetzt in die Map einfließen, kommen aus dem Overlay, der über `SmbAuditContext` aufgebaut wird — beide Round-10-Fixes greifen sauber ineinander.
