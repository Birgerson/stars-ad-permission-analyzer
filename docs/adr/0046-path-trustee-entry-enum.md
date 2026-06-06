# ADR 0046 — `PathTrusteeEntry`-Enum: ACE und Diagnose typisiert trennen

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-06

## Kontext / Context

Stars beantwortet pro Pfad die Frage „wer steht überhaupt auf der DACL?" über eine Liste `PathTrustees.trustees`. Vor dieser ADR enthielt die Liste ausschließlich `PathTrustee`-Records — also flache ACE-Beschreibungen mit `sid`, `kind` (Allow/Deny), `mask`, `inherited`, `inheritance_flags`, `propagation_flags`, `category` (NTFS/Share).

Drei Sonderzustände wurden in dieser Struktur „versteckt mitgeführt":

1. **NTFS NULL-DACL** — der Pfad hat technisch keine DACL, was im Windows-Modell „Vollzugriff für alle" bedeutet. Bisher: Pseudo-`PathTrustee` mit `sid: "S-1-1-0"`, `display_name: "Everyone (NULL DACL — no access restriction)"`, `kind: Allow`, `mask: 0x001F01FF`.
2. **Share-NULL-DACL** — analoger Fall auf SMB-Schicht. Bisher: Pseudo-`PathTrustee` mit `sid: "S-1-1-0"`, `display_name: "Everyone (Share NULL DACL — no SMB restriction)"`, `kind: Allow`, `mask: 0x001F01FF`.
3. **Share-DACL-Lesefehler** — die Share-DACL konnte nicht gelesen werden (Zugriff verweigert, Timeout, parsen gescheitert). Bisher: Pseudo-`PathTrustee` mit `sid: ""`, `display_name: "Share-DACL nicht lesbar: <Fehlertext>"`, `kind: Allow`, `mask: 0`.

Review-Runde 10 Finding 4 hat die Modellierung als **semantisch unscharf** klassifiziert. Drei konkrete Probleme:

- **JSON-Konsumenten konnten Diagnose nicht von ACE unterscheiden.** Ein Audit-Tool, das `path_trustees[].kind == "Allow"` auf alle Einträge zählt, würde Lesefehler und NULL-DACL-Hinweise als reale Allow-ACEs interpretieren. Das könnte Risikoanalysen verzerren.
- **Eine leere SID (`""`) ist kein valider Identitäts-Identifier.** Strict-validierende Pipelines könnten den Eintrag verwerfen — und damit den Diagnose-Hinweis stillschweigend droppen.
- **Maske `0`** im Fehler-Fall sieht wie ein „Allow mit keinerlei Rechten" aus. Auch das ist ein Modell-Misshandling: der Eintrag ist kein ACE, sondern ein Meta-Hinweis.

Die GUI hat das visuell richtig gerendert (über `display_name` als Erklärungstext), aber das war eine Konvention, kein Typsystem. Ein zweiter Render-Code-Pfad oder ein anderer JSON-Konsument hätte das Modell falsch interpretieren können.

## Entscheidung / Decision

Wir ersetzen `PathTrustees.trustees: Vec<PathTrustee>` durch `PathTrustees.trustees: Vec<PathTrusteeEntry>`, wobei `PathTrusteeEntry` ein **typisiertes Enum** ist:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entry_kind", rename_all = "snake_case")]
pub enum PathTrusteeEntry {
    Ace(PathTrustee),
    Diagnostic {
        category: TrusteeCategory,
        message: String,
    },
}
```

Damit:

- **Echte ACEs** werden als `PathTrusteeEntry::Ace(PathTrustee)` getragen — die `PathTrustee`-Struct selbst bleibt unverändert, alle ihre Felder (`sid`, `kind`, `mask`, ...) haben semantisch ihre echte Bedeutung.
- **Diagnose-Hinweise** werden als `PathTrusteeEntry::Diagnostic { category, message }` getragen — keine SID, keine Maske, keine Allow/Deny-Etikette. Nur die fachlich relevanten Felder: an welcher Schicht (NTFS oder Share) tritt der Hinweis auf, und was ist seine menschenlesbare Begründung.

### Warum `entry_kind` und nicht `kind` als Tag?

Internally-tagged Serde-Enums benutzen ein Feld im JSON-Output als Discriminator. Das natürliche Wort wäre `"kind"`. **Aber**: `PathTrustee` traegt bereits ein Feld `pub kind: AceKind` (Allow/Deny). Ein Tag namens `"kind"` würde dieses Feld im JSON silently überschreiben — Serde verhindert das nicht beim Compile-Schritt, sondern liefert ein irreführendes JSON-Output.

Wir wählen deshalb bewusst `tag = "entry_kind"`. Damit ist im JSON klar:

- `entry_kind: "ace"` oder `entry_kind: "diagnostic"` — die *Variante* der Liste.
- `kind: "Allow"` oder `kind: "Deny"` — der *ACE-Typ* (nur in Ace-Variante vorhanden).

### Konkretes JSON-Beispiel (Schema v3)

```json
{
  "version": 3,
  "path_trustees": [
    {
      "path": "C:\\Audit",
      "trustees": [
        {
          "entry_kind": "ace",
          "sid": "S-1-5-32-544",
          "display_name": "BUILTIN\\Administrators",
          "kind": "Allow",
          "mask": 2032127,
          "inherited": true,
          "inheritance_flags": 0,
          "propagation_flags": 0,
          "category": "Ntfs"
        },
        {
          "entry_kind": "diagnostic",
          "category": "Share",
          "message": "Share-DACL nicht lesbar / share DACL not readable: timeout"
        }
      ]
    }
  ]
}
```

Vor v3 hätte der Diagnose-Eintrag wie ein normaler ACE ausgesehen: `"kind": "Allow", "sid": "", "mask": 0`. Jetzt ist er strukturell ein anderes Objekt mit anderem Feld-Set — formal nicht verwechselbar.

### Schema-Versions-Bump

`JSON_SCHEMA_VERSION` wird von 2 auf 3 angehoben. Das ist ein **Breaking Change** für JSON-Konsumenten — alte Parser, die `path_trustees[].kind == "Allow"` direkt lesen, brauchen ein Update auf:

```pseudocode
if entry.entry_kind == "ace":
    use entry.kind, entry.sid, entry.mask, ...
elif entry.entry_kind == "diagnostic":
    use entry.message, entry.category   # NOT an ACE
```

Wir akzeptieren den Bruch, weil:

- JSON-Schema-Versionierung ist genau für solche Fälle da.
- Die Alternative (Option-Feld `synthetic_reason` zusätzlich zum Pseudo-ACE) wäre kompatibler, aber semantisch unsauber — der „flache" Eintrag würde *weiterhin* wie ein ACE aussehen, nur mit zusätzlichem Marker. Das ist eine Variante des ursprünglichen Bugs, nicht seine Auflösung.
- Stars ist v1.5.x und nicht 1.0 — wir sind noch in einer Phase, in der Schema-Breaks legitim sind, solange sie dokumentiert und versioniert sind.

### Render-Anpassungen

- **HTML** (`exporter::html::write_trustees_table`): Diagnose-Zeilen erhalten einen gelblichen Hintergrund (`#fff7d6`), ein Warn-Symbol (⚠), kursive Schrift und kein Allow/Deny-Label. ACEs bleiben unverändert.
- **GUI Slint-Renderer** (`gui::worker::trustee_row_for_display`): Diagnose-Einträge werden als Zeile mit `kind: "Diagnose"` und em-dash-Strichen in den ACE-spezifischen Spalten (Rechte/Maske/Quelle/Anwendung) dargestellt; der `display_name` enthält den Begründungstext mit Warn-Glyph.
- **JSON** (`exporter::json`): wie oben gezeigt — `entry_kind`-Tag macht die Variante eindeutig.
- **CSV** (`exporter::csv`): unverändert, weil CSV nur den identitätsbezogenen `EffectivePermission`-Block exportiert, nicht `path_trustees`.

### Tests

Vier neue / aktualisierte Tests verifizieren die Invarianten:

| Test | Was er garantiert |
|---|---|
| `null_dacl_yields_typed_diagnostic_not_synthetic_ace` | NULL-DACL ist `Diagnostic`, **nicht** `Ace`. Schützt vor Regression auf das ursprüngliche Modell. |
| `diagnostic_and_ace_have_distinct_json_tags` | `entry_kind` ist im JSON-Output unterschiedlich: `"ace"` vs `"diagnostic"`. |
| `export_includes_path_trustees_with_typed_diagnostic` | Ende-zu-Ende: `JsonExporter` schreibt Schema v3 mit gemischter Ace+Diagnostic-Liste. Plus: Diagnose-Eintrag traegt **kein** `sid`-Feld. |
| `ntfs_only_yields_all_ntfs_trustees`, `share_overlay_is_appended_to_ntfs_trustees` | Bestehende Tests an das Enum angepasst — verifizieren, dass die GUI- und CLI-Pfade kategorisch korrekt befüllen. |

## Konsequenzen / Consequences

### Positiv

- **JSON-Konsumenten können Diagnose nicht mehr versehentlich als ACE interpretieren.** Der Audit-Pipeline-Anwendungsfall ist robust gegen das alte Misshandling.
- **Typsystem statt Konvention.** Wer im Code einen `PathTrusteeEntry` hat, *muss* matchen — der Compiler erzwingt, dass beide Varianten behandelt werden. Vorher konnte man einen `PathTrustee` lesen und vergessen, dass `sid == ""` und `mask == 0` möglicherweise ein Diagnose-Hinweis ist.
- **Saubere Render-Trennung.** HTML- und GUI-Renderer leiten ihre Darstellung aus der Variante ab, nicht aus String-Konventionen im `display_name`.
- **Erweiterbar.** Wenn künftig weitere Diagnose-Kategorien dazukommen (zum Beispiel „canonical ordering verletzt" oder „ACE-Typ nicht unterstützt"), kann das als Erweiterung der `Diagnostic`-Variante oder als neue Enum-Variante erfolgen, ohne dass alte Felder umgewidmet werden.

### Negativ / Trade-offs

- **JSON-Schema-Bruch von 2 auf 3.** Ein externer Konsument muss sein Parsing aktualisieren. Wir dokumentieren den Bruch in `JSON_SCHEMA_VERSION`-Doc und im CHANGELOG.
- **Mehr Match-Arme in Render-Code.** HTML und GUI haben jetzt explizite `match`-Blöcke statt einer linearen Iteration. Das ist mehr Code, aber das Mehr ist genau der Typ-Safety-Gewinn.
- **Tag-Name `entry_kind`** ist kein-zucker-Wort — aber er ist der einzige korrekte Weg, um die Kollision mit dem ACE-`kind`-Feld zu vermeiden. Die Begründung steht im Modell-Kommentar und in dieser ADR.

### Beziehung zu anderen ADRs

- **ADR 0044** (Pfadzentrische Trustees als shared module) — hat das gemeinsame `exporter::trustees`-Modul eingeführt, in dem die jetzige Umstellung lebt.
- **ADR 0038** (Share-Trustees im Scan-Pfad) — beschreibt, wie der Share-Overlay einmal pro Share gelesen wird. Diagnose-Hinweise für Read-Failures werden jetzt typisiert getragen.
