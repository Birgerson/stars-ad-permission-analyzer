# ADR 0025 — NULL-DACL-Klassifikation: `bDaclPresent=TRUE, pDacl=NULL` ist NULL DACL

**Status:** Accepted  
**Date:** 2026-05-25

## Context

Per Win32-Doku (`GetSecurityDescriptorDacl`):

| `bDaclPresent` | `pDacl`     | Bedeutung                                           |
|----------------|-------------|-----------------------------------------------------|
| `FALSE`        | egal        | DACL nicht im SD → **NULL DACL** → unrestricted     |
| `TRUE`         | `NULL`      | explizit gesetzte **NULL DACL** → unrestricted      |
| `TRUE`         | non-NULL, `AceCount=0` | leere DACL → **deny all**                |
| `TRUE`         | non-NULL, `AceCount>0` | normale DACL                              |

Der bisherige `parse_share_dacl` machte aus dem zweiten Fall — `present=TRUE, pDacl=NULL` — fälschlich eine **leere DACL** (`Ok(Some((Vec::new(), 0)))` → `ShareDacl::Acl(vec![])`). Die Engine evaluierte das als `Some(AccessMask(0))` → **kein Zugriff**.

Konsequenz: Eine unrestricted Share-NULL-DACL erschien in Reports als „no SMB access". Bei `effective = NTFS ∩ Share` blockierte das jeden NTFS-Zugriff im Effektivergebnis — eine direkte Falsch-Negativ-Quelle für Share-Audits.

Review 2026-05-25, Finding 1 (High).

## Decision

1. **Neue reine Klassifikationsfunktion `classify_dacl(present, ptr_is_null, ace_count) → DaclClassification`** in `share_scanner::scanner`. Drei Ergebnisse:

   - `Null` — unrestricted (Fälle 1 und 2 oben)
   - `Empty` — deny-all (Fall 3)
   - `Normal` — auswertbare DACL (Fall 4)

   Die Funktion enthält keine Win32-Aufrufe und ist damit isoliert unit-testbar — was vorher der Win32-Pointer-Pfad in `parse_share_dacl` versperrte.

2. **`parse_share_dacl` ruft `GetAclInformation` nur wenn `pDacl != NULL`.** Bei null-Pointer wird `ace_count = 0` gesetzt; `classify_dacl` kürzt vor diesem Wert ab (`ptr_is_null` short-circuit). Damit ist `GetAclInformation(NULL, …)` als potentielles UB ausgeschlossen.

3. **Im Anschluss matched `parse_share_dacl` auf die Klassifikation:**
   - `Null` → `Ok(None)` (führt zu `ShareDacl::NullDacl`)
   - `Empty` → `Ok(Some((vec![], 0)))` (führt zu `ShareDacl::Acl(vec![])`)
   - `Normal` → ACE-Loop wie bisher

## Rationale

- **Korrektheit ist nicht verhandelbar** (AGENTS.md Grundregel 1). Eine unrestricted Share, die als „kein Zugriff" gemeldet wird, untergräbt die fundamentale Audit-Funktion.
- **Reine Klassifikation = direkt testbar**: ohne den Helfer hätte jeder Test einen echten Win32-Security-Descriptor brauchen — praktisch unmöglich ohne Integration gegen einen echten Share. Der Helfer kapselt die fehleranfällige Logik in eine vollständig isolierte Funktion.
- **Tabellen-getriebene Tests**: die vier Zeilen der MSDN-Tabelle werden je durch einen eigenen Test geprüft. Der Bug von vorher steht als explizite Assertion mit „**MUST** classify as Null" und Kommentar dokumentiert.

## Consequences

- 4 neue Tests in `share_scanner::scanner::tests`:
  - `classify_dacl_not_present_is_null`
  - `classify_dacl_present_but_pointer_null_is_null` (der **Kern-Bugfix**)
  - `classify_dacl_present_non_null_zero_aces_is_empty`
  - `classify_dacl_present_non_null_with_aces_is_normal`
- `parse_share_dacl`-interne Struktur klarer: erst Win32-Calls, dann reine Klassifikation, dann ggf. ACE-Loop. Trennung Side-Effects / Logik.
- Keine API-Änderung — `ShareDacl::NullDacl` / `Acl(...)` und `ShareDaclScan` bleiben gleich. Externe Aufrufer sehen nur das korrigierte Verhalten.
- Keine Schemamigration.
