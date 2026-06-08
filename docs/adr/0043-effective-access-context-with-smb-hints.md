# ADR 0043 — Effective Access Context bei explizitem SMB-Kontext

**Status:** Accepted
**Date:** 2026-06-05

## Context

`AccessContext::for_path(&path)` leitet den Logon-Kontext aus der **Pfadform** ab:

- UNC-Pfad (`\\server\share\…`) → `RemoteSmb` (fügt `NETWORK` in den Token)
- Lokaler Pfad (`C:\…`) → `LocalInteractive` (fügt `INTERACTIVE` + `LOCAL`)

Für die typischen Auditing-Aufrufe ist das richtig. Es bricht aber in einem realen Auditing-Szenario, das in CLI und GUI bewusst zugelassen ist:

```text
adpa.exe analyze --path "D:\Shares\Data" --user "DOMAIN\alice" \
    --smb-server fs01 --share-name Data
```

Der Auditor sitzt **lokal auf dem Fileserver** und will die effektive **SMB**-Berechtigung der Freigabe wissen. Stars liest die Share-DACL korrekt vom expliziten SMB-Ziel — aber der Token-Kontext wurde weiterhin aus dem lokalen Pfad abgeleitet und blieb `LocalInteractive`. Konsequenz:

- `NETWORK` (S-1-5-2) **fehlte** im Token.
- Share-DACL-ACEs auf `NETWORK` (z. B. ein `Deny NETWORK Read` auf der Freigabe) wirkten dadurch nicht.
- ACEs auf `INTERACTIVE` und `LOCAL` wirkten dagegen fälschlich, obwohl der Audit eine Remote-Sicht modellieren sollte.

Round-7 Review Finding 1 (High) hat den Bug klassifiziert: ein Audit-Tool, das Share-Regeln gegen Well-Known-Logon-SIDs falsch aggregiert, liefert in dem real häufigsten Fall (Fileserver, lokal eingewählt) ein zu permissives Effective-Rights-Ergebnis. Das ist still falsch und damit der gefährlichste Fehler-Klassentyp für ein Read-only-Auditing-Tool.

## Decision

Neue Helfer-Methode `AccessContext::for_path_with_smb`:

```rust
pub fn for_path_with_smb(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Self {
    let has_explicit_smb =
        smb_server.map(|s| !s.is_empty()).unwrap_or(false)
        || share_name.map(|s| !s.is_empty()).unwrap_or(false);
    if has_explicit_smb {
        return Self::RemoteSmb;
    }
    Self::for_path(path)
}
```

Regeln:

- Beide SMB-Hint-Felder sind `Option<&str>` (genau wie sie aus `clap`/Slint kommen) und werden auf „nicht leer" geprüft. Ein leerer GUI-Textinput zwingt nicht.
- Sobald **mindestens einer** der beiden SMB-Hints gesetzt ist, ist der Kontext `RemoteSmb` — auch wenn der Pfad lokal aussieht.
- Sonst fällt die Funktion auf die bestehende `for_path`-Heuristik zurück, sodass UNC weiter zu `RemoteSmb` führt und lokale Pfade zu `LocalInteractive`.

Sechs Call-Sites in CLI und GUI nutzen den Helfer:

- `crates/cli/src/main.rs::analyze` — Share-Status und Engine-Input
- `crates/cli/src/main.rs::scan` — pro Scan-Ergebnis
- `crates/gui/src/worker.rs::handle_analyze` — Share-Status (1) und Engine-Input (2)
- `crates/gui/src/worker.rs::handle_scan` — Share-Status (1) und Scan-Resultat-Aggregation (2)

`AccessContext::for_path` bleibt erhalten — sie ist der korrekte Fall für reine Pfad-Ableitung ohne SMB-Hint, und Tests/Code, die sie direkt nutzen, müssen nicht geändert werden.

## Consequences

### Positiv

- **Stille Fehlauswertung beseitigt**: der real häufigste Audit-Fall (Fileserver, lokal eingewählt) modelliert jetzt korrekt eine Remote-SMB-Sicht.
- **Konsistenz zwischen CLI und GUI**: beide nutzen denselben Helfer, niemand verlässt sich auf doppelte Konditional-Logik.
- **Engine bleibt unverändert**: die `RemoteSmb`-Wirkung war seit ADR 0013/0019 schon korrekt; ADR 0043 stellt sicher, dass CLI/GUI sie auch tatsächlich anfordern.

### Negativ / Trade-offs

- Wer bisher absichtlich `LocalInteractive` über einen lokalen Pfad genutzt hat, *obwohl* er einen SMB-Hint mitgegeben hat, bekommt jetzt andere Ergebnisse. Das ist kein realistischer Use Case — ein SMB-Hint impliziert per Definition eine Remote-Sicht — aber als Breaking-Change-Notiz festhalten.
- `AccessContext::for_path` und `for_path_with_smb` koexistieren. Vermeidet Doppel-Logik, weil `for_path_with_smb` intern `for_path` aufruft.

### Tests

In `crates/core/src/model.rs::tests`:

- `access_context_for_path_with_smb_forces_remote_when_smb_server_given`
- `access_context_for_path_with_smb_forces_remote_when_share_name_given`
- `access_context_for_path_with_smb_keeps_unc_as_remote`
- `access_context_for_path_with_smb_keeps_local_when_no_smb_hint`
- `access_context_for_path_with_smb_ignores_empty_smb_hints`

In `crates/permission_engine/src/engine.rs::tests` als End-to-End-Sicherung:

- `remote_smb_context_grants_network_ace_even_on_local_path` — Allow NETWORK wirkt bei lokaler Pfadform + explizitem RemoteSmb.
- `local_interactive_context_ignores_network_ace` — Spiegelbild: ohne RemoteSmb darf NETWORK nicht wirken.

Live-Verifikation gegen das Lab in [`docs/lab/verification.md`](../lab/verification.md), Teil G:
Szenario E4b liefert vor dem Fix `Result = Modify`, nach dem Fix `Result = Special (0x00000000)` — der Deny-NETWORK auf der Share-Permission wirkt jetzt.

## Beziehung zu anderen ADRs

- **ADR 0013** definiert den `AccessContext`-Enum überhaupt erst.
- **ADR 0019** stellt fest, dass die Engine `NETWORK` nur unter `RemoteSmb` einfügt — das ist die Bedingung, die ADR 0043 nun von der CLI/GUI-Seite endlich konsequent durchsetzt.
