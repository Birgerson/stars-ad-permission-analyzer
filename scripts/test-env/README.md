# Test-Umgebungs-Skripte / Test environment scripts

Automatisierung fuer die Integrationstest-Umgebung. Vollstaendige Anleitung:
[`docs/testing/integration-test-setup.md`](../../docs/testing/integration-test-setup.md).

Automation for the integration test environment. Full guide:
[`docs/testing/integration-test-setup.md`](../../docs/testing/integration-test-setup.md).

| Skript | Ausfuehren auf | Zweck |
|--------|----------------|-------|
| `01-setup-dc.ps1` | Test-VM (Windows Server) | DC fuer `testdomain.local` hochstufen — VM startet neu |
| `02-setup-ad-objects.ps1` | Test-VM (nach Neustart) | Testbenutzer, -Gruppen und Verschachtelung anlegen |
| `03-setup-fileserver.ps1` | Test-VM | Test-Ordner, NTFS-ACLs und SMB-Freigaben anlegen |
| `04-run-integration-tests.ps1` | Entwicklungsrechner | `cargo test -- --ignored` gegen die Test-Domaene |
| `99-teardown.ps1` | Test-VM | Testdaten und AD-Test-OU entfernen |

> **Warnung:** `01-setup-dc.ps1` erfordert **Windows Server** und stuft den
> Rechner zum Domaenencontroller hoch (Neustart). Niemals auf einer
> Arbeitsstation ausfuehren. Vorher einen VM-Snapshot anlegen.
>
> **Warning:** `01-setup-dc.ps1` requires **Windows Server** and promotes the
> host to a domain controller (reboot). Never run it on a workstation. Take a
> VM snapshot first.

Die Skripte `01`–`03` und `99` provisionieren eine Testumgebung und veraendern
daher das jeweilige Testsystem. Der DevMS-Analyzer selbst bleibt strikt
read-only — die Skripte gehoeren nicht zu seinem Funktionsumfang.
