# Integrationstest-Umgebung / Integration Test Environment

Stand: 2026-05-25

Dieses Dokument beschreibt den Aufbau einer Test-Domäne (`testdomain.local`) für
die AD-Integrationstests des DevMS-Analyzers sowie eines Test-Fileservers für
NTFS- und SMB-Szenarien.

This document describes how to set up a test domain (`testdomain.local`) for the
AD integration tests of the DevMS analyzer, plus a test file server for NTFS and
SMB scenarios.

---

## 1. Warum eine eigene VM nötig ist / Why a dedicated VM is required

Die Integrationstests benötigen einen **echten Active-Directory-Domänencontroller**.

- Ein Domänencontroller setzt die Rolle **Active Directory Domain Services (AD DS)**
  voraus. Diese Rolle gibt es **ausschließlich auf Windows Server**, nicht auf
  Windows 10/11 (Client-/Workstation-SKU, `ProductType=1`).
- Die Heraufstufung (`Install-ADDSForest`) erstellt eine Gesamtstruktur und startet
  den Rechner neu. Das ist ein tiefgreifender, kaum reversibler Eingriff.
- Eine Entwickler-Workstation darf **niemals** zum Domänencontroller gemacht werden.

A domain controller requires the **AD DS** role, which only exists on Windows
Server. Promotion (`Install-ADDSForest`) creates a forest and reboots the host —
never do this on a developer workstation.

**Empfehlung / Recommendation:** eine isolierte, wegwerfbare VM
(Hyper-V, VMware, VirtualBox o. Ä.) mit **Windows Server 2019/2022/2025**.
Snapshot vor dem Setup anlegen, damit ein sauberer Rückbau möglich ist.

> Hinweis zum Read-only-Prinzip: Der DevMS-Analyzer verändert niemals Zielsysteme.
> Die Skripte in `scripts/test-env/` sind reine **Testumgebungs-Provisionierung**
> und gehören nicht zum Analyzer. Sie laufen bewusst nur auf der Test-VM.

---

## 2. Voraussetzungen / Prerequisites

| Komponente | Anforderung |
|------------|-------------|
| Test-VM | Windows Server 2019 oder neuer, isoliertes Test-Netz |
| Arbeitsspeicher | ≥ 4 GB für DC + Fileserver kombiniert |
| Rechte | Lokaler Administrator auf der VM |
| Rust-Toolchain | nur auf dem Entwicklungsrechner nötig (Tests laufen per LDAP gegen die VM) |
| Netzwerk | Entwicklungsrechner muss die VM per TCP 389/636 erreichen |

DC und Fileserver können auf **derselben** VM liegen — das ist für Tests zulässig.

---

## 3. Schritt 1 — Domänencontroller einrichten / Set up the domain controller

Auf der **Test-VM** in einer administrativen PowerShell:

```powershell
.\scripts\test-env\01-setup-dc.ps1
```

Das Skript:

1. installiert die Rolle AD DS,
2. stuft die VM zur Gesamtstruktur `testdomain.local` (NetBIOS `TESTDOMAIN`) hoch,
3. fordert ein DSRM-Passwort an,
4. **startet die VM neu**.

Nach dem Neustart ist `testdomain.local` aktiv. Melde dich als
`TESTDOMAIN\Administrator` an.

---

## 4. Schritt 2 — AD-Testobjekte anlegen / Create AD test objects

Nach dem Neustart, erneut in administrativer PowerShell:

```powershell
.\scripts\test-env\02-setup-ad-objects.ps1
```

Das Skript legt unter `OU=DevMS-Test,DC=testdomain,DC=local` an:

**Legacy-Benutzer für Integrationstests / legacy users for integration tests**

| sAMAccountName | Zweck im Test |
|----------------|---------------|
| `max.mustermann` | Gruppenauflösung, transitive Mitgliedschaft |
| `anna.schmidt` | Identity-Caching-Test |
| `Administrator` | bereits vorhanden — `resolve_administrator_identity` |

**Sieben Abteilungen als Sub-OUs / seven departments as sub-OUs**

| Sub-OU | Mitglieder |
|--------|-----------|
| `OU=Geschaeftsleitung` | birger.labinsch |
| `OU=Personal` | susanne.mueller |
| `OU=Analyse` | thomas.hibel, markus.neuer |
| `OU=Produktion` | reiner.wanscher, frank.hilbert |
| `OU=Finanzen` | heidi.weger |
| `OU=Lager` | oscar.wolle |
| `OU=Wissenschaft` | julia.kurz, jasmin.koppen |

Insgesamt **12 Benutzer** (10 aus PASSWORD.md + 2 Legacy). Alle Benutzer
bekommen dasselbe Test-Passwort, das das Skript interaktiv abfragt.

> Die Abteilungs-Zuordnung ist exemplarisch — PASSWORD.md spezifiziert
> sie nicht. Anpassbar im `$testUsers`-Array von `02-setup-ad-objects.ps1`.

**Gruppen / Groups und Verschachtelung / nesting**

Legacy (für `resolve_group_memberships_max_mustermann`):

```text
max.mustermann ─┬─ GRP_IT_Admins   (direkt) ── GRP_FullAccess_FS   (verschachtelt)
                └─ GRP_Development (direkt) ── GRP_ShareAccess_SMB  (verschachtelt)
```

Pro Abteilung eine Members-Gruppe in der jeweiligen Sub-OU:

```text
GRP_Geschaeftsleitung_Members
GRP_Personal_Members
GRP_Analyse_Members
GRP_Produktion_Members
GRP_Finanzen_Members
GRP_Lager_Members
GRP_Wissenschaft_Members
```

Insgesamt **11 Gruppen** (4 Legacy + 7 Members).

Die Legacy-Struktur ist genau das, was `crates/ad_resolver/src/resolver.rs`
erwartet (`resolve_group_memberships_max_mustermann`). Sie darf nicht
entfernt werden, ohne den Test gleichzeitig anzupassen.

Das Skript ist idempotent — vorhandene Objekte werden übersprungen. Für
nicht-interaktive Läufe akzeptiert es `-UserPassword` als SecureString.

---

## 5. Schritt 3 — Test-Fileserver einrichten / Set up the test file server

```powershell
.\scripts\test-env\03-setup-fileserver.ps1
```

Das Skript erstellt unter `C:\DevMS-TestData` zwei Strukturen:

**Legacy-Struktur** (deckt die fachlichen Analysefälle ab):

| Pfad | NTFS-Berechtigung | Freigabe | Testfall |
|------|-------------------|----------|----------|
| `Public` | `Everyone` Read | `Public$` (Full) | Everyone-/Broad-Group-Regel |
| `IT` | `GRP_IT_Admins` Modify (vererbt) | `IT` (Change) | Gruppen-/verschachtelte Rechte |
| `IT\maxdata` | zusätzlich `max.mustermann` explizit | — | `DIRECT_USER_ACE` |
| `Development` | `GRP_Development` Modify | — | Gruppenrechte |
| `Development\Restricted` | Vererbung deaktiviert, explizites Deny | — | Vererbungsunterbrechung, Deny |
| `Shared` | `GRP_FullAccess_FS` Full Control | `Shared` (Read) | NTFS-∩-Share-Kombination |
| `Secrets\passwords` | `GRP_IT_Admins` Read | — | `SENSITIVE_PATH`-Regel |

**Abteilungs-Struktur** unter `C:\DevMS-TestData\Abteilungen` — ein Ordner
und eine sichtbare SMB-Freigabe pro Sub-OU aus Schritt 2:

| Pfad | NTFS-Berechtigung | Freigabe |
|------|-------------------|----------|
| `Abteilungen\Geschaeftsleitung` | `GRP_Geschaeftsleitung_Members` Modify | `Geschaeftsleitung` (Change) |
| `Abteilungen\Personal` | `GRP_Personal_Members` Modify | `Personal` (Change) |
| `Abteilungen\Analyse` | `GRP_Analyse_Members` Modify | `Analyse` (Change) |
| `Abteilungen\Produktion` | `GRP_Produktion_Members` Modify | `Produktion` (Change) |
| `Abteilungen\Finanzen` | `GRP_Finanzen_Members` Modify | `Finanzen` (Change) |
| `Abteilungen\Lager` | `GRP_Lager_Members` Modify | `Lager` (Change) |
| `Abteilungen\Wissenschaft` | `GRP_Wissenschaft_Members` Modify | `Wissenschaft` (Change) |

Damit hat jeder Abteilungs-Benutzer einen eigenen Berechtigungs-Scope
inklusive SMB-Pfad (`\\<dc>\<Dept>`), den der Analyzer auswerten kann.

> Auch diese Schreibvorgänge betreffen ausschließlich die Test-VM. Der Analyzer
> selbst liest diese Strukturen später nur.

---

## 6. Schritt 4 — Integrationstests ausführen / Run the integration tests

Die AD-Integrationstests sind mit `#[ignore]` markiert und lesen ihre Verbindung
aus Umgebungsvariablen. Ohne gesetzte Variablen kehren sie sofort zurück
(`test_config()` liefert `None`).

Benötigte Umgebungsvariablen / required environment variables:

| Variable | Beispiel |
|----------|----------|
| `DEVMS_TEST_LDAP_SERVER` | `dc01.testdomain.local` |
| `DEVMS_TEST_LDAP_BASE_DN` | `DC=testdomain,DC=local` |
| `DEVMS_TEST_LDAP_BIND_DN` | `CN=Administrator,CN=Users,DC=testdomain,DC=local` |
| `DEVMS_TEST_LDAP_PASSWORD` | (Bind-Passwort) |
| `DEVMS_TEST_LDAP_INSECURE` | `1` nur falls kein LDAPS verfügbar — sonst weglassen |

Komfort-Skript auf dem **Entwicklungsrechner** (fragt das Passwort sicher ab):

```powershell
.\scripts\test-env\04-run-integration-tests.ps1 -Server dc01.testdomain.local
```

Oder manuell:

```powershell
$env:DEVMS_TEST_LDAP_SERVER  = "dc01.testdomain.local"
$env:DEVMS_TEST_LDAP_BASE_DN = "DC=testdomain,DC=local"
$env:DEVMS_TEST_LDAP_BIND_DN = "CN=Administrator,CN=Users,DC=testdomain,DC=local"
$env:DEVMS_TEST_LDAP_PASSWORD = (Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText)
cargo test --workspace -- --ignored
```

Erwartete Integrationstests / expected integration tests
(`crates/ad_resolver/src/resolver.rs`):

- `resolve_administrator_identity`
- `resolve_group_memberships_max_mustermann`
- `orphaned_sid_returns_unknown`
- `identity_is_cached_after_first_lookup`

> **Sicherheit:** Das Bind-Passwort niemals als Klartext-Argument oder in der
> Shell-History ablegen. `DEVMS_TEST_LDAP_PASSWORD` nur prozesslokal setzen.
> `DEVMS_TEST_LDAP_INSECURE=1` aktiviert unverschlüsseltes LDAP — ausschließlich
> in isolierten Testnetzen verwenden.

---

## 7. Funktionaler End-to-End-Test mit der CLI / Functional end-to-end CLI test

Gegen den Test-Fileserver lässt sich der Analyzer direkt prüfen:

```powershell
# Effektive Rechte eines Benutzers auf einem Ordner
adpa analyze --path C:\DevMS-TestData\Shared `
  --user max.mustermann `
  --server dc01.testdomain.local `
  --base-dn "DC=testdomain,DC=local" `
  --bind-dn "CN=Administrator,CN=Users,DC=testdomain,DC=local"

# Rekursiver Scan mit HTML-Report inkl. Risikobefunden
adpa scan --path C:\DevMS-TestData `
  --user max.mustermann `
  --server dc01.testdomain.local `
  --base-dn "DC=testdomain,DC=local" `
  --bind-dn "CN=Administrator,CN=Users,DC=testdomain,DC=local" `
  --output report.html
```

Das Bind-Passwort wird über `ADPA_BIND_PASSWORD` erwartet (siehe `adpa --help`).

---

## 8. Aufräumen / Teardown

Bevorzugt: **VM-Snapshot zurückspielen**.

Falls die VM erhalten bleiben soll:

```powershell
.\scripts\test-env\99-teardown.ps1
```

Das Skript entfernt die AD-Test-OU, die Freigaben und `C:\DevMS-TestData`.
Die Herabstufung des Domänencontrollers (`Uninstall-ADDSDomainController`) muss
bewusst manuell erfolgen und ist nicht Teil des Skripts.

---

## 9. Kurzreferenz / Quick reference

```text
Test-VM (Windows Server):
  1. scripts\test-env\01-setup-dc.ps1          -> DC, Neustart
  2. scripts\test-env\02-setup-ad-objects.ps1  -> Benutzer + Gruppen
  3. scripts\test-env\03-setup-fileserver.ps1  -> Ordner + ACLs + Shares

Entwicklungsrechner:
  4. scripts\test-env\04-run-integration-tests.ps1 -Server <dc-fqdn>
```
