# Kann Stars dir helfen? / Can Stars help you?

> **In zwei Sätzen:** Stars beantwortet die Frage *„Warum hat dieser Benutzer auf diesen Ordner oder diese Freigabe genau diese effektive Berechtigung?"* — mit einem **nachvollziehbaren Pfad**, **strikt read-only**, ohne Installation auf Zielsystemen, ohne Hintergrunddienste, ohne Änderungs- oder Reparaturfunktionen.
> Stars ersetzt **keine** Enterprise-Access-Governance-Suite, **keine** AD-Security-Score-Plattform und **keine** Angriffspfad-Analyse — und behauptet das auch nicht.

---

## Wann ist Stars das richtige Werkzeug?

Stars passt zu deinem Anwendungsfall, wenn **mindestens eine** dieser Aussagen zutrifft:

- Du sitzt vor einem Fileserver und willst wissen: *„Wer kann auf `D:\Shares\Buchhaltung` was — und über welche Gruppenkette?"*
- Du musst nach einem Audit-Befund erklären, **warum** ein Benutzer Modify-Rechte hat (oder warum nicht).
- Du suchst ein Tool, das **nichts** an AD, NTFS oder SMB verändert — auch nicht „nur korrigieren".
- Du arbeitest mit verschachtelten AD-Gruppen, lokalen Server-Gruppen (`BUILTIN\Administrators`, `Users`), Deny-ACEs und SMB-Shares, deren Restriktivität mit der NTFS-DACL kombiniert werden muss.
- Du möchtest einen Berechtigungs-Snapshot eines Ordnerbaums (z. B. 5000 Verzeichnisse), CSV/JSON/HTML als Bericht.

Was Stars in **diesen** Fällen liefert:

| Feature | Stars rechnet/liefert | Beleg |
|---|---|---|
| Effektive NTFS-Berechtigung pro Pfad und Benutzer | korrekte Aggregation von Allow + Deny aus expliziten und geerbten ACEs | ADR 0042 |
| Effektive SMB-Berechtigung über UNC-Pfad | restriktive Kombination Share-DACL ∩ NTFS-DACL | ADR 0019, 0043 |
| Lokal anliegende Audit-Sicht mit explizitem SMB-Hint | `--smb-server` + `--share-name` zwingt Remote-SMB-Token (NETWORK im Token) | ADR 0043 |
| Verschachtelte AD-Gruppen | rekursive Auflösung über `memberOf:1.2.840.113556.1.4.1941:=…`, keine N+1-Recursion | ADR 0036 |
| Lokale Server-Gruppen | werden über `NetUserGetLocalGroups` aufgelöst, fließen sowohl in den Token als auch in den **Erklärungspfad** ein | ADR 0040, 0041 |
| Vollständiger Pfad-Bericht | jeder Step (Identität → Gruppe → Mediator → ACE → Aggregation) ist eine eigene lesbare Zeile | ADR 0036, 0041, 0042 |
| Foreign Security Principals | Cross-Forest-SIDs in der DACL werden zur Quell-Domain aufgelöst und im Pfad benannt | siehe Lab-Verifikation Block C |
| Risiko-Findings | 5 fest verdrahtete Regeln (Full Control, Write Access, Broad Group, Direct ACE, Sensitive Path) | `crates/risk_engine/src/rules.rs` |
| Bericht-Export | CSV, JSON, HTML (selbsterklärend, eigenständig, Dark Theme) | `crates/exporter/` |
| Skalierung | 5000 Verzeichnisse + Live-LDAP-Resolve in unter 5 Sekunden gemessen | docs/lab/verification.md Block C |

---

## Wann ist Stars **NICHT** das richtige Werkzeug?

Stars löst dein Problem **nicht**, wenn du nach einer dieser Eigenschaften suchst:

- **Aktive Reparatur** von Berechtigungen, ACL-Bereinigung, Owner-Wechsel, Gruppen-Anlage. → Stars ist und bleibt **read-only**. Behebung machst du selbst.
- **Kontinuierliches Auditing** mit Echtzeit-Event-Stream, Logon-Tracking, File-Server-Audit-Trail. → Stars ist eine punktuelle Analyse, kein Monitoring-System.
- **AD-Security-Score** und allgemeine Härtungs-Bewertung des Forests. → Dafür gibt es PingCastle, Purple Knight.
- **Angriffspfad-Analyse** aus Angreifer-Perspektive (z. B. „wie komme ich zu Domain Admin"). → Dafür gibt es BloodHound.
- **Access-Governance, Rezertifizierung, Rollenmodelle, Workflows**. → Dafür gibt es SolarWinds ARM, Netwrix, Quest, Lepide u. a.
- **AD-Inventarbericht** über Benutzer, GPOs, Trusts, Computer, OUs etc. → Dafür gibt es ADRecon.
- **Multiuser-Webplattform** mit Mandanten-Trennung, SIEM-Integration, E-Mail-Reports. → Stars ist eine Single-User-Desktop-Anwendung.
- **Datenklassifizierung** (sensible Inhalte automatisch erkennen). → Stars markiert nur Pfade mit sicherheitsrelevant klingenden Namen.

---

## Entscheidungs-Matrix

| Deine Frage | Stars | Anderes Tool |
|---|---|---|
| „Warum hat alice Modify auf diesem Share?" | ✅ | — |
| „Welche Pfade öffnen Modify für eine breite Gruppe?" | ✅ via Risk Engine | — |
| „Welche Konten haben in unserem Forest schwache Passwörter?" | ❌ | PingCastle / Purple Knight |
| „Wie komme ich von einem Standard-Benutzer zu Domain Admin?" | ❌ | BloodHound CE |
| „Wer hat sich gestern an unserem Fileserver angemeldet?" | ❌ | ADAudit Plus / SIEM |
| „Generiere mir einen Quartals-Compliance-Bericht inkl. Rezertifizierung." | ❌ | SolarWinds ARM / Netwrix |
| „Liste alle GPOs, Trusts, Sites, Subnets unseres Forests." | ❌ | ADRecon |
| „Korrigiere automatisch die offenen Rechte auf Engineering\Project." | ❌ — und das ist Absicht | dein bevorzugtes ACL-Mgmt-Werkzeug |

---

## Drei harte Grenzen, die Stars **niemals** überschreitet

1. **Read-only.** Stars wird in **keinem** Release Schreibfunktionen für NTFS, SMB, AD oder Zielsysteme bekommen. Das ist eine Architekturentscheidung (siehe `AGENTS.md`).
2. **Kein Agent auf Zielsystemen.** Stars läuft auf einer Audit-Workstation oder einem Audit-DC. Es installiert nichts auf Fileservern oder anderen DCs.
3. **Keine Backdoor-Authentifizierung.** Stars bindet per LDAP-Bind (idealerweise LDAPS) und fragt sonst nichts ab. Keine versteckten Telemetrie-Endpunkte, keine Update-Beacons ohne Signaturprüfung.

---

## Was du vor dem ersten Einsatz wissen musst

- **Backup-Pflicht.** Auch wenn Stars rein liest, gilt für jede produktive Nutzung eine getestete Backup-Strategie der Zielsysteme. Read-only schützt nicht vor Treiberbugs, Antivirus-Sperren oder Last-Spitzen. (Siehe Disclaimer in `README.md`.)
- **Keine offizielle Haftung.** Stars wird von einem einzelnen Prompt Engineer (Birger Labinsch) entwickelt; die Implementierung erfolgt zum Großteil KI-gestützt. Es gibt keinen Hersteller-Support, keine SLA, keine Hotline. Nutzung erfolgt auf eigene Verantwortung.
- **Windows-only.** Stars läuft auf Windows 10/11 und Windows Server (2016+). Linux/macOS sind kein Ziel.
- **Eigenständige EXE.** Kein .NET Framework, kein Visual C++ Redistributable, kein Installer-Bootstrap.

---

# Can Stars help you? (English)

> **In two sentences:** Stars answers the question *“Why does this user have exactly this effective permission on this folder or share?”* — with a **traceable explanation path**, **strictly read-only**, no agent install on target systems, no background services, no remediation features.
> Stars does **not** replace an enterprise access-governance suite, an AD security-score platform, or attack-path analytics — and doesn’t claim to.

## When Stars is the right tool

Stars fits if **at least one** of these is true for you:

- You are sitting on a fileserver and need to know: *“Who can do what on `D:\Shares\Finance` — and through which group chain?”*
- You need to explain after an audit finding **why** a user has Modify (or why not).
- You want a tool that changes **nothing** in AD, NTFS, or SMB — not even “just to fix it”.
- You work with nested AD groups, local server groups (`BUILTIN\Administrators`, `Users`), Deny ACEs, and SMB shares whose restriction must be combined with the NTFS DACL.
- You want a permission snapshot of a directory tree (e.g. 5000 dirs) as CSV/JSON/HTML.

## When Stars is **not** the right tool

Stars does **not** solve your problem if you need:

- **Active remediation** of permissions, ACL cleanup, owner change, group creation. → Stars is and stays read-only.
- **Continuous auditing** with real-time event stream, logon tracking, file-server audit trail. → Stars is a point-in-time analyzer.
- **AD security score** and forest-wide hardening assessment. → PingCastle, Purple Knight.
- **Attack-path analysis** from an attacker’s perspective. → BloodHound CE.
- **Access governance, recertification, role models, workflows**. → SolarWinds ARM, Netwrix, Quest, Lepide.
- **Broad AD inventory reports** (users, GPOs, trusts, computers, OUs). → ADRecon.
- **Multi-user web platform** with tenant separation, SIEM integration, email reports. → Stars is a single-user desktop app.

## Three hard limits Stars will **never** cross

1. **Read-only.** No release will ever ship write functions for NTFS, SMB, AD or any target system. Architectural decision — see `AGENTS.md`.
2. **No agent on target systems.** Stars runs on an audit workstation or audit DC. It installs nothing on file servers or other DCs.
3. **No backdoor auth.** Stars binds via LDAP (ideally LDAPS) and asks for nothing else. No hidden telemetry, no update beacons without signature checks.

## What you need to know before first use

- **Backup duty.** Even though Stars only reads, a tested backup strategy for the target systems is mandatory for any production use. Read-only does not protect you from driver bugs, antivirus locks, or load spikes.
- **No vendor liability.** Stars is developed by a single prompt engineer (Birger Labinsch); implementation is largely AI-assisted. There is no vendor support, no SLA, no hotline. Use at your own risk.
- **Windows only.** Stars runs on Windows 10/11 and Windows Server (2016+). Linux/macOS are out of scope.
- **Standalone EXE.** No .NET Framework, no Visual C++ Redistributable, no installer bootstrap.
