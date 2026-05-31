# Audit-Kriterien und Bewertungsprinzipien / Audit Criteria and Evaluation Principles

> **Stars — AD Permission Analyzer**
>
> **Deutsch:** Diese Lektüre beschreibt **vollständig und genau**, nach welchen Kriterien das Tool seine Audit-Bewertungen vornimmt, welche Risikoregeln implementiert sind, wie sie wirken — und welche Rechte für welche Identitäten in einer Active-Directory-/NTFS-Umgebung als „optimal" gelten und warum.
>
> **English:** This document describes **completely and precisely** which criteria the tool uses for its audit evaluations, which risk rules are implemented, how they operate — and which permissions are considered "optimal" for which identities in an Active Directory / NTFS environment, and why.

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

### Inhaltsverzeichnis

1. [Grundprinzipien](#1-grundprinzipien)
2. [Was Stars analysiert](#2-was-stars-analysiert)
3. [Wie effektive Berechtigung berechnet wird](#3-wie-effektive-berechtigung-berechnet-wird)
4. [Die sechs Risikoregeln im Detail](#4-die-sechs-risikoregeln-im-detail)
5. [Das Severity-Modell](#5-das-severity-modell)
6. [Der `incomplete`-Marker](#6-der-incomplete-marker)
7. [Optimale Rechte pro Rolle und Pfad-Klasse](#7-optimale-rechte-pro-rolle-und-pfad-klasse)
8. [Sensible Pfade — was Stars als Hinweis nimmt](#8-sensible-pfade)
9. [Was Stars bewusst nicht tut](#9-was-stars-bewusst-nicht-tut)
10. [Bekannte Grenzen der Bewertung](#10-bekannte-grenzen-der-bewertung)
11. [Persistierte Daten und Scan-Historie](#11-persistierte-daten-und-scan-historie)

#### <a name="1-grundprinzipien"></a>1. Grundprinzipien

Stars wertet Berechtigungen **streng read-only** aus. Das Tool macht **keinerlei Änderungen** an AD-Objekten, NTFS-DACLs oder SMB-Freigaben — weder automatisch noch auf Knopfdruck. Es zeigt, erklärt und exportiert; mehr nicht.

Die Bewertung steht auf vier Säulen:

| Säule | Bedeutung |
|---|---|
| **Korrektheit** | Die Berechtigungsberechnung muss das tun, was Windows beim echten Zugriff auch tut — sonst sind alle weiteren Aussagen wertlos. |
| **Nachvollziehbarkeit** | Jedes Ergebnis trägt einen vollständigen Erklärungspfad: über welche Gruppen, welche ACEs und welche Vererbungsregeln das Recht zustande kam. |
| **Risiko-Wertung nach festen Regeln** | Sechs in `risk_engine` implementierte Regeln, jede mit klar definiertem Auslöser und definierter Severity. Keine „Heuristik". |
| **Ehrlichkeit beim Unsicherheitsfall** | Wenn die Auswertung Lücken hatte (z.B. Share-DACL nicht lesbar), wird das Ergebnis als `incomplete` markiert. Stars verschweigt seine eigenen Grenzen nicht. |

Diese Säulen entsprechen exakt den Prioritäten aus der internen Spezifikation:
> Sicherheit > Korrektheit > Nachvollziehbarkeit > Testbarkeit > Stabilität > Performance > Bedienkomfort > Optik.

#### <a name="2-was-stars-analysiert"></a>2. Was Stars analysiert

Pro untersuchtem Pfad zieht Stars **fünf Eingangsdatensätze**:

##### 2.1 Identitäts­auflösung

Aus der angegebenen Benutzer-SID werden vollständige Identitäts- und Gruppendaten ermittelt — **direkt über die Windows-LSA/SAM-API**, ohne dass ein LDAP-Bind nötig ist:

* `LookupAccountSidW` → Klartextname (z.B. `VORDEFINIERT\Administrator`) und Kontotyp
* `NetUserGetGroups` → **globale (Domänen-)Gruppen** wie `Domain Admins`, `Schema Admins`
* `NetUserGetLocalGroups` → **lokale Gruppen** des Zielservers (z.B. `BUILTIN\Administrators`)

Optional kann zusätzlich LDAP angebunden werden — das ist relevant, wenn Stars **nicht** auf einem Domain Controller läuft und die Daten von außen geholt werden müssen.

##### 2.2 Token-Konstruktion

Stars baut den **Access Token** so nach, wie Windows ihn beim echten Zugriff aufbauen würde. Dazu gehören:

* die User-SID selbst
* alle direkten Gruppen-SIDs
* alle transitiven Gruppen-SIDs (z.B. Administrator → Domain Admins → `BUILTIN\Administrators`)
* lokale Server-Gruppen-SIDs
* kontextabhängige Well-Known-SIDs:
  * `Everyone` (S-1-1-0) — immer
  * `Authenticated Users` (S-1-5-11) — immer (für nicht-anonyme Logons)
  * `INTERACTIVE` (S-1-5-4) und `LOCAL` (S-1-2-0) — nur bei lokalem Zugriff
  * `NETWORK` (S-1-5-2) — nur bei SMB-Zugriff

Welche der letzten Gruppe drin ist, hängt vom **AccessContext** ab. Stars leitet diesen aus dem Pfadtyp ab: lokale Pfade → `LocalInteractive`, UNC-Pfade → `RemoteSmb`. Das ist wichtig, weil ACEs auf `NETWORK` zwar bei SMB greifen, bei lokalem Zugriff aber ignoriert werden — und umgekehrt.

##### 2.3 NTFS-DACL

Die rohe Discretionary Access Control List des Pfades wird direkt mit Win32-API gelesen. Pro ACE merkt sich Stars:

* Trustee-SID
* Allow oder Deny
* Access-Mask (Rohwert)
* explizit oder vererbt
* Inheritance- und Propagation-Flags

##### 2.4 SMB-Share-DACL (optional)

Bei UNC-Pfaden (`\\server\share\…`) liest Stars zusätzlich die **Share-Permissions** des Shares. Die effektive Berechtigung über SMB ist dann das **restriktivere** der beiden Sets:

```
effective_smb = NTFS ∩ Share
```

Beispiele:

| NTFS | Share | Effective |
|---|---|---|
| Modify | Read | **Read** |
| Read & Execute | Full Control | **Read & Execute** |
| Full Control | Change | **Change** |

NULL-DACL auf dem Share wird als „keine Beschränkung über SMB" interpretiert — nicht als „Full Control" — und mit dem dedizierten Status `Unrestricted` markiert, statt eine künstliche `0xFFFFFFFF`-Maske zu fabrizieren. Das ist wichtig, weil ein Auditor sonst denken könnte, jemand habe absichtlich Full Control gewährt.

##### 2.5 Diagnose-Marker

Während der Auswertung sammelt Stars strukturierte **Diagnostik-Marker** an:

* `NonCanonicalDaclOrder` — Reihenfolge der ACEs entspricht nicht dem Windows-Standardmuster (`explicit deny → explicit allow → inherited deny → inherited allow`). Windows wertet die DACL trotzdem in **Stored Order** aus; das Tool zeigt das aber als Audit-Hinweis, weil eine nicht-kanonische DACL meist durch manuelle Bearbeitung entstanden ist.
* `UnsupportedShareAces { count }` — Share-DACL enthielt ACE-Typen, die der Parser nicht auswerten konnte (Object-, Callback- oder herstellerspezifische ACEs). Die Effective-Maske ist dann eine **untere Grenze**, ein versteckter Deny könnte das Ergebnis kippen.
* `unsupported_ace_count > 0` (NTFS-Seite) — dasselbe für die NTFS-DACL.

Diese Marker beeinflussen den `incomplete`-Flag der Risikobefunde (siehe Abschnitt 6).

#### <a name="3-wie-effektive-berechtigung-berechnet-wird"></a>3. Wie effektive Berechtigung berechnet wird

Die Berechnung läuft in vier Phasen:

##### Phase 1 — Token-Bildung

Aus User-SID + Memberships + lokalen Gruppen + Well-Knowns wird ein **HashSet** aller wirksamen Token-SIDs gebaut.

##### Phase 2 — DACL-Anwendung (Stored Order)

Für jeden ACE in **gespeicherter Reihenfolge**:

* Trustee-SID gegen den Token prüfen → matcht nicht? Überspringen.
* Deny-ACE → Bits zur **Deny-Maske** addieren.
* Allow-ACE → Bits zur **Allow-Maske** addieren, **aber nur Bits, die nicht bereits in der Deny-Maske stehen** (das ist die Windows-Semantik: ein zuvor gesehener Deny kippt einen späteren Allow).

Generische Bits (`GENERIC_ALL`, `GENERIC_READ`, etc.) werden dabei in ihre konkreten Bits expandiert. INHERIT_ONLY-ACEs werden ausgefiltert — sie wirken nicht auf das aktuelle Objekt selbst, nur auf Kinder.

##### Phase 3 — Owner-Sonderregel

Wenn der eigene User der Owner des Objekts ist, addiert Stars die Bits `READ_CONTROL` und `WRITE_DAC` zur Allow-Maske — Windows räumt dem Owner immer das Recht ein, die ACL zu lesen und zu ändern, unabhängig vom DACL-Inhalt.

##### Phase 4 — Share-Kombination

Wenn ein Share-Kontext da ist:
* `share_status == Applied(mask)` → Effective = NTFS AND Share-Mask
* `share_status == Unrestricted` (NULL-DACL) → Effective = NTFS (kein zusätzlicher Filter)
* `share_status == ReadFailed` → Effective = NTFS, **incomplete**-Flag wird gesetzt
* `share_status == NotApplicable` → Effective = NTFS (kein Share-Kontext)

Das Endergebnis ist die **Effective Access Mask**, plus der vollständige Erklärungspfad mit allen wirksamen Memberships und ACEs.

#### <a name="4-die-sechs-risikoregeln-im-detail"></a>4. Die sechs Risikoregeln im Detail

Alle Regeln liegen in `crates/risk_engine/src/rules.rs` und werden über `RuleRegistry::with_defaults()` registriert. Jede Regel ist eine eigenständige Implementierung des Traits `RiskRule` und kann unabhängig getestet werden.

##### 4.1 Regel: `FULL_CONTROL` — Severity **Critical**

**Quelle:** `FullControlRule` (rules.rs:135ff)

**Auslöser:** Die effektive Maske enthält **alle** Bits von `MASK_FULL_CONTROL` (`0x001F01FF` plus `WRITE_DAC`, `WRITE_OWNER`).

**Logik:** `effective_mask & MASK_FULL_CONTROL == MASK_FULL_CONTROL`

**Begründung der Severity:**
Full Control gibt dem Principal das Recht, die ACL selbst zu ändern (`WRITE_DAC`) und den Besitzer zu ändern (`WRITE_OWNER`). Wer Full Control auf ein Objekt hat, kann sich praktisch jede beliebige Berechtigung verschaffen — und Änderungen revisionssicher nicht mehr von einem normalen Schreibvorgang unterscheiden. Das ist der schwerste Befund, den die Engine kennt.

**Wann das *normal* ist:**
* `BUILTIN\Administrators` auf System-Pfaden (`C:\Windows`, `C:\Program Files`)
* `SYSTEM` auf praktisch allen System-Pfaden
* `TrustedInstaller` auf Komponenten, die nur Windows Update verändern darf
* Der Besitzer auf seinem eigenen Benutzerprofil

**Wann das *kritisch* ist:**
* `Everyone`, `Authenticated Users`, `Domain Users` haben Full Control auf eine Freigabe → sofortiger Handlungsbedarf
* Ein normaler Benutzer hat Full Control auf eine *fremde* Freigabe oder auf ein freigegebenes Datenverzeichnis
* Ein Service-Account hat Full Control jenseits seines eigenen Datenverzeichnisses

##### 4.2 Regel: `WRITE_ACCESS` — Severity **High**

**Quelle:** `WriteAccessRule` (rules.rs:166ff)

**Auslöser:** Die effektive Maske enthält Modify oder Write, aber **nicht** Full Control.

**Logik:** `(MASK_MODIFY oder MASK_WRITE) gesetzt, MASK_FULL_CONTROL nicht`

**Begründung der Severity:**
Schreibzugriff erlaubt das Erstellen, Ändern oder Löschen von Dateien. Auf Daten, die Andere zum Lesen verwenden (Konfigurationen, Skripte, Berichte), bedeutet das ein **Tampering-Risiko**: ein Angreifer (oder ein versehentlich kompromittierter Account) kann Inhalte austauschen. Auf User-Profilen ist Schreibzugriff normal, auf Systemdateien nicht.

**Beziehung zu Full Control:**
Die Regel meldet bewusst **nicht**, wenn Full Control vorliegt — das übernimmt bereits `FullControlRule`. Sonst gäbe es Doppelmeldungen für denselben Befund.

**Wann das *normal* ist:**
* User auf seinem eigenen `%USERPROFILE%`
* Service-Account auf seinem Datenverzeichnis
* Editoren einer Freigabe (Domain Local Group `<Share>_Modify`)

**Wann das *kritisch* ist:**
* `Everyone` oder `Authenticated Users` haben Modify auf System- oder Programmdateien
* Normale Benutzer haben Modify auf Konfigurationsdateien (Konfigurationen sind dann nicht mehr vertrauenswürdig)

##### 4.3 Regel: `PERMISSION_CHANGE` / `OWNER_CHANGE` / `DELETE_RIGHT` / `DELETE_CHILD_RIGHT`

**Quelle:** `AdminRightsRule` (rules.rs:217ff)

Diese Regel schließt eine Lücke, die `WriteAccessRule` und `FullControlRule` lassen: **destruktive oder administrative Einzelrechte**, die zwar nicht in Modify/Write enthalten sind, aber alleine schon eine Privilege-Escalation-Möglichkeit darstellen.

**Bits, die je einzeln gemeldet werden:**

| Rule-ID | Bit | Severity | Bedeutung |
|---|---|---|---|
| `PERMISSION_CHANGE` | `FILE_WRITE_DAC` | **High** | Kann ACL ändern → kann sich weitere Rechte selbst geben |
| `OWNER_CHANGE` | `FILE_WRITE_OWNER` | **High** | Kann Besitzer übernehmen → Owner-Sonderregel wirkt dann zugunsten des Angreifers |
| `DELETE_RIGHT` | `FILE_DELETE` | **Medium** | Kann das Objekt selbst löschen |
| `DELETE_CHILD_RIGHT` | `FILE_DELETE_CHILD` | **Medium** | Kann Kinder eines Ordners löschen, ohne Schreibrecht auf den Kindern zu haben |

**Wichtige Eigenschaft:** Die Regel **schweigt**, wenn der Principal bereits Full Control hat — das ist dann bereits `FULL_CONTROL` Critical, und eine zusätzliche Aufschlüsselung würde nur Rauschen erzeugen.

**Begründung der Severity-Unterschiede:**
* `WRITE_DAC` und `WRITE_OWNER` sind **High**, weil sie Privilege-Escalation ermöglichen — der Principal kann sich selbst weitere Rechte verschaffen, ohne dass das Audit-Tool das mitkriegt.
* `DELETE` und `DELETE_CHILD` sind **Medium** — kein Privilege-Gain, aber Tampering und Datenverlust möglich.

##### 4.4 Regel: `BROAD_GROUP_WRITE` — Severity **Critical**

**Quelle:** `BroadGroupWriteRule` (rules.rs:290ff)

**Auslöser:** Schreibzugriff ist über einen ACE auf eine **breit gefächerte Well-Known-Gruppe** entstanden, **und** dieser ACE hat tatsächlich Write-Bits beigetragen.

**Breit gefächerte SIDs:**

| SID | Bedeutung |
|---|---|
| `S-1-1-0` | `Everyone` — wirklich jeder, inkl. anonymer Zugriffe je nach Konfiguration |
| `S-1-5-11` | `Authenticated Users` — jeder mit gültigem Domain-/lokalem Login |
| `S-1-5-7` | `Anonymous Logon` — Zugriffe ohne Authentifizierung |
| `S-1-5-2` | `NETWORK` — jeder, der über SMB zugreift |

**Wichtig (Anti-False-Positive):** Die Regel feuert **nur**, wenn der breite Principal tatsächlich **Write-Bits** zur effektiven Maske beigetragen hat (über das Feld `contributing_sids`). Wenn `Everyone` nur Read hat und die Modify-Rechte über eine spezifische Gruppe kommen, wird **nicht** gemeldet. Das wäre sonst ein klassischer Fehlalarm gewesen, der das ganze Audit unbrauchbar macht.

**Begründung der Severity:**
Schreibzugriff durch eine breite SID ist die schlimmste praktisch vorkommende Konfiguration — sie macht jeden Benutzer im Netzwerk (oder bei `Anonymous Logon` jeden Unauthentifizierten) zum potentiellen Angreifer auf diesem Pfad. Es ist quasi ein „offenes Tor", das oft historisch durch Quick-Fixes entstanden ist und nie zurückgedreht wurde.

##### 4.5 Regel: `DIRECT_USER_ACE` — Severity **Low**

**Quelle:** `DirectUserAceRule` (rules.rs:356ff)

**Auslöser:** Der Benutzer hat eine **direkte explizite ACE** auf den Pfad — also nicht über eine Gruppe, sondern auf seine eigene User-SID, **nicht geerbt** sondern explizit am Objekt vergeben.

**Datenquelle:** Das Feld `matched_aces` der `EffectivePermission`. Die Regel ist deshalb **lokalisierungssicher** und unabhängig vom Erklärungstext — auch auf deutschen Systemen mit übersetzten Namen wirkt sie korrekt.

**Behandlung von Allow und Deny:** Beide werden gemeldet — ein direkter explicit Deny ist genauso eine Best-Practice-Verletzung wie ein direkter explicit Allow.

**INHERIT_ONLY:** ACEs mit `INHERIT_ONLY_ACE`-Flag sind in `matched_aces` bewusst gefiltert (die Engine räumt sie vorher aus). Ein direkter User-ACE, der nur Kinder treffen würde, wirkt nicht auf das aktuelle Objekt und löst hier keinen Befund aus.

**Begründung der Severity:**
Das ist **Low**, weil es selten ein konkretes Sicherheitsrisiko ist — eher ein **Verwaltungsproblem**. Best Practice in AD-Umgebungen ist `AGDLP` (Account → Global Group → Domain Local Group → Permission): Berechtigungen werden über Gruppen vergeben, niemals direkt an Benutzer. Direkte User-ACEs sind:
* schwer auditierbar (sie sind unsichtbar, sobald der Benutzer aus dem Verzeichnis entfernt wird → orphaned SID)
* schwer zu pflegen (man muss jeden Pfad einzeln anfassen, statt einen Gruppenwechsel zu nutzen)
* historisch oft Indiz für „mal eben durchgewunken"-Aktionen

`incomplete`-Flag: bleibt immer `false`. Die strukturierte ACE-Quelle ist NTFS-Eigenschaft, vom Share-Status unabhängig.

##### 4.6 Regel: `SENSITIVE_PATH` — Severity **Medium**

**Quelle:** `SensitivePathRule` (rules.rs:394ff)

**Auslöser:** Der Pfadname enthält eines der folgenden Schlüsselwörter (case-insensitive), **und** der Principal hat tatsächlich Zugriff (`effective_mask > 0`):

```
password, passwort, pwd, login, credential, credentials, secret, secrets,
token, api-key, apikey, keyfile, private-key, ssh-key, private_key, ssh_key
```

**Wichtig (Anti-False-Positive):** Die Regel meldet **nur**, wenn `effective_mask > 0`. Ein Pfad namens `passwords.txt`, auf den die Identität explizit gedenied bekommen hat, ist **kein** Befund — sonst würde Stars eine Nicht-Berechtigung als Risiko fehlmelden.

**Was die Regel *nicht* tut:** Sie öffnet die Datei nicht, liest keinen Inhalt, sucht nicht nach echten Geheimnissen im Klartext. Das wäre selbst ein Datenschutzproblem. Sie schaut **nur auf den Pfadnamen** als Heuristik.

**Begründung der Severity:**
Medium, weil der **Pfadname allein** ein schwacher Indikator ist. `password-policies.pdf` hat das Stichwort und ist trotzdem harmlos. `c:\dev\password-resets\logs\` ist hoch sensibel. Stars unterscheidet das nicht — der Auditor muss das tun. Aber der Hinweis ist wichtig, weil:
* sensible Pfade gerne mit weiten Berechtigungen versehen sind (Bequemlichkeit über Sicherheit)
* sensible Pfade typische Ziele bei Pentests und realen Angriffen sind

`incomplete`-Flag: bleibt immer `false`. Pfadname ist NTFS-Eigenschaft, vom Share-Status unabhängig.

#### <a name="5-das-severity-modell"></a>5. Das Severity-Modell

Stars klassifiziert jeden Befund in eine von fünf Stufen (`adpa_core::model::RiskSeverity`):

| Severity | Bedeutung | Beispiele aus den Regeln |
|---|---|---|
| **Critical** | Sofortige Aufmerksamkeit. Privilege-Escalation, Tampering durch breite Benutzergruppen oder direkter Datenverlust drohen. | `FULL_CONTROL`, `BROAD_GROUP_WRITE` |
| **High** | Erhöhtes Risiko. Schreibrechte auf wertvollen Objekten, einzelne Privilege-Escalation-Bits. | `WRITE_ACCESS`, `PERMISSION_CHANGE`, `OWNER_CHANGE` |
| **Medium** | Beachtenswert. Destruktive Einzelrechte, sensible Pfadnamen. | `DELETE_RIGHT`, `DELETE_CHILD_RIGHT`, `SENSITIVE_PATH` |
| **Low** | Eher Best-Practice- oder Verwaltungs­findung als akutes Risiko. | `DIRECT_USER_ACE` |
| **Info** | Hinweise ohne Risiko-Charakter (aktuell von keiner Standardregel benutzt; reserviert für Erweiterungen). | — |

**Wichtig:** Severity ist **kein** absoluter Wert. Ein `FULL_CONTROL`-Critical von `SYSTEM` auf `C:\Windows` ist trivial und korrekt; dasselbe Critical von `Authenticated Users` auf `\\server\Buchhaltung` ist ein Notfall. Severity sortiert nach **technischer Schwere**, der Kontext muss vom Auditor mitgedacht werden.

#### <a name="6-der-incomplete-marker"></a>6. Der `incomplete`-Marker

Jeder `RiskFinding` trägt ein boolesches Feld `incomplete`. Es markiert Befunde, deren zugrundeliegende **Berechtigungsauswertung** Lücken hatte und die deshalb **vorsichtig** zu lesen sind.

`incomplete = true` wird gesetzt, wenn mindestens eine der vier Ursachen vorliegt:

1. **Share-DACL war nicht lesbar** (`ShareEvalStatus::ReadFailed(...)`).
   `effective_mask` ist dann nur eine **NTFS-Untergrenze** — der echte SMB-Zugriff könnte restriktiver sein.

2. **DACL enthielt unsupported ACEs** (`unsupported_ace_count > 0`).
   Object-, Callback- oder Conditional-ACEs werden vom Parser übersprungen; ein versteckter Deny könnte das Ergebnis kippen.

3. **Lokale Server-Gruppen konnten nicht aufgelöst werden** (`LocalGroupEvalStatus::NotAvailable(...)`).
   ACEs auf z.B. eine lokale `Administrators`-Gruppe sind dann unsichtbar; die effektiven Rechte können **zu niedrig** sein.

4. **Share-DACL enthielt unsupported ACEs** (Diagnostik `UnsupportedShareAces`).
   Analog zu Punkt 2, aber auf der Share-Seite.

Ein Befund mit `incomplete = true` heißt **nicht**, dass er falsch ist — er heißt, dass das zugrundeliegende Ergebnis nicht 100% vollständig sein könnte. Für ein Audit ist das die ehrliche Aussage; für eine automatisierte Eskalation darf man darauf nicht blind vertrauen.

#### <a name="7-optimale-rechte-pro-rolle-und-pfad-klasse"></a>7. Optimale Rechte pro Rolle und Pfad-Klasse

Dieser Abschnitt zeigt, **was als gut konfiguriert gilt**. Stars markiert Abweichungen über die Risikoregeln — die folgenden Sektionen geben den Auditor die Maßstäbe in die Hand, gegen die er die Befunde beurteilt.

Die Empfehlungen folgen den seit Jahrzehnten etablierten Microsoft-Best-Practices, insbesondere dem **AGDLP-Modell**:

```
Account  →  Global Group  →  Domain Local Group  →  Permission
```

Konkret: Benutzer kommen in globale Gruppen, globale Gruppen in domänen­lokale Gruppen, **NTFS-Rechte werden ausschließlich an domänenlokale Gruppen vergeben** — nie direkt an Benutzer, nie an globale Gruppen, nie an breite Well-Known-Identitäten.

##### 7.1 System-Pfade — `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`

**Optimale ACL:**

| Identität | NTFS-Recht | Begründung |
|---|---|---|
| `NT-AUTORITÄT\SYSTEM` (S-1-5-18) | **Full Control** | Windows-Dienste laufen unter SYSTEM und müssen Systemdateien jederzeit ändern können |
| `VORDEFINIERT\Administratoren` (S-1-5-32-544) | **Full Control** | Administrative Wartung, manuelle Updates |
| `TrustedInstaller` | **Full Control** auf System­komponenten | Nur Windows Update darf Kerndateien anfassen |
| `VORDEFINIERT\Benutzer` (S-1-5-32-545) | **Lesen & Ausführen** | Programme müssen lesbar und startbar sein |
| `Authenticated Users` | **Lesen & Ausführen** | Wie oben, fängt domänen-eingebundene User mit |
| `Everyone` | Nichts (oder höchstens Lesen) | Anonyme Zugriffe haben hier nichts zu suchen |

**Was Stars meldet (und warum es hier *normal* ist):**
* `FULL_CONTROL` für Administratoren → bei System-Pfaden erwartet, kein realer Befund
* `FULL_CONTROL` für SYSTEM → erwartet
* `WRITE_ACCESS` für Modify-Inhaber (z.B. bei `TrustedInstaller`) → erwartet

**Was Stars meldet und was *kritisch* ist:**
* `BROAD_GROUP_WRITE` für `Everyone` oder `Authenticated Users` auf System-Dateien → echter Befund, sofort handeln
* `WRITE_ACCESS` für normale User auf System-Dateien → System-Integrität bedroht

##### 7.2 Benutzerprofile — `C:\Users\<benutzer>`

**Optimale ACL:**

| Identität | NTFS-Recht | Begründung |
|---|---|---|
| Der Benutzer selbst | **Full Control** auf seinem eigenen Profil | Eigene Daten, eigener Verantwortungs­bereich |
| `NT-AUTORITÄT\SYSTEM` | **Full Control** | Backup, Profil-Loading |
| `VORDEFINIERT\Administratoren` | **Full Control** (oder bewusst entfernt für Privacy) | Administrative Wartung |
| **Andere Benutzer** | Nichts | Strikt — fremde Profile sind tabu |

**Was Stars meldet:**
* `FULL_CONTROL` für den Profil-Inhaber → erwartet
* `FULL_CONTROL` für SYSTEM/Administratoren → erwartet
* `FULL_CONTROL` für **andere** User → echter Befund (Privacy-Verletzung)
* `BROAD_GROUP_WRITE` jemals auf einem Profil → echter Befund

##### 7.3 Freigegebene Datenverzeichnisse — `\\server\Daten\…`

Hier wird das AGDLP-Modell besonders sichtbar. Eine Beispiel-ACL für `\\server\Buchhaltung`:

| Identität | NTFS-Recht | Share-Recht | Begründung |
|---|---|---|---|
| `NT-AUTORITÄT\SYSTEM` | Full Control | — | Backup-Agent |
| `BUILTIN\Administratoren` | Full Control | Full Control | Notfall-Zugriff |
| Domain Local Group `FS_Buchhaltung_RW` | **Modify** | **Change** | Editor-Rolle |
| Domain Local Group `FS_Buchhaltung_RO` | **Lesen & Ausführen** | **Read** | Leser-Rolle |
| `CREATOR OWNER` | Modify (inherit-only) | — | Eigene Dokumente bearbeiten |
| **Niemand sonst** | Nichts | Nichts | Strikt |

Die Mitglieder der domänenlokalen Gruppen sind **globale Gruppen** (z.B. `GG_Buchhaltung_Mitarbeiter`), in die die einzelnen Benutzer als Account-Mitglieder reinkommen.

**Was Stars meldet:**
* `FULL_CONTROL` für `SYSTEM` und Administratoren → erwartet
* `WRITE_ACCESS` für Mitglieder von `FS_Buchhaltung_RW` → erwartet
* `DIRECT_USER_ACE` für irgendeinen Benutzer → Best-Practice-Verletzung (Low)
* `BROAD_GROUP_WRITE` jemals → echter Critical-Befund

##### 7.4 Service-Accounts und Dienst-Datenverzeichnisse

**Optimale ACL:** Ein Service-Account darf **ausschließlich** in seinem eigenen Datenverzeichnis schreiben. Lese­zugriffe nur auf Konfig­dateien, die der Dienst tatsächlich braucht.

| Identität | NTFS-Recht auf Service-DataDir | Begründung |
|---|---|---|
| `NT-AUTORITÄT\SYSTEM` | Full Control | Backup |
| Administratoren | Full Control | Wartung |
| Der Service-Account selbst | **Modify** | Datenverzeichnis schreiben |
| **Niemand sonst** | Nichts | Strikt |

**Was Stars meldet:**
* `WRITE_ACCESS` für den Service-Account auf *seinem* Verzeichnis → erwartet
* `WRITE_ACCESS` für den Service-Account auf *anderen* Verzeichnissen → echter Befund
* `FULL_CONTROL` für den Service-Account → fast immer Übermaß; Modify hätte gereicht

##### 7.5 Administratoren auf Daten (nicht System)

Eine besondere Frage: Sollten `BUILTIN\Administratoren` Full Control auf **Daten**­verzeichnissen haben?

* **System-Pfade:** ja, immer (Notfall-Wartung, Recovery).
* **Daten-Pfade:** technisch ja, aber **bewusst gesetzt und dokumentiert**. Wenn jemand „Admin" ist, hat er praktisch unbeschränkten Zugriff auf den Server — das Audit-Logging sollte das nachvollziehbar machen.
* **Sensible Daten-Pfade (Lohn, HR, Geschäftsführung):** Erwägenswert, Administratoren-Zugriff durch eine separate Berechtigungsstruktur (z.B. eigene Domain Local Group `FS_HR_FullControl` mit *expliziter* Mitgliedschaft) zu ersetzen, statt sich auf die globale Administrator-Mitgliedschaft zu verlassen. Das schützt vor versehentlichem Datenabfluss durch generelle Admin-Tasks.

Stars meldet hier `FULL_CONTROL` als Critical — wie ernst das im Einzelfall ist, entscheidet der Auditor anhand der Sensibilität des Pfades.

#### <a name="8-sensible-pfade"></a>8. Sensible Pfade — was Stars als Hinweis nimmt

Die `SensitivePathRule` (siehe 4.6) sucht nach Schlüsselwörtern im Pfadnamen. Sie meldet nicht den **Inhalt**, sondern nur den **Verdacht**.

**Praktische Lese-Hinweise:**

| Pfadname enthält | Typische Bedeutung | Audit-Aufmerksamkeit |
|---|---|---|
| `password`, `passwort`, `pwd` | Passwort-Listen, Reset-Workflows, Konfigurationen | Sehr hoch — auch wenn der Pfad „passwort-richtlinie.docx" ist, sollte Zugriff streng kontrolliert sein |
| `credential`, `credentials` | Credential-Speicher, Skript-Konfigs mit Klartext-Logins | Sehr hoch |
| `secret`, `secrets` | Application Secrets, Tokens | Sehr hoch |
| `token`, `api-key`, `apikey` | OAuth-Tokens, API-Schlüssel | Sehr hoch |
| `private-key`, `private_key`, `ssh-key`, `ssh_key`, `keyfile` | Private Krypto-Schlüssel | **Höchste Priorität** — ein kompromittierter Schlüssel ist nicht widerrufbar wie ein Passwort |
| `login` | Login-Skripte, Profile, manchmal Konfigs | Hoch |

**Was Stars *nicht* abdeckt** (und der Auditor zusätzlich prüfen sollte):
* Verschlüsselte Container, deren Dateiname neutral klingt
* Konfigurationsdateien mit Klartext-Credentials, aber unverdächtigem Namen (`config.ini`, `web.config`, `appsettings.json`)
* Datenbank-Backups (`.bak`, `.dmp`), die personenbezogene Daten enthalten können

#### <a name="9-was-stars-bewusst-nicht-tut"></a>9. Was Stars bewusst nicht tut

Das Tool ist **dauerhaft als read-only Analyse- und Anzeige­werkzeug** konzipiert. Folgendes ist nicht vorgesehen und wird auch in Zukunft nicht implementiert:

* **Berechtigungen ändern** — weder automatisch noch auf Knopfdruck
* **ACLs bereinigen** oder „reparieren"
* **AD-Gruppenmitgliedschaften ändern**
* **AD-Benutzer ändern**
* **Freigaben anlegen, ändern, löschen**
* **Dateien oder Ordner auf Zielsystemen verändern**
* **Reparaturvorschläge automatisch anwenden**
* **Agenten auf Dateiservern ausrollen**
* **SIEM-Integration mit aktiver Reaktion**
* **Datei­inhalte zum Zweck der Geheimnis­suche öffnen** (`SensitivePathRule` schaut nur auf den Pfadnamen)

Diese Selbst­beschränkung ist nicht zufällig, sondern wesentlich: ein Audit-Werkzeug, das mehr kann, ist ein Angriffs­werkzeug. Stars darf nicht selbst zum Risiko werden.

#### <a name="10-bekannte-grenzen-der-bewertung"></a>10. Bekannte Grenzen der Bewertung

Auch ein technisch korrektes Audit hat Grenzen — Stars bewertet keine Fakten, die es nicht sieht:

##### 10.1 Was Stars *sieht*

* NTFS-DACLs in der Reihenfolge, in der sie gespeichert sind
* SMB-Share-DACLs (sofern lesbar)
* Gruppenmitgliedschaften (via SAM/LSA, optional LDAP)
* Lokale Server-Gruppen (via NetUserGetLocalGroups)
* AccessContext (lokal vs. SMB) — abgeleitet aus dem Pfad

##### 10.2 Was Stars *nicht* sieht

* **Datei­inhalte** — Was in `Lohn_2025.xlsx` drinsteht, ist für die Berechtigungs­berechnung egal
* **Audit-Logs** — *Wer wann tatsächlich was getan hat*, ist Sache des Event Logs, nicht der DACL
* **Zentrale Zugriffsregeln (CAR)** — Dynamic Access Control mit zentralen Richtlinien wird vom Parser noch nicht ausgewertet
* **SACLs** (System Access Control Lists) — nur DACLs werden gelesen; SACLs für Audit-Protokollierung sind ein anderes Thema
* **Mandatory Integrity Control (Integrity Levels)** — Low/Medium/High Integrity Labels werden nicht berücksichtigt
* **Conditional ACEs** — werden als `unsupported` gemeldet, nicht ausgewertet
* **Object- und Callback-ACEs** — ebenfalls als `unsupported` markiert

##### 10.3 Grenzen der Heuristik

* `SENSITIVE_PATH` ist Schlüsselwort­-basiert — `password-richtlinie.pdf` löst aus, `creds.cfg` nicht
* `BROAD_GROUP_WRITE` deckt die vier praktisch wichtigsten Well-Knowns ab. Eigene große Verteiler­gruppen (`Alle Mitarbeiter`) sind als Domain-Gruppen nicht in der Liste — der Auditor muss solche Eigen­gruppen manuell als „breit" erkennen
* Severity ist **technisch klassifiziert**, nicht **geschäftlich** — eine Critical-Meldung kann normal sein (SYSTEM), eine Low kann gefährlich sein (Direct ACE auf einen Geschäftsführer-Ordner)

##### 10.4 Plattform-Verifikation

Stars ist gegen die folgenden Windows-Versionen verifiziert oder bewusst nicht verifiziert:

| Plattform | Status |
|---|---|
| **Windows Server 2022 Standard** | ✅ **getestet** — Audit-Pfade (Identitäts­auflösung, NTFS-DACL, SMB-Share-DACL, Risiko­regeln, GUI) wurden auf einem realen Domain Controller dieser Version durchgeführt. |
| **Windows Server 2025** | ⚠ **noch nicht geprüft** — keine systematische Verifikation. |
| **Andere Windows-Versionen** (10/11, ältere Server) | Implementierungs­ziel, aber nicht systematisch verifiziert. Erfahrungs­gemäß sollte die LSA-/NetAPI-Schicht auf Windows 10/11 und Server 2016+ identisch funktionieren — Verlass auf diese Annahme ist aber kein Test­ersatz. |

Diese Aufstellung wird mit jedem dokumentierten Test­lauf aktualisiert. Eine fehlende Markierung bedeutet **nicht** „funktioniert nicht" — sondern **„nicht überprüft"**.

> **Wichtig — Haftung und Eigen­verantwortung:** Der Vermerk „getestet" bedeutet ausschließlich, dass die Audit-Funktionen auf der genannten Plattform manuell durchlaufen wurden. Er ist **keine Zusicherung von Korrektheit, Vollständigkeit oder Eignung für einen bestimmten Einsatz­zweck**. Die Nutzung von Stars erfolgt auf **allen** Plattformen — auch auf den getesteten — **ausschließlich auf eigene Verantwortung des Anwenders**. Birger Labinsch übernimmt **keine Haftung** für Schäden, Datenverluste, fehlerhafte Audit-Ergebnisse oder daraus abgeleitete Entscheidungen. Der vollständige Haftungsausschluss steht in der README des Repositories und ist Bestandteil jeder Nutzung dieses Werkzeugs.

##### 10.5 Empfehlung für den Audit-Workflow

1. **Zielidentität sorgfältig wählen** — als welcher Benutzer soll geprüft werden? Ein Domain-Admin sieht überall Full Control, das produziert Rauschen. Sinnvolle Ziele:
   * Stell­vertreter­konten (Test-Accounts mit normalem Profil)
   * Service-Accounts (auf ihren spezifischen Wirkbereich prüfen)
   * `Authenticated Users` und `Everyone` (gezielt: was kann „irgendwer im Domain" eigentlich?)
2. **Scan-Tiefe begrenzen** — der ganze Wurzelpfad eines Servers braucht Stunden und produziert tausende Befunde. Lieber pro Abteilung/Freigabe scannen
3. **Befunde mit `incomplete = true` separat behandeln** — sie sind keine harten Aussagen, sondern Untersuchungs­aufträge
4. **HTML-Bericht für die Doku, CSV für die Nachbearbeitung** — beide Exportformate sind vorhanden und dokumentationsfähig
5. **Delta-Tab für wiederkehrende Audits nutzen** — bei regelmäßiger Prüfung derselben Freigabe trägt der Delta-Tab die Veränderungen heraus (hinzugekommene Pfade, geänderte Rechte). Voraussetzung: die Scans sind in der lokalen SQLite-Historie gespeichert (siehe Kapitel 11)
6. **Namen statt SIDs eingeben** — das Feld „Benutzer/Gruppe" hat eine Live-Suche mit bis zu 15 Vorschlägen pro Tippe. Vier Typ-Marker grenzen die Klasse ein:
   * `[U]` = Domänen-/lokaler User
   * `[G]` = globale (Domänen-)Gruppe
   * `[L]` = lokale Gruppe (`BUILTIN\…`)
   * `[W]` = Well-Known-Identität (`Everyone`, `Authenticated Users`, `SYSTEM`, `NETWORK`, `ANONYMOUS LOGON`, …)

   Klick übernimmt den Namen, der `LookupAccountNameW`-Aufruf liefert die SID automatisch. Der „🔍 SID auflösen"-Button erlaubt dieselbe Auflösung auch ohne Suche, wenn der Name schon im Kopf ist

#### <a name="11-persistierte-daten-und-scan-historie"></a>11. Persistierte Daten und Scan-Historie

Stars speichert jeden abgeschlossenen Scan in einer **lokalen SQLite-Datenbank**, damit der Delta-Tab zwei Läufe vergleichen kann und Identitäts­auflösungen über mehrere Sessions hinweg zwischen­gespeichert sind.

**Standort:** `%APPDATA%\Stars\stars_data.db` (typisch: `C:\Users\<Anwender>\AppData\Roaming\Stars\stars_data.db`).
Falls `%APPDATA%` nicht gesetzt ist, fällt Stars auf das Verzeichnis der EXE zurück — relevant nur für Entwicklungs­läufe.

**Tabellen:**

| Tabelle | Inhalt |
|---|---|
| `scan_runs` | Eine Zeile pro abgeschlossenem Scan: UUID, Startzeit, Endzeit, Zielpfad |
| `permissions` | Alle ausgewerteten Pfade pro Lauf mit Identität, NTFS-Maske, Share-Maske, effektiver Maske, vollständigem Erklärungspfad |
| `scan_errors` | Walk-/Eval-Fehler pro Scan (z.B. „Access denied", „Path not found", „Cancelled by user") |
| `identity_cache` | SAM-/LDAP-Auflösungs-Cache (SID → Name, Domäne, Gruppenmitgliedschaften) — beschleunigt wiederholte Scans für dieselbe Identität |

**Auditor-relevante Eigenschaften:**

* **Pro Benutzer­profil getrennt.** Wenn mehrere Admins denselben Server pflegen, hat jeder seine eigene Audit-Historie. Das ist saubere Trennung der Aktivitäts­spuren, aber kein „Team-Audit-Pool".
* **Überlebt eine Stars-Deinstallation** — der Installer entfernt standardmäßig nur sein Install-Verzeichnis (`%LOCALAPPDATA%\Stars\` ohne `logs\`). Die Audit-Historie in `%APPDATA%\Stars\stars_data.db` bleibt erhalten. Das ist Absicht: Audit-Historie ist Beweismittel und sollte nicht versehentlich mit dem Tool weggehen. Wer sie bewusst entfernen will, hakt im Uninstaller die optionale Komponente **„Audit-Historie und Logs entfernen"** an — diese ist standardmäßig deaktiviert.
* **Kein Passwort, keine Verschlüsselung der Datei selbst.** Wer Zugriff auf das Benutzerprofil hat, kann die Audit-Ergebnisse lesen. Für sensible Audit-Daten muss der Profil­pfad selbst entsprechend abgesichert sein (NTFS-Rechte auf das Verzeichnis, BitLocker auf der Platte). Stars verschlüsselt **nicht** selbst — bewusst, damit der Auditor die DB mit Standard-SQLite-Tools öffnen kann.
* **Inspizierbar im Read-only-Modus** — jedes SQLite-Tool (DB Browser for SQLite, DBeaver, `sqlite3.exe`) kommt rein, auch wenn Stars gar nicht läuft. Das ermöglicht externe Auswertung oder Archivierung.
* **Schemamigrationen idempotent** — beim Start wird das Schema bei Bedarf hochmigriert (`run_migrations`). Alte DBs werden weiterverwendet.
* **Persistenz-Fehler werden sichtbar gemeldet, nicht verschluckt.** Wenn das Anlegen der DB fehlschlägt (Schreibrechte, Plattenplatz), läuft der Scan trotzdem durch, aber jeder Scan trägt einen sichtbaren Persistenz­fehler in der Statuszeile. So kann der Auditor nicht versehentlich glauben, die Historie sei intakt, wenn sie es nicht ist.

**Was Stars zur Datenbank *nicht* tut:**
* Keine automatische Größen­begrenzung oder Retention — alte Scans bleiben drin, bis sie manuell entfernt werden.
* Keine Replikation, kein Cloud-Sync, keine Mehrbenutzer-Synchronisation.
* Keine Verschlüsselung „in Transit" — die DB ist eine lokale Datei, nichts geht übers Netz.
* Keine Backups — der Auditor ist verantwortlich, die Datei in seine Backup-Routine zu nehmen, wenn die Audit-Historie langfristig erhalten bleiben soll.

#### Anhang A — Glossar

| Begriff | Bedeutung |
|---|---|
| **SID** | Security Identifier — die technische Identität in Windows, z.B. `S-1-5-21-1234-1234-1234-500` für den Domain-Admin |
| **DACL** | Discretionary Access Control List — Liste der ACEs, die festlegt, wer was darf |
| **ACE** | Access Control Entry — ein einzelner Eintrag in der DACL |
| **SACL** | System Access Control List — Liste für Audit-Logging (von Stars nicht ausgewertet) |
| **Effective Mask** | Berechnete tatsächliche Berechtigung nach Anwendung aller relevanten ACEs |
| **Access Mask** | Rohwert der Berechtigung als 32-bit Maske, z.B. `0x001F01FF` für Full Control |
| **AGDLP** | Account → Global → Domain Local → Permission, Microsoft-Best-Practice für Berechtigungs­vergabe |
| **AccessContext** | Stars-Konzept: simuliert lokalen vs. Remote-SMB-Zugriff für korrekte Token-Bildung |
| **incomplete** | Marker an Risikobefunden: Auswertung hatte Lücken, Ergebnis ist eine Annäherung |
| **WARP** | Software-D3D12-Renderer, irrelevant für die Audit-Logik, relevant für die GUI auf einem DC |
| **`[U]` / `[G]` / `[L]` / `[W]`** | Typ-Marker in der Live-Suche der GUI: User / globale (Domänen-)Gruppe / lokale Gruppe (`BUILTIN\…`) / Well-Known-SID. Steht jeweils vor dem Klartextnamen, damit der Auditor auf einen Blick die Mitgliedschaftsklasse sieht |
| **Live-Suche** | Auto-Complete-Hilfe im Namensfeld der Analyze- und Scan-Maske. Aus einer Cache-Liste (`NetUserEnum` + `NetGroupEnum` + `NetLocalGroupEnum` + Well-Known-Tabelle) werden bis zu 15 Treffer pro Suchanfrage angezeigt. Klick übernimmt den Namen, die SID wird automatisch via `LookupAccountNameW` aufgelöst |

#### Anhang B — Querverweise zum Code

| Konzept | Implementiert in |
|---|---|
| Effektive-Rechte-Berechnung | `crates/permission_engine/src/engine.rs::evaluate` |
| Token-Bildung mit AccessContext | `crates/permission_engine/src/lib.rs::build_token_sids_with_context` |
| SAM-basierte Identitäts­auflösung | `crates/ad_resolver/src/sam.rs` |
| LDAP-basierte Identitäts­auflösung | `crates/ad_resolver/src/resolver.rs` |
| Lokale Server-Gruppen­auflösung | `crates/ad_resolver/src/local_groups.rs` |
| Alle Risikoregeln | `crates/risk_engine/src/rules.rs` |
| Strukturierte Diagnose-Marker | `adpa_core::model::PermissionDiagnostic` |
| Erklärungspfad | `adpa_core::model::PermissionPath` |
| HTML-Export | `crates/exporter/src/html.rs` |
| Persistenz (SQLite, Schema, Migrationen) | `crates/persistence/src/` |
| Delta-Vergleich zweier Scan-Läufe | `crates/persistence/src/delta.rs::compare_scans` |
| Datenbank-Standardpfad | `crates/gui/src/worker.rs::default_db_path` |
| Identitäts-Enumeration für die GUI-Live-Suche | `crates/ad_resolver/src/enumerate.rs::enumerate_all` |
| Name → SID (LSA, GUI-Button und Live-Suche) | `crates/ad_resolver/src/sam.rs::lookup_sid_for_account` |

---

## <a name="english"></a>English

### Table of Contents

1. [Core principles](#1-core-principles)
2. [What Stars analyzes](#2-what-stars-analyzes)
3. [How effective permissions are computed](#3-how-effective-permissions-are-computed)
4. [The six risk rules in detail](#4-the-six-risk-rules)
5. [The severity model](#5-the-severity-model)
6. [The `incomplete` marker](#6-the-incomplete-marker)
7. [Optimal rights per role and path class](#7-optimal-rights)
8. [Sensitive paths — what Stars takes as a hint](#8-sensitive-paths)
9. [What Stars deliberately does not do](#9-what-stars-does-not-do)
10. [Known limits of the evaluation](#10-known-limits)
11. [Persisted data and scan history](#11-persisted-data)

#### <a name="1-core-principles"></a>1. Core principles

Stars evaluates permissions **strictly read-only**. The tool makes **no changes** to AD objects, NTFS DACLs, or SMB shares — neither automatically nor on a button click. It shows, explains, and exports; nothing more.

The evaluation stands on four pillars:

| Pillar | Meaning |
|---|---|
| **Correctness** | The permission calculation must do what Windows does on a real access — otherwise every other statement is worthless. |
| **Traceability** | Every result carries a complete explanation path: through which groups, which ACEs, and which inheritance rules the right came about. |
| **Risk evaluation by fixed rules** | Six rules implemented in `risk_engine`, each with a clearly defined trigger and severity. No "heuristic". |
| **Honesty about uncertainty** | When the evaluation had gaps (e.g. share DACL not readable), the result is marked `incomplete`. Stars does not hide its own limits. |

These pillars match the priorities of the internal specification exactly:
> Security > Correctness > Traceability > Testability > Stability > Performance > Usability > Aesthetics.

#### <a name="2-what-stars-analyzes"></a>2. What Stars analyzes

For every examined path, Stars pulls **five input data sets**:

##### 2.1 Identity resolution

From the supplied user SID, Stars determines the full identity and group data — **directly through the Windows LSA/SAM API**, with no LDAP bind required:

* `LookupAccountSidW` → plain-text name (e.g. `BUILTIN\Administrator`) and account type
* `NetUserGetGroups` → **global (domain) groups** like `Domain Admins`, `Schema Admins`
* `NetUserGetLocalGroups` → **local groups** of the target server (e.g. `BUILTIN\Administrators`)

LDAP can optionally be added — relevant when Stars does **not** run on a domain controller and the data must be fetched from outside.

##### 2.2 Token construction

Stars reconstructs the **access token** the way Windows would build it on a real access. It includes:

* the user SID itself
* every direct group SID
* every transitive group SID (e.g. Administrator → Domain Admins → `BUILTIN\Administrators`)
* local server group SIDs
* context-dependent well-known SIDs:
  * `Everyone` (S-1-1-0) — always
  * `Authenticated Users` (S-1-5-11) — always (for non-anonymous logons)
  * `INTERACTIVE` (S-1-5-4) and `LOCAL` (S-1-2-0) — only on local access
  * `NETWORK` (S-1-5-2) — only on SMB access

Which of the last group is present depends on the **AccessContext**. Stars derives it from the path type: local paths → `LocalInteractive`, UNC paths → `RemoteSmb`. This matters because ACEs on `NETWORK` apply on SMB but are ignored on local access — and vice versa.

##### 2.3 NTFS DACL

The raw Discretionary Access Control List of the path is read directly via Win32 API. For each ACE, Stars remembers:

* trustee SID
* Allow or Deny
* access mask (raw value)
* explicit or inherited
* inheritance and propagation flags

##### 2.4 SMB share DACL (optional)

For UNC paths (`\\server\share\…`) Stars additionally reads the **share permissions**. The effective permission over SMB is then the **more restrictive** of the two sets:

```
effective_smb = NTFS ∩ Share
```

Examples:

| NTFS | Share | Effective |
|---|---|---|
| Modify | Read | **Read** |
| Read & Execute | Full Control | **Read & Execute** |
| Full Control | Change | **Change** |

A NULL DACL on the share is interpreted as "no restriction over SMB" — not as "Full Control" — and marked with the dedicated status `Unrestricted`, instead of fabricating an artificial `0xFFFFFFFF` mask. This matters because otherwise an auditor could think someone deliberately granted Full Control.

##### 2.5 Diagnostic markers

During evaluation Stars collects structured **diagnostic markers**:

* `NonCanonicalDaclOrder` — the order of ACEs does not match Windows' canonical pattern (`explicit deny → explicit allow → inherited deny → inherited allow`). Windows still evaluates the DACL in **stored order**; the tool surfaces this as an audit hint, since a non-canonical DACL usually arose from manual editing.
* `UnsupportedShareAces { count }` — the share DACL contained ACE types the parser could not evaluate (object, callback, or vendor-specific ACEs). The effective mask is then a **lower bound**; a hidden Deny could flip the result.
* `unsupported_ace_count > 0` (NTFS side) — the same thing on the NTFS DACL.

These markers feed into the `incomplete` flag of risk findings (see section 6).

#### <a name="3-how-effective-permissions-are-computed"></a>3. How effective permissions are computed

The calculation runs in four phases:

##### Phase 1 — Token building

From user SID + memberships + local groups + well-knowns, a **HashSet** of all effective token SIDs is built.

##### Phase 2 — DACL application (stored order)

For every ACE in **stored order**:

* Check the trustee SID against the token → no match? Skip.
* Deny ACE → add bits to the **Deny mask**.
* Allow ACE → add bits to the **Allow mask**, **but only bits that are not already in the Deny mask** (this is Windows semantics: a Deny seen earlier overrides a later Allow).

Generic bits (`GENERIC_ALL`, `GENERIC_READ`, etc.) are expanded into their concrete bits. INHERIT_ONLY ACEs are filtered out — they do not apply to the current object, only to children.

##### Phase 3 — Owner special rule

If the user is the owner of the object, Stars adds `READ_CONTROL` and `WRITE_DAC` to the Allow mask — Windows always grants the owner the right to read and modify the ACL, regardless of DACL content.

##### Phase 4 — Share combination

When a share context is present:
* `share_status == Applied(mask)` → Effective = NTFS AND Share-Mask
* `share_status == Unrestricted` (NULL DACL) → Effective = NTFS (no additional filter)
* `share_status == ReadFailed` → Effective = NTFS, **incomplete** flag is set
* `share_status == NotApplicable` → Effective = NTFS (no share context)

The end result is the **Effective Access Mask**, plus the full explanation path with every effective membership and ACE.

#### <a name="4-the-six-risk-rules"></a>4. The six risk rules in detail

All rules live in `crates/risk_engine/src/rules.rs` and are registered via `RuleRegistry::with_defaults()`. Each rule is an independent implementation of the `RiskRule` trait and can be tested in isolation.

##### 4.1 Rule: `FULL_CONTROL` — severity **Critical**

**Source:** `FullControlRule` (rules.rs:135ff)

**Trigger:** The effective mask contains **all** bits of `MASK_FULL_CONTROL` (`0x001F01FF` plus `WRITE_DAC`, `WRITE_OWNER`).

**Logic:** `effective_mask & MASK_FULL_CONTROL == MASK_FULL_CONTROL`

**Severity justification:**
Full Control gives the principal the right to change the ACL itself (`WRITE_DAC`) and to take ownership (`WRITE_OWNER`). Anyone with Full Control on an object can grant themselves practically any permission — and audit-relevant changes become indistinguishable from a normal write. This is the most severe finding the engine knows.

**When this is *normal*:**
* `BUILTIN\Administrators` on system paths (`C:\Windows`, `C:\Program Files`)
* `SYSTEM` on practically every system path
* `TrustedInstaller` on components that only Windows Update should touch
* The owner on their own user profile

**When this is *critical*:**
* `Everyone`, `Authenticated Users`, `Domain Users` have Full Control on a share → immediate action required
* A normal user has Full Control on a *foreign* share or on a shared data directory
* A service account has Full Control beyond its own data directory

##### 4.2 Rule: `WRITE_ACCESS` — severity **High**

**Source:** `WriteAccessRule` (rules.rs:166ff)

**Trigger:** The effective mask contains Modify or Write, but **not** Full Control.

**Logic:** `(MASK_MODIFY or MASK_WRITE) set, MASK_FULL_CONTROL not set`

**Severity justification:**
Write access allows creating, modifying, or deleting files. On data that others use for reading (configs, scripts, reports), this is a **tampering risk**: an attacker (or an accidentally compromised account) can swap content. Write access on user profiles is normal; on system files it is not.

**Relation to Full Control:**
The rule deliberately does **not** fire when Full Control is present — that is already covered by `FullControlRule`. Otherwise there would be duplicate findings for the same situation.

**When this is *normal*:**
* User on their own `%USERPROFILE%`
* Service account on its data directory
* Editors on a share (domain local group `<Share>_Modify`)

**When this is *critical*:**
* `Everyone` or `Authenticated Users` have Modify on system or program files
* Normal users have Modify on configuration files (configurations can no longer be trusted)

##### 4.3 Rule: `PERMISSION_CHANGE` / `OWNER_CHANGE` / `DELETE_RIGHT` / `DELETE_CHILD_RIGHT`

**Source:** `AdminRightsRule` (rules.rs:217ff)

This rule closes a gap left by `WriteAccessRule` and `FullControlRule`: **destructive or administrative individual rights** that are not included in Modify/Write but already represent a privilege escalation opportunity.

**Bits reported individually:**

| Rule-ID | Bit | Severity | Meaning |
|---|---|---|---|
| `PERMISSION_CHANGE` | `FILE_WRITE_DAC` | **High** | Can change the ACL → can grant themselves further rights |
| `OWNER_CHANGE` | `FILE_WRITE_OWNER` | **High** | Can take ownership → the owner special rule then works in favor of the attacker |
| `DELETE_RIGHT` | `FILE_DELETE` | **Medium** | Can delete the object itself |
| `DELETE_CHILD_RIGHT` | `FILE_DELETE_CHILD` | **Medium** | Can delete children of a folder without write access on the children themselves |

**Important property:** The rule **stays silent** when the principal already has Full Control — that is already `FULL_CONTROL` Critical, and additional break-down would only produce noise.

**Justification for the severity differences:**
* `WRITE_DAC` and `WRITE_OWNER` are **High** because they enable privilege escalation — the principal can grant themselves further rights without the audit tool noticing.
* `DELETE` and `DELETE_CHILD` are **Medium** — no privilege gain, but tampering and data loss are possible.

##### 4.4 Rule: `BROAD_GROUP_WRITE` — severity **Critical**

**Source:** `BroadGroupWriteRule` (rules.rs:290ff)

**Trigger:** Write access arose from an ACE on a **broad well-known group**, **and** that ACE actually contributed write bits.

**Broad SIDs:**

| SID | Meaning |
|---|---|
| `S-1-1-0` | `Everyone` — literally anyone, including anonymous accesses depending on configuration |
| `S-1-5-11` | `Authenticated Users` — anyone with a valid domain/local login |
| `S-1-5-7` | `Anonymous Logon` — accesses without authentication |
| `S-1-5-2` | `NETWORK` — anyone accessing via SMB |

**Important (anti-false-positive):** The rule fires **only** when the broad principal actually contributed **write bits** to the effective mask (via the `contributing_sids` field). If `Everyone` only has Read and the Modify rights come through a specific group, it is **not** reported. Otherwise it would be a classic false alarm that makes the entire audit unusable.

**Severity justification:**
Write access via a broad SID is the worst configuration that practically occurs — it makes every user on the network (or with `Anonymous Logon`, every unauthenticated client) a potential attacker on that path. It is essentially an "open door" that often arose historically from quick fixes and was never rolled back.

##### 4.5 Rule: `DIRECT_USER_ACE` — severity **Low**

**Source:** `DirectUserAceRule` (rules.rs:356ff)

**Trigger:** The user has a **direct explicit ACE** on the path — not via a group but on their own user SID, **not inherited** but explicitly assigned on the object.

**Data source:** The `matched_aces` field of `EffectivePermission`. The rule is therefore **localization-safe** and independent of the explanation text — it also works on German systems with translated names.

**Treatment of Allow and Deny:** Both are reported — a direct explicit Deny violates the best practice just as much as a direct explicit Allow.

**INHERIT_ONLY:** ACEs with `INHERIT_ONLY_ACE` flag are deliberately filtered out of `matched_aces` (the engine removes them earlier). A direct user ACE that would only affect children has no effect on the current object and does not trigger a finding here.

**Severity justification:**
This is **Low** because it is rarely a concrete security risk — rather a **management problem**. Best practice in AD environments is `AGDLP` (Account → Global Group → Domain Local Group → Permission): permissions go through groups, never directly on users. Direct user ACEs are:
* hard to audit (they become invisible once the user is removed from the directory → orphaned SID)
* hard to maintain (every path must be touched individually instead of swapping a group)
* historically often a sign of "just rubber-stamped" actions

`incomplete` flag: always `false`. The structured ACE source is an NTFS property, independent of share status.

##### 4.6 Rule: `SENSITIVE_PATH` — severity **Medium**

**Source:** `SensitivePathRule` (rules.rs:394ff)

**Trigger:** The path name contains one of the following keywords (case-insensitive), **and** the principal actually has access (`effective_mask > 0`):

```
password, passwort, pwd, login, credential, credentials, secret, secrets,
token, api-key, apikey, keyfile, private-key, ssh-key, private_key, ssh_key
```

**Important (anti-false-positive):** The rule reports **only** when `effective_mask > 0`. A path named `passwords.txt` on which the identity is explicitly denied is **not** a finding — otherwise Stars would falsely report a non-access as a risk.

**What the rule does *not* do:** It does not open the file, does not read content, does not search for actual secrets in cleartext. That would itself be a privacy problem. It looks **only at the path name** as a heuristic.

**Severity justification:**
Medium, because the **path name alone** is a weak indicator. `password-policies.pdf` matches the keyword but is harmless. `c:\dev\password-resets\logs\` is highly sensitive. Stars does not distinguish that — the auditor must. The hint still matters because:
* sensitive paths often carry overly broad permissions (convenience over security)
* sensitive paths are typical targets in pentests and real attacks

`incomplete` flag: always `false`. The path name is an NTFS property, independent of share status.

#### <a name="5-the-severity-model"></a>5. The severity model

Stars classifies every finding into one of five levels (`adpa_core::model::RiskSeverity`):

| Severity | Meaning | Examples from the rules |
|---|---|---|
| **Critical** | Immediate attention. Privilege escalation, tampering by broad user groups, or direct data loss are imminent. | `FULL_CONTROL`, `BROAD_GROUP_WRITE` |
| **High** | Elevated risk. Write rights on valuable objects, individual privilege escalation bits. | `WRITE_ACCESS`, `PERMISSION_CHANGE`, `OWNER_CHANGE` |
| **Medium** | Worth attention. Destructive individual rights, sensitive path names. | `DELETE_RIGHT`, `DELETE_CHILD_RIGHT`, `SENSITIVE_PATH` |
| **Low** | More of a best-practice or management finding than an acute risk. | `DIRECT_USER_ACE` |
| **Info** | Hints without risk character (not currently used by any default rule; reserved for extensions). | — |

**Important:** Severity is **not** an absolute value. A `FULL_CONTROL` Critical from `SYSTEM` on `C:\Windows` is trivial and correct; the same Critical from `Authenticated Users` on `\\server\Accounting` is an emergency. Severity sorts by **technical seriousness**; context must be added by the auditor.

#### <a name="6-the-incomplete-marker"></a>6. The `incomplete` marker

Every `RiskFinding` carries a boolean `incomplete` field. It marks findings whose underlying **permission evaluation** had gaps and which should therefore be read **cautiously**.

`incomplete = true` is set when at least one of four causes applies:

1. **Share DACL was not readable** (`ShareEvalStatus::ReadFailed(...)`).
   `effective_mask` is then only an **NTFS lower bound** — actual SMB access could be more restrictive.

2. **DACL contained unsupported ACEs** (`unsupported_ace_count > 0`).
   Object, callback, or conditional ACEs are skipped by the parser; a hidden Deny could flip the result.

3. **Local server groups could not be resolved** (`LocalGroupEvalStatus::NotAvailable(...)`).
   ACEs targeting e.g. a local `Administrators` group are then invisible; effective rights may be **too low**.

4. **Share DACL contained unsupported ACEs** (diagnostic `UnsupportedShareAces`).
   Analogous to point 2 but on the share side.

A finding with `incomplete = true` does **not** mean it is wrong — it means the underlying result might not be 100% complete. For an audit that is the honest statement; for an automated escalation you should not blindly trust it.

#### <a name="7-optimal-rights"></a>7. Optimal rights per role and path class

This section shows **what counts as well configured**. Stars flags deviations through the risk rules — the following sections give the auditor the yardsticks against which to judge findings.

The recommendations follow long-established Microsoft best practices, notably the **AGDLP model**:

```
Account  →  Global Group  →  Domain Local Group  →  Permission
```

Concretely: users go into global groups, global groups into domain local groups, **NTFS rights are assigned exclusively to domain local groups** — never directly to users, never to global groups, never to broad well-known identities.

##### 7.1 System paths — `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`

**Optimal ACL:**

| Identity | NTFS right | Justification |
|---|---|---|
| `NT AUTHORITY\SYSTEM` (S-1-5-18) | **Full Control** | Windows services run as SYSTEM and must be able to modify system files at any time |
| `BUILTIN\Administrators` (S-1-5-32-544) | **Full Control** | Administrative maintenance, manual updates |
| `TrustedInstaller` | **Full Control** on system components | Only Windows Update should touch core files |
| `BUILTIN\Users` (S-1-5-32-545) | **Read & Execute** | Programs must be readable and runnable |
| `Authenticated Users` | **Read & Execute** | Like above, also covers domain-joined users |
| `Everyone` | Nothing (or at most Read) | Anonymous accesses have no business here |

**What Stars reports (and why it is *normal* here):**
* `FULL_CONTROL` for Administrators → expected on system paths, no real finding
* `FULL_CONTROL` for SYSTEM → expected
* `WRITE_ACCESS` for Modify holders (e.g. `TrustedInstaller`) → expected

**What Stars reports that is *critical*:**
* `BROAD_GROUP_WRITE` for `Everyone` or `Authenticated Users` on system files → real finding, act immediately
* `WRITE_ACCESS` for normal users on system files → system integrity at risk

##### 7.2 User profiles — `C:\Users\<user>`

**Optimal ACL:**

| Identity | NTFS right | Justification |
|---|---|---|
| The user themselves | **Full Control** on their own profile | Own data, own responsibility |
| `NT AUTHORITY\SYSTEM` | **Full Control** | Backup, profile loading |
| `BUILTIN\Administrators` | **Full Control** (or deliberately removed for privacy) | Administrative maintenance |
| **Other users** | Nothing | Strict — foreign profiles are off-limits |

**What Stars reports:**
* `FULL_CONTROL` for the profile owner → expected
* `FULL_CONTROL` for SYSTEM/Administrators → expected
* `FULL_CONTROL` for **other** users → real finding (privacy violation)
* `BROAD_GROUP_WRITE` on a profile, ever → real finding

##### 7.3 Shared data directories — `\\server\Data\…`

The AGDLP model becomes especially visible here. An example ACL for `\\server\Accounting`:

| Identity | NTFS right | Share right | Justification |
|---|---|---|---|
| `NT AUTHORITY\SYSTEM` | Full Control | — | Backup agent |
| `BUILTIN\Administrators` | Full Control | Full Control | Emergency access |
| Domain Local Group `FS_Accounting_RW` | **Modify** | **Change** | Editor role |
| Domain Local Group `FS_Accounting_RO` | **Read & Execute** | **Read** | Reader role |
| `CREATOR OWNER` | Modify (inherit-only) | — | Edit one's own documents |
| **No one else** | Nothing | Nothing | Strict |

The members of the domain local groups are **global groups** (e.g. `GG_Accounting_Staff`) into which individual users go as account members.

**What Stars reports:**
* `FULL_CONTROL` for `SYSTEM` and Administrators → expected
* `WRITE_ACCESS` for members of `FS_Accounting_RW` → expected
* `DIRECT_USER_ACE` for any user → best-practice violation (Low)
* `BROAD_GROUP_WRITE` ever → real Critical finding

##### 7.4 Service accounts and service data directories

**Optimal ACL:** A service account may write **only** in its own data directory. Read access only on configuration files the service actually needs.

| Identity | NTFS right on service data dir | Justification |
|---|---|---|
| `NT AUTHORITY\SYSTEM` | Full Control | Backup |
| Administrators | Full Control | Maintenance |
| The service account itself | **Modify** | Write to data directory |
| **No one else** | Nothing | Strict |

**What Stars reports:**
* `WRITE_ACCESS` for the service account on *its* directory → expected
* `WRITE_ACCESS` for the service account on *other* directories → real finding
* `FULL_CONTROL` for the service account → almost always excessive; Modify would have sufficed

##### 7.5 Administrators on data (not system)

A particular question: should `BUILTIN\Administrators` have Full Control on **data** directories?

* **System paths:** yes, always (emergency maintenance, recovery).
* **Data paths:** technically yes, but **deliberately set and documented**. Whoever is "Admin" has practically unrestricted access to the server — the audit log should make this traceable.
* **Sensitive data paths (payroll, HR, executive):** worth considering replacing administrator access with a separate permission structure (e.g. a dedicated domain local group `FS_HR_FullControl` with *explicit* membership) instead of relying on global administrator membership. This protects against accidental data leakage through general admin tasks.

Stars reports `FULL_CONTROL` as Critical here — how seriously to take that in each case is up to the auditor based on the path's sensitivity.

#### <a name="8-sensitive-paths"></a>8. Sensitive paths — what Stars takes as a hint

The `SensitivePathRule` (see 4.6) searches for keywords in the path name. It does not report the **content**, only the **suspicion**.

**Practical reading hints:**

| Path name contains | Typical meaning | Audit attention |
|---|---|---|
| `password`, `passwort`, `pwd` | Password lists, reset workflows, configurations | Very high — even if the path is "password-policy.docx", access should be strictly controlled |
| `credential`, `credentials` | Credential stores, script configs with cleartext logins | Very high |
| `secret`, `secrets` | Application secrets, tokens | Very high |
| `token`, `api-key`, `apikey` | OAuth tokens, API keys | Very high |
| `private-key`, `private_key`, `ssh-key`, `ssh_key`, `keyfile` | Private crypto keys | **Highest priority** — a compromised key is not revocable like a password |
| `login` | Login scripts, profiles, sometimes configs | High |

**What Stars *does not* cover** (and the auditor should additionally check):
* Encrypted containers whose file name sounds neutral
* Configuration files with cleartext credentials but innocuous names (`config.ini`, `web.config`, `appsettings.json`)
* Database backups (`.bak`, `.dmp`) that may contain personal data

#### <a name="9-what-stars-does-not-do"></a>9. What Stars deliberately does not do

The tool is **permanently designed as a read-only analysis and display utility**. The following is not planned and will not be implemented in the future:

* **Change permissions** — neither automatically nor on a button click
* **Clean up** or "repair" ACLs
* **Change AD group memberships**
* **Change AD users**
* **Create, change, or delete shares**
* **Modify files or folders on target systems**
* **Automatically apply repair suggestions**
* **Deploy agents to file servers**
* **SIEM integration with active response**
* **Open file contents for the purpose of secret hunting** (`SensitivePathRule` only looks at the path name)

This self-restriction is not coincidental but essential: an audit tool that can do more is an attack tool. Stars must not become a risk itself.

#### <a name="10-known-limits"></a>10. Known limits of the evaluation

Even a technically correct audit has limits — Stars does not evaluate facts it cannot see:

##### 10.1 What Stars *sees*

* NTFS DACLs in the order in which they are stored
* SMB share DACLs (if readable)
* Group memberships (via SAM/LSA, optionally LDAP)
* Local server groups (via NetUserGetLocalGroups)
* AccessContext (local vs. SMB) — derived from the path

##### 10.2 What Stars *does not* see

* **File contents** — what is in `Payroll_2025.xlsx` is irrelevant to the permission calculation
* **Audit logs** — *who actually did what when* belongs in the event log, not the DACL
* **Central Access Rules (CAR)** — Dynamic Access Control with central policies is not yet evaluated by the parser
* **SACLs** (System Access Control Lists) — only DACLs are read; SACLs for audit logging are a different topic
* **Mandatory Integrity Control (Integrity Levels)** — Low/Medium/High integrity labels are not taken into account
* **Conditional ACEs** — reported as `unsupported`, not evaluated
* **Object and callback ACEs** — also marked as `unsupported`

##### 10.3 Limits of the heuristics

* `SENSITIVE_PATH` is keyword-based — `password-policy.pdf` matches, `creds.cfg` does not
* `BROAD_GROUP_WRITE` covers the four practically most important well-knowns. Your own large distribution groups (`All Employees`) are not on the list as domain groups — the auditor must recognize such own groups as "broad" manually
* Severity is **technically classified**, not **business-classified** — a Critical can be normal (SYSTEM), a Low can be dangerous (Direct ACE on an executive's folder)

##### 10.4 Platform verification

Stars is verified or deliberately not verified against the following Windows versions:

| Platform | Status |
|---|---|
| **Windows Server 2022 Standard** | ✅ **tested** — audit paths (identity resolution, NTFS DACL, SMB share DACL, risk rules, GUI) were exercised on a real domain controller of this version. |
| **Windows Server 2025** | ⚠ **not yet verified** — no systematic verification. |
| **Other Windows versions** (10/11, older servers) | Implementation target but not systematically verified. The LSA/NetAPI layer is expected to work identically on Windows 10/11 and Server 2016+, but that expectation is no substitute for testing. |

This list is updated with every documented test run. A missing entry does **not** mean "does not work" — it means **"not verified"**.

> **Important — liability and personal responsibility:** "Tested" only means the audit functions were manually exercised on the named platform. It is **not a guarantee of correctness, completeness, or suitability for any particular use**. Use of Stars on **all** platforms — including the tested ones — is **at the sole risk of the user**. Birger Labinsch assumes **no liability** for damages, data loss, faulty audit results, or decisions derived from them. The full disclaimer is in the repository's README and is part of every use of this tool.

##### 10.5 Audit workflow recommendation

1. **Choose the target identity carefully** — as which user should the check be done? A domain admin sees Full Control everywhere; that produces noise. Useful targets:
   * Deputy accounts (test accounts with a normal profile)
   * Service accounts (check their specific scope of effect)
   * `Authenticated Users` and `Everyone` (deliberately: what can "anyone on the domain" actually do?)
2. **Limit scan depth** — the whole root path of a server takes hours and produces thousands of findings. Better to scan per department/share
3. **Treat `incomplete = true` findings separately** — they are not hard statements but investigation requests
4. **HTML report for documentation, CSV for postprocessing** — both export formats are available and reportable
5. **Use the Delta tab for recurring audits** — for regular checks of the same share, the Delta tab brings out the changes (added paths, changed rights). Prerequisite: the scans are stored in the local SQLite history (see chapter 11)
6. **Enter names instead of SIDs** — the "User/group" field has a live search with up to 15 suggestions per keystroke. Four type markers narrow the class:
   * `[U]` = domain/local user
   * `[G]` = global (domain) group
   * `[L]` = local group (`BUILTIN\…`)
   * `[W]` = well-known identity (`Everyone`, `Authenticated Users`, `SYSTEM`, `NETWORK`, `ANONYMOUS LOGON`, …)

   Clicking takes the name; the `LookupAccountNameW` call delivers the SID automatically. The "🔍 Resolve SID" button performs the same resolution without search, if the name is already in mind.

#### <a name="11-persisted-data"></a>11. Persisted data and scan history

Stars stores every completed scan in a **local SQLite database** so the Delta tab can compare two runs and identity resolutions are cached across sessions.

**Location:** `%APPDATA%\Stars\stars_data.db` (typically `C:\Users\<account>\AppData\Roaming\Stars\stars_data.db`).
If `%APPDATA%` is not set, Stars falls back to the directory next to the EXE — relevant only for development runs.

**Tables:**

| Table | Content |
|---|---|
| `scan_runs` | One row per completed scan: UUID, start time, end time, target path |
| `permissions` | Every evaluated path per run with identity, NTFS mask, share mask, effective mask, full explanation path |
| `scan_errors` | Walk/eval errors per scan (e.g. "Access denied", "Path not found", "Cancelled by user") |
| `identity_cache` | SAM/LDAP resolution cache (SID → name, domain, group memberships) — speeds up repeated scans for the same identity |

**Auditor-relevant properties:**

* **Separate per user profile.** If multiple admins maintain the same server, each has their own audit history. Clean separation of activity traces, but not a "team audit pool".
* **Survives a Stars uninstall** — by default the uninstaller removes only its install directory (`%LOCALAPPDATA%\Stars\` without `logs\`). The audit history at `%APPDATA%\Stars\stars_data.db` is kept. This is by design: audit history is evidence and should not vanish accidentally with the tool. To remove it deliberately, check the optional component **"Audit-Historie und Logs entfernen"** in the uninstaller — it is off by default.
* **No password, no encryption of the file itself.** Anyone with access to the user profile can read the audit results. For sensitive audit data the profile path itself must be secured accordingly (NTFS permissions on the directory, BitLocker on the disk). Stars deliberately does **not** encrypt — so the auditor can open the DB with standard SQLite tools.
* **Inspectable in read-only mode** — any SQLite tool (DB Browser for SQLite, DBeaver, `sqlite3.exe`) can open it, even when Stars is not running. Enables external evaluation or archiving.
* **Schema migrations are idempotent** — on start the schema is migrated up if needed (`run_migrations`). Old DBs continue to work.
* **Persistence errors are visibly reported, not swallowed.** If creating the DB fails (permissions, disk space), the scan still runs but every scan carries a visible persistence error in the status bar. So the auditor cannot accidentally believe the history is intact when it is not.

**What Stars *does not* do with the database:**
* No automatic size limit or retention — old scans stay until they are removed manually.
* No replication, no cloud sync, no multi-user synchronization.
* No "in-transit" encryption — the DB is a local file, nothing goes over the network.
* No backups — the auditor is responsible for adding the file to their backup routine if the audit history must be retained long-term.

#### Appendix A — Glossary

| Term | Meaning |
|---|---|
| **SID** | Security Identifier — the technical identity in Windows, e.g. `S-1-5-21-1234-1234-1234-500` for the domain admin |
| **DACL** | Discretionary Access Control List — list of ACEs that decide who may do what |
| **ACE** | Access Control Entry — a single entry in the DACL |
| **SACL** | System Access Control List — list for audit logging (not evaluated by Stars) |
| **Effective Mask** | Computed actual permission after applying all relevant ACEs |
| **Access Mask** | Raw permission value as a 32-bit mask, e.g. `0x001F01FF` for Full Control |
| **AGDLP** | Account → Global → Domain Local → Permission, Microsoft best practice for permission assignment |
| **AccessContext** | Stars concept: simulates local vs. remote SMB access for correct token building |
| **incomplete** | Marker on risk findings: the evaluation had gaps, the result is an approximation |
| **WARP** | Software D3D12 renderer, irrelevant for audit logic, relevant for the GUI on a DC |
| **`[U]` / `[G]` / `[L]` / `[W]`** | Type markers in the GUI's live search: user / global (domain) group / local group (`BUILTIN\…`) / well-known SID. Precede the plain-text name so the auditor immediately sees the membership class |
| **Live search** | Autocomplete helper in the name field of the Analyze and Scan masks. From a cache list (`NetUserEnum` + `NetGroupEnum` + `NetLocalGroupEnum` + well-known table) up to 15 matches are shown per query. Click takes the name; the SID is resolved automatically via `LookupAccountNameW` |

#### Appendix B — Code cross-references

| Concept | Implemented in |
|---|---|
| Effective-rights calculation | `crates/permission_engine/src/engine.rs::evaluate` |
| Token building with AccessContext | `crates/permission_engine/src/lib.rs::build_token_sids_with_context` |
| SAM-based identity resolution | `crates/ad_resolver/src/sam.rs` |
| LDAP-based identity resolution | `crates/ad_resolver/src/resolver.rs` |
| Local server group resolution | `crates/ad_resolver/src/local_groups.rs` |
| All risk rules | `crates/risk_engine/src/rules.rs` |
| Structured diagnostic markers | `adpa_core::model::PermissionDiagnostic` |
| Explanation path | `adpa_core::model::PermissionPath` |
| HTML export | `crates/exporter/src/html.rs` |
| Persistence (SQLite, schema, migrations) | `crates/persistence/src/` |
| Delta comparison of two scan runs | `crates/persistence/src/delta.rs::compare_scans` |
| Database default path | `crates/gui/src/worker.rs::default_db_path` |
| Identity enumeration for the GUI live search | `crates/ad_resolver/src/enumerate.rs::enumerate_all` |
| Name → SID (LSA, GUI button and live search) | `crates/ad_resolver/src/sam.rs::lookup_sid_for_account` |

---

*Diese Lektüre ist Bestandteil der Stars-Dokumentation und wird mit dem Repository versioniert. Änderungen an Regeln, Severities oder Schwellwerten müssen hier nachgepflegt werden, sonst läuft die Doku auseinander.*

*This document is part of the Stars documentation and is versioned with the repository. Changes to rules, severities or thresholds must be reflected here, otherwise the documentation drifts out of sync.*

---

### Urheberschaft / Authorship

**Konzeption, Spezifikation, Steuerung und Review / Concept, specification, direction, and review:** Birger Labinsch — Fachinformatiker Anwendungs­entwicklung / IT Specialist for Application Development / Prompt Engineer.

**Verfasst durch / Authored by:** Claude Opus 4.7 (Anthropic) als KI-Modell, unter direkter Anleitung und Review von Birger Labinsch / as an AI model under direct guidance and review by Birger Labinsch. Inhaltlich abgeleitet aus dem tatsächlich im Repository implementierten Code (`crates/risk_engine/src/rules.rs`, `crates/permission_engine/`, `crates/ad_resolver/`) — keine erdachten Regeln, keine Wunsch­vorstellungen / Content derived from the code actually implemented in the repository — no invented rules, no wishful thinking.

Birger Labinsch hat den hier dokumentierten Code **nicht selbst geschrieben**, sondern als Prompt Engineer beauftragt, gesteuert und freigegeben / did **not** write the code documented here himself but, as a prompt engineer, commissioned, directed and approved it.
