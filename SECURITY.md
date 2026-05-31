# Security Policy

## Sicherheitslücken melden / Reporting a Vulnerability

**Deutsch:**

Bitte melde Sicherheitslücken in Stars **nicht über öffentliche GitHub-Issues**.
Ich möchte sicherstellen, dass eine Lücke geprüft und behoben ist, bevor sie
öffentlich diskutiert wird.

Melde sie bitte direkt per E-Mail an:

    **birger@labinsch.de**

Hilfreich ist eine kurze Beschreibung mit:
- betroffener Version oder Commit-SHA,
- konkretem Reproduktionsweg,
- ggf. die Auswirkung, die du siehst.

Ich antworte nach Möglichkeit innerhalb von 14 Tagen mit einer Einschätzung.

**English:**

Please do **not** report security vulnerabilities in Stars through public
GitHub issues. I want to ensure a vulnerability is verified and fixed before
it is discussed publicly.

Please report by email to:

    **birger@labinsch.de**

Helpful information:
- affected version or commit SHA,
- a concrete reproduction path,
- the impact you observe.

I will try to respond with an initial assessment within 14 days.

---

## Was als Sicherheitslücke zählt / What counts as a vulnerability

Stars ist ein **read-only Audit- und Analyse-Werkzeug**. Es verändert keine
Berechtigungen, AD-Objekte oder Dateisysteme.

Als Sicherheitslücken behandle ich insbesondere:

- **Falsche Berechtigungs­berechnung**, die einen Anwender zu falschen Audit-
  Entscheidungen verleiten könnte (z.B. ein Recht wird fälschlich als nicht
  vorhanden ausgewiesen, obwohl es wirkt).
- **Umgehung des Read-only-Prinzips** — jeder Pfad, über den Stars
  Berechtigungen, AD-Objekte oder Dateien tatsächlich verändern würde.
- **Eingaben, die Stars zum Absturz bringen** oder beliebigen Code in der
  Anwendung ausführen können (Buffer Overflow, Deserialization, etc.).
- **Leck von Zugangsdaten** — z.B. wenn ein LDAP-Passwort in einem Logfile,
  Bericht oder Trace-Aufruf landen würde.
- **Verstoesse gegen die in `docs/audit-kriterien.md` dokumentierten
  Audit-Garantien** (z.B. fehlende ACE-Behandlung, falsche Token-Bildung).

**Nicht als Sicherheitslücke** im engeren Sinne, aber dennoch wichtig
— bitte als reguläres Issue oder Diskussion melden:

- Funktionale Fehler ohne Vertrauens­folgen
- UX-/Darstellungs­fehler in der GUI
- Performance-Probleme
- Wünsche nach neuen Features oder Regeln

---

## Verantwortungs­volle Offenlegung

Sobald eine gemeldete Lücke bestätigt und gefixt ist, veröffentliche ich
einen Patch und eine Release-Notiz, die das Problem beschreibt — mit
Anerkennung des Melders, sofern dieser einverstanden ist.
