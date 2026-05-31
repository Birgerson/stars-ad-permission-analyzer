# ADR 0014 — LDAP-Paging und serverseitige Transitivität

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

Die ursprüngliche `LdapResolver`-Implementierung hatte zwei klassische
AD-Probleme:

1. **Keine Paginierung.** `search_by_query` rief `Ldap::search()` direkt
   auf — das nutzt kein Paged-Results-Control. Trifft das Ergebnis die
   AD-Default-Begrenzung `MaxPageSize` (1000), wird es serverseitig
   abgeschnitten, ohne dass der Client das bemerkt. In großen Domänen
   sind dadurch Suchen unvollständig.

2. **`memberOf`-Walking mit Range-Retrieval-Risiko.** Die Auflösung
   transitiver Gruppen lief client-seitig: zuerst `memberOf` am User
   lesen, dann für jede Gruppe wieder `memberOf` lesen, usw. AD schneidet
   `memberOf` ab ~1500 Werten ab — Benutzer in vielen Gruppen verlieren
   damit Teile ihrer Mitgliedschaft. Zusätzlich entstanden N+1 LDAP-
   Roundtrips pro Hierarchieebene.

Sichtbarer Live-Effekt im Test-Server-Scan (vor Finding 8): selbst für
`max.mustermann` (direkt in zwei Gruppen, transitiv in zwei weiteren)
gab der Resolver nur `Domain Users` (die Primärgruppe) zurück.

Siehe Review-Befund 8.

## Entscheidung / Decision

1. **Paged Search als Standard.** Neue private Helper-Funktion
   `search_paged_with_limit` in `ldap_client` baut eine
   `streaming_search_with`-Pipeline mit den ldap3-Adaptern
   `EntriesOnly` + `PagedResults`. Standard-Seitengröße: 1000 (AD-
   `MaxPageSize`-Default). Optionales `client_limit` für Anwendungsfälle
   wie „Namensvorschläge" (max. 50 Treffer für die Picker-Liste).
   `search_by_query` nutzt diese Funktion.

2. **Transitive Gruppenauflösung serverseitig.** Neue Funktion
   `search_transitive_groups_for_member(member_dn)` schickt einen
   einzigen Filter

   ```text
   (&(objectClass=group)(member:1.2.840.113556.1.4.1941:=<dn>))
   ```

   an den Domain Controller. Die OID `1.2.840.113556.1.4.1941`
   (`LDAP_MATCHING_RULE_IN_CHAIN`) lässt AD die Transitivität in einem
   Roundtrip auflösen. Die Suche läuft selbst paged.

3. **Resolver vereinfacht.** `resolve_memberships_internal` nutzt nun:

   1. Eintrag laden (für DN + `primaryGroupID` + `memberOf` als
      „direkt"-Marker).
   2. `primaryGroupID` separat auflösen (sie ist nicht über `member`
      modelliert).
   3. Eine einzige Transitivsuche für den User-DN — liefert alle
      Gruppen, in denen der User über `member`-Ketten enthalten ist.
   4. Primärgruppe nochmal transitiv auflösen (für deren Parent-
      Gruppen).
   5. Ergebnisse als `direct=true/false` markieren, anhand der
      `memberOf`-Liste des Users.

   Die alte `resolve_groups_recursive` mit `MAX_GROUP_DEPTH=64` ist
   ersatzlos entfernt — Zyklen können in dieser Form gar nicht mehr
   auftreten (der Server liefert nur Gruppen-Mengen, keine Pfade).

4. **`memberOf` wird nur noch als Hint genutzt.** Die maßgebliche
   Mitgliedschaftsliste kommt aus der Transitivsuche; `memberOf` dient
   nur zur Klassifikation „direkt vs. transitiv". Falls AD `memberOf`
   abschneidet, betrifft das jetzt höchstens die `direct`-Markierung
   einzelner Gruppen (eine geerbte könnte fälschlich als transitiv
   markiert werden) — die Mitgliedschaft selbst ist vollständig.

## Begründung / Rationale

- **Korrektheit:** „Große AD-Umgebungen sind Standardfall" (AGENTS.md
  Regel 9). Der bisherige Pfad versagte still in genau diesen Umgebungen.
- **Weniger Roundtrips:** Eine LDAP-Operation pro User statt N pro
  Hierarchieebene. Skaliert deutlich besser bei tiefen Gruppen-
  Schachtelungen.
- **Keine eigene Cycle-Detection mehr nötig** — der Server liefert
  eine Menge, keine Traversierungs-Pfade.
- **Backwards-kompatible Public-API:** `search_by_query` behält
  Signatur und Begrenzung auf 50; nur die Implementierung darunter
  ist robuster geworden.
- **Bewusst nicht implementiert: explizites Range-Retrieval auf
  `memberOf`.** Mit dem Transitivsuch-Pfad ist es überflüssig. Sollte
  ein zukünftiger Use-Case `memberOf` als Wahrheit benötigen, kann
  Range-Retrieval als zusätzliche `ldap_client`-Funktion folgen.

## Konsequenzen / Consequences

- `LDAP_MATCHING_RULE_IN_CHAIN` ist AD-spezifisch (Windows Server 2003 R2
  und neuer). OpenLDAP & Co. unterstützen die OID nicht — das Projekt
  zielt aber explizit auf Active Directory.
- Der bestehende Integrationstest
  `resolve_group_memberships_max_mustermann` wurde verschärft: die
  zuvor optionalen Transitivitäts-Asserts sind jetzt unbedingt. Neu
  geprüft wird zusätzlich die `direct`-Markierung der zurückgegebenen
  Memberships.
- Konstante `MAX_GROUP_DEPTH` ist entfernt; `MAX_GROUP_DEPTH`-Warnungen
  im Log entfallen.
