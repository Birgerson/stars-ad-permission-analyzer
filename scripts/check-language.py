#!/usr/bin/env python3
"""Language check — verifies the repository stays US-English only.

Passes:

1. Umlaut/eszett scan (`[äöüÄÖÜß]`). Catches the obvious German.
2. ASCII whole-word denylist. Catches German words that have no umlauts —
   "Hell", "Dunkel", "Berechtigungspfad", "Abbrechen", "fehlgeschlagen",
   etc. The first version only ran pass 1, which gave false confidence
   (review 2026-06-08 finding 6).
3. German-stem SUBSTRING scan. Catches German hiding inside compounds and
   filenames that the word-boundary denylist misses — e.g. "Risikobefunde",
   "Deutsche Version", "anwender-handbuch.md" (review 2026-06-14 finding 2).
4. Mojibake scan for corrupted UTF-8 sequences.

`--selftest` runs detector regression checks (the known compound/phrase
misses must flag; clean English must pass).

Both passes use character-level UTF-8 matching, not byte regex, so
emoji and em-dashes are not false positives.

All ADRs are US English (the 0016–0044 migration completed 2026-06-15);
the language check covers them like any other tracked file.

Usage:
    python scripts/check-language.py          # check; exit 1 on hit
    python scripts/check-language.py --list   # check; print every hit

Designed for CI: cheap, no external deps beyond a Python 3 and git.
"""

import argparse
import os
import re
import subprocess
import sys


UMLAUT_RE = re.compile(r"[äöüÄÖÜß]")


# Mojibake: UTF-8 bytes that were decoded as Latin-1/CP1252 and re-saved.
# These sequences (e.g. "â€”" for an em dash, "Ã¤" for "ä") indicate a
# corrupted file and must never appear in a tracked text file. Catching
# them here turns an invisible encoding regression into a hard CI failure
# (engine review 2026-06-12 finding 6).
MOJIBAKE_RE = re.compile(
    r"Ã[¤¶¼„–œŸ©Ÿ]|â€[”“˜™œ]|â†['’]|Â[·\xa0]|â‚¬|Ã\x9f"
)


# Whole-word ASCII denylist for German words that cannot collide with
# English. These are matched case-insensitively as standalone words
# (word boundary on both sides). Add new entries here when they show up
# in a finding; remove an entry only when it is proven to collide with a
# legitimate English usage somewhere in the repo.
DE_WORDS = [
    # Theme-toggle and obvious GUI labels
    "Hell", "Dunkel", "Abbrechen", "Schliessen",
    "Ziel", "Modus",
    # Review 2026-06-08 part 3
    "Cache-Treffer", "Verwaiste",
    "Spezifische", "Erweiterte", "Synchronisationspunkt",
    "Eingabeformen", "Walk-Fehler",
    "Schliesst",
    "Tiefe",
    # German compound nouns from Stars' GUI that have no English meaning
    "Berechtigungspfad", "Berechtigungen", "Berechtigung",
    "Zieldatei", "Zielordner", "Berichte",
    "Eintraege",
    "Schemaversion", "Spaltenwert", "Hilfsspalten",
    "Geschaeftsleitung",
    "Datenbankschema",
    "Vorpruefung",
    "Sichtbarkeit",
    "Reihenfolge",
    # German verbs/participles that cannot be English words
    "fehlgeschlagen", "abgeschlossen", "gespeichert",
    "angemeldete", "angemeldet",
    "geprueft", "pruefen", "Pruefe",
    "Anhaken",
    "Implizit", "Implizite",
    "Jeder",
    "Unauthentifizierte", "Unauthentifiziert",
    "Authentifizierte",
    "Stoerungen", "Stoerung",
    "Notbetrieb",
    "Vorgaenge",
    "Pflicht", "Pflichten",
    # Additional DE-only nouns and verbs found in remaining comments
    "Freigabe", "Freigaben",
    "Befund", "Befunde",
    "listet", "liefert", "lieferte",
    "durchreichen", "weiterreichen",
    "Enumerationsreihenfolge", "Auswertungsreihenfolge",
    "Aenderungsursache",
    "rekonstruieren", "rekonstruierbar",
    "Mitgliedschaftspfad",
    "ausgefiltert",
    "Aenderung", "Aenderungen",
    "vorpruefen", "Vorpruefung",
    "Validierungsfehler",
    "konservativ", "konservativen",
    "Schlieber",
    "Komposition",
    "Endmaske",
    "wechselt",
    "Validierungs",
    # Round 4 (review 2026-06-08 part 2)
    "Effektive", "effektive", "effektiv",
    "Daten",
    "Lade", "lade", "laden",
    "erfolgreich",
    "Entfernt", "entfernt",
    "Hinzugefuegt", "hinzugefuegt",
    "Geaendert", "geaendert",
    "uebernehmen", "uebernommen",
    "uebertragen",
    "ueberpruefen", "ueberprueft",
    "Ueberpruefung",
    "ueberprueft",
    "verfeuern",
    "feuern",
    "GUI-Ausgabe", "GUI-Backend",
    "Aufnahme",
    "Pruefe", "geprueft",
    "verarbeiten",
    "Standard-Spalten", "Standard-Felder",
    "Stoerung", "Stoerungen",
    "Schreibfehler",
    "Bedeutung",
    "Hingegen",
    "Achtung",
    "Achtsamkeit",
    "Auflistung",
    "klassifiziert", "klassifizieren", "Klassifikation",
    # High-frequency German stopwords / particles. These never appear in
    # natural English sentences. Each one matched as a standalone word
    # catches German prose that has no umlauts (e.g. "der Scan" vs.
    # "the scan").
    "der", "die", "das", "dass", "den", "dem", "des",
    "und", "oder", "aber", "doch", "denn",
    "ist", "sind", "war", "waren", "wird", "wurden", "werden",
    "nicht", "nichts", "kein", "keine", "keinen", "keiner",
    "auf", "fuer", "ueber", "unter", "neben", "zwischen",
    "mit", "vom", "zum", "zur", "beim", "am", "im",
    "noch", "schon", "auch", "sowie", "sondern",
    "weil", "wenn", "damit", "sobald",
    "dieser", "diese", "dieses", "diesem", "diesen",
    "sein", "seine", "seiner", "seinem", "seinen",
    "ihr", "ihre", "ihrer", "ihrem", "ihren",
    "wir", "ihr", "sie", "uns", "euch",
    # German verbs that clash too rarely with English to be a problem
    "haben", "hatte", "hatten", "habe",
    "kann", "kannst", "koennen", "konnte", "konnten",
    "muss", "muessen", "musste", "mussten",
    "soll", "sollen", "sollte", "sollten",
    "darf", "duerfen", "durfte", "durften",
    "moechte", "moechten",
    # Engine review 2026-06-12 finding 6: German remnants the earlier
    # denylist missed (orphaned doc-comment fragments).
    "aus", "bedeutet", "aufbauen", "setzt", "durch", "Zeiger", "Parst",
    "Statuscode", "Eltern", "wendet", "ausstehenden", "Migrationen",
    "kompatibel", "anderen", "technischen", "Fehlern",
    "lokal", "lokale", "lokalen", "Anzeigeform", "Mischung",
    "Schritt", "Versionierte", "indexiert", "stammt", "ersetzen",
    "Sicherheits", "Puffer", "Darstellung", "geliefert", "lesbar",
    "Erklaerungspfad", "Serialisiert", "nachvollziehbar",
    # Further German-only words found in orphaned doc fragments.
    "Bestandteile", "valide", "konstruiert", "konstruieren",
    "Unterscheidung", "durchzuprobieren", "stille", "Kandidatenlisten",
    "mindestens", "Szenarien", "uebrig", "ueblich",
    "Funktion", "gelieferten", "bleibt", "ausgeschlossen",
    "Bezeichnung", "Sekundenbruchteile", "beenden", "manueller",
    "Volle", "Eindeutigkeitssuche", "Vorpruefung", "umgangen",
    "ermittelt", "ermittelbar", "erweitert", "vorhanden",
    "zugehoerige", "zugehoerigen", "benoetigt", "benoetigten",
    "braucht", "unbegrenzt", "Rekursionstiefe", "Maximale",
    # Engine review 2026-06-13 (Codex) finding 6: fragments the denylist
    # missed (Cargo author title + traits.rs doc remnants).
    "Fachinformatiker", "pusht", "markiert", "abgeleitete",
    # Deep review 2026-07-04 finding F3: umlaut-free German that slipped
    # through (orphaned half-lines above their English translations, plus
    # the user-visible GUI status string "Lese DACL...").
    "wie", "Wichtig", "Aktionen", "starten", "Vergleichen",
    "destruktive", "destruktiven", "verworfen",
    "entsteht", "entstehen", "bleiben", "unterscheidbar",
    "denen", "Einzelrechte",
    "Mitgliedschaft", "Mitgliedschaften",
    "Lese", "lesen", "liest",
    # Post-v1.7.7 review finding X2: more umlaut-free German the gate still
    # leaked (orphaned RAII-guard/SAFETY half-lines, comment fragments).
    "Kante", "Kanten", "Beziehung", "Beziehungen",
    "zusaetzlich", "freizugeben", "leakte", "entfaellt",
    "existierende", "existierenden", "Aufrufstellen", "Aufrufstelle",
    "weiterlaufen", "zeige",
    # NOTE: "neuer"/"neue" are deliberately NOT listed — they collide with
    # the surname "Neuer" used in AD test fixtures (Markus Neuer). The
    # denylist must never flag legitimate proper names.
    "Verzeichnis", "Verzeichnisse", "Sequenz",
    # Identity-picker work (2026-07-19): more German remnants in the GUI that
    # leaked past the gate (short stopword-like stems in main.rs comments).
    "reserviert", "drei", "voll", "funktional", "funktionale", "funktionalen",
]

DE_WORDS_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in DE_WORDS) + r")\b",
    re.IGNORECASE,
)


# German stems that hide INSIDE compounds, where the whole-word denylist
# above cannot see them. The word-boundary match misses e.g.
# "Risikobefunde" (contains "befund"), "Deutsche Version" (contains
# "deutsch") and German doc filenames such as "anwender-handbuch.md",
# "technische-dokumentation.md", "audit-kriterien.md". These are matched
# case-insensitively as SUBSTRINGS (no word boundary). Every entry must be
# unambiguously German — it may never be a substring of a real English word
# used in the repo (e.g. German "dokumentation"/"kriterien" never collide
# with English "documentation"/"criteria"). Review 2026-06-14.
DE_SUBSTRINGS = [
    "befund",        # Befund, Risikobefund(e)
    "deutsch",       # "Deutsche Version", Deutschland
    "anwender",      # anwender-handbuch
    "handbuch",      # *-handbuch
    "dokumentation", # technische-dokumentation (German "k"; EN: "documentation")
    "kriterien",     # audit-kriterien (EN: "criteria")
    "berechtigung",  # Berechtigungspfad and other compounds
    "risiko",        # Risiko, Risikobefund
    "mitglied",      # Mitglied(schaften), Gruppenmitglied — no EN collision
    # Post-v1.7.7 review finding X2 (compound stems):
    "terminiert",    # null-terminierte (EN "terminated" is "terminat", no ie)
    "dateiattribut", # Dateiattribute (EN: "file attributes")
    "verschachtel",  # verschachtelte (EN: "nested")
    "aufrufstell",   # Aufrufstelle(n) (EN: "call site")
    "dereferenzier", # dereferenzieren (EN "dereference" ends "enc", not "enzier")
    "topologie",     # Topologie (EN "topology" has no "ie")
]

DE_SUBSTR_RE = re.compile(
    "|".join(re.escape(s) for s in DE_SUBSTRINGS),
    re.IGNORECASE,
)


def line_has_german(line: str) -> bool:
    """True if a line contains German per any of the detection passes."""
    return bool(
        UMLAUT_RE.search(line)
        or DE_WORDS_RE.search(line)
        or DE_SUBSTR_RE.search(line)
        or MOJIBAKE_RE.search(line)
    )


# Paths that legitimately contain umlauts in tracked content. Each entry
# is a (path-suffix, optional substring) tuple. When a new legitimate
# need shows up, add it here with a short comment why.
ALLOWLIST = [
    # Risk-engine sensitive-path rule keywords intentionally include
    # German variants ("passwort").
    ("crates/risk_engine/src/rules.rs", "passwort"),
    # Audit criteria spell out the keyword list and reference the rule.
    ("docs/audit-criteria.md", "passwort"),
    ("docs/features-and-limitations.md", "passwort"),
    # CHANGELOG entries from the time before the English-only switch
    # explicitly describe what was done; the historical entries stay.
    ("CHANGELOG.md", None),
    # Lab verification cites the German localized Windows display
    # names that Stars correctly resolves on a Server 2025 trust.
    ("docs/lab/verification.md", "VORDEFINIERT"),
    ("docs/lab/verification.md", "Domänen-Benutzer"),
    ("docs/lab/verification.md", "Jeder"),
    ("docs/lab/verification.md", "EIGENTÜMERRECHTE"),
    # This script itself describes the German words it checks for.
    ("scripts/check-language.py", None),
    # Real test fixture data: the lab uses a German user name as a
    # legacy identity (max.mustermann); these scripts have to mention
    # it for testdata generation.
    ("docs/testing/integration-test-setup.md", "mustermann"),
    ("scripts/test-env/02-setup-ad-objects.ps1", "mustermann"),
]


def is_allowlisted(path: str, line_text: str) -> bool:
    """Return True if the hit should be ignored per ALLOWLIST."""
    norm = path.replace("\\", "/")
    for suffix, needle in ALLOWLIST:
        if norm.endswith(suffix) or norm == suffix:
            if needle is None:
                return True
            if needle.lower() in line_text.lower():
                return True
    return False


def tracked_files():
    """Return tracked text files we care about (skip binaries)."""
    extensions = (
        ".rs", ".md", ".toml", ".yml", ".yaml",
        ".sh", ".ps1", ".nsi", ".sql", ".manifest",
    )
    out = subprocess.check_output(
        ["git", "ls-files"], encoding="utf-8", errors="replace"
    )
    for raw_path in out.splitlines():
        path = raw_path.strip()
        if not path:
            continue
        if path.endswith(extensions):
            yield path


def selftest() -> int:
    """Detector regression checks (review 2026-06-14).

    Guards that the compound/phrase misses which slipped past the
    word-boundary denylist (e.g. ``Risikobefunde``, ``Deutsche Version``,
    German doc filenames) are now caught, and that clean English is not
    falsely flagged.
    """
    must_flag = [
        "Risikobefunde",                 # compound — missed before
        "## Deutsche Version",           # phrase — missed before
        "anwender-handbuch.md",          # German doc filename
        "technische-dokumentation.md",   # German doc filename
        "audit-kriterien.md",            # German doc filename
        "Berechtigungspfad",             # compound
        "der Scan",                      # whole-word denylist still works
        "Schlüssel",                     # umlaut pass still works
        # Deep review 2026-07-04 F3: the exact umlaut-free lines that
        # slipped through the gate while it reported green.
        "Haupt-Aktionen wie Analyze, Scan starten, Vergleichen.",
        "DangerButton — destruktive Aktionen wie Cancel/Delete.",
        "Mitgliedschaften.",
        "verworfen.",
        "entsteht.",
        "Wichtig: `horizontal-stretch: 0` plus",
        "in denen `NullDacl` vs. `Acl(vec![])` unterscheidbar bleiben",
        "AdminRightsRule: destruktive/administrative Einzelrechte",
        'ui.set_a_status("Lese DACL...".into());',
        # Post-v1.7.7 review finding X2: the exact umlaut-free lines the
        # gate still leaked (orphaned RAII-guard/SAFETY half-lines and
        # comment fragments across win_safe/ad_resolver/fs_scanner).
        "// null-terminierte UTF-16-Sequenz",
        "// direkte Kante; verschachtelte Beziehungen zwischen Gruppen.",
        "// --- Dateiattribute (is_directory, is_reparse_point) ---",
        "//! freizugeben.",
        "//! leakte.",
        "//! entfaellt.",
        "/// dereferenzieren.",
        "// Topologie ab.",
        "// existierende Aufrufstellen weiterlaufen.",
        "// 1 Root + 12 verschachtelte Verzeichnisse = 13 Objekte.",
        "// Code Review Finding 3: zeige zusaetzlich",
        # Identity-picker work: the exact GUI main.rs lines the gate leaked.
        "// drei voll funktionalen Tabs (Analyze, Scan Tree, Delta).",
        "// Phase reserviert.",
    ]
    must_pass = [
        "Risk Findings",
        "effective permissions",
        "documentation",
        "audit criteria",
        "the scan result",
        "OWNER RIGHTS (S-1-3-4)",
        # Guards against false positives from the F3 word additions.
        "DangerButton — destructive actions like Cancel/Delete.",
        "restart the scan and compare results",
        "group membership path reconstruction",
        "actions remain enabled while scanning",
        # Guards against false positives from the X2 stem additions.
        "// RAII guard per iteration — new variable, new lifetime.",
        'Display = "Markus Neuer"',  # surname must not be flagged as German
        "// null-terminated UTF-16 sequence",
        "// direct edge; nested relationships between groups.",
        "// --- file attributes (is_directory, is_reparse_point) ---",
        "// existing call sites keep working unchanged.",
        "// 1 root + 12 nested directories = 13 objects.",
        "dereference the pointer after the guard is dropped",
        "reconstruct the group topology on every run",
        "three fully functional tabs (Analyze, Scan Tree, Delta)",
        "SearchResults stays reserved for a later phase",
    ]
    failures = []
    failures += [f"MISS (should flag): {s!r}" for s in must_flag if not line_has_german(s)]
    failures += [f"FALSE POSITIVE (should pass): {s!r}" for s in must_pass if line_has_german(s)]
    if failures:
        print("Language self-test FAILED:", file=sys.stderr)
        for line in failures:
            print("  " + line, file=sys.stderr)
        return 1
    print(f"Language self-test passed: {len(must_flag)} flagged, {len(must_pass)} clean.")
    return 0


def check():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print every offending line as path:line:text",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run detector regression checks and exit",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()

    hits = []
    for path in tracked_files():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    if line_has_german(line):
                        if not is_allowlisted(path, line):
                            hits.append((path, line_no, line.rstrip("\n")))
        except (UnicodeDecodeError, OSError):
            # Skip binary/unreadable files silently.
            continue

    if not hits:
        print("Language check passed: no German content in non-historical tracked files.")
        return 0

    print(
        f"Language check: {len(hits)} line(s) contain German content.",
        file=sys.stderr,
    )
    if args.list:
        for path, line_no, text in hits[:500]:
            print(f"{path}:{line_no}: {text}", file=sys.stderr)
        if len(hits) > 500:
            print(f"... and {len(hits) - 500} more.", file=sys.stderr)
    else:
        print(
            "Tip: run `python scripts/check-language.py --list` to see the offending lines.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(check())
