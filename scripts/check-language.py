#!/usr/bin/env python3
"""Language check — verifies the repository stays US-English only.

Two passes:

1. Umlaut/eszett scan (`[äöüÄÖÜß]`). Catches the obvious German.
2. ASCII word denylist. Catches German words that have no umlauts —
   "Hell", "Dunkel", "Berechtigungspfad", "Abbrechen", "fehlgeschlagen",
   etc. The previous version only ran pass 1, which gave false
   confidence (review 2026-06-08 finding 6).

Both passes use character-level UTF-8 matching, not byte regex, so
emoji and em-dashes are not false positives.

Historical ADRs 0001–0044 are excluded because they predate the
English-only convention; their migration is tracked separately.

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


# Whole-word ASCII denylist for German words that cannot collide with
# English. These are matched case-insensitively as standalone words
# (word boundary on both sides). Add new entries here when they show up
# in a finding; remove an entry only when it is proven to collide with a
# legitimate English usage somewhere in the repo.
DE_WORDS = [
    # Theme-toggle and obvious GUI labels
    "Hell", "Dunkel", "Abbrechen", "Schliessen",
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
]

DE_WORDS_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in DE_WORDS) + r")\b",
    re.IGNORECASE,
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
    # ADR-README explains the language status for historical ADRs.
    ("docs/adr/README.md", None),
    # CHANGELOG entries from the time before the English-only switch
    # explicitly describe what was done; the historical entries stay.
    ("CHANGELOG.md", None),
    # Lab verification cites the German localized Windows display
    # names that Stars correctly resolves on a Server 2025 trust.
    ("docs/lab/verification.md", "VORDEFINIERT"),
    ("docs/lab/verification.md", "Domänen-Benutzer"),
    # This script itself describes the German words it checks for.
    ("scripts/check-language.py", None),
    # README.md "Wie Stars entstanden ist" — a deliberate German
    # marketing section addressing German-speaking IT professionals.
    # The four substrings cover the section heading and one phrase
    # per paragraph so only those four lines stay allowlisted; the
    # rest of the README must remain English.
    ("README.md", "Wie Stars entstanden ist"),
    ("README.md", "Fachinformatiker Anwendungsentwicklung gebaut"),
    ("README.md", "Audit-Tool, im 3-Forest-Lab gegen 1000"),
    ("README.md", "Verstärker des eigenen Handwerks"),
    # Real test fixture data: the lab uses a German user name as a
    # legacy identity (max.mustermann); these scripts have to mention
    # it for testdata generation.
    ("docs/testing/integration-test-setup.md", "mustermann"),
    ("scripts/test-env/02-setup-ad-objects.ps1", "mustermann"),
]


# Historical ADRs are kept in their original prose for now — tracked
# in docs/adr/README.md.
HISTORICAL_ADR = re.compile(r"^docs/adr/00(1[6-9]|[2-3][0-9]|4[0-4])-.+\.md$")


def is_allowlisted(path: str, line_text: str) -> bool:
    """Return True if the hit should be ignored per ALLOWLIST."""
    norm = path.replace("\\", "/")
    if HISTORICAL_ADR.match(norm):
        return True
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


def check():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print every offending line as path:line:text",
    )
    args = parser.parse_args()

    hits = []
    for path in tracked_files():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    if UMLAUT_RE.search(line) or DE_WORDS_RE.search(line):
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
