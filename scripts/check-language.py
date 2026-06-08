#!/usr/bin/env python3
"""Language check — verifies the repository stays US-English only.

Catches German text in any tracked file by looking for umlauts and the
eszett (ä ö ü Ä Ö Ü ß), which never appear in English words. Uses
character-level (UTF-8 decoded) matching, not byte regex — so emoji and
em-dashes are not false positives.

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
]


# Historical ADRs are kept in German for now — tracked in
# docs/adr/README.md and project_en_migration_pending memory.
HISTORICAL_ADR = re.compile(r"^docs/adr/00(0[1-9]|[1-3][0-9]|4[0-4])-.+\.md$")


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
    extensions = (".rs", ".md", ".toml", ".yml", ".yaml", ".sh", ".ps1", ".nsi")
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
                    if UMLAUT_RE.search(line):
                        if not is_allowlisted(path, line):
                            hits.append((path, line_no, line.rstrip("\n")))
        except (UnicodeDecodeError, OSError):
            # Skip binary/unreadable files silently.
            continue

    if not hits:
        print("Language check passed: no German umlauts in non-historical tracked files.")
        return 0

    print(
        f"Language check: {len(hits)} line(s) contain German umlauts.",
        file=sys.stderr,
    )
    if args.list:
        for path, line_no, text in hits[:200]:
            print(f"{path}:{line_no}: {text}", file=sys.stderr)
        if len(hits) > 200:
            print(f"... and {len(hits) - 200} more.", file=sys.stderr)
    else:
        print(
            "Tip: run `python scripts/check-language.py --list` to see the offending lines.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(check())
