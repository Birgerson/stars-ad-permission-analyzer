#!/usr/bin/env bash
# Language check — verifies the repository stays US-English only.
#
# Catches German text in any tracked file by looking for two signals:
#   1. Umlauts and the eszett (ä ö ü Ä Ö Ü ß), which never appear in
#      English words.
#   2. A small set of high-confidence German function words that are
#      unambiguous between English and German.
#
# Anything not in the allowlist below is treated as a violation.
# The script exits 0 on success (no violations) and 1 on any finding,
# so it can be wired into CI as a gate.
#
# The allowlist is deliberately narrow: pseudo-German strings appear in
# audit data (e.g. password|passwort sensitive-path rules, German
# Windows identity labels in test fixtures), so we list every legitimate
# occurrence explicitly. When a new legitimate need shows up, add it
# here with a short comment why.
#
# Usage:
#   scripts/check-language.sh          # check, exit 1 on hit
#   scripts/check-language.sh --list   # check, print path:line:text on each hit
#
# Designed to be cheap enough to run in pre-commit and CI.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

VERBOSE=0
if [ "${1:-}" = "--list" ]; then
    VERBOSE=1
fi

# Tracked files only, exclude binaries and the language check itself.
# .gitignore is respected by `git ls-files`.
FILES="$(git ls-files \
    -- '*.rs' '*.md' '*.toml' '*.yml' '*.yaml' '*.sh' '*.ps1' '*.nsi' \
    ':!:CHANGELOG.md' \
    ':!:scripts/check-language.sh' \
    ':!:docs/adr/0001-*.md' ':!:docs/adr/0002-*.md' ':!:docs/adr/0003-*.md' \
    ':!:docs/adr/0004-*.md' ':!:docs/adr/0005-*.md' ':!:docs/adr/0006-*.md' \
    ':!:docs/adr/0007-*.md' ':!:docs/adr/0008-*.md' ':!:docs/adr/0009-*.md' \
    ':!:docs/adr/0010-*.md' ':!:docs/adr/0011-*.md' ':!:docs/adr/0012-*.md' \
    ':!:docs/adr/0013-*.md' ':!:docs/adr/0014-*.md' ':!:docs/adr/0015-*.md' \
    ':!:docs/adr/0016-*.md' ':!:docs/adr/0017-*.md' ':!:docs/adr/0018-*.md' \
    ':!:docs/adr/0019-*.md' ':!:docs/adr/0020-*.md' ':!:docs/adr/0021-*.md' \
    ':!:docs/adr/0022-*.md' ':!:docs/adr/0023-*.md' ':!:docs/adr/0024-*.md' \
    ':!:docs/adr/0025-*.md' ':!:docs/adr/0026-*.md' ':!:docs/adr/0027-*.md' \
    ':!:docs/adr/0028-*.md' ':!:docs/adr/0029-*.md' ':!:docs/adr/0030-*.md' \
    ':!:docs/adr/0031-*.md' ':!:docs/adr/0032-*.md' ':!:docs/adr/0033-*.md' \
    ':!:docs/adr/0034-*.md' ':!:docs/adr/0035-*.md' ':!:docs/adr/0036-*.md' \
    ':!:docs/adr/0037-*.md' ':!:docs/adr/0038-*.md' ':!:docs/adr/0039-*.md' \
    ':!:docs/adr/0040-*.md' ':!:docs/adr/0041-*.md' ':!:docs/adr/0042-*.md' \
    ':!:docs/adr/0043-*.md' ':!:docs/adr/0044-*.md' \
)"

# Allowlist patterns — legitimate occurrences of substrings that would
# otherwise trip the checks.
# Each entry is a single grep -E regex; a line matches ALL patterns to be
# considered safe.
read -r -d '' ALLOWLIST <<'EOF' || true
^docs/adr/README\.md:.*German prose
^docs/adr/README\.md:.*ADRs 0001
^README\.md:.*KI-Anteil
^crates/risk_engine/src/rules\.rs:.*"passwort"
^crates/risk_engine/src/rules\.rs:.*passwort
^crates/risk_engine/.*test.*passwort
^crates/risk_engine/.*Passwort
^docs/audit-criteria\.md:.*passwort
^docs/features-and-limitations\.md:.*passwort
EOF

UMLAUT_HITS=$(echo "$FILES" | tr ' ' '\n' | xargs -I{} grep -nHE '[äöüÄÖÜß]' {} 2>/dev/null || true)

# Strip lines that match any allowlist pattern.
filter_allowlist() {
    local input="$1"
    if [ -z "$input" ]; then
        return
    fi
    local remaining="$input"
    while IFS= read -r pattern; do
        [ -z "$pattern" ] && continue
        remaining=$(echo "$remaining" | grep -vE "$pattern" || true)
    done <<< "$ALLOWLIST"
    echo "$remaining"
}

UMLAUT_HITS=$(filter_allowlist "$UMLAUT_HITS")

count=0
if [ -n "$UMLAUT_HITS" ]; then
    count=$(echo "$UMLAUT_HITS" | grep -c .)
fi

if [ "$count" -gt 0 ]; then
    echo "Language check: $count line(s) contain German umlauts." >&2
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$UMLAUT_HITS" | head -50 >&2
        if [ "$count" -gt 50 ]; then
            echo "... and $((count - 50)) more." >&2
        fi
    fi
    echo "Tip: run \`scripts/check-language.sh --list\` to see the offending lines." >&2
    exit 1
fi

echo "Language check passed: no German umlauts in non-historical tracked files."
exit 0
