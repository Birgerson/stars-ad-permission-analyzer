#!/usr/bin/env python3
"""Secret check — no passwords, tokens or keys in tracked files.

AGENTS.md: no credentials, tokens, passwords or secrets in the source.
Until 2026-10-11 nothing enforced it, and an early commit carried a lab
password into the public history. This gate fails CI when a tracked file
contains:

1. tokens and keys with a recognisable format — GitHub tokens, AWS access
   key IDs, Slack tokens, private-key blocks, Azure storage account keys;
2. a password literal handed to a tool — `ConvertTo-SecureString '…'
   -AsPlainText`, `plink -pw …`, `net use … /user:X <password>`,
   `--password / --bind-password <value>`, credentials inside a URL;
3. a credential assignment with a literal value —
   `password = "…"`, `secret: '…'`, `api_key = "…"` and alike.

Values that are clearly not secrets pass: environment or variable
references (`$env:…`, `${…}`, `%…%`), placeholders (`<…>`, `***`, `…`).
A line that must contain a fake value on purpose (a test fixture) carries
the marker `secret-gate: allow` — explicit, and visible in every review.

Every tracked file is scanned — binary files too, decoded leniently — and
the number of files is reported; nothing is skipped silently. Hits are
printed **masked**: the gate must not copy a secret into the CI log.

A password passed as a bare string (`connect(host, user, "…")`) has no
pattern a generic rule can recognise — that is how the lab password reached
the public history in May 2026. `--denylist FILE` closes that gap locally:
the file (gitignored, never committed — `.secrets-denylist` by default in
the pre-commit hook) holds the real secrets, one per line (`#` comments),
and any tracked or staged line containing one fails. Denylisted values are
never printed. CI has no denylist and runs the generic rules.

Usage:
    python scripts/check-secrets.py              # check; exit 1 on a hit
    python scripts/check-secrets.py --list       # check; print every hit (masked)
    python scripts/check-secrets.py --selftest   # detector regression checks
    python scripts/check-secrets.py --staged --denylist .secrets-denylist
                                                 # pre-commit: the staged content

Designed for CI: no dependencies beyond Python 3 and git.
"""

import argparse
import re
import subprocess
import sys

ALLOW_MARKER = "secret-gate: allow"

# A value that is a reference or a placeholder, not a secret.
_NOT_A_VALUE = r"(?![$%<*{]|\.\.\.|…)"

RULES = [
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("azure-account-key", re.compile(r"AccountKey=[A-Za-z0-9+/]{20,}={0,2}")),
    (
        "securestring-literal",
        re.compile(
            r"ConvertTo-SecureString\s+(['\"])" + _NOT_A_VALUE + r"[^'\"]+\1\s+-AsPlainText",
            re.IGNORECASE,
        ),
    ),
    ("plink-password", re.compile(r"(?<![\w-])-pw\s+(['\"]?)" + _NOT_A_VALUE + r"[^\s'\"]{3,}\1")),
    (
        "net-use-password",
        re.compile(
            r"net\s+use\b[^\n]*?/user:\S+\s+(['\"]?)" + _NOT_A_VALUE + r"(?!/)[^\s'\"]{3,}\1",
            re.IGNORECASE,
        ),
    ),
    (
        "password-flag",
        re.compile(
            # The value must hold an uppercase letter, a digit or a symbol —
            # prose such as "--bind-password will be removed" is not a value.
            r"--(?:bind-)?password(?:=|\s+)(['\"]?)"
            + _NOT_A_VALUE
            + r"(?!-)(?=[^\s'\"]*[^a-z\s'\"])[^\s'\"]{3,}\1",
            re.IGNORECASE,
        ),
    ),
    (
        "url-credentials",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"<>]+:" + _NOT_A_VALUE + r"[^/\s@'\"<>]+@", re.IGNORECASE),
    ),
    (
        "credential-assignment",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:password|passwd|pwd|passwort|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"[\"']?\s*(?::|=|:=|=>)\s*([\"'])" + _NOT_A_VALUE + r"([^\"'\s]{4,})\1",
            re.IGNORECASE,
        ),
    ),
]


def find_secrets(line: str):
    """Return the rule names that match `line`, unless it carries the marker."""
    if ALLOW_MARKER in line:
        return []
    return [name for name, rx in RULES if rx.search(line)]


def mask(line: str) -> str:
    """The line with every rule match reduced to its first 3 characters."""
    out = line
    for _, rx in RULES:
        out = rx.sub(lambda m: m.group(0)[:3] + "...[masked]", out)
    return out.strip()[:160]


def load_denylist(path):
    """The secrets of a local denylist file: one per line, `#` comments.
    Values shorter than 4 characters are refused — they would match
    everywhere and say nothing."""
    with open(path, "r", encoding="utf-8") as f:
        values = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    short = [v for v in values if len(v) < 4]
    if short:
        raise ValueError(f"{len(short)} denylist value(s) shorter than 4 characters")
    return values


def denylisted(line: str, denylist) -> bool:
    return any(v in line for v in denylist)


def tracked_files():
    out = subprocess.check_output(["git", "ls-files", "-z"])
    return [p.decode("utf-8", errors="replace") for p in out.split(b"\0") if p]


def staged_files():
    out = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    )
    return [p.decode("utf-8", errors="replace") for p in out.split(b"\0") if p]


def read_file(path, staged):
    if staged:
        # The content that will be committed, not the working copy.
        return subprocess.check_output(["git", "show", f":{path}"])
    with open(path, "rb") as f:
        return f.read()


def scan(staged=False, denylist=()):
    hits = []
    files = staged_files() if staged else tracked_files()
    unreadable = []
    for path in files:
        try:
            data = read_file(path, staged)
        except (OSError, subprocess.CalledProcessError) as e:
            unreadable.append(f"{path} ({e})")
            continue
        text = data.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            rules = find_secrets(line)
            if denylisted(line, denylist):
                # Never echo the line: it contains a known secret.
                hits.append((path, line_no, "denylisted-secret", "(line not shown)"))
            elif rules:
                hits.append((path, line_no, ",".join(rules), mask(line)))
    return files, hits, unreadable


def selftest() -> int:
    must_flag = [
        "$pw = ConvertTo-SecureString 'Winter2026!' -AsPlainText -Force",  # secret-gate: allow (fake sample)
        "plink.exe -batch -pw Winter2026! root@10.0.0.1",  # secret-gate: allow (fake sample)
        r"net use \\fs01\IPC$ /user:CORP\admin Winter2026!",  # secret-gate: allow (fake sample)
        "adpa scan --bind-password Winter2026! --server dc01",  # secret-gate: allow (fake sample)
        "adpa scan --password=hunter22",  # secret-gate: allow (fake sample)
        "https://alice:Winter2026!@example.org/repo.git",  # secret-gate: allow (fake sample)
        'let password = "Winter2026!";',  # secret-gate: allow (fake sample)
        "secret: 'abcd1234efgh'",  # secret-gate: allow (fake sample)
        "api_key = \"0123456789abcdef\"",  # secret-gate: allow (fake sample)
        "$env:ADPA_BIND_PASSWORD = 'Winter2026!'; password='x1y2z3'",  # secret-gate: allow (fake sample)
        "token " + "ghp_" + "A" * 36,  # secret-gate: allow (fake sample)
        "-----BEGIN " + "RSA PRIVATE KEY-----",  # secret-gate: allow (fake sample)
        "AKIA" + "ABCDEFGHIJKLMNOP",  # secret-gate: allow (fake sample)
    ]
    must_pass = [
        "$env:ADPA_BIND_PASSWORD = $env:LAB_ADMIN_PASSWORD",
        'ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"',
        "--bind-password <password>",
        r"net use \\fs01\IPC$ /user:CORP\admin *",
        r"net use \\fs01\IPC$ /delete /y",
        "$pw = ConvertTo-SecureString $plain -AsPlainText -Force",
        "plink -pw %PW% root@host",
        'password = "***"',
        "The `--bind-password` flag is deprecated; use ADPA_BIND_PASSWORD.",
        "--bind-password will be removed in a future release.",
        "https://github.com/owner/repo",
        "secret = \"…\"",
        'let password = "fake-for-test";  // secret-gate: allow',
        "Passwords never go into a commit (see Credentials.md).",
    ]
    failures = []
    for s in must_flag:
        if not find_secrets(s):
            failures.append(f"MISSED: {s}")
    for s in must_pass:
        if find_secrets(s):
            failures.append(f"FALSE POSITIVE ({find_secrets(s)}): {s}")
    # The denylist catches what no pattern can: a bare string argument.
    deny = ["Bare-Secret-42"]
    if not denylisted('    connect("dc01", "admin", "Bare-Secret-42",', deny):
        failures.append("MISSED: denylisted bare string argument")
    if denylisted('    connect("dc01", "admin", password),', deny):
        failures.append("FALSE POSITIVE: denylist without the value")
    if failures:
        print("Secret self-test FAILED:", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        return 1
    print(f"Secret self-test passed: {len(must_flag)} flagged, {len(must_pass)} clean.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print every hit (masked)")
    parser.add_argument("--selftest", action="store_true", help="run detector regression checks")
    parser.add_argument("--staged", action="store_true", help="scan the staged content (pre-commit)")
    parser.add_argument("--denylist", metavar="FILE", help="local file of real secrets, one per line")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    denylist = []
    if args.denylist:
        try:
            denylist = load_denylist(args.denylist)
        except (OSError, ValueError) as e:
            print(f"Secret check: denylist {args.denylist} unusable: {e}", file=sys.stderr)
            return 1
    files, hits, unreadable = scan(staged=args.staged, denylist=denylist)
    scope = "staged" if args.staged else "tracked"
    if unreadable:
        print(f"Secret check: {len(unreadable)} {scope} file(s) could not be read:", file=sys.stderr)
        for u in unreadable:
            print("  " + u, file=sys.stderr)
        return 1
    if not hits:
        extra = f", {len(denylist)} denylisted value(s) checked" if denylist else ""
        print(f"Secret check passed: {len(files)} {scope} files scanned{extra}, no secret found.")
        return 0
    print(f"Secret check: {len(hits)} line(s) look like a secret.", file=sys.stderr)
    if args.list:
        for path, line_no, rules, text in hits:
            print(f"{path}:{line_no}: [{rules}] {text}", file=sys.stderr)
    else:
        print("Tip: run `python scripts/check-secrets.py --list` (output is masked).", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
