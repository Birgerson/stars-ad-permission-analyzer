# Security Policy

## Supported versions

Only the **latest release** receives fixes. Stars is maintained by one person in their spare time; backporting is not realistic. Please reproduce on the current release before reporting.

## Reporting a vulnerability

Please do **not** report security vulnerabilities in Stars through public GitHub issues. I want to ensure a vulnerability is verified and fixed before it is discussed publicly.

Two private channels:

1. **Preferred:** GitHub → **Security** → **Report a vulnerability** (private security advisory on this repository).
2. **Alternative:** email to **birger@labinsch.de**, with `[Stars security]` in the subject.

Helpful information:

- affected version or commit SHA,
- a concrete reproduction path,
- the impact you observe,
- **the diagnostic markers Stars displayed** — they usually show whether it was aware of the gap (GUI: the *Diagnostics* block; CLI: the `Diagnostics (structured)` section).

I will try to respond with an initial assessment within 14 days. There is no bug bounty, and I cannot promise a fix deadline — but I will tell you plainly what I intend to do, including if the answer is "documented limitation, no fix planned".

---

## What counts as a vulnerability

Stars is a **read-only audit and analysis tool**. It does not modify permissions, AD objects, or filesystems.

I treat the following classes as security vulnerabilities in particular:

- **Bypass of the read-only principle** — any path through which Stars would actually modify NTFS ACLs, SMB share permissions, AD objects, group memberships, ownership, inheritance flags, or files and folders on a scanned system. This is the highest-severity class here.
- **Wrong permission calculation** that could lead an auditor to wrong decisions (e.g. a right is reported as absent when in fact it applies). Understating access while presenting the result as complete is worse than overstating it: the auditor closes a real risk as harmless.
- **A silent omission** — a path, ACE, group or share skipped **without a visible diagnostic marker**. Stars is built to flag its own gaps; an omission that looks like a clean result defeats the tool's purpose.
- **Credential leaks** — for example an LDAP password ending up in a log file, a report, an error message, a process listing, or the scan database.
- **Injection through exported data** — e.g. spreadsheet formula injection from attacker-influenceable AD names (CWE-1236, hardened in v1.8.0) or markup injection into the HTML report.
- **Weaknesses in the update check** — e.g. a way past the HTTPS-only / no-embedded-credentials validation of the update source.
- **Inputs that crash Stars** or allow arbitrary code execution in the application: malformed SIDs, security descriptors, LDAP responses or persisted database rows causing a panic, a memory-safety violation, or a wrong-but-confident result.
- **Violations of the audit guarantees documented in `docs/audit-criteria.md`** (e.g. missing ACE handling, incorrect token composition).

**Not vulnerabilities** in the strict sense, but still important — please report as regular issues or discussions:

- functional bugs without trust consequences,
- UX or rendering issues in the GUI,
- performance problems,
- requests for new features or rules.

---

## Explicitly out of scope

- **The SmartScreen / "unknown publisher" warning.** The installer is not code-signed yet; this is documented, not a vulnerability. Verify the published SHA256 instead (see the release notes).
- **Antivirus false positives** (typically `Wacatac.*!ml`) — the release notes explain the reasoning and publish the hash to verify against.
- **The documented limitations** in [`docs/known-limitations.md`](docs/known-limitations.md): cross-forest SID filtering is not simulated (L4), Global Catalog memberships can be partial (L2), conditional ACEs / Dynamic Access Control are not evaluated (L8), token privileges such as `SeBackupPrivilege` are not modelled (L7), and so on. These are deliberate boundaries, and each is surfaced as a diagnostic marker where it applies.

  **However:** if you find a case where such a limitation applies but **no marker is shown**, that *is* a valid security report — see "a silent omission" above.
- Findings that require the attacker to already hold administrative rights on the machine running Stars.

---

## Responsible disclosure

Once a reported issue has been confirmed and fixed, I publish a patch and a release note describing the problem — with credit to the reporter, if they consent.
