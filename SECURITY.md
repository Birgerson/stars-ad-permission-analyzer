# Security Policy

## Reporting a vulnerability

Please do **not** report security vulnerabilities in Stars through public GitHub issues. I want to ensure a vulnerability is verified and fixed before it is discussed publicly.

Please report by email to:

    **birger@labinsch.de**

Helpful information:

- affected version or commit SHA,
- a concrete reproduction path,
- the impact you observe.

I will try to respond with an initial assessment within 14 days.

---

## What counts as a vulnerability

Stars is a **read-only audit and analysis tool**. It does not modify permissions, AD objects, or filesystems.

I treat the following classes as security vulnerabilities in particular:

- **Wrong permission calculation** that could lead an auditor to wrong decisions (e.g. a right is reported as absent when in fact it applies).
- **Bypass of the read-only principle** — any path through which Stars would actually modify permissions, AD objects, or files.
- **Inputs that crash Stars** or allow arbitrary code execution in the application (buffer overflow, deserialization, etc.).
- **Credential leaks** — for example an LDAP password ending up in a log file, a report, or a trace call.
- **Violations of the audit guarantees documented in `docs/audit-criteria.md`** (e.g. missing ACE handling, incorrect token composition).

**Not vulnerabilities** in the strict sense, but still important — please report as regular issues or discussions:

- functional bugs without trust consequences,
- UX or rendering issues in the GUI,
- performance problems,
- requests for new features or rules.

---

## Responsible disclosure

Once a reported issue has been confirmed and fixed, I publish a patch and a release note describing the problem — with credit to the reporter, if they consent.
