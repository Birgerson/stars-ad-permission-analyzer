# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions prior to `v0.2.0-rc1` are summarized because no formal release notes existed there yet. From `v0.2.0-rc1` onwards every version has its own entry.

---

## [Unreleased]

### Fixed

- **Analyze and Scan tabs resolve LDAP-only identities (completes the F1
  parity fix).** Both tabs still pre-resolved the typed identity via the local
  LSA and aborted when that failed — the same gap fixed for the Groups tab in
  1.7.6-rc2. They now send the raw identity (name, `DOMAIN\user`, UPN, or SID)
  to the worker, which dispatches it through the LDAP principal pipeline (or
  the local LSA/SAM path without LDAP). The share-token evaluation now always
  uses the **resolved** SID rather than the raw input. The "🔍 Resolve SID"
  button remains as an explicit preview.

---

## [1.7.6-rc2] — 2026-07-01

**Second release candidate for 1.7.6.** Adds the code-review fixes (F1, F2) and
the "Active for groups" correction on top of rc1's logon-name binding.

### Fixed

- **Groups tab resolves LDAP-only identities (GUI/CLI parity, F1).** The Groups
  tab pre-resolved the name→SID via the local LSA and aborted if that failed;
  it now passes the raw identity to the worker, which resolves it via the LDAP
  principal pipeline (`PrincipalInput::Auto`) just like the CLI. Cross-domain,
  Global Catalog, and LDAP-only name/UPN identities now work in the GUI.
  Isolating alt-vs-new proof against the lab (`ext.lab\selauth01`).
- **Membership dedup keeps the most informative entry (F2).** When a group was
  reachable via several entries, the report kept the *first*; it now ranks by
  direct > complete path > more names > named, so a group is never shown as
  `nested` (or with an incomplete path, or undercounted "direct") when a better
  entry existed later in the resolver output.
- **No "Active" status for groups.** Enabled/disabled is a user-account concept
  (`userAccountControl`); a group has no such state, so the membership view now
  shows a Status line only for accounts (`User`/`Computer`) and just the kind
  for groups.

---

## [1.7.6-rc1] — 2026-06-30

**Pre-release / release candidate for the upcoming 1.7.6.** Sorts *above* the
stable `1.7.5` by SemVer, so it shows at the top of the releases list while
`1.7.5` keeps the "Latest" (stable) badge. Adds logon-name LDAP binding for
live lab testing ahead of the final 1.7.6.

### Added

- **Bind by logon name, not just the DN.** The LDAP **Bind DN** field (GUI:
  Analyze / Groups / Scan tabs; CLI: `--bind-dn`) now also accepts
  **`DOMAIN\user`** and **`user@domain`** (UPN), in addition to a full DN —
  all three are valid for an Active Directory simple bind. The logon-name
  forms use the stable `sAMAccountName`, so a display-name change (rename,
  marriage) no longer breaks the bind, and you no longer have to look up the
  exact `CN=…,OU=…` path of the account. Validated by a new
  `validation::net::validate_bind_identity` (the **Base DN** stays a strict DN,
  since it is a path). Verified live against the lab with `RES\Administrator`.

---

## [1.7.5] — 2026-06-30

**Groups-tab polish & GUI/CLI timeout parity.** Live identity suggestions and
an LDAP `Timeout (s)` control in the GUI, plus the Groups-tab layout fix. No
engine-behaviour changes.

### Added

- **Groups tab: live identity suggestions.** Typing in the Groups identity
  field now shows the same suggestion list as the Analyze tab (local users,
  groups, and well-known identities with `[U]`/`[G]`/`[L]`/`[W]` type markers
  and descriptions) — so you can tell apart similarly named accounts before
  running.
- **GUI: an LDAP `Timeout (s)` control on all three LDAP-capable tabs**
  (Analyze, Scan, Groups), range 1–600 s, default 10. The GUI was previously
  stuck at a fixed 10 s and ran into a timeout on large or deeply nested
  domains; the `--ldap-timeout` flag had existed only in the CLI. Values are
  clamped to 1–600 before they reach the LDAP layer.

### Fixed

- **Groups tab layout.** The sparse tab inflated the identity field and the
  mode selector to fill the empty vertical space ("an elephant could write in
  it"). They now keep their natural height and the tab matches the Analyze
  tab's look (`alignment: start`).
- The LDAP password label read **"Passwort"** (German) on the Analyze and Scan
  tabs; it now reads **"Password"**, consistent with the Groups tab and the
  US-English-only convention.

---

## [1.7.4] — 2026-06-30

**New feature: the group-membership view.** A dedicated, read-only
*"which groups is this user in?"* view — CLI `adpa groups` and a new GUI
`Groups` tab — with privileged-membership flagging and the recursive nesting
chain. No engine-behaviour changes to Analyze/Scan.

### Added

- **Group-membership view — "which groups is this user in?"** A dedicated,
  read-only view that lists an identity's **recursive** group memberships
  (primary, nested domain, and local groups) **without** a path, ACL, or
  effective-rights computation — answering the pure identity question that
  previously forced you to analyse an arbitrary path just to read the
  resolved-groups panel. Available identically as:
  - **CLI:** `adpa groups --user <name|SID> [--server … --ldap-* … --ldap-timeout N] [--output report.json|.csv] [--force]`.
  - **GUI:** a new **Groups** tab — one identity field (local name ·
    `DOMAIN\user` · UPN · SID, auto-resolved) plus the same LDAP modes as
    Analyze/Scan.

  Each membership shows **how it arose** ("direct", "primary group", "local
  group", or the chain "via A → B"), and memberships in a **well-known
  privileged group** (Administrators, Domain/Enterprise/Schema Admins, Group
  Policy Creator Owners, Key Admins, the built-in Operators) are flagged
  prominently — the high-value audit signal, detected by SID/RID with no extra
  directory query. The same identity-level diagnostic markers as the rest of
  Stars are surfaced (SAM/LSA fallback, FSP, Global Catalog, outside-base,
  `sIDHistory`, resolution timeout), so an incomplete list never looks
  complete. The view is one direction only (user → groups); group → members is
  a planned later step. See ADR 0053.

---

## [1.7.3] — 2026-06-28

**UI polish & consistency release.** One identity field with auto-resolve on
the Analyze and Scan tabs, a unified *attention-based* severity colour scheme
shared by the GUI and the HTML report (light + dark), and a clean-up of
leftover German UI/code strings. No engine-behaviour changes.

### Changed

- **GUI: one identity field, auto-resolved on run.** The Analyze and Scan
  tabs now take the identity (local name, `DOMAIN\user`, UPN, or a raw SID) in
  a **single** field and resolve it automatically when you click Analyze/Scan
  — the separate "Resolve SID" step is now an optional preview, and the SID
  field is relabelled "Resolved SID" (auto-filled). Removes the mandatory
  "type a name → resolve → analyze" three-step.
- **Unified, saturated severity colours across the GUI and HTML report.** One
  source of truth in the core drives the colour everywhere, and **visual
  attention is decoupled from the correctness flag** — "do I need to look?"
  rather than "is it incomplete?". `PermissionDiagnostic::severity` →
  `Neutral` (grey, ℹ) for correct **and expected caveats** (e.g. the SAM/LSA
  fallback, cross-domain/FSP/GC, disabled account, OWNER RIGHTS), `Notice`
  (amber, ⚠) for "worth a look" (unsupported ACEs — a hidden Deny could
  change the result), `Concern` (orange-red, ⚠) for likely real gaps
  (sIDHistory under-report, resolution failures). Risk severities use the same
  saturated ramp (green · amber · orange-red · red), each with a light- and
  dark-mode tone in the GUI. A SAM-mode scan is now calm grey instead of a
  wall of amber; only genuine problems stand out. `is_incompleteness_trigger`
  (the correctness flag for the risk engine) is unchanged. Report font set to
  Arial to match the GUI; a Microsoft-blue (`#0067C0`) `confirmed` badge marks
  complete risk findings.

### Fixed

- **Purged leftover German UI/code strings** that the umlaut-only CI language
  gate did not catch: GUI labels (`Wurzelpfad:`→`Root path:`,
  `HTML-Bericht exportieren`→`Export HTML report`, Delta `Alt`/`Neu`→
  `Old`/`New`) and a duplicated German module-doc line in
  `exporter/json.rs`. The project is English-only since v1.7.1.
- **ADR index** (`docs/adr/README.md`) was missing entries 0049–0052 — added.
  Refreshed `known-limitations` status and the `user-guide` installer
  reference to v1.7.2.

---

## [1.7.2] — 2026-06-28

**Visibility & diagnostics release.** Stars now flags its two most dangerous
silent-evaluation gaps instead of being quietly wrong — migrated-account
`sIDHistory` (under-report) and cross-forest trust filtering / Selective
Authentication (over-report) — adds a configurable LDAP timeout for large
domains, and makes the GUI distinguish warnings from informational markers.
All demonstrated live against a multi-forest test lab.

### Added

- **L3/L4 silent-gap markers (visibility step, ADR 0052).** Two new
  `PermissionDiagnostic` variants make the most dangerous "looks safe,
  isn't safe" cases visible instead of silently wrong:
  `SidHistoryPresent { count }` (an incompleteness trigger) fires when a
  migrated account carries `sIDHistory` — the real token includes SIDs
  Stars does not evaluate, so effective rights may be **understated**;
  `TrustBoundaryEffectsNotModeled` (informational) fires for identities
  resolved across a domain/trust boundary (FSP, or outside the configured
  LDAP base), warning that *if* it is a forest trust, SID filtering and
  Selective Authentication may make access **lower** than shown. `sIDHistory`
  is now fetched (`IDENTITY_ATTRS`) and counted on `Identity` — the marker
  covers LDAP-resolved in-base identities (the SAM/LSA/FSP path cannot read
  it). This step makes the gaps **visible**; it does not yet evaluate the
  historical SIDs or read trust attributes (the deeper follow-up). Rendered
  in the CLI and HTML report; surfaced live by the lab L3/L4 fixtures.
- **`--ldap-timeout <SECONDS>` CLI flag** (analyze and scan) overrides the
  default 10-second LDAP operation timeout, validated to the range 1–600s
  via the new `validation::numbers::LdapTimeout` wrapper. Large or densely
  cross-linked forests can make the transitive membership query
  (`LDAP_MATCHING_RULE_IN_CHAIN`) exceed 10s, after which Stars marks the
  result incomplete (no silent under-report); raising the cap lets the
  resolution finish. Passing it without `--server` prints a warning rather
  than ignoring it silently. Surfaced by the lab stress test on a
  3500-group, deeply nested domain. See ADR 0032.

### Changed

- **GUI diagnostics are now severity-aware.** Previously any diagnostic
  turned a scan row red and every marker rendered identically. The GUI now
  distinguishes a **warning** (the evaluation may be incomplete — red, ⚠)
  from purely **informational** markers (info colour, ℹ); a row that carries
  only info markers is no longer shown as an error. The warning/info split
  comes from a single source of truth in the core
  (`PermissionDiagnostic::is_incompleteness_trigger` and
  `EffectivePermission::is_incomplete`), to which `risk_engine::is_incomplete`
  now delegates — removing the previously duplicated marker list.

---

## [1.7.0] — 2026-06-13

**Hardened-DC support (minor release).** The headline change closes lab
finding F1: Stars can now query a default-hardened Windows Server
2022/2025 domain controller — which enforces LDAP signing and may have no
LDAPS certificate — and run its full recursive group resolution there.
Also: a warm-orange UI accent for readability and a tidied README.

### Signed LDAP bind (SASL GSSAPI/Kerberos) — query hardened DCs without a certificate (lab finding F1)

Stars could not connect to a default-hardened Windows Server 2022/2025
domain controller: plain LDAP (389) is rejected with `strongerAuthRequired`
(LDAP signing enforced) and LDAPS (636) needs a trusted certificate the lab
DCs did not have. Stars only did a `simple_bind`, never the SASL sign+seal
bind that native Windows tools use — so its recursive nested-group
resolution (the core feature) could not run there.

New **signed-LDAP** mode binds on port 389 with **SASL GSSAPI/Kerberos
sign+seal** (via the `ldap3` `gssapi` feature; Windows SSPI), which is
encrypted, accepted by a hardened DC, and needs **no certificate**. It uses
the **current Windows logon** (single sign-on; no bind DN or password) — so
run Stars as the domain account whose context you want, from an interactive
or service logon (Kerberos needs a real ticket; a bare remote shell without
delegation will not have one).

- CLI: `--ldap-signing` on `analyze` and `scan`. `--server` must be the
  DC's FQDN; no `--bind-dn` / `ADPA_BIND_PASSWORD` needed.
- GUI: a fifth LDAP mode "Signed LDAP — Kerberos sign & seal, port 389" on
  the Analyze and Scan Tree tabs.
- New `LdapConfig::new_signed` / `TlsMode::GssapiSign`; ADR 0051.

Verified live against a hardened Windows Server 2025 DC: the signed bind
resolved a user's full five-level nested group chain over LDAP — which the
certificate-less, signing-required DC had previously made impossible.

### Warm-orange accent (readability)

The UI accent changed from blue to a dark, warm orange — easier on the
eyes and a distinct identity. The GUI (primary buttons, active-tab/focus
accents), the HTML report headings, and the README release badge all use
the new accent; the HTML report uses a lighter warm orange because its
background is dark.

### README tidied

Added a table of contents and grouped the previously flat list of 21
sections under six top-level headings (Overview, Download & install, What
Stars is, Using Stars, Project & development, Legal) so a long page is
easy to scan.

---

## [1.6.5] — 2026-06-13

**GUI parity, audit-trace polish, and CI maintenance.** Validated against
a live three-domain Windows Server 2025 lab (deep cross-domain nesting,
deny precedence, inheritance breaks, NTFS∩Share). The effective-rights
engine matched the ground truth on every evaluable case; this release
adds the GUI Global Catalog mode, removes a duplicate audit-trace line,
and keeps CI green past the GitHub Actions Node 24 cutover.

### GUI gains the Global Catalog LDAP mode (CLI/GUI parity)

The Global Catalog bind existed only in the CLI (`--global-catalog`); the
GUI could *display* the GC incompleteness diagnostic but offered no way to
*select* GC. The Analyze and Scan Tree tabs now have a fourth LDAP mode
**"Global Catalog — forest-wide, port 3269 (LDAPS)"**. In that mode the
base DN may be left empty (forest-wide search) and memberships are flagged
potentially incomplete (only universal groups replicate fully to the GC).
The mode→parameters and parameters→`LdapConfig` mappings were extracted
into the unit-tested `LdapParams::from_mode` / `to_config` helpers. The
GUI LDAP help texts now also state the LDAPS certificate-trust requirement
(CA-issued and host-trusted, FQDN not IP; self-signed is rejected).

### Explanation path no longer prints duplicate membership lines (lab finding F2)

When the same membership edge was reached through more than one resolution
path (e.g. a local group entered via two domain groups, or the SAM/LSA
fallback adding the same local-group membership once per containing group),
the explanation path printed the identical "Member of …" line twice. Such
identical edges are now de-duplicated; the effective mask was always
correct (token building already used a set) — this only cleans up the
audit trace. Distinct via-chains to the same group still format
differently and are all kept.

### Documentation: LDAPS certificate requirements

The user guide and README now state plainly that LDAPS/Global Catalog need
a certificate the Stars host trusts (CA-issued; self-signed is rejected),
connected by FQDN not IP, and that a failed LDAP bind aborts with a clear
error rather than returning a result that looks complete. Corrected a
stale "Global Catalog not implemented" note.

### CI / release maintenance

GitHub Actions were bumped to their Node 24 majors ahead of the runner
cutover: `actions/checkout` v4→v5, `actions/cache` v4→v5,
`actions/setup-python` v5→v6, `softprops/action-gh-release` v2→v3. The
release workflow now also embeds the antivirus false-positive note with
the build's SHA256 automatically (no per-release manual edit).

---

## [1.6.4] — 2026-06-13

**Large-environment and consistency release.** Closes all five open
construction sites from the second 2026-06-13 full-repository review. No
change to the effective-rights calculation; the read-only boundary is
intact.

### CLI scan streams the tree instead of buffering it (finding 1)

The CLI scan (`run_scan`) no longer materializes the whole
`Vec<FileSystemObject>` before evaluation. A new
`ad_resolver::SidNameResolver` (an incremental SID→name cache) replaces
the up-front SID-collection pass, so the blocking walk can stream each
object through a bounded channel, be evaluated, and dropped immediately.
Peak memory no longer holds the full object set, first results appear as
enumeration proceeds, and cancellation is more responsive. The streamed
result is identical to the previous buffered one (ADR 0050).

### GUI scan rows now show *why* they are flagged, not just *that* they are (finding 2)

The `Scan Tree` table colored a path when it carried any diagnostic but
did not say which uncertainty applied — weaker than the CLI, HTML and
CSV/JSON outputs, which all spell out the reason. Expanding a flagged row
now shows a **Diagnostics** block listing one human-readable line per
marker, using a single source-of-truth `PermissionDiagnostic::summary()`
shared across surfaces. Closes the last "show uncertainty in the GUI"
consistency gap.

### Shell-layer wiring pinned with focused tests (finding 3)

The CLI argument mapping and the GUI worker's scan-to-persist hand-off
were the thinnest-tested layers. The `--base-dn` / `--global-catalog`
interaction was extracted into a pure, unit-tested `resolve_search_base`
helper (+4 tests), and a test now pins that `persist_scan` round-trips
the actual permission payload (identity, masks, explanation,
diagnostics), not just the run row and errors.

### Write-side serialization surfaces errors instead of defaulting silently (finding 4)

Symmetric to the v1.6.3 read-side fix: `persistence::insert_permission`
and the CSV exporter now propagate an error if JSON evidence
serialization were to fail, instead of substituting an empty `[]`. For
the plain types involved this is theoretical (serialization does not
realistically fail), but for an audit tool the failure must be surfaced,
not hidden.

### SIDs constructed via the validating typed constructor (finding 5)

The CLI's SAM-path SID construction now uses `Sid::try_new` (full syntax
validation) instead of the bare constructor after a weak prefix check, so
a malformed SID-like string fails at construction rather than flowing
into resolution. Defense in depth — the invariant is now enforced by the
type at the construction site.

---

## [1.6.3] — 2026-06-13

**Audit-fidelity and hygiene release.** Closes six of the seven findings
from the 2026-06-13 full-repository review (Codex). No change to the
effective-rights calculation. The remaining finding — converting the
CLI/GUI scans to streaming/batched evaluation — is a deliberate
follow-up (it requires reworking the up-front SID-name collection into a
lazy cache; tracked separately).

### Corrupt persisted audit evidence no longer defaults silently (finding 3)

Reading scan history back used `unwrap_or_default()` on JSON evidence and
mapped unknown status strings to normal defaults — which for an audit
tool can make damaged history look cleaner and more complete than it was.
Now:

- A required evidence field (explanation, contributing SIDs, matched
  ACEs) that fails to decode is a **hard `CoreError`** naming the field
  and path, instead of becoming an empty list.
- Optional/legacy decode problems (an unparseable stored diagnostics
  list, an unrecognized status value) surface a new
  `PermissionDiagnostic::PersistedEvidenceDecodeFailed { detail }` marker
  (an incompleteness trigger, rendered in CLI and HTML) and fall back
  conservatively.

### Windows authorization conformance now runs in CI per commit (finding 5)

The `#[ignore]` conformance harness (engine effective mask vs.
`GetEffectiveRightsFromAclW` single-trustee and `AccessCheck` token-based
multi-group) now runs in a dedicated `conformance` CI job on
`windows-latest` for **every push**, so conformance is verified per
commit rather than only locally.

### Robustness and honesty

- **RAII for the security descriptor (finding 4):** new
  `win_safe::localalloc::LocalFreeGuard` replaces the manual `LocalFree`
  in the scanner, so a future early return can no longer leak the
  descriptor.
- **No production `unreachable!` (finding 7):** the resolver's
  `PrincipalInput::Auto` arm returns a structured `CoreError` instead of
  panicking if the classify-invariant is ever broken.
- **SD deduplication scope stated honestly (finding 2):** the docs and
  the `sd_hash` comment now make clear the dedup is **scan-local** (saves
  repeated parsing), not storage-level; durable storage dedup is tracked
  as known-limitation L10.
- **Language/encoding gate tightened (finding 6):** remaining German
  fragments removed (Cargo author title rendered in English, traits.rs
  doc remnants); the denylist now catches them. The dash/arrow "mojibake"
  the reviewer noted was verified to be valid UTF-8 punctuation.

### Verification

- `cargo fmt` / `clippy --workspace --all-targets -- -D warnings` /
  `python scripts/check-language.py`: clean.
- `cargo test --workspace`: 575 passed, 0 failed, 14 ignored
  (+8 since v1.6.2).
- `conformance` CI job (7 tests) green on windows-latest.

---

## [1.6.2] — 2026-06-12

**Scaling and polish release.** Closes the three Medium findings of the
2026-06-12 full-repository review (the large-environment behaviour the
project is built for) plus four self-review follow-ups. No change to the
effective-rights calculation.

### Transactional scan persistence (review finding 1)

A completed scan run — the run row, every permission, every error — is
now written in a **single transaction** (`ScanStore::persist_scan_atomic`,
`BEGIN IMMEDIATE` … `COMMIT` with `ROLLBACK` on error). Previously each
permission ran in its own implicit transaction (one commit + fsync per
path — the dominant cost of a large scan) and a failed row was only
warn-logged, so a partial scan could be stored looking complete. The
history is now all-or-nothing; CLI and GUI both use the atomic path.

### Security-descriptor deduplication, validated before reuse (review finding 2)

On a tree where most directories inherit one DACL from a shared parent,
each distinct descriptor is now parsed **once** instead of once per
object: a per-scan cache keyed by a stable 64-bit FNV-1a hash of the raw
descriptor bytes. `FileSystemObject` carries the hash (`sd_hash`) so
storage can deduplicate too.

Correctness before speed: a cache hit is only trusted after a **full
byte-for-byte comparison** of the raw descriptor bytes — a hash collision
degrades to a fresh parse and can never assign a wrong DACL. Dedup
changes performance and storage only, never computed rights. Documented
in technical-documentation §12.5.

### Streaming tree walk; parallelization deliberately deferred (review finding 3)

New `walk_tree_streaming` delivers each object/error through a callback
as it is discovered, so a memory-sensitive consumer never holds the whole
tree (performance rule 7). `walk_tree` is now a thin buffering wrapper —
identical traversal, ordering, loop detection. The walk stays
**sequential** on purpose: parallelizing the order-sensitive
reparse-loop-detection state is a separate, riskier step. The decision
and its full justification are recorded in **ADR 0049**.

### Self-review follow-ups

- SD-cache hits no longer clone the raw validation bytes (only the
  parsed fields) — removes pointless per-object allocations.
- The walk completion log carries the error count again.
- GUI scan history stores the **real scan duration**: `started_at` is
  captured before the work begins instead of at persist time (previously
  every GUI run showed a duration of zero).
- Doc drift fixed (worker.rs comments now describe the atomic write);
  two German doc remnants removed and their words added to the
  language-gate denylist.

### Verification

- `cargo fmt` / `clippy --workspace --all-targets -- -D warnings` /
  `python scripts/check-language.py`: clean.
- `cargo test --workspace`: 571 passed, 0 failed, 11 ignored
  (was 563 at v1.6.1; +8 new regression tests).

---

## [1.6.1] — 2026-06-12

**Engine maturity release.** Closes all six findings of the 2026-06-12
deep engine review. No behavioural change to the effective-mask
calculation — these are correctness-of-explanation, visibility,
validation, hygiene, and proof improvements.

### Explanation path is now contribution-accurate (finding 1)

ACE steps were listed identically whether an ACE actually decided bits or
merely matched the token. Each step is now annotated from the same
stored-order walk that produces the effective mask:
`[granted <rights>]` / `[denied <rights>]` / `[matched, no effective bits
contributed]` / `[inherit-only — not applied]`. An auditor can no longer
mistake a merely-matched ACE for one that mattered.

### Explicit share-side explanation for every state (finding 5)

The explanation previously omitted the share line unless a concrete share
mask was applied. Now each share state is spelled out: applied
intersection, NULL share DACL (unrestricted), share read failure
(NTFS-only / incomplete), and no-SMB context.

### Unsupported NTFS ACEs are a first-class incompleteness state (finding 3)

New structured diagnostic `UnsupportedNtfsAces` plus an explicit
"lower-confidence approximation" warning in the explanation, CLI, and
HTML — not just a bare count. The wording states that a hidden Deny among
the skipped ACEs could change the result.

### Validated core constructors (finding 4)

`Sid::try_new` / `NormalizedPath::try_new` (plus documented
`new_unchecked` escape hatches) enforce the type invariants;
`validation::validate_sid` now delegates to `Sid::try_new`, so there is
exactly one SID validator in the workspace.

### Language / encoding hygiene (finding 6)

The CI language gate gained mojibake detection and a broader (collision-
free) German-word denylist; ~25 remaining German doc-comment remnants
were removed across the workspace.

### Windows authorization conformance harness (finding 2)

New `crates/permission_engine/tests/windows_conformance.rs` proves the
stored-order DACL algorithm against the OS itself: it builds a real
in-memory Windows ACL, reads the effective rights via
`GetEffectiveRightsFromAclW`, and asserts the engine agrees bit-for-bit.
`#[ignore]` by default; run with
`cargo test -p permission_engine --test windows_conformance -- --ignored`.

### Verification

- `cargo fmt` / `cargo clippy --workspace --all-targets -- -D warnings` /
  `python scripts/check-language.py`: clean.
- `cargo test --workspace`: 563 passed, 0 failed, 11 ignored.
- Conformance harness: 4 passed against a live Windows session.

---

## [1.6.0] — 2026-06-12

**Cross-forest and multi-domain feature release.** Closes the two
High-priority gaps from `known-limitations.md` (L1 + L2). Both features
are unit/integration tested and were additionally **live-verified**
against the 3-forest lab over LDAPS (lab verification Block K).

### Global Catalog bind (closes known-limitations L2)

New CLI flag `--global-catalog`: Stars binds against the Global Catalog
(port 3269 LDAPS / 3268 with `--insecure-ldap`). Identity lookups (SID,
UPN) become forest-wide and `--base-dn` becomes optional (empty = all
forest partitions) — multi-domain audits no longer need one Stars run
per domain.

Honest caveat, marked structurally: only **universal** group
memberships replicate fully to the GC — global and domain-local
memberships of foreign domains can be missing. Every GC-resolved
finding carries the new structured marker
`GroupResolutionViaGlobalCatalog` (rendered in CLI output and HTML
reports) and the risk engine flags it `incomplete = true`.

Details:

- `LdapConfig::new_global_catalog` / `new_global_catalog_insecure`;
  `global_catalog` field on the config (Debug-safe).
- `IdentityBackend::is_forest_wide()` (default `false`) lets the
  principal resolver know the search scope; the UPN miss error in GC
  mode now says "the search was forest-wide" instead of recommending
  the flag that is already active.
- GUI integration of a GC toggle is a follow-up; the engine flag and
  marker plumbing is shared and ready.

Tests: +8 (config ports/URLs, forest-wide fake backend, UPN miss
wording, engine marker propagation, risk-rule incompleteness).

### Foreign Security Principal resolution (closes known-limitations L1)

Cross-forest trust principals are represented in the home domain as a
**Foreign Security Principal** object (`CN=ForeignSecurityPrincipals,…`).
Pre-fix behaviour was worse than L1 documented: when an FSP existed, the
LDAP SID search *found* it, parsed it as `IdentityKind::Unknown` with the
raw SID string as display name, classified the scope as
`InsideConfiguredLdapBase`, and set **no marker** — the missing
trust-forest memberships were silently invisible, violating the
no-silent-skips principle.

New behaviour:

- `classify_identity` recognizes `objectClass=foreignSecurityPrincipal`
  → new `IdentityKind::ForeignSecurityPrincipal`.
- `PrincipalResolver::resolve_by_sid` routes FSP hits through a
  dedicated path: the identity is enriched via LSA reverse lookup
  (real `TRUSTDOM\user` name, domain, and principal type), home-domain
  groups are resolved through the FSP DN (transitive LDAP chain), and
  the disabled state is honestly reported as Unknown (the FSP object
  carries no `userAccountControl`).
- New structured marker
  `PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal`,
  rendered in CLI output and HTML reports; an incompleteness trigger
  in the risk engine (the principal's memberships in its **own forest**
  remain unknown — resolving those needs a trust-side query, see L2).
- GUI identity picker shows `F` for FSP-fallback identities.
- No DB migration needed (tagged-enum diagnostics, kind string map
  extended).

Tests: +4 (fake-backend FSP resolution with and without LSA, engine
marker propagation, risk-rule incompleteness).

---

## [1.5.18] — 2026-06-09

**Engine correctness patch.** Closes the findings from a self-review of the permission engine (Claude Fable 5, documented in the repo-local review). v1.5.17 users should upgrade if they audit environments that use the OWNER RIGHTS mechanism.

### Finding 1 (Medium) — OWNER RIGHTS SID (S-1-3-4) is now handled

Windows (Server 2008+) semantics: when the DACL contains an ACE for the well-known SID `S-1-3-4` ("OWNER RIGHTS"), that entry **replaces** the implicit owner grant of `READ_CONTROL + WRITE_DAC`. Administrators use this deliberately to restrict owner rights (e.g. so service accounts cannot rewrite the ACLs of their own files).

Stars previously ignored the S-1-3-4 ACE (it matched no token SID) **and** still applied the implicit grant — overstating the owner's effective rights in exactly the case where someone had deliberately restricted them.

- When the analyzed identity is the object's owner, S-1-3-4 entries are now evaluated in stored DACL order like any other ACE.
- The implicit grant fires only when no applicable S-1-3-4 ACE exists (inherit-only entries do not count, matching Windows).
- New informational diagnostic `OwnerRightsAceApplied` (not an incompleteness trigger — the evaluation is exact), rendered in CLI output and HTML reports. No DB migration needed (tagged-enum diagnostics are forward-compatible since schema v6).

### Finding 2 (Medium) — owner grant is now explained

The implicit `READ_CONTROL + WRITE_DAC` bits appeared in "NTFS effective" without any explanation step — breaking the "every bit explainable" promise. New steps: "Owner special rule: READ_CONTROL + WRITE_DAC granted implicitly (owner: …)" when the rule fires, or a step naming the S-1-3-4 mechanism when an OWNER RIGHTS ACE suppressed it. The deny-aggregation step now excludes owner-restored bits so it no longer claims bits were removed that the owner rule restored.

### Finding 4 (Low) — single stored-order walk

`evaluate_dacl_ordered` and `collect_contributing_sids` implemented the same stored-order algorithm twice — the v1.5.17 provenance bug existed precisely because the two walks diverged. Both replaced by a single `walk_dacl_stored_order` returning `(granted, denied, contributions)` from one pass.

### Finding 3 (documentation) — canonical-order detector limitation

The `NonCanonicalDaclOrder` diagnostic uses a single-level 4-phase model and can flag legitimate multi-level inheritance orderings (parent-allow before grandparent-deny is canonical in Windows). Exact detection is impossible without ancestry data, which `GetNamedSecurityInfoW` does not expose. The warn log states this; `docs/known-limitations.md` gains entry **L9**.

### Tests

- **`cargo test --workspace`: 537 passed** (was 530; +7 new S-1-3-4 / owner-explanation regression tests). 0 failed, 7 ignored.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `python scripts/check-language.py`: all clean.

### Documentation

README owner-rule bullet updated; download examples set to `v1.5.18`.

---

## [1.5.17] — 2026-06-08

**Engine correctness patch.** Closes two real bugs found by an external ChatGPT review in the NTFS + SMB combination Stars is built to audit. v1.5.16 users should upgrade.

### Finding 1 (High) — BroadGroupWriteRule false positive on NTFS + Share Read

`crates/risk_engine/src/rules.rs` gated the rule on `effective_mask & MASK_WRITE != 0`. `MASK_WRITE` includes `READ_CONTROL` and `SYNCHRONIZE`, which a Read-only final mask also satisfies. Concrete scenario: NTFS grants Everyone Modify but the SMB share caps the final effective permission to Read. The engine correctly computed Read, but `BroadGroupWriteRule` reported a critical `BROAD_GROUP_WRITE` finding anyway. This was exactly the NTFS + SMB audit case Stars advertises.

Fix:

- Gate on write-specific effective bits (`effective_mask & WRITE_SPECIFIC_BITS`).
- Require both the contributing SID's mask AND the final effective mask to overlap on write-specific bits, so a contribution whose write bits got capped away by the share layer no longer triggers.
- New regression test `ntfs_modify_via_everyone_but_share_read_no_broad_group_write`.

### Finding 2 (Medium) — `collect_contributing_sids` over-attributed bits

`crates/permission_engine/src/engine.rs` recomputed permission provenance via plain mask overlap against the final NTFS result, ignoring stored ACE order. Two consequences:

1. **Allow specific-group Modify followed by Allow Everyone Modify**: the later Everyone ACE decided no new bit but was still recorded as contributing Modify. Plumbed forward into a false `BROAD_GROUP_WRITE` for paths where Everyone in fact only inherited bits a specific group had already granted.
2. **Deny Everyone Write followed by Allow Everyone Modify**: the denied write bits were recorded as contributed Allow bits. Wrong provenance in CSV/JSON; risk rules consuming `contributing_sids` could mis-attribute.

Fix: rewrite `collect_contributing_sids` as a stored-order walk that mirrors `evaluate_dacl_ordered`. Per right-bit, the first ACE wins; only the actually-decided `bits` value is recorded against the Allow ACE's SID. Deny ACEs consume bits without crediting any SID.

Three new regression tests:

- `stored_order_later_everyone_allow_does_not_contribute_if_already_granted`
- `stored_order_first_everyone_read_contributes_only_read_bits`
- `stored_order_deny_first_excludes_denied_bits_from_contribution`

### Finding 3 — Language gate misses and remaining DE

- Duplicated "Deutsche Sektion" of the Info tab in `crates/gui/src/main.rs` (a copy of the English Info section that crept back in with a "— Deutsch —" marker and a German GroupBox title). Removed.
- Scan-tab labels `"Tiefe:"` / `"Tiefe begrenzen"` → `"Depth:"` / `"Limit depth"`.
- Slint title `"Ergebnisse (N Pfade)"` → `"Results (N paths)"`.
- `crates/permission_engine/src/mask.rs` module doc and section headers collapsed to English-only.
- Various doc-comment leftovers in `ad_resolver`, `core`, `fs_scanner`, `gui/worker`, `Cargo.toml`.
- `scripts/check-language.py` denylist extended (Cache-Treffer, Verwaiste, Spezifische, Erweiterte, Synchronisationspunkt, Eingabeformen, Walk-Fehler, Schliesst, Tiefe, Ziel, Modus) so this regression class is caught at CI time.

### Tests

- **`cargo test --workspace`: 530 passed** (was 526; +4 new regression tests from findings 1 and 2). 0 failed, 7 ignored.
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `python scripts/check-language.py`: passes.

### Documentation

Version notes in `README.md`, `docs/user-guide.md` and the download examples set to `v1.5.17`.

---

## [1.5.16] — 2026-06-06

**Code review response (2026-06-07).** Four findings from an external ChatGPT review implemented — not symptom fixes, but structural corrections with regression tests. Plus lab verification on Windows Server 2025 Standard and a first README restructuring pass for GitHub visitors.

### Finding 1 (High) — audit integrity: identity snapshot per permission row

Until v1.5.16 `name`, `domain`, `kind` and `disabled` were kept in the global `identities` table and resolved on read against historical permissions via a JOIN. A later upsert could change how older scans looked when re-read — e.g. a user who was active at scan time would appear disabled on re-read. That broke the audit property "evidence is immutable".

- Schema migration **v7**: `effective_permissions` gains four snapshot columns (`identity_name`, `identity_domain`, `identity_kind`, `identity_disabled`). Backfill from the `identities` cache as best effort for existing rows.
- `insert_permission` now additionally writes the identity snapshot per permission row.
- `get_permissions` reads identity **exclusively from the snapshot** — the previous LEFT JOIN against `identities` is removed. Backfill cases without an `identities` entry appear as `Unknown` instead of showing a potentially mutated value.
- `identities` stays as a cache for live lookups, **but is no longer the source of historical reports**.
- Regression test `run_a_immutable_against_later_identity_upsert_in_run_b` creates run A with "alice.old"/active, then run B with the same SID as "alice.new"/disabled; run A must still return "alice.old"/active.

### Finding 2 (Medium) — `analyze_trustees` uses `SmbAuditContext::resolve`

CLI analyze and GUI scan have used `SmbAuditContext::resolve` since Round 10 to derive server/share from a UNC path. `analyze_trustees` (the GUI "Who has access?" action) did not — on a bare UNC path without explicit SMB fields, the trustee tab showed only the NTFS layer while scan tab and CLI analyze picked up the share layer. Inconsistency between GUI paths for the same UNC path.

- Fix in `crates/gui/src/worker.rs` line 1505 — the same `SmbAuditContext::resolve` call as in the other code paths.
- Regression test covers four semantic cases (bare UNC, explicit fields, local path, half-set).

### Finding 3 (Medium) — delta comparison over all audit-relevant fields

`compare_scans` only marked a path as `Changed` when `effective_mask` changed. Audit-relevant changes with the same final mask silently disappeared — e.g. NTFS/share swap with identical result mask, `share_status` flipping to `ReadFailed`, new diagnostic markers.

- New module `delta::PermissionSignature` bundles all audit-relevant fields for comparison (effective/ntfs/share mask, `share_status`, `local_group_status`, `unsupported_ace_count`, diagnostics).
- `DeltaKind::Changed` gains a `reasons: Vec<DeltaReason>` field in addition to `old_mask`/`new_mask`. Seven variants: `EffectiveMaskChanged`, `NtfsMaskChanged`, `ShareMaskChanged`, `ShareStatusChanged`, `LocalGroupStatusChanged`, `UnsupportedAceCountChanged`, `DiagnosticsChanged`.
- The GUI delta row renders the reasons in the `kind_label` column ("Changed (NTFS mask + share status)").
- Five regression tests in `delta.rs` cover all five trigger scenarios from the review example.

### Finding 4 (Medium) — documentation on JSON schema v3 + LDAP note for Server 2025

User guide and technical documentation still described schema v2 and the old flat `Vec<PathTrustee>` API. The code has been on schema v3 with the typed `PathTrusteeEntry` union since Round 10.

- `docs/user-guide.md` updated including JSON v3 examples for `entry_kind: "ace"` and `entry_kind: "diagnostic"`.
- `docs/technical-documentation.md` shows the Round-10 API with `build_path_trustees_with_share_and_names` and the SID name map parameter.
- README: note added that Server 2025 enforces LDAP signing by default and LDAPS without AD CS has no working bind. Stars detects both cases and emits clear diagnostic markers.

### Lab — verification on Windows Server 2025 Standard

3-forest setup (`tier0/1/2.lab` with forest mode `Windows2025Forest`) with 3 bidirectional forest trusts, 6 conditional DNS forwarders, 1000 test users (mm0001–mm1000), and 5000 directories with an ACL mix (Modify / Protected Inheritance / Deny).

Live verified:

- **H.4** Three smoke tests against `mm0001` (Modify via membership, Protected Inheritance, Deny doesn't apply to an Alpha user).
- **H.6.2** CLI `scan` over 5105 paths in 1.1–1.5 s per format (HTML 22.9 MB, JSON 25.4 MB, CSV 6.9 MB).
- **H.6.3** JSON schema v3 with `entry_kind: "ace"` 41 342×, correctly populated `display_name` map from the Round-10 SID name cache.
- **H.6.5** SMB share with UNC path: `NTFS Modify ∩ Share Read = Read & Execute`, aggregation as step 12 in the explanation path.
- **H.6.6** Cross-forest T2: ACE for `T1LAB\mm0501` on a tier0 path — SID resolution via trust, correct evaluation, `DIRECT_USER_ACE` risk finding.
- **H.6.7** Cross-forest T3 (negative): `T2LAB\mm0801` without an ACE → `Special (0x00000000)`, no "account not found" false negative.
- **H.6.8** HTML trustee render: 5108 trustee tables, localized display names correct.
- **H.6.4** LDAP bind behaviour documented as a Server 2025 finding (not a bug — Stars' diagnostic markers work honestly).

Block H in `docs/lab/verification.md` contains the full test results and a structured backlog of remaining tests (H.6.1 GUI walkthrough, H.6.9 performance comparison, H.6.10 delta GUI test).

### Documentation restructuring

From a ChatGPT review of the GitHub perspective: README came across as product documentation rather than a landing page. Three steps:

- **Step A:** Screenshot of the `Analyze` tab directly below the read-only note, a concrete 10-second example with the full permission path, top disclaimer block shortened to one sentence with an anchor link.
- **Step B:** Long sections "Database and stored data" and "Uninstallation" extracted into their own doc files (`docs/scan-history-and-database.md` and `docs/installation-and-uninstallation.md`).
- **Step C:** Tab labels aligned with the GUI source repository-wide — the user guide listed five tabs while only four exist in reality (`Analyze`, `Scan Tree`, `Delta`, `Info`). "Identity", "Trustees", and "Risk Findings" are sections inside the tabs, not top-level.

### Repository-wide US English (2026-06-07)

All repository content switched to US English only. German content removed from all user-facing files; bilingual files trimmed to English; German-only files translated; the German user guide and technical documentation deleted in favour of their existing English counterparts; GitHub repository description set to English. The previous bilingual policy is replaced by a single-language convention going forward.

### Tests

- **`cargo test --workspace`: 526 passed** (up from 519, plus +7 regression tests from findings 1–3 and the analyze_trustees test from finding 2). 0 failed, 7 ignored (live AD/LSA tests).
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.

---

## [1.5.16] — 2026-06-06

**Round-10 architecture release.** Four structural findings from ChatGPT's v1.5.15 review implemented — not symptom fixes but clean solutions with type safety, RAII guarantees, and honest layering separation.

### Finding 3 (Medium) — `win_safe` crate with RAII guard

`get_share_dacl` could leak the NetAPI buffer when `parse_share_dacl(...)?` returned an `Err` — the `?` jumped out of the function before `NetApiBufferFree` ran. The same risk pattern existed at at least 11 other sites.

- New workspace crate **`crates/win_safe/`** for safe Windows resource wrappers.
- New type **`NetApiBuffer<T>`** with `Drop` guarantee: every path — success, `return`, `?`, panic — frees the buffer correctly.
- 11 NetAPI call sites in `share_scanner` and `ad_resolver` migrated to the guard — no more manual `NetApiBufferFree` in business code.
- ADR 0045 documents the pattern and the layering decision.

### Finding 4 (Low) — `PathTrusteeEntry` enum: ACE and diagnostic typed separately

Share-DACL read errors and NULL DACL were modelled as synthetic `PathTrustee` records with an empty SID and `kind: Allow` — JSON consumers could not distinguish them from real ACEs.

- New enum **`PathTrusteeEntry::Ace(PathTrustee)`** / **`Diagnostic { category, message }`** in `adpa_core::model`.
- **JSON_SCHEMA_VERSION 2 → 3** (breaking change for JSON consumers). Discriminator `entry_kind: "ace"` / `"diagnostic"` — deliberately NOT `kind`, because the inner `PathTrustee.kind: AceKind` (Allow/Deny) would have collided there.
- HTML renderer shows diagnostic rows visually differently (yellowish background, ⚠ symbol, italic, no Allow/Deny label).
- GUI renderer shows them as a "diagnostic" row with em-dash placeholders in the ACE-specific columns.
- ADR 0046 documents the modelling including the `entry_kind` vs. `kind` rationale.

### Finding 1 (Medium) — `SmbAuditContext`: single source for server/share

CLI analyze and scan derived server/share for the trustee overlay **only from explicit flags**. A UNC call `adpa scan --path \\fs01\data` without `--smb-server`/`--share-name` produced correct `share_status` (`resolve_scan_share_status` used a UNC fallback) but an empty share part in `path_trustees` — silent data asymmetry in the same report.

- New typed wrapper **`SmbAuditContext { server, share }`** in `validation::path`.
- **`SmbAuditContext::resolve(path, explicit_server, explicit_share) -> Option<Self>`** is the single source of truth. Per field: explicit > UNC. Either both fields or `None` (half information previously led to `get_share_dacl` calls with an empty share name).
- All 5 call sites (CLI analyze + scan trustees, `resolve_scan_share_status`, GUI scan trustees, GUI mask compute) use the same helper.
- 6 new unit tests (UNC alone, explicit override, local path, server without share, mixed, empty-string flags).
- ADR 0047 documents the design decision.

### Finding 2 (Medium) — SID map as caller responsibility

`build_path_trustees_with_share` performed an LSA `LookupAccountSid` **per path** — on 50 000 paths with the same BUILTIN SIDs, the same lookup ran thousands of times. CLI and GUI were already building a scan-wide SID→name map (for the engine explanation path) but the trustee module couldn't use it.

- New function **`build_path_trustees_with_share_and_names(fso, overlay, sid_names)`** takes a prebuilt map.
- Helper **`collect_ace_sids_for_resolution(fso, overlay)`** collects all relevant SIDs from the NTFS DACL AND the share overlay (diagnostic entries skipped).
- Existing functions `build_path_trustees` / `build_path_trustees_with_share` delegate internally to the map variant with a per-call map — **no code duplication**.
- CLI scan and GUI scan now use the scan-wide map; **one** LSA lookup per scan instead of N × M.
- The map now also covers share overlay SIDs (previously only NTFS DACL SIDs).
- 3 new unit tests verify map application, diagnostic protection, helper completeness.
- ADR 0048 documents the layering.

### Tests

- **519 tests pass** (+16 over v1.5.15: +6 SmbAuditContext, +4 PathTrusteeEntry, +2 NetApiBuffer, +3 SID map, +1 further spec widening).
- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` all green.

### Documentation

- ADRs 0045, 0046, 0047, 0048 new.
- Version notes in `README.md`, `docs/user-guide.md`, `docs/technical-documentation.md`, and `docs/known-limitations.md` set to `v1.5.16`.

---

## [1.5.15] — 2026-06-06

**Mandatory information in-app release.** New **"Info" tab** in the GUI containing all mandatory information that previously only lived in the repo. So that anyone who passes on a `Setup.exe` doesn't strip the recipient of the trail back to the original.

The tab contains: author and license (Copyright 2026 Birger Labinsch; AGPL-3.0-or-later; source-code link required by AGPL: https://github.com/Birgerson/stars-ad-permission-analyzer; attribution: "Code with Anthropic Claude Opus, Birger Labinsch is the prompt engineer, not the code author"); the three read-only hard limits; backup duty and disclaimer; contact (email `birger@labinsch.de`, issues URL); platform status.

### AGPL compliance

With this tab Stars fulfils the AGPL requirement that the source-code link must be visible in the delivered software — not only in the repository LICENSE.

Version notes in the user docs set to `v1.5.15`.

---

## [1.5.14] — 2026-06-06

**CLI reports fully populated release.** Closes the remaining medium finding from the ChatGPT review for v1.5.13 (Round 9): `path_trustees` are now populated not only by the GUI but also by CLI `analyze` and CLI `scan`. JSON and HTML audit reports from the CLI are as complete as those from the GUI.

### Architecture (Round 9 finding 1)

The raw trustee-build logic lived in `crates/gui/src/worker.rs`. To let the CLI use the same logic without either layer referencing the other:

- New module **`crates/exporter/src/trustees.rs`** carries the three functions plus the `ShareTrusteeOverlay` type, with three unit tests (NTFS-only, NULL DACL pseudo row, share overlay attached). SID→name resolution stays `cfg(windows)`-only.
- **`crates/exporter/Cargo.toml`** adds `share_scanner` and `ad_resolver` dependencies.
- **`crates/gui/src/worker.rs`** removes the old private helpers and re-exports the symbols. 11 GUI tests still pass unchanged.
- **`crates/cli/src/main.rs`** — `run_analyze` populates `AnalysisResult.path_trustees`; `run_scan` reads the share overlay **once** before the path loop (cfg-gated for Windows), no N+1 share reads.

The JSON schema version stays at **`2`**. The field has existed in the schema since v1.5.13; v1.5.14 simply populates it from the CLI now too.

Version notes in the user docs set to `v1.5.14`.

---

## [1.5.13] — 2026-06-06

**Exporter contract release.** Closes the two medium findings from the ChatGPT review for v1.5.12 (Round 8 follow-up).

### Exporter contract (finding 1, Medium)

The `Exporter` trait now carries the overwrite policy itself. New `ExportTarget::{File(PathBuf), FileOverwrite(PathBuf)}` enum: `File` uses `create_new` (fails on an existing file), `FileOverwrite` truncates as an explicit opt-in. New helper `crates/exporter/src/lib.rs::open_export_file` centralizes the policy; HTML/CSV/JSON use it. CLI with `--force` sends `FileOverwrite`; the GUI always uses `File`. Three new tests verify the policy live per exporter.

### JSON schema (finding 2, Medium)

`AnalysisResult.path_trustees` (path-centric trustee list) was previously only visible in the HTML export. `JsonReport` now contains `path_trustees: &'a [PathTrustees]`; `JSON_SCHEMA_VERSION` raised from `1` to `2`. HTML and JSON now carry the same audit information.

Version notes in the user docs set to `v1.5.13`.

---

## [1.5.12] — 2026-06-05

**GUI bugfix release.** Fixes two visibility issues in the HeaderBar that surfaced during the manual lab test after v1.5.11.

- **Version number in the HeaderBar:** `app_version` had been set to an empty string in v1.5.10 on the assumption that the Rust side would set it at runtime via `CARGO_PKG_VERSION` — nobody did, the version badge was never rendered. Fixed: `run_ui` now calls `ui.set_app_version(format!("v{}", env!("CARGO_PKG_VERSION")))` right after `MainWindow::new()`. The version sits next to the title "Stars".
- **Theme toggle visible:** The toggle was a 32×32 square with a single Unicode glyph (`☾` / `☀`) that Slint's software backend with the default font on Server 2022 rendered unreliably. Fixed: 110×32 button with border, background, glyph, and text label ("☾ Dark" / "☀ Light").

Version notes in the user docs set to `v1.5.12`.

---

## [1.5.11] — 2026-06-05

**UX release.** When a new user starts to type in the GUI field "User/group", Stars deliberately suggests only local accounts marked with `[L]` — domain users are not searched live in LDAP to avoid flooding the DC. The GUI now says so:

- Placeholder explicitly shows accepted formats: `DOMAIN\user`, `user@domain.lab`, `S-1-5-21-...`.
- Hint row directly below the user field: "Suggestion list shows only local accounts of this machine. For domain users: type DOMAIN\user or the UPN, then click 'Resolve SID'."
- Picker header: "[L] = local identity of this machine".
- Better error message on empty input names the accepted formats.

Both tabs (Analyze + Scan Tree) handled identically. `docs/user-guide.md` and `docs/technical-documentation.md` extended accordingly. Version notes in the user docs set to `v1.5.11`.

---

## [1.5.10] — 2026-06-05

**License consistency release.** Cleans up the last two findings from the ChatGPT review for v1.5.9 (Round 8).

### License (finding 1, High — public-release blocker)

Before v1.5.10 `Cargo.toml` (`license = "proprietary"`), `LICENSE` (MIT), and the README (referenced MIT) contradicted each other. Final choice: **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. Pulled through everywhere:

- `LICENSE` replaced with the official AGPL-3.0 full text from the FSF, plus a liability annex and copyright note.
- `Cargo.toml` workspace metadata: `license = "AGPL-3.0-or-later"` (SPDX compliant).
- README license section explains the AGPL network-use clause for non-lawyers.
- **SPDX-License-Identifier header** in all 53 Rust source files: `// SPDX-License-Identifier: AGPL-3.0-or-later` plus a copyright line.

### GUI (finding 2, Low)

Slint property default `in property <string> app-version: "v1.5.5";` was an outdated default. Default set to an empty string; the runtime setting via `env!("CARGO_PKG_VERSION")` remains authoritative.

Version notes in the user docs set to `v1.5.10`.

---

## [1.5.9] — 2026-06-05

**Bugfix release.** Closes three findings from the ChatGPT review for v1.5.8 (Round 7).

### Engine / CLI / GUI — finding 1 (High, ADR 0043)

`AccessContext::for_path` derived the logon context only from the **path form**. A local NTFS path with an explicit SMB context (`--smb-server` and `--share-name`) was therefore incorrectly classified as `LocalInteractive`. `NETWORK` was missing from the token, share-DACL ACEs targeting `NETWORK` did not apply — a silent under/overestimate in the most common real audit case.

New: `AccessContext::for_path_with_smb(path, smb_server, share_name)`. As soon as either SMB hint is set, the context is `RemoteSmb`. CLI and GUI paths (3 sites each) use the helper consistently. Live verified in the lab (`docs/lab/verification.md`, part G, scenario E4b).

### GUI — finding 2 (Medium)

`export_html` now refuses an existing target file with a clear error message instead of silently truncating it via `fs::File::create`. Worker test `export_html_refuses_to_overwrite_existing_file` covers the behaviour.

### CLI — finding 3 (Low)

`--bind-password` explicitly marked as **DEPRECATED** (help text + runtime warning, suggests `ADPA_BIND_PASSWORD`). Argument stays functional for backwards compatibility.

### Documentation — finding 4

`docs/lab/verification.md` cleaned up with a block overview per Stars version. New part G (Block D — NETWORK SID) with setup, three scenarios, and engine-test references.

### Tests

Five new `for_path_with_smb` tests, two new engine tests, one new GUI worker test. Version notes set to `v1.5.9`. ADR 0043, `docs/lab/scripts/14-blockD-network-context.sh` as the reproduction script.

---

## [1.5.8] — 2026-06-05

**Verification / documentation release.** Block C of the lab verification added: Stars was run against a realistic bulk setup (1000 test users across three forests with 3-level group nesting, 5000 folder dirs under `C:\Data` with 100 varied project ACLs) and delivered the effective-rights profile of a user across the full tree in **4.89 s** — ≈ 1 ms per directory including ACL read, token aggregation, and CSV serialization.

No engine or functional changes — code bit-identical to v1.5.7, only the verification layer is extended. `docs/lab/verification.md` extended by part F including the honestly documented lab limitation around cross-forest FSP auto provisioning (not a Stars bug, but a gap in the bulk setup script). Three new reproduction scripts added. Version notes in the user docs set to `v1.5.8`.

---

## [1.5.7] — 2026-06-05

**Bugfix / verification release.** Two topics:

1. **Deny aggregation explicit in the explanation path** (ADR 0042). When a Deny ACE blocks bits of an Allow ACE, a dedicated path step now names it. Without a Deny nothing changes.
2. **Lab verification Block A** executed: E1 Deny Modify vs. inherited Allow Modify → correct; E2 inheritance broken (`Protect`), only Admins+SYSTEM → correct; E3 UNC, Share=Read + NTFS=Modify → Result=Read (Share dominates). Plus a GUI boot smoke on tier0.

Version notes in the user docs set to `v1.5.7`.

---

## [1.5.6] — 2026-06-05

**Identity-input hardening release.** Closes four medium-priority findings from the ChatGPT review for v1.5.5 (Round 6): SAM ↔ UPN ambiguity at first input, GUI fallback rendering for missing display names, scan-error grouping, and pre-flight validation of LDAP target URLs (Round-6 findings 1–4). ADRs 0040 (local-group candidate-name list) and 0041 (local-group source in the explanation path). Tests +7. Version notes set to `v1.5.6`.

---

## [1.5.5] — 2026-06-05

**Lab-verification baseline release.** First execution of the full lab verification (`docs/lab/verification.md`) against a 3-forest topology (tier0/1/2.lab on Windows Server 2022) with three smoke tests T1/T2/T3 (within-forest nested groups, cross-forest FSP, cross-forest without ACE). Forms the verification baseline subsequent releases build on. Version notes set to `v1.5.5`.

---

## [1.5.4] — 2026-06-05

**Permission-pipeline robustness release.** Round 5 finding 1: ambiguous `sAMAccountName` hits (multiple users with the same SAM in different OUs) now produce a clear uniqueness error instead of silently picking the first hit. Three new ad_resolver tests plus a tightened ADR 0032. Version notes set to `v1.5.4`.

---

## [1.5.3] — 2026-06-04

**Validated-wrapper propagation release.** Round 5 finding 2: the validated wrappers (`ValidatedUncPath`, `ValidatedLocalPath`, `ValidatedSid`, …) reach all interior call sites instead of being stripped down to raw strings before crate boundaries. ADR 0037 documents the propagation rule. Four new validation tests. Version notes set to `v1.5.3`.

---

## [1.5.2] — 2026-06-04

**Failed-resolution diagnostics release.** Round 5 finding 3: when LDAP identity or group resolution fails, Stars now writes a structured `IdentityLookupFailed { reason }` or `GroupResolutionFailed { reason }` diagnostic marker plus an `incomplete = true` risk-engine flag instead of returning an empty token silently. ADR 0039 documents the diagnostic schema. Tests +3. Version notes set to `v1.5.2`.

---

## [1.5.1] — 2026-06-04

**SAM-fallback honesty release.** The SAM path now sets `IdentityDisabled` via `NetUserGetInfo` level 1 (ADR 0035) instead of leaving the flag undefined. Plus a clarifying note on the `--insecure-ldap` switch in CLI help. Version notes set to `v1.5.1`.

---

## [1.5.0] — 2026-06-04

**Unified principal-resolution pipeline release.** All identity input forms — `DOMAIN\user`, UPN, plain `sAMAccountName`, direct SID, and the GUI name → SID picker — now flow through the same central pipeline (`ad_resolver::principal`, ADR 0036). The pipeline classifies the result as `IdentityScopeStatus::InsideConfiguredLdapBase`, `OutsideConfiguredLdapBase`, or `Orphaned` and attaches diagnostic markers when applicable. UPN is a special case: it fails with an explicit error pointing at the Global Catalog (port 3268) instead of falling back silently. Eleven new resolver tests. Version notes set to `v1.5.0`.

---

## [1.4.1] — 2026-06-04

**LSA-fallback for cross-domain identities release.** Fix for ADR 0034: when LDAP cannot find a SID in the configured `base_dn` but LSA can resolve it (typical for trust users), Stars now constructs an LSA-only identity with name + domain and emits the `IdentityNotInConfiguredLdapBase` marker instead of treating it as orphan. Initial scope: `DOMAIN\user` input only; UPN and other forms followed in v1.5.0. Version notes set to `v1.4.1`.

---

## [1.4.0] — 2026-06-04

**Local-group resolution release.** Round 4: Stars resolves local server groups on the file/SMB server (e.g. `BUILTIN\Administrators` or a custom local group) via `NetLocalGroupGetMembers` and renders them as mediator steps in the explanation path. `LocalGroupEvalStatus::{NotQueried, Applied, NotAvailable}` carries the resolution state. Plus initial UNC long-path support (`\\?\…`, `\\?\UNC\…`). ADRs 0029, 0030, 0031. Tests +8. Version notes set to `v1.4.0`.

---

## [1.3.0] — 2026-06-04

**Diagnostic-marker model release.** `EffectivePermission.diagnostics` switches from a free-text vector to a variant-tagged enum (`PermissionDiagnostic`) — ADR 0021. CLI, HTML, and JSON renderers map every marker to its own description. The `risk_engine::is_incomplete()` helper consumes the marker variant directly. Version notes set to `v1.3.0`.

---

## [1.2.0] — 2026-06-02

**Persistent scan history release.** SQLite scan history (`persistence` crate) — ADR 0026. Two new GUI tabs: Delta (compare two scan runs) and the start of the path-centric trustee view. Version notes set to `v1.2.0`.

---

## [1.1.2] — 2026-06-01

**Cancellable scan release.** Scans can be cancelled mid-run from the GUI; the worker thread exits cleanly without leaving handles or temporary files behind. Version notes set to `v1.1.2`.

---

## [1.1.1] — 2026-06-01

**Risk-engine completeness release.** Six built-in risk rules (FullControl, WriteAccess, AdminRights, BroadGroupWrite, DirectUserAce, SensitivePath) — every finding carries an `incomplete = true` flag when the underlying evaluation was structurally incomplete. Version notes set to `v1.1.1`.

---

## [1.1.0] — 2026-06-01

**HTML report release.** Stand-alone HTML exporter with diagnostic badges, color-coded risk severity, and a per-path trustee table in addition to the existing CSV/JSON output. Version notes set to `v1.1.0`.

---

## [1.0.0] — 2026-05-31

**First stable release.** Engine + CLI + GUI considered feature-complete for the documented audit use case. Read-only by design, three hard limits (no NTFS/SMB/AD writes, no agent on target systems, no backdoor authentication). Version notes set to `v1.0.0`.

---

## [0.2.0-rc17] — 2026-05-31

GUI polish: theme toggle, headerbar version badge, scan progress reporting.

## [0.2.0-rc16] — 2026-05-31

Update manager skeleton: signature verification, manifest validation, rollback preparation. No live update path yet.

## [0.2.0-rc15] — 2026-05-31

Identity input dispatcher (ADR 0032): `DOMAIN\user`, UPN, and direct SID treated as separate input branches with explicit timeout handling.

## [0.2.0-rc14] — 2026-05-31

Local long-path support (`\\?\…`).

## [0.2.0-rc13] — 2026-05-31

`PermissionPath` rendering: explanation steps now carry their source label (`PrimaryGroup`, `DomainGroup`, `LocalGroup`).

## [0.2.0-rc12] — 2026-05-30

Validation layer (`validation` crate): typed wrappers for UNC paths, local paths, SIDs, LDAP filters, scan depth, thread limits.

## [Unreleased between rc11 and rc12] — Documentation consolidation

Consolidation of fragmented documentation files; introduction of the user-guide / technical-documentation split.

## [0.2.0-rc11] — 2026-05-30

Audit-criteria documentation (`docs/audit-criteria.md`): risk rules, severities, role-based optimal permissions.

## [0.2.0-rc10] — 2026-05-30

SQLite persistence schema v1 (ADR 0026): `scan_runs`, `effective_permissions`, `scan_errors`, `identities`, `group_memberships`.

## [0.2.0-rc9] — 2026-05-30

CLI HTML output: initial standalone HTML exporter (without diagnostic badges).

## [0.2.0-rc8] — 2026-05-30

Engine: NTFS ∩ Share aggregation as an explicit explanation step.

## [0.2.0-rc7] — 2026-05-30

Engine: ordered DACL evaluation (`evaluate_dacl_ordered`) — stored order respected even on non-canonical DACLs.

## [0.2.0-rc4 — rc6] — 2026-05-30 (withdrawn wgpu attempts)

Three release candidates attempting a wgpu-based GUI; rolled back in favour of Slint with the software backend due to instability on the deployment target.

## [0.2.0-rc3] — 2026-05-25

Initial Slint GUI prototype: Analyze tab and Scan tab.

## [0.2.0-rc2] — 2026-05-25

Initial CLI prototype: `analyze` and `scan` commands, CSV output.

## [0.2.0-rc1] — 2026-05-24

First versioned release. Core engine (`permission_engine`), AD resolver (`ad_resolver`), filesystem scanner (`fs_scanner`), share scanner (`share_scanner`).

## [0.1.0] — 2026-05-21

Workspace bootstrap: 13-crate Cargo workspace, initial data model, error types. Followed by: effective NTFS permission computation in `permission_engine`; CLI prototype with formatted output; CSV export via CLI `--output` flag; SQLite cache and scan history (`persistence`); multi-folder tree scan with DB persistence; SMB share scanner (`share_scanner`); NTFS ∩ Share combination in the CLI scan; GUI prototype with `egui`/`eframe` (later replaced by Slint); risk engine, HTML export, delta comparison, installer script; README with project description, usage, and development status; GitHub Actions release pipeline.

---

## Authorship

**Concept, specification, steering, and review:** Birger Labinsch — IT Specialist for Application Development / Prompt Engineer.
**Implementation:** Claude Opus 4.7 (Anthropic) as the AI model, under direct guidance from Birger Labinsch.

Every commit in this repository carries a `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` trailer that makes the AI contribution visible per change.
