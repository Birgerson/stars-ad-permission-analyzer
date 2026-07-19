# ADR 0060 — Read-only trust-topology inventory (`trustAttributes` / `trustDirection`)

**Status:** Accepted (2026-07-19)
**References:** known-limitations L4 (cross-forest trust effects), ADR 0052
(visibility step / `TrustBoundaryEffectsNotModeled`), ADR 0056 &
verification.md M.5 (foreign-forest `sIDHistory` on an in-base account)

## Context

Known-limitations **L4** is the last place Stars can confidently
*over*-report: a forest/external trust can be configured with **SID
filtering / quarantine** (`trustAttributes` `QUARANTINED_DOMAIN`, 0x4) or
**Selective Authentication** (`CROSS_ORGANIZATION`, 0x10). Both take effect at
runtime on the DC — a DACL may grant, yet the real access is filtered or
authentication is blocked before the ACL is even reached. The M.5 edge is
concrete: an **in-base** account whose evaluated `sIDHistory` SID belongs to a
*foreign* forest is honored only while that trust's `/EnableSIDHistory` state
allows it, and because the identity is in-base, no
`TrustBoundaryEffectsNotModeled` marker fires.

ADR 0052 made the *boundary* visible (an informational marker on FSP /
outside-base identities) but deliberately did **not** read the trust
configuration. The remaining question — *"is this trust actually configured to
filter?"* — needs the trust objects themselves.

Real detection of the runtime effect would require Stars to attempt a
synthetic logon. That violates the read-only principle and is **out of
scope** (and stays out of scope). What Stars *can* do, read-only, is read and
display the trust topology so an auditor can judge the caveat themselves.

## Decision

1. **Read the domain's `trustedDomain` objects, read-only.** A new
   `ldap_client::search_domain_trusts` subtree-searches
   `(objectClass=trustedDomain)` under the domain-root base DN (trust objects
   live in `CN=System,<domain DN>`), reading `trustPartner`, `flatName`,
   `trustDirection`, `trustAttributes`, `trustType` and `securityIdentifier`.
   No write, ever.

2. **Typed, testable model in `core`.**
   - `TrustDirection` (`from_code`: 0 disabled / 1 inbound / 2 outbound /
     3 bidirectional / else `Unknown(raw)`).
   - `TrustAttributes` — wraps the raw bitmask (nothing lost) and decodes the
     MS-ADTS flags, with named accessors for the two that matter to an
     auditor: `sid_filtering_enabled()` (`QUARANTINED_DOMAIN`) and
     `selective_authentication()` (`CROSS_ORGANIZATION`), plus
     `forest_transitive()` / `within_forest()` and a `labels()` list.
   - `DomainTrust` bundles partner, flat name, direction, attributes and the
     trusted domain SID.

3. **Parsing is a pure function** (`ad_resolver::trusts::parse_trust`),
   unit-tested against synthetic `RawEntry`s. A missing/unreadable
   `trustDirection` is reported as `Unknown`, never silently conflated with
   the real `Disabled` (code 0) — no silent misreport.

4. **Surface it via a new read-only CLI command, `adpa trusts`.** It lists
   each trust with direction and decoded attributes and explicitly calls out
   SID filtering and Selective Authentication, with a note that Stars shows
   the DACL view, not the filtered runtime result. Requires `--server`;
   `--base-dn` should be the domain root.

## Scope boundary (honest)

This ADR delivers the **"(optional) read `trustAttributes` / `trustDirection`
and display them as read-only info"** item from the L4 solution sketch. It
does **not**:

- model the runtime filter/selective-auth effect on a specific finding
  (needs a synthetic logon — out of scope, read-only principle), or
- automatically cross-reference a token's foreign-forest history SIDs against
  a filtering trust to flag the M.5 over-report on a per-evaluation basis.

Those remain documented L4 follow-ups. The trust inventory gives an auditor
the exact facts needed to apply the L4 caveat by hand.

## Consequences

- L4 moves from "documented only" to "trust configuration is now readable and
  displayed"; the runtime-effect modelling stays explicitly out of scope.
- New surface is additive and read-only: a `core` model, one `ad_resolver`
  LDAP reader + parser, and one CLI command. No change to the permission
  engine or its evaluation.
- GUI / HTML-report integration and the per-finding M.5 cross-reference are
  natural follow-ups on top of this model.
