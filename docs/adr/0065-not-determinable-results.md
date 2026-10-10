# ADR 0065 — Results that cannot be determined are never stated as facts

## Status
Accepted (2026-10-10). Builds on the diagnostic marker system (ADR 0021/
0024) and the incompleteness flag; follows the owner's requirement after the
lab campaign of 2026-10-10: "no misinformation in any respect — rather a
message that at this point the evaluation is not correctly possible".

## Context

Stars already knew when a result had gaps: markers such as
`DomainGroupRecursionIncomplete`, `IdentityNotResolvable`, an unreadable
share DACL or unavailable local groups set `EffectivePermission::
is_incomplete()`, and risk findings were flagged `[INCOMPLETE]`. But every
surface still printed the computed mask as **the** answer — "Result : No
access (0x00000000)" — with the caveat elsewhere: in a diagnostics block,
a badge, a JSON list. A reader who looks at the value (a CSV filter, a
scan row, the GUI rights label) takes it as fact. For the lab case of a
trusted-domain account the value was simply wrong.

A second gap was silent: ACEs for well-known SIDs whose presence in the
real token depends on **how** the user logs on — `This Organization`
(S-1-5-15), the authentication-assertion SIDs (S-1-18-*), `NTLM` /
`SChannel` / `Digest Authentication` (S-1-5-64-*), remote-interactive or
console logon, local account — were treated as "not in the token" without
any marker, although a normal domain logon carries e.g. `This
Organization`.

## Decision

1. **One classification.** `PermissionDiagnostic::uncertain_layer()` says
   which part of a result a marker makes uncertain: `Token` (the evaluated
   token may lack SIDs — NTFS and share alike), `Ntfs` or `Share`, or
   `None` (informational). `is_incompleteness_trigger()` is derived from
   it. `EffectivePermission::uncertainty()` lists every reason (markers
   plus the share-read and local-group statuses) with its layer;
   `ntfs_determinable()`, `share_determinable()` and
   `effective_determinable()` follow, and `is_incomplete()` means "not
   determinable".
2. **Every surface states it.** A value that is not determinable is
   written as `NOT DETERMINABLE — the known data alone gives Read
   (0x00120089); the real right may differ` (long form) or
   `NOT DETERMINABLE (known data: Read)` (compact) via the shared helpers
   `rights_statement` / `rights_label_compact`:
   - CLI `analyze`: NTFS, share and result lines, followed by "Why not
     determinable" with every reason;
   - CLI `scan`: the reasons that apply to every result are listed once in
     the header, each row carries the compact form, the summary counts the
     undeterminable results; the header's share mask follows the same rule;
   - CSV: the `*_rights` columns use the compact form; new columns
     `determinable` (`yes`/`no`) and `not_determinable_reasons`; the
     `*_mask_hex` columns keep the computed value;
   - JSON (schema **v4**): each permission additionally carries
     `determinable` (`ntfs`/`share`/`effective`), `uncertainty` (`layer` +
     `reason`) and `account_status`, flattened next to the v3 fields;
   - HTML: a `NOT DETERMINABLE` badge with the computed value as "known
     data"; the summary card reads "Not determinable";
   - GUI: Analyze rights label and scan-row label in the same wording,
     status-derived reasons listed with the markers, undeterminable rows
     never shown as unremarkable.
3. **Logon-dependent trustees are bounded, not ignored.** The engine
   computes, for applicable ACEs whose trustee is such a SID, a lower and
   an upper bound of the stored-order walk (upper: every such Allow
   matches, no such Deny; lower: the opposite — per bit the first deciding
   ACE wins, so the real result lies within). Equal bounds mean those ACEs
   cannot change the result, which stays exact. Otherwise the new marker
   `LogonDependentTrustees { sids, min_mask, max_mask }` (layer `Ntfs`,
   Notice) is attached and the explanation states the range. The share
   side counts such share ACEs as not evaluable when they can change the
   share mask. Which SIDs count depends on the access context: over SMB
   the logon is a network logon, so remote-interactive and console logon
   SIDs are certainly absent.

## Consequences

- A result Stars cannot determine is never shown as a plain value
  anywhere; an exact result looks exactly as before.
- Without LDAP (SAM/LSA path) every result is "not determinable" — that
  is correct, because nested domain groups are unknown there.
- The computed value stays visible (labelled "known data") and machine
  readable (`*_mask_hex`, `ntfs_mask`/`effective_mask` in JSON), so a
  lower or partial picture is still available, never presented as the
  answer.
- CSV gains two columns at the end; JSON consumers keep every v3 field.
- Lab acceptance (2026-10-10): `u00030` over 41 project paths — 41 exact,
  plain; `EXT\ext_partner04` — 41 of 41 "NOT DETERMINABLE" with the trust
  and local-group reasons in the header and the CSV.
- Tests: layer attribution and agreement with the trigger flag for every
  marker, CSV/JSON/HTML rendering, the bounds (range, no-effect case,
  Deny side, inherit-only, context dependence) and the share-side count.
