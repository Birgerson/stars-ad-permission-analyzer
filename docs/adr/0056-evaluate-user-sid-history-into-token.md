# ADR 0056 — Evaluate the user's `sIDHistory` SIDs into the access token

**Status:** Accepted (2026-07-04)
**References:** ADR 0052 (visibility step / option A), known-limitations L3/L4,
deep review 2026-07-04 finding F1, ADR 0019 (share token = NTFS token),
ADR 0021 (diagnostic markers)

## Context

ADR 0052 made the SID-history gap **visible**: a migrated account's
`sIDHistory` count is fetched and `SidHistoryPresent { count }` marks the
result incomplete. The historical SID **values** were discarded, so an ACE
granting rights to an old SID still did not match — the main result could
say "no access" while Windows grants access through the old SID. The deep
review of 2026-07-04 (finding F1, High) called this out: for a tool whose
central promise is accurate effective-rights analysis, "honestly uncertain"
must not remain the end state when the evaluation can be made correct.

Windows ground truth: when a DC builds a logon token (PAC) for an account,
**all** `sIDHistory` values of the account are included unconditionally —
inside the account's own forest there is no filtering of history SIDs.
SID filtering / quarantine only strips history SIDs when the access
**crosses a trust boundary** (inter-forest access, or an external trust).
Stars already rests on the standing assumption that the analyzed file
server is joined to the connected forest — the entire group-membership
model is only valid under that same assumption. Within that assumption,
adding the user's history SIDs to the evaluated token is not a guess; it
is the faithful reproduction of `AccessCheck` inputs.

ADR 0052 rejected "blindly adding history SIDs" because it would trade the
L3 under-report for an L4 over-report *in the cross-forest case*. That
concern is honored here by scoping: history values are only fetched on the
**direct in-base LDAP path** — exactly where the same-forest assumption
holds. Identities resolved via SAM/LSA, via a Foreign Security Principal,
or outside the configured LDAP base keep `sid_history_count = 0` and are
already flagged by their own boundary markers (`…ViaForeignSecurityPrincipal`,
`IdentityNotInConfiguredLdapBase`, `TrustBoundaryEffectsNotModeled`).

## Decision

1. **`Identity.sid_history: Vec<Sid>`** (new, `#[serde(default)]`) carries
   the parsed historical SIDs. `sid_history_count` stays the authoritative
   **total** as reported by LDAP; `sid_history.len() <= sid_history_count`.
   A value that cannot be parsed (malformed bytes) is logged and skipped —
   the count then exceeds the parsed values and the difference stays
   visibly un-evaluated (see marker split below).
2. **Resolver** (`parse_identity_from_entry`): parse the multi-valued
   binary `sIDHistory` attribute via the existing `bytes_to_sid_str`.
   `RawEntry` gains an `all_values(name)` accessor that returns string and
   binary values uniformly (the LDAP layer classifies per value).
3. **Token construction**: `build_token_sids_with_context` gains a
   `sid_history: &[Sid]` parameter. The engine, the CLI share-mask path and
   the GUI share-mask path all pass the identity's history so the NTFS and
   share sides keep matching the same token (ADR 0019 invariant).
4. **Explanation path**: one step per historical SID, directly after the
   user step — `Historical SID (sIDHistory): S-… — included in the
   evaluated token (migrated account; Windows includes it in the logon
   token within the forest)`. An ACE matched via a history SID then
   appears in the ACE step list like any other match, and the reader can
   correlate it with the history step.
5. **Marker split** (both can fire together on a partial parse):
   - **`SidHistoryEvaluated { count }`** (new) — informational, `Neutral`,
     **not** an incompleteness trigger. Fires when ≥ 1 historical SID was
     included in the token. It exists so the token composition change is
     never silent: an auditor seeing an ACE match on an unfamiliar SID
     finds the reason in the diagnostics and in the explanation path.
   - **`SidHistoryPresent { count }`** — narrowed meaning: *present but
     **not** evaluated*. `count` is now the number of history SIDs that
     were **not** added to the token (`sid_history_count −
     sid_history.len()`). Stays `Concern` and an incompleteness trigger.
     Old persisted rows keep decoding to exactly this meaning — under
     ADR 0052 none of the values had been evaluated, so their stored
     `count` is precisely "present, not evaluated".
6. **Single source of truth**: the split lives in
   `Identity::sid_history_diagnostics()` (core model), consumed by both
   the permission engine and the membership view
   (`PrincipalResolution::membership_diagnostics`), so the two surfaces
   cannot drift.

## Scope boundary (deliberate)

- **Group `sIDHistory` stays unevaluated.** The PAC also carries the
  history SIDs of the *groups* in the token, so an ACE on a migrated
  group's old SID is honored by Windows but still not matched by Stars.
  This gap predates this ADR (it was never counted or flagged) and needs
  its own step: `sIDHistory` in `MEMBERSHIP_ATTRS`, a field on
  `GroupMembership` (32 construction sites), and a decision about the
  membership cache schema. Tracked in known-limitations L3 as the open
  remainder; the transitive in-chain group search already returns the
  entries, so the values are cheap to fetch when that step lands.
- **Trust topology is still not read** (`trustAttributes`, SID filtering,
  Selective Authentication — L4 unchanged). Cross-boundary identities do
  not get history evaluation (count stays 0 on those paths), so this ADR
  does not widen the L4 over-report surface.
- **No risk rule yet** for "access granted via historical SID" (a stale-ACL
  audit signal). Candidate follow-up once real-world feedback shows how
  common the case is; the evidence (explanation step + `SidHistoryEvaluated`)
  is already in place for such a rule to consume.

## Alternatives considered

- **Config toggle for history evaluation.** Rejected: faithful
  `AccessCheck` reproduction is not an option to switch off; a toggle would
  reintroduce the silent under-report as a configuration hazard.
- **Keep visibility-only (ADR 0052 end state).** Rejected per review F1:
  the main result must be correct where correctness is achievable; honest
  incompleteness remains only for the genuinely unknowable parts (unparsed
  values, cross-boundary identities, group history until its follow-up).
- **`MembershipResolvedViaSidHistory` marker** (the name sketched in
  known-limitations L3). Rejected as a name: a history SID is not a
  membership; the marker pair chosen here separates "evaluated" from
  "present but not evaluated", which is the distinction the auditor needs.

## Consequences

- The review-F1 acceptance case holds: user `S-new` with
  `sIDHistory = [S-old]` and an ACL granting `S-old: Modify` now yields
  Modify, with an explanation path naming the historical SID, and the
  result is **not** marked incomplete for history reasons.
- Old persisted reports stay truthful: their stored `SidHistoryPresent`
  markers decode unchanged and still mean "was not evaluated at scan time".
- `build_token_sids_with_context` is a breaking internal API change
  (new parameter); all three call sites (engine, CLI, GUI) updated in the
  same commit.
- The GUI count field (`sIDHistory: N`) keeps showing the total; the
  evaluated/not-evaluated split is carried by the diagnostics list.

## Tests

- Engine: acceptance case above; partial-parse case (count 2, one value
  parsed → `SidHistoryEvaluated{1}` + `SidHistoryPresent{1}`, incomplete);
  zero-history case unchanged; token builder includes history SIDs;
  explanation contains the history step.
- Resolver: binary multi-value parse (2 values), malformed value skipped
  with count kept, absent attribute → empty + count 0.
- Principal resolution: `membership_diagnostics` applies the same
  evaluated/not-evaluated split (shared helper, so it cannot drift from
  the engine).
- Risk engine: `SidHistoryEvaluated` does **not** mark a finding
  incomplete; `SidHistoryPresent` still does.
