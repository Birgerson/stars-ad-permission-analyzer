# ADR 0048 — SID→Name Map as a Caller Responsibility in the Trustee Module

**Status:** Accepted
**Date:** 2026-06-06

## Context

The `exporter::trustees` module (ADR 0044) builds a list of trustee entries for every path. So that the auditor sees readable identities instead of raw SIDs, the module resolves every ACE SID via LSA (`LookupAccountSidLocal`) into a name such as `BUILTIN\Administrators`.

Previously this lookup happened **inside** the build function, once per call:

```rust
pub fn build_path_trustees_with_share(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrusteeEntry> {
    // ... build out ...
    #[cfg(windows)]
    {
        let sids: Vec<String> = out.iter().filter_map(...).collect();
        let map = ad_resolver::build_sid_name_map(&[], sids);
        for entry in &mut out {
            // set display_name from map
        }
    }
    out
}
```

On the analyze path (exactly one path) that is semantically fine. On the **scan path** (potentially tens of thousands of paths under a root directory) it becomes a performance problem:

- Stars project rule: "large environments are the default case, not the exception".
- 50 000 paths × ~5 distinct SIDs in the DACL = 250 000 LSA lookups, of which ~99 % are repeats of the same standard SIDs (`S-1-5-32-544` = BUILTIN\Administrators, `S-1-5-18` = SYSTEM, `S-1-5-11` = Authenticated Users, domain groups).
- LSA lookups are not trivial — they can be remote, carry RPC overhead, and fail in multi-domain forests.

Both consumers — `cli::main::run_scan` and `gui::worker::sweep_one_root` — were already building **a scan-wide SID→name map for the engine explanation paths**:

```rust
// CLI scan
let scan_sid_names = {
    let trustees: Vec<String> = walk.objects.iter()
        .flat_map(|fso| fso.dacl.iter())
        .filter_map(|ace| { /* unique SID */ })
        .collect();
    ad_resolver::build_sid_name_map(&memberships, trustees)
};
```

This map was passed to `PermissionEvaluationInput.sid_names` so the engine explanation path (`EffectivePermission.path_explanation`) had readable names. But it was **not available to `path_trustees`**. Result:

| Component | Used the scan map? |
|---|---|
| `EffectivePermission.path_explanation` | ✅ yes (via `PermissionEvaluationInput.sid_names`) |
| `path_trustees` display names | ❌ no (called LSA per path) |

Review round 10 finding 2 classified this as Medium.

## Decision

We separate the build function from SID-name resolution. The map is populated **by the caller** and passed into the build function — layering becomes honest: trustee build is data transformation, LSA lookup is an external dependency, and that becomes visible at the caller.

### New interface

```rust
// crates/exporter/src/trustees.rs

/// Collects all ACE SIDs from the FSO DACL and share overlay that
/// need LSA resolution. Diagnostic entries have no SID and are
/// skipped.
pub fn collect_ace_sids_for_resolution(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<String>;

/// Trustee build WITHOUT a built-in LSA lookup. The caller supplies
/// the pre-built SID→name map.
pub fn build_path_trustees_with_share_and_names(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
    sid_names: &BTreeMap<String, String>,
) -> Vec<PathTrusteeEntry>;
```

The two existing functions `build_path_trustees` and `build_path_trustees_with_share` stay around for the analyze path and delegate internally to the map variant — **with a per-call map**. That means:

- **Analyze path** (CLI `run_analyze`, GUI Analyze tab): API unchanged, behavior unchanged.
- **Scan path** (CLI `run_scan`, GUI Scan tab): uses the map variant explicitly with the scan-wide map.

No code duplication — the map variant is the implementation, everything else is a wrapper.

### What the scan caller now does

```rust
// 1. Read the share overlay once per scan (ADR 0044).
let share_overlay = SmbAuditContext::resolve(...).map(|c| read_share_overlay(...));

// 2. COLLECT SIDs (NTFS DACL + share overlay).
let unique_sids = {
    let mut seen = HashSet::new();
    let mut sids = Vec::new();
    for fso in &walk.objects {
        for sid in collect_ace_sids_for_resolution(fso, share_overlay.as_ref()) {
            if seen.insert(sid.clone()) { sids.push(sid); }
        }
    }
    sids
};

// 3. One LSA round for the entire scan.
let scan_sid_names = ad_resolver::build_sid_name_map(&memberships, unique_sids);

// 4. Per path: no more LSA, only map lookups.
for fso in &walk.objects {
    let trustees = build_path_trustees_with_share_and_names(
        fso, share_overlay.as_ref(), &scan_sid_names,
    );
    // ...
}
```

### Where the map is used

| Call site | Map source | LSA per path? |
|---|---|---|
| CLI `run_analyze` (trustees) | per-call inside `build_path_trustees` (internal, only 1 path) | yes, but n=1 |
| CLI `run_scan` (trustees) | scan-wide `scan_sid_names`, now incl. share-overlay SIDs | **no** |
| CLI `run_scan` (engine explanation path) | the same map via `PermissionEvaluationInput.sid_names` | unchanged |
| GUI Analyze (trustees) | per-call, n=1 | yes, but n=1 |
| GUI Scan (trustees) | scan-wide `scan_sid_names`, now incl. share-overlay SIDs | **no** |

The scan-wide map now covers **three consumers** instead of two: engine explanation path, GUI/HTML trustee render, JSON trustee export.

### Tests

Three new unit tests guard the invariants:

| Test | What it guarantees |
|---|---|
| `caller_owned_map_sets_display_names` | ACE display names are taken from the passed-in map. |
| `caller_owned_map_does_not_touch_diagnostics` | Diagnostic entries (NULL DACL, share-read failure) are NOT overwritten with a foreign display name. |
| `collect_ace_sids_for_resolution_covers_ntfs_and_share` | Helper collects NTFS ACE SIDs AND share-overlay ACE SIDs; diagnostic entries are skipped. |

## Consequences

### Positive

- **Performance on large scans.** Instead of N × M LSA lookups (N paths × M SIDs per path), we now do M_unique LSA lookups per scan. For Stars' standard cases (large file tree, few unique SIDs) this is a three- to four-digit reduction in LSA round trips.
- **Consistency between the engine explanation path and the trustee display.** Both consumers now share the same map — one identity, one display name, no aliasing risk.
- **Visible dependency.** The scan caller sees in the code that it does an LSA lookup. That is semantically more honest: the trustee module is data-transforming, the LSA call is infrastructure.
- **Share-overlay SIDs are now resolved as well.** Previously share-overlay SIDs were not in the scan-wide map (it came only from `fso.dacl`). Now the helper collects from both sources.
- **Platform-independent tests.** The `caller_owned_map_*` tests run through on CI Linux because they don't need a real LSA — they pass a BTreeMap and verify the map application.

### Negative / trade-offs

- **API extension.** One additional function (`build_path_trustees_with_share_and_names`) and one additional helper (`collect_ace_sids_for_resolution`). Cleanly encapsulated in the workspace, re-exported from `exporter::lib` and `gui::worker`.
- **Per-call map stays for the simple form.** `build_path_trustees_with_share` still builds its own per-call map internally — for the analyze path (n=1) this is exactly the previous cost, no regression but no improvement either. The map variant is the optimization for the N-paths cases.
- **Scan-loop initialization gains a bit of code.** The scan caller has to collect SIDs and build the map before processing the paths. That is deliberate — making the dependency visible is a goal, not a trade-off.

### Relationship to other ADRs

- **ADR 0036** (unified principal resolution pipeline): "one data source, both consumers" — this ADR applies the same principle to trustee SID resolution.
- **ADR 0044** (path-centric trustees as a shared module): the module is extended here, not changed. The interface stays compatible for analyze consumers.
- **ADR 0047** (SmbAuditContext): the share-overlay SIDs that now flow into the map come from the overlay, which is built via `SmbAuditContext` — both Round-10 fixes mesh cleanly.
