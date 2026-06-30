# ADR 0054 — GUI LDAP timeout control (GUI/CLI parity)

**Status:** Accepted (2026-06-30)
**References:** ADR 0032 (identity-input dispatcher & LDAP timeouts),
ADR 0051 (signed LDAP bind), ADR 0053 (group-membership view)

## Context

ADR 0032 added the CLI `--ldap-timeout` flag (1–600 s, default 10) because the
transitive membership query (`LDAP_MATCHING_RULE_IN_CHAIN`) on large or densely
nested domains can exceed the fixed 10 s cap — Stars then aborts that step and
**marks the result incomplete** rather than hanging or silently under-reporting.

The GUI never gained that control. Every GUI LDAP operation (Analyze, Scan, and
the new Groups tab, ADR 0053) was stuck at the constructor default of 10 s, so a
dense domain that the CLI could query with `--ldap-timeout 120` simply timed out
in the GUI. That is the exact "silently incomplete in practice" gap the timeout
flag was introduced to close — present in the GUI but not fixable there.

## Decision

Carry the timeout on the GUI's shared `LdapParams` and apply it where the
`LdapConfig` is built — the same single carrier all three LDAP-capable tabs
already use, so one change covers them all.

- `LdapParams` gains `timeout_secs: Option<u64>` (`None` keeps the 10 s
  `LdapConfig` default — identical to the CLI, where `None` also keeps 10 s).
- `LdapParams::from_mode(...)` takes the raw UI value and **clamps it to
  1–600** before storing it, so an out-of-range value can never reach the LDAP
  layer (the GUI boundary is the validation point, mirroring the CLI's
  `validate_optional_ldap_timeout`).
- `LdapParams::to_config()` sets `config.timeout_secs` from the field on every
  branch (signed / GC / insecure / plain) — exactly the CLI's
  `config.timeout_secs = secs` step.
- Each LDAP-capable tab (Analyze, Scan, Groups) gets a `Timeout (s)` `SpinBox`
  (`minimum: 1`, `maximum: 600`, default 10) in its `Identity resolution`
  section, shown only when a mode other than Off is selected. Keeping the field
  on all three keeps the LDAP sections visually identical across tabs.

## Why on `LdapParams` (not a per-tab request field)

The Analyze / Scan / Groups worker requests already carry `ldap:
Option<LdapParams>`. Putting the timeout on `LdapParams` means **no** change to
the request structs or the worker dispatch — the value rides along with the
connection parameters it belongs to, and `to_config()` stays the one place that
turns parameters into a config. This mirrors how `global_catalog` and `signing`
were added (GUI/CLI parity on the same struct).

## Consequences

- The GUI can now query dense/nested domains that previously timed out; the
  honest-incompleteness behaviour (a timeout marker instead of a hang) is
  unchanged — only the cap is now adjustable.
- GUI and CLI reach full parity on LDAP connection options (mode, GC, signing,
  timeout).
- Unit test: `from_mode` clamps out-of-range values and `to_config` applies the
  result to `timeout_secs`.

## Out of scope (same Groups-tab review, not architectural)

Two polish fixes shipped alongside this and are recorded in the CHANGELOG, not
here: the Groups tab now packs its form at the top (`alignment: start`) so the
sparse tab no longer inflates its fields, and the Groups identity field reuses
the Analyze tab's live suggestion list (the shared `filter_suggestions_model`).
