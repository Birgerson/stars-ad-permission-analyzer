# Test environment scripts

Automation for the integration test environment. Full guide: [`docs/testing/integration-test-setup.md`](../../docs/testing/integration-test-setup.md).

| Script | Run on | Purpose |
|--------|--------|---------|
| `01-setup-dc.ps1` | Test VM (Windows Server) | Promote to DC for `testdomain.local` — VM reboots |
| `02-setup-ad-objects.ps1` | Test VM (after reboot) | Create test users, groups, and nesting |
| `03-setup-fileserver.ps1` | Test VM | Create test folders, NTFS ACLs, and SMB shares |
| `04-run-integration-tests.ps1` | Developer machine | `cargo test -- --ignored` against the test domain |
| `99-teardown.ps1` | Test VM | Remove test data and AD test OU |

> **Warning:** `01-setup-dc.ps1` requires **Windows Server** and promotes the host to a domain controller (reboot). Never run it on a workstation. Take a VM snapshot first.

Scripts `01`–`03` and `99` provision a test environment and therefore modify the test system. The DevMS analyzer itself stays strictly read-only — the scripts are not part of its feature set.
