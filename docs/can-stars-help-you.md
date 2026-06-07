# Can Stars help you?

> **In two sentences:** Stars answers the question *“Why does this user have exactly this effective permission on this folder or share?”* — with a **traceable explanation path**, **strictly read-only**, no agent install on target systems, no background services, no remediation features.
> Stars does **not** replace an enterprise access-governance suite, an AD security-score platform, or attack-path analytics — and doesn’t claim to.

## When Stars is the right tool

Stars fits if **at least one** of these is true for you:

- You are sitting on a fileserver and need to know: *“Who can do what on `D:\Shares\Finance` — and through which group chain?”*
- You need to explain after an audit finding **why** a user has Modify (or why not).
- You want a tool that changes **nothing** in AD, NTFS, or SMB — not even “just to fix it”.
- You work with nested AD groups, local server groups (`BUILTIN\Administrators`, `Users`), Deny ACEs, and SMB shares whose restriction must be combined with the NTFS DACL.
- You want a permission snapshot of a directory tree (e.g. 5000 dirs) as CSV/JSON/HTML.

## When Stars is **not** the right tool

Stars does **not** solve your problem if you need:

- **Active remediation** of permissions, ACL cleanup, owner change, group creation. → Stars is and stays read-only.
- **Continuous auditing** with real-time event stream, logon tracking, file-server audit trail. → Stars is a point-in-time analyzer.
- **AD security score** and forest-wide hardening assessment. → PingCastle, Purple Knight.
- **Attack-path analysis** from an attacker’s perspective. → BloodHound CE.
- **Access governance, recertification, role models, workflows**. → SolarWinds ARM, Netwrix, Quest, Lepide.
- **Broad AD inventory reports** (users, GPOs, trusts, computers, OUs). → ADRecon.
- **Multi-user web platform** with tenant separation, SIEM integration, email reports. → Stars is a single-user desktop app.

## Three hard limits Stars will **never** cross

1. **Read-only.** No release will ever ship write functions for NTFS, SMB, AD or any target system. Architectural decision — see `AGENTS.md`.
2. **No agent on target systems.** Stars runs on an audit workstation or audit DC. It installs nothing on file servers or other DCs.
3. **No backdoor auth.** Stars binds via LDAP (ideally LDAPS) and asks for nothing else. No hidden telemetry, no update beacons without signature checks.

## What you need to know before first use

- **Backup duty.** Even though Stars only reads, a tested backup strategy for the target systems is mandatory for any production use. Read-only does not protect you from driver bugs, antivirus locks, or load spikes.
- **No vendor liability.** Stars is developed by a single prompt engineer (Birger Labinsch); implementation is largely AI-assisted. There is no vendor support, no SLA, no hotline. Use at your own risk.
- **Windows only.** Stars runs on Windows 10/11 and Windows Server (2016+). Linux/macOS are out of scope.
- **Standalone EXE.** No .NET Framework, no Visual C++ Redistributable, no installer bootstrap.
