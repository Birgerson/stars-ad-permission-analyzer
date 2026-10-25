# ADR 0088 — A link's row says what opening it reaches; a folder without identity says it may be listed twice

## Status
Accepted (2026-10-25).

## Context

Two findings of the enterprise campaign (verification Block W).

**1. A junction's row looked like the rights on its content.**

- What the row shows: for a junction or symbolic link, Stars evaluates the link object's own security descriptor. `GetNamedSecurityInfoW` reads the link itself, not its target. Windows reads the same descriptor, and the exhaustive comparison matched both on every link of the tree.
- What a client gets: whoever opens the path reaches the target, and the target's permissions decide.
  - A real network logon of `ent_std` opened `Archive\P00_Media\Link_to_P01_Shared`. The row shows Modify, inherited by the link object from its folder. The logon got access denied: the rights on `P01_Shared`.
  - Over SMB from WIN11-01, opening each of 22 junction paths gave exactly the Stars row of its target.
- The row did not say that it was a link.

**2. A folder was listed twice under load.**

- What happened: four archive scans ran at once while the oracle read the same server. In one of them, the walker did not recognize the direct route to `Archive\P01_Shared` as the folder it had already enumerated through `P00_Media\Link_to_P01_Shared`. It caught the duplicate one level deeper, so the 83 objects directly in `P01_Shared` were listed twice. Their values were correct.
- The cause: over SMB, a directory is identified by its volume serial and file ID (ADR 0062), read with one open. When that open failed, the walker silently keyed the directory by its path, which no other route shares.

Over SMB, the reparse attribute of an open is unreliable, because the open follows the junction on the server (ADR 0062). The directory listing reports the entry itself.

## Decision

1. **The file system object carries what a link stores.** `link: Option<LinkInfo>` holds the kind, the stored target and whether it is relative. It is read with `FSCTL_GET_REPARSE_POINT`, with every value checked. This happens when the object's attributes say it is a reparse point, or when its parent's directory listing marks it as a junction or symbolic link. `fs_scanner`'s own link types move to `core`.
2. **A link row says what opening it reaches.** It gets the marker `LinkObject` (Notice) and, as the last explanation step, the same wording:

   > This object is a junction to `<target>`: the rights shown are those on the link itself (who can delete it or change its permissions). Opening this path reaches the target, and the target's own permissions decide what an account can do there.

   The values do not change. They are the exact rights on the link object.
3. **A directory's identity is read again before it stands as unknown.** Over SMB, the walker retries a failed probe twice, after 50 ms and after 250 ms.
4. **If the identity is still unknown, the row says so.** The reason goes into `identity_unknown`, and the row gets the marker `DirectoryIdentityUnknown` (Notice): a second route to it through a link is not recognized, so its content may be listed twice. The values are exact. The reason is also logged.

## Consequences

- **Risk rules and values** are unchanged.
- **Delta:** compared with a scan of an older version, the rows of links (and of unidentified folders) differ in their diagnostics once.
- **Local scans:** links are marked too. Identities are only probed over SMB.
- **Non-Windows SMB servers** that report a file ID of 0 get the marker on every directory. That is accurate: there, a second route through a link cannot be recognized.

Lab proof: verification Block Y.
