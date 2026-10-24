# ADR 0085 — DFS paths are evaluated on the target the client is referred to

## Status
Accepted (2026-10-24). New known limitation L18 for DFS folders with more
than one target.

## Context

The lab got a domain-based DFS namespace on 2026-10-24:

- **Namespace root:** `\\corp.test\dfs`, root share `dfs` on DC-01 (share permission Everyone Read).
- **Folder `Projects`:** two targets with deliberately different permissions.
  - `\\FS-01\DfsProj`: share Everyone Change; NTFS `rt_gt01` Modify, Domain Users RX.
  - `\\FS-02\DfsProj`: share Everyone Read; NTFS `rt_gt01` RX, `rt_gt02` Modify.
- **Folder `Team`:** one target, `\\FS-02\DfsTeam` (share Everyone Full; NTFS `rt_gt02` Modify, Domain Users RX).

Ground truth came from real SMB logons from MS-01 through the namespace:

- Each account opened each folder with single access rights.
- `target.txt` in each target root showed which target the client got.
- MS-01 is referred to FS-01 for `Projects`, and to FS-02 for `Team`.

| Path | Account | Windows | Stars v1.18.0 / main 79e316e |
| --- | --- | --- | --- |
| `\\corp.test\dfs\Projects\Sub` | `rt_gt01` | Modify (FS-01, share Change) | **Read & Execute**, "limited by the share" |
| `\\corp.test\dfs\Team\Sub` | `rt_gt02` | Modify (FS-02, share Full) | **Read & Execute**, "limited by the share" |

The cause:

- **NTFS:** the redirector follows the DFS referral, so the DACL came from the target. That part was correct.
- **Share permission:** read with `NetShareGetInfo(corp.test, dfs)`, which is the namespace's root share, not the target's share.
- **Server context:** local groups, remote UAC and the Selective Authentication computer object were also those of the namespace server.

A right the account really has was under-reported. That is the security
problem the project rules forbid.

### API measurements (MS-01, 2026-10-24)

- **`GetFinalPathNameByHandle(FILE_NAME_NORMALIZED)`** on a handle opened through the namespace returns the target, for example `\\?\UNC\FS-01.corp.test\DfsProj\Sub`. It does so for every name form: `\\corp.test\dfs\…`, `\\corp\dfs\…`, and the physical root share `\\DC-01\dfs\Projects\…`. For a plain UNC path it returns the same server and share, with the case normalized; an IP stays an IP, a short name stays a short name.
- **`NetDfsGetClientInfo` (level 3)** matches by prefix: for `\\corp.test\dfs\Projects\Sub\x.txt` it returns the folder `\corp.test\dfs\Projects` (one leading backslash) with every target. The target the client uses is flagged `DFS_STORAGE_STATE_ACTIVE`. A path outside DFS returns `NERR_DfsNoSuchVolume` (2662). For some name forms the answer is 2662 until the path has been opened once.

## Decision

1. **Evaluate where Windows serves the path.** Before any other step, CLI and GUI (`analysis::dfs::resolve_evaluation_target`, one implementation) open the path. When the redirector opened it on another share than the one given, the path is a DFS path. The path the redirector opened is then evaluated: its NTFS DACL, the share permission of that share, and its server's local groups, UAC policies and Selective Authentication. The path returned by the OS is validated like any input.
2. **Name the folder and its targets.** The DFS client's answer (after the open) gives the folder and all its targets. The result carries the marker `DfsTargetEvaluated { requested, target, folder, other_targets, other_targets_known }`, and the explanation path gets the step "DFS: … evaluated on …". The report keeps the path as given.
3. **One target means exact; more targets or unknown targets mean not determinable.** A client referred to another target has that target's NTFS and share permissions. With further targets, or with targets that could not be read consistently (no active target, or the active target is not the one the handle went to), the result is not determinable. The new uncertainty layer `Target` covers NTFS and share alike, the share no longer bounds the upper limit, and the reason is a step of the explanation (CR-5). The known values are those of the evaluated target.
4. **Scans.**
   - A scan root inside a DFS folder is walked on its target; rows keep the requested form.
   - In a remote scan the walker opens every directory once anyway (file ID, ADR 0062) and now reads the final path from the same handle. A directory served from **another share** than the scan root is reported as a visible scan error (`CoreError::OtherShare`) and not enumerated. That is a DFS folder below a namespace root, or a link to another share. It is not evaluated with the wrong share. The message says to scan that path on its own.
5. **No claim without evidence.** If the path cannot be opened and the DFS client does not name it, the path is evaluated as given, as before. If only the DFS client answers, its active target is used. Without an active target, the path is evaluated as given and the result stays open.

## Consequences

- `rt_gt02` on `Team\Sub` is exact (Modify); before it was Read & Execute. `rt_gt01` on `Projects\Sub` shows FS-01's values (Modify) as known data and is not determinable because of FS-02. The namespace-root scan reports `Projects` and `Team` as served from another share.
- Paths outside DFS are unchanged. The regression against the step 5a binary found 0 differing rows.
- Cost: one extra open per analysis root. In remote scans there is no extra open, only one extra local call per directory.
- Not covered (L18): evaluating every target of a multi-target folder in one run. The admin scans each target share directly; the marker names them. A client referred to a different target than this machine (site costing) is covered by the same rule: more than one target means not determinable.
- Read-only: an open with `FILE_READ_ATTRIBUTES` and a query of the client's referral cache.
