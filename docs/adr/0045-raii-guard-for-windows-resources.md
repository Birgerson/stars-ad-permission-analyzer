# ADR 0045 — RAII guard for Windows API resources (`win_safe`)

**Status:** Accepted
**Date:** 2026-06-06

## Context

Stars accesses the Windows NetAPI at several places to read local groups, domain users, local group members, and SMB share DACLs. Each of these API functions (`NetShareEnum`, `NetShareGetInfo`, `NetUserEnum`, `NetUserGetGroups`, `NetUserGetInfo`, `NetUserGetLocalGroups`, `NetLocalGroupGetMembers`, `NetLocalGroupEnum`, `NetGroupEnum`, `NetWkstaGetInfo`) allocates an internal buffer on success and hands the caller an out pointer. The caller is required to free the buffer with `NetApiBufferFree`.

The implementation followed this pattern:

```rust
let mut buf_ptr: *mut u8 = std::ptr::null_mut();
let status = unsafe { NetSomething(..., &mut buf_ptr, ...) };
if status != NO_ERROR {
    if !buf_ptr.is_null() {
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }
    return Err(...);
}
// ... work with buf_ptr ...
match unsafe { parse_share_dacl(...) }? {     // ← `?` exits the function
    ...                                       //   before NetApiBufferFree is reached
}
unsafe { NetApiBufferFree(buf_ptr.cast()) };  // ← not executed when `?` fires
```

Review round 10 finding 3 uncovered the concrete case in `get_share_dacl`: the `?` after `parse_share_dacl(...)` exits the function before `NetApiBufferFree` is reached. If the parser returns an error, the buffer leaks.

The same risk pattern existed at at least 11 other sites in the workspace — everywhere a NetAPI buffer and a potential early return coincide.

A spot fix (store the parse result first, free the buffer, then apply `?`) would have fixed the concrete occurrence but not the **pattern**. Future refactorings could reintroduce the same bug at a different site, and code review would have to scan every NetAPI-calling function for hidden early returns.

## Decision

We introduce a **new, dedicated workspace crate `crates/win_safe/`** that provides safe Windows API resource wrappers. First module: `netapi`. First type: **`NetApiBuffer<T>`** as a RAII guard for NetAPI buffers.

### Why a dedicated crate?

Three alternatives were considered:

1. **Module in `share_scanner`** — rejects the semantics ("share_scanner is about SMB shares, not about Windows API resources").
2. **Module in `ad_resolver`** — same rejection, plus `share_scanner` would have to depend on `ad_resolver`, which violates the crate layering direction.
3. **Dedicated crate `win_safe`** — clean separation of concerns. Future Windows resources (HANDLE wrappers, LSA buffers, `LocalAlloc`/`LocalFree` guards) belong there without watering down a domain crate. On non-Windows platforms the crate compiles empty (`#[cfg(windows)]` at the module level) so CI on Linux does not fail.

We picked (3).

### Interface

```rust
pub struct NetApiBuffer<T> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

impl<T> NetApiBuffer<T> {
    pub unsafe fn from_raw(ptr: *mut T) -> Self;
    pub fn null() -> Self;
    pub fn as_ptr(&self) -> *mut T;
    pub fn out_ptr(&mut self) -> *mut *mut T;
    pub fn is_null(&self) -> bool;
}

impl<T> Drop for NetApiBuffer<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { NetApiBufferFree(self.ptr.cast()) };
            self.ptr = ptr::null_mut();
        }
    }
}
```

Usage in a typical NetAPI function:

```rust
let mut buf: NetApiBuffer<SHARE_INFO_502> = NetApiBuffer::null();
let status = unsafe {
    NetShareGetInfo(server, share, 502, buf.out_ptr().cast())
};
if status != NERR_SUCCESS {
    return Err(...);              // buf is dropped → NetApiBufferFree runs
}
if buf.is_null() {
    return Ok(default);           // buf is dropped → no-op (null)
}
let info = unsafe { &*buf.as_ptr() };
let result = unsafe { parse_share_dacl(...) }?;  // ← now safe: on Err, Drop runs
Ok(result)
// buf is dropped here → NetApiBufferFree runs
```

Three properties the guard guarantees:

1. **Success path**: Drop at function end → free.
2. **Status error**: `return Err(...)` → Drop runs along → free.
3. **`?` early return**: Drop runs along → free. **This was the bug.**

No free is triggered on a null pointer — compatible with the NetAPI convention that failed calls may not set the pointer.

### Where the guard is used

With review round 10, all 11 NetAPI call sites in the workspace were migrated:

| Crate / module | Function | NetAPI call |
|---|---|---|
| `share_scanner::scanner` | `get_share_enum` | `NetShareEnum` |
| `share_scanner::scanner` | `get_share_dacl` | `NetShareGetInfo` ← **original finding** |
| `ad_resolver::sam` | `user_global_group_names` | `NetUserGetGroups` |
| `ad_resolver::sam` | `user_account_disabled` | `NetUserGetInfo` |
| `ad_resolver::local_groups` | `resolve_local_group_sids` | `NetUserGetLocalGroups` |
| `ad_resolver::local_groups` | `resolve_local_groups` | `NetUserGetLocalGroups` |
| `ad_resolver::local_groups` | `get_local_group_members` | `NetLocalGroupGetMembers` |
| `ad_resolver::enumerate` | `list_users` | `NetUserEnum` (loop) |
| `ad_resolver::enumerate` | `list_global_groups` | `NetGroupEnum` (loop) |
| `ad_resolver::enumerate` | `list_local_groups` | `NetLocalGroupEnum` (loop) |
| `ad_resolver::enumerate` | `local_netbios_domain` | `NetWkstaGetInfo` |

In loops (`NetUserEnum`, `NetGroupEnum`, `NetLocalGroupEnum`) a fresh guard is created per iteration. Each iteration has its own lifetime — no buffer leftover from the previous loop, no accidental reuse.

## Consequences

### Positive

- **Bug class eliminated.** Neither `?` nor `return` can leave a successful NetAPI buffer unfreed any more — and the compiler enforces that via the `Drop` pattern, without humans having to scan every function in review.
- **Readability:** the business function reads more linearly. `if !buf_ptr.is_null() { unsafe { NetApiBufferFree(...) } }` at three or four places per function is gone.
- **Consistency:** all 11 NetAPI call sites use the same pattern — making code review and future refactorings trivial.
- **Future extension:** when next a `LocalAllocBuffer<T>` for `ConvertSidToStringSidW` is needed, or a `HandleGuard` for `OpenSCManager` etc., it lives in `win_safe` as well and inherits the same layering argument.
- **Test coverage:** two sanity tests in the module (`drop_on_null_is_no_op`, `out_ptr_can_be_written_and_read_back`) run platform independently and guard the base invariant. Real NetAPI paths stay in the crate-internal integration tests.

### Negative / trade-offs

- **One additional crate** in the workspace (`win_safe`). A one-file crate looks like overkill at first, but separating the concerns is the clean answer: `share_scanner`/`ad_resolver` are not mixed with Windows resource wrapper logic.
- **`cfg(windows)`-only.** On non-Windows platforms `netapi` compiles empty; the crate itself compiles. Consumers still have to `#[cfg(windows)]`-gate their own call sites — the guard does not save against missing NetAPI symbols on Linux.
- **`unsafe` stays** at the call sites. The guard does not reduce the amount of unsafe code (the NetAPI calls themselves are still `unsafe`), but it reduces the unsafe *places where something can be forgotten*.

### Relationship to other ADRs

- **ADR 0023** (workspace layering): `win_safe` lives below `core` and above no domain crate. `share_scanner` and `ad_resolver` depend on `win_safe`, not the other way around.
- **ADR 0036** (unified principal resolution pipeline): uses several NetAPI calls that now all use the guard.

## Verification

Locally verified after the refactoring:

- `cargo fmt --all -- --check`: success
- `cargo clippy --workspace --all-targets -- -D warnings`: success
- `cargo test --workspace`: success, **507 tests pass**, 7 tests ignored (NetAPI / AD live integration). The 507 include two new tests from `win_safe::netapi::tests` and all previous crate tests stay green.
