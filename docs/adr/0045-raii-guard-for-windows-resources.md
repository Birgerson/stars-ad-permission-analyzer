# ADR 0045 — RAII-Guard für Windows-API-Ressourcen (`win_safe`)

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-06

## Kontext / Context

Stars greift an mehreren Stellen auf die Windows-NetAPI zu, um lokale Gruppen, Domänenbenutzer, lokale Gruppenmitglieder und SMB-Share-DACLs zu lesen. Jede dieser API-Funktionen (`NetShareEnum`, `NetShareGetInfo`, `NetUserEnum`, `NetUserGetGroups`, `NetUserGetInfo`, `NetUserGetLocalGroups`, `NetLocalGroupGetMembers`, `NetLocalGroupEnum`, `NetGroupEnum`, `NetWkstaGetInfo`) alloziert bei Erfolg intern einen Puffer und übergibt dem Aufrufer einen Out-Pointer. Der Aufrufer ist verpflichtet, den Puffer mit `NetApiBufferFree` wieder freizugeben.

Die Implementierung folgte bisher dem Muster:

```rust
let mut buf_ptr: *mut u8 = std::ptr::null_mut();
let status = unsafe { NetSomething(..., &mut buf_ptr, ...) };
if status != NO_ERROR {
    if !buf_ptr.is_null() {
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }
    return Err(...);
}
// ... arbeite mit buf_ptr ...
match unsafe { parse_share_dacl(...) }? {     // ← `?` springt aus der Funktion
    ...                                       //   bevor NetApiBufferFree erreicht wird
}
unsafe { NetApiBufferFree(buf_ptr.cast()) };  // ← wird nicht ausgeführt, wenn `?` greift
```

Review-Runde 10 Finding 3 hat den konkreten Fall in `get_share_dacl` aufgedeckt: das `?` nach `parse_share_dacl(...)` springt aus der Funktion heraus, bevor `NetApiBufferFree` erreicht wird. Wenn der Parser einen Fehler liefert, leakt der Puffer.

Das gleiche Risiko-Muster existierte an mindestens 11 weiteren Stellen im Workspace — überall, wo ein NetAPI-Puffer und ein potenzieller Early-Return zusammentreffen.

Die punktuelle Lösung (das Parse-Ergebnis erst speichern, Puffer freigeben, dann `?` anwenden) hätte das konkrete Vorkommen behoben, aber das **Muster** nicht. Künftige Refactorings könnten denselben Bug an einer anderen Stelle wieder einführen, und Code-Review müsste in jeder NetAPI-aufrufenden Funktion nach versteckten Early-Returns suchen.

## Entscheidung / Decision

Wir führen einen **neuen, eigenständigen Workspace-Crate `crates/win_safe/`** ein, der sichere Windows-API-Ressourcen-Wrapper bereitstellt. Erstes Modul: `netapi`. Erster Typ: **`NetApiBuffer<T>`** als RAII-Guard für NetAPI-Puffer.

### Warum eine eigene Crate?

Drei Alternativen wurden geprüft:

1. **Modul in `share_scanner`** — verwirft die Semantik („share_scanner ist über SMB-Shares, nicht über Windows-API-Resourcen").
2. **Modul in `ad_resolver`** — gleiche Verwerfung, plus `share_scanner` müsste auf `ad_resolver` verlinken, was die Crate-Layering-Richtung verletzt.
3. **Eigener Crate `win_safe`** — saubere Trennung der Concerns. Zukünftige Windows-Ressourcen (HANDLE-Wrapper, LSA-Buffer, `LocalAlloc`/`LocalFree`-Guards) gehören dort hin, ohne eine fachliche Crate zu verwässern. Auf Nicht-Windows-Plattformen kompiliert die Crate leer (`#[cfg(windows)]` auf der Modul-Ebene), damit CI auf Linux nicht scheitert.

Wir haben uns für (3) entschieden.

### Schnittstelle

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

Verwendung in einer typischen NetAPI-Funktion:

```rust
let mut buf: NetApiBuffer<SHARE_INFO_502> = NetApiBuffer::null();
let status = unsafe {
    NetShareGetInfo(server, share, 502, buf.out_ptr().cast())
};
if status != NERR_SUCCESS {
    return Err(...);              // buf wird gedroppt → NetApiBufferFree läuft
}
if buf.is_null() {
    return Ok(default);           // buf wird gedroppt → no-op (null)
}
let info = unsafe { &*buf.as_ptr() };
let result = unsafe { parse_share_dacl(...) }?;  // ← jetzt sicher: bei Err läuft Drop
Ok(result)
// buf wird hier gedroppt → NetApiBufferFree läuft
```

Drei Eigenschaften garantiert der Guard:

1. **Erfolg-Pfad**: Drop am Funktionsende → Free.
2. **Status-Fehler**: `return Err(...)` → Drop läuft mit aus → Free.
3. **`?`-Early-Return**: Drop läuft mit aus → Free. **Genau das war der Bug.**

Auf einen Null-Pointer wird kein Free ausgelöst — kompatibel mit der NetAPI-Konvention, dass fehlgeschlagene Calls den Pointer möglicherweise nicht setzen.

### Wo der Guard verwendet wird

Mit Review-Runde 10 wurden alle 11 NetAPI-Aufrufstellen im Workspace umgestellt:

| Crate / Modul | Funktion | NetAPI-Call |
|---|---|---|
| `share_scanner::scanner` | `get_share_enum` | `NetShareEnum` |
| `share_scanner::scanner` | `get_share_dacl` | `NetShareGetInfo` ← **Original-Finding** |
| `ad_resolver::sam` | `user_global_group_names` | `NetUserGetGroups` |
| `ad_resolver::sam` | `user_account_disabled` | `NetUserGetInfo` |
| `ad_resolver::local_groups` | `resolve_local_group_sids` | `NetUserGetLocalGroups` |
| `ad_resolver::local_groups` | `resolve_local_groups` | `NetUserGetLocalGroups` |
| `ad_resolver::local_groups` | `get_local_group_members` | `NetLocalGroupGetMembers` |
| `ad_resolver::enumerate` | `list_users` | `NetUserEnum` (Schleife) |
| `ad_resolver::enumerate` | `list_global_groups` | `NetGroupEnum` (Schleife) |
| `ad_resolver::enumerate` | `list_local_groups` | `NetLocalGroupEnum` (Schleife) |
| `ad_resolver::enumerate` | `local_netbios_domain` | `NetWkstaGetInfo` |

In Schleifen (`NetUserEnum`, `NetGroupEnum`, `NetLocalGroupEnum`) wird pro Iteration ein neuer Guard angelegt. Damit ist jede Iteration eine eigene Lifetime — kein Pufferreste vom vorigen Loop, kein versehentliches Reuse.

## Konsequenzen / Consequences

### Positiv

- **Bug-Klasse eliminiert.** Kein `?` und kein `return` kann mehr einen erfolgreichen NetAPI-Puffer ungefreigegeben verlassen — und der Compiler erzwingt das über das `Drop`-Pattern, ohne dass der Mensch im Review jede Funktion abklopfen muss.
- **Lesbarkeit:** Die fachliche Funktion liest sich linearer. `if !buf_ptr.is_null() { unsafe { NetApiBufferFree(...) } }` an drei oder vier Stellen pro Funktion ist weg.
- **Konsistenz:** alle 11 NetAPI-Aufrufstellen haben dasselbe Pattern — was Code-Review und zukünftige Refactorings trivialer macht.
- **Zukünftige Erweiterung:** Wenn als nächstes ein `LocalAllocBuffer<T>` für `ConvertSidToStringSidW` gebraucht wird, oder ein `HandleGuard` für `OpenSCManager` usw., wohnt das ebenfalls in `win_safe` und erbt dasselbe Layering-Argument.
- **Test-Abdeckung:** zwei Sanity-Tests im Modul (`drop_on_null_is_no_op`, `out_ptr_can_be_written_and_read_back`) laufen plattform-unabhängig und sichern die Grundinvariante. Echte NetAPI-Pfade bleiben in den Crate-eigenen Integrationstests.

### Negativ / Trade-offs

- **Ein zusätzlicher Crate** im Workspace (`win_safe`). 1-Datei-Crates wirken zunächst overkill, aber die Trennung der Concerns ist die saubere Antwort: `share_scanner`/`ad_resolver` werden nicht mit Windows-Resource-Wrapper-Logik vermischt.
- **`cfg(windows)`-only.** Auf Nicht-Windows-Plattformen ist `netapi` leer kompiliert; die Crate als solche compiled aber. Konsumenten müssen ihre eigenen Aufrufstellen weiterhin `#[cfg(windows)]`-gaten — der Guard rettet nicht vor fehlenden NetAPI-Symbolen auf Linux.
- **`unsafe` bleibt** in den Aufrufstellen. Der Guard reduziert nicht die Menge an unsafe-Code (die NetAPI-Calls selbst sind weiterhin `unsafe`), aber er reduziert die unsicheren *Stellen, wo etwas vergessen werden kann*.

### Beziehung zu anderen ADRs

- **ADR 0023** (Workspace-Layering): `win_safe` wohnt unter `core` und über keiner fachlichen Crate. `share_scanner` und `ad_resolver` haben `win_safe` als Dependency, nicht umgekehrt.
- **ADR 0036** (Unified Principal Resolution Pipeline): nutzt mehrere NetAPI-Aufrufe, die jetzt alle den Guard verwenden.

## Verification

Lokal verifiziert nach dem Refactoring:

- `cargo fmt --all -- --check`: erfolgreich
- `cargo clippy --workspace --all-targets -- -D warnings`: erfolgreich
- `cargo test --workspace`: erfolgreich, **507 Tests bestanden**, 7 Tests ignoriert (NetAPI-/AD-Live-Integration). Die 507 enthalten zwei neue Tests aus `win_safe::netapi::tests` und alle vorherigen Crate-Tests bleiben grün.
