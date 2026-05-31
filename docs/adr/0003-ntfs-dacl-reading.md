# ADR 0003 — NTFS-DACL-Lesen mit GetNamedSecurityInfoW

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-20

## Kontext / Context

Um NTFS-Berechtigungen zu lesen, muss der Security Descriptor eines Pfades
gelesen werden. Windows bietet mehrere APIs:

- `GetFileSecurity` — erfordert separates Speichermanagement für den Descriptor
- `GetNamedSecurityInfoW` — allokiert den Security Descriptor intern, gibt
  `PSECURITY_DESCRIPTOR` zurück, das mit `LocalFree` freigegeben werden muss
- `NtQuerySecurityObject` — low-level, erfordert HANDLE-Öffnung

## Entscheidung / Decision

Verwendung von `GetNamedSecurityInfoW` aus `windows-sys 0.59`.

## Begründung / Rationale

- Höchster Abstraktionsgrad: gibt Owner-SID und DACL-Zeiger direkt zurück
- Unterstützt UNC-Pfade nativ
- Kein separates Speichermanagement für den Security Descriptor nötig
- `SE_FILE_OBJECT` als Objekttyp deckt Dateien und Ordner ab

## Technische Besonderheiten / Technical Details

- `ACCESS_ALLOWED_ACE_TYPE` (0) und `ACCESS_DENIED_ACE_TYPE` (1) sind in
  windows-sys 0.59 nicht als Konstante exportiert; Rohwerte aus WinNT.h werden
  als lokale `const` definiert.
- `INHERITED_ACE` ist in windows-sys als `u32` exportiert; wird per `as u8`
  auf das `AceFlags`-Byte (u8) im ACE-Header angewendet.
- `HLOCAL` = `*mut c_void` in windows-sys 0.59; `LocalFree` nimmt entsprechend
  `*mut c_void`, kein `isize`.
- `SidStart` in `ACCESS_ALLOWED_ACE` ist ein Platzhalter (u32); `addr_of!`
  gibt den Startzeiger des SID-Byte-Blocks zurück.
- `SE_DACL_PROTECTED` (0x1000) im Security-Descriptor-Control-Feld zeigt an,
  ob die Vererbung auf diesem Pfad unterbrochen ist.

## Konsequenzen / Consequences

- Alle Windows-API-Aufrufe sind in `crates/fs_scanner/src/acl.rs` gekapselt.
- `scanner.rs` und Aufrufer erhalten typisierte `FileSystemObject`-Modelle.
- 7 Unit-Tests mit `C:\Windows` und `C:\Windows\System32` als bekannten
  Testpfaden; kein Mocking notwendig.
- Nicht unterstützte ACE-Typen (Object-ACEs etc.) werden übersprungen und
  können in einem späteren Schritt ergänzt werden.
