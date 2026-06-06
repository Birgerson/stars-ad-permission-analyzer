// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::{error::CoreError, model::NormalizedPath};

use crate::net::{validate_share_name, validate_smb_server};

/// Obergrenze für Pfadlängen (extended-length-Limit von Windows).
/// Upper bound for path length (Windows extended-length limit).
const MAX_PATH_LEN: usize = 32_767;

/// In Windows-Pfadkomponenten verbotene Zeichen (zusätzlich zu Steuerzeichen).
/// Characters forbidden inside Windows path components (in addition to controls).
const FORBIDDEN_PATH_CHARS: &[char] = &['<', '>', '"', '|', '?', '*'];

/// Reservierte Windows-Gerätenamen (case-insensitive). Eine Pfadkomponente, deren
/// Stamm einem dieser Namen entspricht, ist unzulässig — egal mit welcher Endung.
/// Reserved Windows device names (case-insensitive). A path segment whose stem
/// equals one of these is invalid regardless of its extension.
const RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Null-Byte ist in keinem Pfad zulässig.
/// Null byte disallowed in any path.
fn contains_null(s: &str) -> bool {
    s.contains('\0')
}

/// Validierter UNC-Pfad (z. B. \\server\share\folder)
/// Validated UNC path (e.g. \\server\share\folder)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUncPath(pub String);

/// Validierter lokaler Windows-Pfad
/// Validated local Windows path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLocalPath(pub String);

/// Prüft ein einzelnes Pfadsegment auf Steuerzeichen, verbotene Zeichen und
/// reservierte Gerätenamen.
/// Checks a single path segment for control characters, forbidden characters
/// and reserved device names.
fn check_path_segment(segment: &str, full_path: &str) -> Result<(), CoreError> {
    if segment.is_empty() {
        // Doppel-Backslashes innerhalb des Pfads werden nicht akzeptiert, weil
        // sie auf ein leeres Segment hindeuten (Tippfehler oder Injektion).
        // Double backslashes inside the path are not accepted because they
        // imply an empty segment (typo or injection).
        return Err(CoreError::Validation(format!(
            "Path contains an empty segment (consecutive separators): {full_path}"
        )));
    }
    if let Some(c) = segment.chars().find(|c| c.is_control()) {
        return Err(CoreError::Validation(format!(
            "Path segment '{segment}' contains a control character (U+{:04X}): {full_path}",
            c as u32
        )));
    }
    if let Some(bad) = segment.chars().find(|c| FORBIDDEN_PATH_CHARS.contains(c)) {
        return Err(CoreError::Validation(format!(
            "Path segment '{segment}' contains a forbidden character '{bad}': {full_path}"
        )));
    }
    if segment.contains(':') {
        return Err(CoreError::Validation(format!(
            "Path segment '{segment}' must not contain ':' (drive separator): {full_path}"
        )));
    }
    // Reservierter Gerätename — Stamm ohne Endung prüfen.
    // Reserved device name — check the stem without extension.
    let stem = segment.split('.').next().unwrap_or(segment);
    if RESERVED_DEVICE_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
    {
        return Err(CoreError::Validation(format!(
            "Path segment '{segment}' uses the reserved Windows device name '{stem}': {full_path}"
        )));
    }
    Ok(())
}

/// Prüft die Segmente eines Pfads ohne Prefix (`X:\…` oder `\\server\share\…`).
/// Checks the segments of a path without its prefix (`X:\…` or `\\server\share\…`).
fn check_path_segments(rest: &str, full_path: &str) -> Result<(), CoreError> {
    // Ein abschließender Backslash ergibt nach split ein leeres Segment — den
    // tolerieren wir, alles andere wird geprüft.
    // A trailing backslash produces an empty segment after split — tolerate it,
    // check everything else.
    let segments: Vec<&str> = rest.split('\\').collect();
    let last_idx = segments.len().saturating_sub(1);
    for (i, segment) in segments.iter().enumerate() {
        if i == last_idx && segment.is_empty() {
            continue; // trailing backslash
        }
        check_path_segment(segment, full_path)?;
    }
    Ok(())
}

pub fn validate_unc_path(input: &str) -> Result<ValidatedUncPath, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("UNC path must not be empty".into()));
    }
    if contains_null(trimmed) {
        return Err(CoreError::Validation(
            "UNC path must not contain null bytes".into(),
        ));
    }
    if trimmed.len() > MAX_PATH_LEN {
        return Err(CoreError::Validation(format!(
            "UNC path must not exceed {MAX_PATH_LEN} characters"
        )));
    }
    if !trimmed.starts_with(r"\\") {
        return Err(CoreError::Validation(format!(
            "UNC path must start with '\\\\': {trimmed}"
        )));
    }
    // Mindestens \\server\share mit nicht-leeren Komponenten.
    // At least \\server\share with non-empty components.
    let without_prefix = &trimmed[2..];
    let mut parts = without_prefix.splitn(3, '\\');
    let server = parts.next().unwrap_or("");
    let share = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    if server.is_empty() || share.is_empty() {
        return Err(CoreError::Validation(format!(
            "UNC path must contain at least \\\\server\\share: {trimmed}"
        )));
    }
    // Server- und Share-Komponenten gegen die strengeren Regeln aus
    // `validation::net` prüfen — keine doppelte Pflege mehr.
    // Server and share components validated against the stricter rules from
    // `validation::net` — no duplicate maintenance.
    validate_smb_server(server).map_err(|e| {
        CoreError::Validation(format!("UNC server component '{server}' invalid: {e}"))
    })?;
    validate_share_name(share).map_err(|e| {
        CoreError::Validation(format!("UNC share component '{share}' invalid: {e}"))
    })?;
    if !rest.is_empty() {
        check_path_segments(rest, trimmed)?;
    }
    Ok(ValidatedUncPath(trimmed.to_string()))
}

pub fn validate_local_path(input: &str) -> Result<ValidatedLocalPath, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("Local path must not be empty".into()));
    }
    if contains_null(trimmed) {
        return Err(CoreError::Validation(
            "Local path must not contain null bytes".into(),
        ));
    }
    if trimmed.len() > MAX_PATH_LEN {
        return Err(CoreError::Validation(format!(
            "Local path must not exceed {MAX_PATH_LEN} characters"
        )));
    }
    // Absoluter Pfad: Laufwerksbuchstabe gefolgt von `:\` (z. B. C:\).
    // Absolute path: drive letter followed by `:\` (e.g. C:\).
    let is_absolute_drive = trimmed.len() >= 3
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed[1..].starts_with(":\\");
    if !is_absolute_drive {
        return Err(CoreError::Validation(format!(
            "Local path must be an absolute Windows path (e.g. C:\\folder): {trimmed}"
        )));
    }
    // Segmentprüfung erst nach dem `X:\`-Prefix; das `:` im Prefix ist legitim.
    // Segment checks only after the `X:\` prefix; the `:` in the prefix is legitimate.
    let rest = &trimmed[3..];
    if !rest.is_empty() {
        check_path_segments(rest, trimmed)?;
    }
    Ok(ValidatedLocalPath(trimmed.to_string()))
}

/// Validiert einen Benutzer-Pfad und liefert die normalisierte Anzeigeform.
///
/// Akzeptiert:
/// - UNC-Pfade `\\server\share\…`
/// - absolute lokale Pfade `X:\…`
/// - Windows-Long-Path-Form `\\?\X:\…` (lokal)
/// - Windows-Long-Path-UNC-Form `\\?\UNC\server\share\…`
///
/// Das `\\?\`-Präfix wird vor der Segmentprüfung entfernt und durch die
/// kanonische Anzeigeform ersetzt, weil `?` sonst von der Segmentvalidierung
/// als verbotenes Zeichen abgelehnt würde. Downstream-Code, der das Präfix
/// für Win32-APIs benötigt, fügt es über [`to_windows_api_path`] wieder
/// hinzu — die Funktion ist idempotent.
///
/// Validates a user-supplied path and returns the canonical display form.
///
/// Accepts:
/// - UNC paths `\\server\share\…`
/// - absolute local Windows paths `X:\…`
/// - Windows long-path form `\\?\X:\…` (local)
/// - Windows long-path UNC form `\\?\UNC\server\share\…`
///
/// The `\\?\` prefix is stripped before segment checking and replaced with
/// the canonical display form, because `?` would otherwise be rejected as
/// a forbidden character. Downstream code that needs the prefix for Win32
/// APIs re-adds it via [`to_windows_api_path`] — that function is idempotent.
pub fn validate_path(input: &str) -> Result<NormalizedPath, CoreError> {
    let trimmed = input.trim();
    // \\?\UNC\server\share\… → kanonische UNC-Form \\server\share\…
    // \\?\UNC\server\share\… → canonical UNC form \\server\share\…
    if let Some(rest) = trimmed.strip_prefix(r"\\?\UNC\") {
        let canonical = format!(r"\\{rest}");
        return validate_unc_path(&canonical).map(Into::into);
    }
    // \\?\X:\… → lokale Anzeigeform X:\…
    // \\?\X:\… → local display form X:\…
    if let Some(rest) = trimmed.strip_prefix(r"\\?\") {
        return validate_local_path(rest).map(Into::into);
    }
    if trimmed.starts_with(r"\\") {
        validate_unc_path(trimmed).map(Into::into)
    } else {
        validate_local_path(trimmed).map(Into::into)
    }
}

impl From<ValidatedLocalPath> for NormalizedPath {
    fn from(v: ValidatedLocalPath) -> Self {
        NormalizedPath(v.0)
    }
}

impl From<ValidatedUncPath> for NormalizedPath {
    fn from(v: ValidatedUncPath) -> Self {
        NormalizedPath(v.0)
    }
}

/// Windows-API-tauglicher Pfad mit Long-Path-Präfix.
///
/// Win32-ANSI-/Wide-APIs wie `GetFileAttributesW` und
/// `GetNamedSecurityInfoW` sind ohne den Präfix `\\?\` auf `MAX_PATH`
/// (260 Zeichen) limitiert. Mit dem Präfix akzeptiert Windows bis zu
/// 32.767 Zeichen — passend zu unserer Validierungs-Obergrenze.
///
/// Long-path-prefixed Windows API path. Win32 ANSI/Wide APIs such as
/// `GetFileAttributesW` and `GetNamedSecurityInfoW` are limited to
/// `MAX_PATH` (260 characters) without the `\\?\` prefix. With the
/// prefix Windows accepts up to 32,767 characters — matching our
/// validation upper bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsApiPath(pub String);

impl WindowsApiPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&ValidatedLocalPath> for WindowsApiPath {
    fn from(v: &ValidatedLocalPath) -> Self {
        WindowsApiPath(to_windows_api_path(&v.0))
    }
}

impl From<&ValidatedUncPath> for WindowsApiPath {
    fn from(v: &ValidatedUncPath) -> Self {
        WindowsApiPath(to_windows_api_path(&v.0))
    }
}

/// Zerlegt einen UNC-Pfad in `(server, share)`. Lokale Pfade (`C:\…`),
/// `\\?\C:\…`-Long-Paths und Pfade mit nur einem führenden Slash
/// liefern `None` — damit kein Share-Lookup mit einem Laufwerks­buchstaben
/// als Servername gestartet wird.
///
/// Akzeptierte Eingabeformen:
/// - `\\server\share\…` (klassisches UNC)
/// - `//server/share/…` (POSIX-Variante)
/// - `\\?\UNC\server\share\…` (Long-Path-UNC)
///
/// Schließt **Review-Befund 1** (CLI hielt `C:\Windows\SYSVOL` für UNC) und
/// **Review-Befund 4** (Long-Path-UNC wurde als Server=`?`, Share=`UNC`
/// zerlegt). Die GUI hatte eine ähnliche Lokal-Pfad-Prüfung schon; CLI nicht.
/// Diese Funktion ist die *eine* Quelle der Wahrheit für CLI **und** GUI.
///
/// Splits a UNC path into `(server, share)`. Local paths (`C:\…`),
/// `\\?\C:\…` long paths and single-prefix paths return `None` — so no
/// share lookup is started with a drive letter as the server name.
///
/// Accepted input forms:
/// - `\\server\share\…` (classic UNC)
/// - `//server/share/…` (POSIX variant)
/// - `\\?\UNC\server\share\…` (long-path UNC)
///
/// Closes **review finding 1** (CLI mistook `C:\Windows\SYSVOL` for UNC)
/// and **finding 4** (long-path UNC was split as Server=`?`, Share=`UNC`).
/// The GUI had a similar local-path guard already; the CLI did not. This
/// function is the *single* source of truth for both CLI and GUI.
pub fn parse_unc_components(path: &str) -> Option<(String, String)> {
    // Long-Path-UNC erst normalisieren — sonst sieht der Split `?` als
    // Server. Lokale Long-Path-Form (`\\?\C:\…`) bleibt ausgeschlossen,
    // weil sie nach dem Strip mit einem Laufwerks­buchstaben anfängt
    // statt mit `\\`.
    // Normalize long-path UNC first — otherwise the split would treat `?`
    // as the server. Local long-path form (`\\?\C:\…`) is excluded by the
    // strip because it starts with a drive letter, not `\\`.
    let normalized = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if path.starts_with(r"\\?\") || path.starts_with("//?/") {
        // Lokaler Long-Path — niemals UNC.
        // Local long-path — never UNC.
        return None;
    } else {
        path.to_string()
    };

    let bytes = normalized.as_bytes();
    let has_unc_prefix =
        matches!(bytes.first(), Some(b'\\' | b'/')) && matches!(bytes.get(1), Some(b'\\' | b'/'));
    if !has_unc_prefix {
        return None;
    }
    let stripped = normalized.trim_start_matches(['\\', '/']);
    let mut parts = stripped.splitn(3, ['\\', '/']);
    let server = parts.next().filter(|s| !s.is_empty())?.to_owned();
    let share = parts.next().filter(|s| !s.is_empty())?.to_owned();
    Some((server, share))
}

/// Liefert den effektiven SMB-Zielserver für lokale-Gruppen- und
/// Share-DACL-Abfragen. Ein explizit gesetzter `smb_server` hat
/// Vorrang vor dem aus dem Pfad abgeleiteten UNC-Server — sonst werden
/// lokale Gruppen vom Pfad-Server gelesen, während die Share-DACL vom
/// Override-Server kommt (Review-Befund 2: Token-Mismatch).
///
/// Returns the effective SMB target server for local-group and share-DACL
/// lookups. An explicit `smb_server` takes precedence over the server
/// derived from the path's UNC components — otherwise local groups would
/// be read from the path server while the share DACL comes from the
/// override server (review finding 2: token mismatch).
pub fn effective_smb_target(path: &str, explicit_smb_server: Option<&str>) -> Option<String> {
    if let Some(server) = explicit_smb_server.filter(|s| !s.is_empty()) {
        return Some(server.to_owned());
    }
    parse_unc_components(path).map(|(server, _share)| server)
}

/// Typisierter SMB-Audit-Kontext: enthaelt **beide** Bausteine
/// (`server`, `share`), die nötig sind, um eine Share-DACL zu lesen
/// oder einen Share-Overlay zu bauen. Ein UNC-Pfad wie
/// `\\fs01\data\foo\bar` liefert `("fs01", "data")`; ein lokaler Pfad
/// ohne explizite SMB-Flags liefert `None`.
///
/// Eingefuehrt fuer Review-Runde 10 Finding 1: vorher hat die CLI an
/// drei Stellen einzeln Server **oder** Share aus Pfad und Flags
/// abgeleitet, das fuehrte dazu, dass `path_trustees` bei einem reinen
/// UNC-Aufruf ohne `--smb-server`/`--share-name` die Share-Schicht
/// stillschweigend wegliess, waehrend `share_status` sie korrekt
/// auswertete. Mit diesem Typ haben CLI und GUI genau **eine** Quelle
/// fuer die Ableitung.
///
/// Typed SMB audit context: holds **both** building blocks (`server`,
/// `share`) needed to read a share DACL or build a share overlay. A
/// UNC path like `\\fs01\data\foo\bar` yields `("fs01", "data")`; a
/// local path without explicit SMB flags yields `None`.
///
/// Introduced for review round 10 finding 1: the CLI used to derive
/// server **or** share from path and flags at three separate sites,
/// which caused `path_trustees` to silently drop the share layer on a
/// plain UNC call without `--smb-server`/`--share-name` while
/// `share_status` evaluated it correctly. With this type CLI and GUI
/// have exactly **one** source for the derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAuditContext {
    pub server: String,
    pub share: String,
}

impl SmbAuditContext {
    /// Leitet den effektiven SMB-Kontext aus Pfad und optionalen
    /// expliziten Flags ab. Prioritaet pro Feld: **explizit > UNC**.
    ///
    /// Wichtige Eigenschaft (vgl. Review-Runde 10 Finding 1): liefert
    /// **immer beide** Felder oder `None`. Wenn explizit nur ein
    /// Server angegeben ist (und der Pfad nicht UNC), reicht das
    /// nicht — der Share-Name fehlt fuer den DACL-Lookup. Ergebnis:
    /// `None`, der Aufrufer sieht klar „kein SMB-Kontext bestimmbar".
    ///
    /// Derives the effective SMB context from path and optional
    /// explicit flags. Per-field priority: **explicit > UNC**.
    ///
    /// Important property (review round 10 finding 1): always
    /// returns **both** fields or `None`. If only a server is given
    /// explicitly (and the path is not UNC), the share name is
    /// missing and a DACL lookup is impossible — result: `None`, so
    /// the caller sees clearly "no SMB context derivable".
    pub fn resolve(
        path: &str,
        explicit_smb_server: Option<&str>,
        explicit_share_name: Option<&str>,
    ) -> Option<Self> {
        let unc = parse_unc_components(path);
        let server = explicit_smb_server
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .or_else(|| unc.as_ref().map(|(s, _)| s.clone()))?;
        let share = explicit_share_name
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .or_else(|| unc.map(|(_, n)| n))?;
        Some(SmbAuditContext { server, share })
    }
}

/// Entfernt das Long-Path-Präfix (`\\?\` bzw. `\\?\UNC\`) und liefert die
/// menschenlesbare Form als Eigentümer-String zurück. Inverse zu
/// [`to_windows_api_path`]; wird genutzt, um `FileSystemObject.path`
/// präfix-frei zu speichern, auch wenn der Walker intern mit präfixierten
/// Pfaden arbeitet.
///
/// Strips the long-path prefix (`\\?\` or `\\?\UNC\`) and returns the
/// human-readable form as an owned string. Inverse of
/// [`to_windows_api_path`]; used to keep `FileSystemObject.path`
/// prefix-free even when the walker passes prefixed paths internally.
pub fn strip_long_path_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        // "\\?\UNC\server\share\..." → "\\server\share\..."
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        // "\\?\C:\..." → "C:\..."
        return rest.to_string();
    }
    path.to_string()
}

/// Wandelt einen Pfad in die Long-Path-Form um, die Win32-Wide-APIs
/// für Pfade > `MAX_PATH` benötigen:
///
/// - Bereits präfixiert (`\\?\…`) → unverändert
/// - UNC `\\server\share\…` → `\\?\UNC\server\share\…`
/// - Lokal `C:\…` → `\\?\C:\…`
/// - Sonst (relativ o. ä.) → unverändert (keine sinnvolle Konvertierung;
///   Validierung sollte solche Pfade ohnehin abgelehnt haben)
///
/// Converts a path into the long-path form required by Win32 wide APIs
/// for paths exceeding `MAX_PATH`:
///
/// - Already prefixed (`\\?\…`) → returned as-is
/// - UNC `\\server\share\…` → `\\?\UNC\server\share\…`
/// - Local `C:\…` → `\\?\C:\…`
/// - Other (e.g. relative) → returned as-is (no meaningful conversion;
///   validation should have rejected these already)
pub fn to_windows_api_path(path: &str) -> String {
    if path.starts_with(r"\\?\") {
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix(r"\\") {
        return format!(r"\\?\UNC\{rest}");
    }
    if path.len() >= 3 && path.as_bytes()[0].is_ascii_alphabetic() && path[1..].starts_with(":\\") {
        return format!(r"\\?\{path}");
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_unc_path_accepted() {
        let result = validate_unc_path(r"\\server\share\folder");
        assert!(result.is_ok());
    }

    #[test]
    fn unc_path_without_share_rejected() {
        let result = validate_unc_path(r"\\server");
        assert!(result.is_err());
    }

    #[test]
    fn unc_path_server_only_with_trailing_slash_rejected() {
        let result = validate_unc_path(r"\\server\");
        assert!(result.is_err());
    }

    #[test]
    fn empty_unc_path_rejected() {
        let result = validate_unc_path("");
        assert!(result.is_err());
    }

    #[test]
    fn local_path_without_prefix_rejected_as_unc() {
        let result = validate_unc_path(r"C:\folder");
        assert!(result.is_err());
    }

    #[test]
    fn valid_local_path_accepted() {
        let result = validate_local_path(r"C:\Users\test");
        assert!(result.is_ok());
    }

    #[test]
    fn empty_local_path_rejected() {
        let result = validate_local_path("");
        assert!(result.is_err());
    }

    #[test]
    fn relative_local_path_rejected() {
        let result = validate_local_path(r"relative\path");
        assert!(result.is_err());
    }

    #[test]
    fn unc_path_dispatched_correctly_by_validate_path() {
        let result = validate_path(r"\\dc\sysvol");
        assert!(result.is_ok());
    }

    #[test]
    fn local_path_dispatched_correctly_by_validate_path() {
        let result = validate_path(r"D:\Data\Reports");
        assert!(result.is_ok());
    }

    #[test]
    fn relative_path_rejected_by_validate_path() {
        let result = validate_path(r"data\folder");
        assert!(result.is_err());
    }

    // --- F6: schärfere Validierung / tighter validation ---

    #[test]
    fn local_path_with_forbidden_char_rejected() {
        for bad in &[
            r"C:\bad<name",
            r"C:\bad>name",
            r#"C:\bad"name"#,
            r"C:\bad|name",
            r"C:\bad?name",
            r"C:\bad*name",
        ] {
            assert!(
                validate_local_path(bad).is_err(),
                "must reject forbidden chars: {bad}"
            );
        }
    }

    #[test]
    fn local_path_with_extra_colon_rejected() {
        assert!(validate_local_path(r"C:\folder:stream").is_err());
    }

    #[test]
    fn local_path_with_reserved_device_name_rejected() {
        for bad in &[
            r"C:\CON",
            r"C:\con",
            r"C:\sub\NUL",
            r"C:\COM1",
            r"C:\LPT9",
            r"C:\PRN.txt",
        ] {
            assert!(
                validate_local_path(bad).is_err(),
                "must reject reserved device name: {bad}"
            );
        }
    }

    #[test]
    fn local_path_with_control_char_rejected() {
        assert!(validate_local_path("C:\\bad\x07name").is_err());
    }

    #[test]
    fn local_path_with_consecutive_separators_rejected() {
        assert!(validate_local_path(r"C:\foo\\bar").is_err());
    }

    #[test]
    fn local_path_with_trailing_backslash_accepted() {
        assert!(validate_local_path(r"C:\Users\").is_ok());
    }

    #[test]
    fn unc_path_with_invalid_share_name_rejected() {
        // Share-Name darf laut validate_share_name kein '*' enthalten.
        // Share name may not contain '*' per validate_share_name.
        assert!(validate_unc_path(r"\\dc\bad*share\sub").is_err());
    }

    #[test]
    fn unc_path_with_invalid_server_rejected() {
        assert!(validate_unc_path(r"\\bad server\share").is_err());
    }

    #[test]
    fn unc_path_with_forbidden_char_in_tail_rejected() {
        assert!(validate_unc_path(r"\\dc\share\bad<name").is_err());
    }

    #[test]
    fn overlong_local_path_rejected() {
        let long = format!("C:\\{}", "a".repeat(MAX_PATH_LEN));
        assert!(validate_local_path(&long).is_err());
    }

    // --- Finding 5: Long-Path-Normalisierung / long path normalization ---

    #[test]
    fn to_windows_api_path_prefixes_local_path() {
        assert_eq!(to_windows_api_path(r"C:\Windows"), r"\\?\C:\Windows");
        assert_eq!(
            to_windows_api_path(r"D:\Data\file.txt"),
            r"\\?\D:\Data\file.txt"
        );
    }

    #[test]
    fn to_windows_api_path_prefixes_unc_path() {
        assert_eq!(
            to_windows_api_path(r"\\server\share\folder"),
            r"\\?\UNC\server\share\folder"
        );
        assert_eq!(
            to_windows_api_path(r"\\192.168.11.100\Shared"),
            r"\\?\UNC\192.168.11.100\Shared"
        );
    }

    #[test]
    fn to_windows_api_path_keeps_already_prefixed_paths() {
        // Bereits präfixierte Pfade dürfen nicht doppelt präfixiert werden.
        // Already prefixed paths must not be prefixed twice.
        assert_eq!(
            to_windows_api_path(r"\\?\C:\very\long\path"),
            r"\\?\C:\very\long\path"
        );
        assert_eq!(
            to_windows_api_path(r"\\?\UNC\server\share\sub"),
            r"\\?\UNC\server\share\sub"
        );
    }

    #[test]
    fn to_windows_api_path_handles_long_local_path() {
        // Konstruiert einen klar über MAX_PATH (260) liegenden Pfad und prüft,
        // dass die Präfix-Form korrekt entsteht.
        let long = format!("C:\\{}", "a".repeat(400));
        let api = to_windows_api_path(&long);
        assert!(api.starts_with(r"\\?\C:\"));
        assert!(api.len() > 260);
    }

    #[test]
    fn windows_api_path_from_validated_local_adds_prefix() {
        let v = validate_local_path(r"C:\Users\test").unwrap();
        let api: WindowsApiPath = (&v).into();
        assert_eq!(api.as_str(), r"\\?\C:\Users\test");
    }

    #[test]
    fn windows_api_path_from_validated_unc_adds_unc_prefix() {
        let v = validate_unc_path(r"\\dc\share\folder").unwrap();
        let api: WindowsApiPath = (&v).into();
        assert_eq!(api.as_str(), r"\\?\UNC\dc\share\folder");
    }

    #[test]
    fn to_windows_api_path_leaves_unrecognized_input_untouched() {
        // Ein relativer oder unbekannter Pfad darf nicht zerstört werden —
        // Validierung sollte ihn ohnehin schon abgelehnt haben.
        assert_eq!(to_windows_api_path("relative/path"), "relative/path");
        assert_eq!(to_windows_api_path(""), "");
    }

    #[test]
    fn strip_long_path_prefix_local() {
        assert_eq!(strip_long_path_prefix(r"\\?\C:\Windows"), r"C:\Windows");
        assert_eq!(strip_long_path_prefix(r"\\?\D:\Data"), r"D:\Data");
    }

    #[test]
    fn strip_long_path_prefix_unc() {
        assert_eq!(
            strip_long_path_prefix(r"\\?\UNC\server\share\folder"),
            r"\\server\share\folder"
        );
    }

    #[test]
    fn strip_long_path_prefix_untouched_when_no_prefix() {
        assert_eq!(strip_long_path_prefix(r"C:\Windows"), r"C:\Windows");
        assert_eq!(
            strip_long_path_prefix(r"\\server\share\sub"),
            r"\\server\share\sub"
        );
        assert_eq!(strip_long_path_prefix(""), "");
    }

    #[test]
    fn strip_and_to_api_path_roundtrip_local() {
        // Roundtrip: lokaler Pfad → API-Form → wieder Strip → Original.
        let original = r"C:\Users\test\file.txt";
        let api = to_windows_api_path(original);
        assert_eq!(strip_long_path_prefix(&api), original);
    }

    #[test]
    fn strip_and_to_api_path_roundtrip_unc() {
        let original = r"\\dc\share\sub\file.txt";
        let api = to_windows_api_path(original);
        assert_eq!(strip_long_path_prefix(&api), original);
    }

    // --- Finding 2: Long-Path-Eingaben an validate_path / long-path inputs at validate_path ---

    #[test]
    fn validate_path_accepts_long_local_prefix() {
        let np = validate_path(r"\\?\C:\Windows\System32").expect("must accept long-path local");
        // Anzeigeform ohne Präfix — to_windows_api_path setzt es bei Bedarf wieder.
        // Display form without prefix — to_windows_api_path re-adds it when needed.
        assert_eq!(np.0, r"C:\Windows\System32");
    }

    #[test]
    fn validate_path_accepts_long_unc_prefix() {
        let np = validate_path(r"\\?\UNC\dc\share\folder").expect("must accept long-path UNC");
        assert_eq!(np.0, r"\\dc\share\folder");
    }

    #[test]
    fn validate_path_accepts_long_unc_ip_prefix() {
        let np = validate_path(r"\\?\UNC\192.168.11.100\Shared\sub")
            .expect("must accept long-path UNC with IP");
        assert_eq!(np.0, r"\\192.168.11.100\Shared\sub");
    }

    #[test]
    fn validate_path_accepts_overlong_local_with_prefix() {
        // Ein Pfad > MAX_PATH (260) muss in Long-Path-Form akzeptiert werden,
        // solange er unter MAX_PATH_LEN (32767) bleibt.
        // A path > MAX_PATH (260) must be accepted in long-path form as long as
        // it stays under MAX_PATH_LEN (32767).
        let long = format!(r"\\?\C:\{}", "a".repeat(400));
        let np = validate_path(&long).expect("must accept overlong long-path local");
        assert!(np.0.starts_with(r"C:\"));
        assert!(np.0.len() > 260);
    }

    #[test]
    fn validate_path_long_local_roundtrips_via_to_windows_api_path() {
        let np = validate_path(r"\\?\C:\Users\test\file.txt").unwrap();
        let api = to_windows_api_path(&np.0);
        assert_eq!(api, r"\\?\C:\Users\test\file.txt");
    }

    #[test]
    fn validate_path_long_unc_roundtrips_via_to_windows_api_path() {
        let np = validate_path(r"\\?\UNC\dc\share\folder").unwrap();
        let api = to_windows_api_path(&np.0);
        assert_eq!(api, r"\\?\UNC\dc\share\folder");
    }

    #[test]
    fn validate_path_rejects_long_prefix_without_drive() {
        // `\\?\foo` ist nach Strip ein relativer Pfad und damit ungültig.
        // `\\?\foo` becomes a relative path after stripping and is invalid.
        assert!(validate_path(r"\\?\foo").is_err());
    }

    #[test]
    fn validate_path_rejects_long_unc_prefix_without_share() {
        // `\\?\UNC\server` hat keine Share-Komponente.
        // `\\?\UNC\server` lacks a share component.
        assert!(validate_path(r"\\?\UNC\server").is_err());
    }

    #[test]
    fn validate_path_rejects_bare_long_prefix() {
        // `\\?\` ohne Inhalt darf nicht akzeptiert werden.
        // `\\?\` with no content must not be accepted.
        assert!(validate_path(r"\\?\").is_err());
    }

    #[test]
    fn validate_path_rejects_bare_long_unc_prefix() {
        // `\\?\UNC\` ohne Server/Share darf nicht akzeptiert werden.
        // `\\?\UNC\` without server/share must not be accepted.
        assert!(validate_path(r"\\?\UNC\").is_err());
    }

    #[test]
    fn validate_path_rejects_long_path_with_forbidden_char_in_segment() {
        // Das Präfix `\\?\` wird gestrippt; ein `?` *im Segment* danach bleibt
        // verboten.
        // The `\\?\` prefix is stripped; a `?` *inside a segment* after that
        // is still forbidden.
        assert!(validate_path(r"\\?\C:\bad?name").is_err());
    }

    // --- Review-Findings 1, 2, 4 — UNC-Zerlegung + SMB-Zielserver ---
    // --- Review findings 1, 2, 4 — UNC parsing + SMB target server ---

    #[test]
    fn parse_unc_components_rejects_local_paths() {
        // Finding 1: lokale Pfade dürfen nicht als UNC durchgehen, sonst
        // landet `C:\Windows` als NetShareGetInfo("C:", "Windows") im
        // share_scanner.
        // Finding 1: local paths must not pass as UNC, otherwise
        // `C:\Windows` ends up as NetShareGetInfo("C:", "Windows") in the
        // share scanner.
        assert_eq!(parse_unc_components(r"C:\Windows"), None);
        assert_eq!(parse_unc_components(r"C:\Windows\SYSVOL"), None);
        assert_eq!(parse_unc_components(r"D:\Daten\Abteilung"), None);
        assert_eq!(parse_unc_components(r"\singlebackslash\foo"), None);
        assert_eq!(parse_unc_components(""), None);
    }

    #[test]
    fn parse_unc_components_accepts_classic_unc() {
        assert_eq!(
            parse_unc_components(r"\\server\share\sub"),
            Some(("server".to_string(), "share".to_string()))
        );
        assert_eq!(
            parse_unc_components("//server/share"),
            Some(("server".to_string(), "share".to_string()))
        );
    }

    #[test]
    fn parse_unc_components_handles_long_path_unc() {
        // Finding 4: \\?\UNC\server\share\folder darf nicht in Server=`?`,
        // Share=`UNC` zerfallen — vorher genau dieser Bug.
        // Finding 4: \\?\UNC\server\share\folder must not decompose into
        // Server=`?`, Share=`UNC` — that was exactly the bug.
        assert_eq!(
            parse_unc_components(r"\\?\UNC\server\share\folder"),
            Some(("server".to_string(), "share".to_string()))
        );
        assert_eq!(
            parse_unc_components(r"\\?\UNC\192.168.11.100\Shared\sub"),
            Some(("192.168.11.100".to_string(), "Shared".to_string()))
        );
    }

    #[test]
    fn parse_unc_components_rejects_local_long_path() {
        // \\?\C:\… ist eine lokale Long-Path-Form, kein UNC.
        // \\?\C:\… is a local long-path form, not a UNC.
        assert_eq!(parse_unc_components(r"\\?\C:\Windows\System32"), None);
        assert_eq!(parse_unc_components(r"\\?\D:\Data"), None);
    }

    #[test]
    fn parse_unc_components_rejects_incomplete_unc() {
        // \\server (ohne Share) ist kein vollständiger UNC.
        // \\server (without a share) is not a complete UNC.
        assert_eq!(parse_unc_components(r"\\server"), None);
        assert_eq!(parse_unc_components(r"\\server\"), None);
    }

    #[test]
    fn effective_smb_target_prefers_explicit_server_for_local_path() {
        // Finding 2: lokaler Pfad mit explizit gesetztem SMB-Server →
        // lokale Gruppen müssen vom Override-Server gelesen werden, nicht
        // vom lokalen Rechner.
        // Finding 2: local path with explicit SMB server → local groups
        // must come from the override server, not from the local machine.
        assert_eq!(
            effective_smb_target(r"C:\Daten", Some("fileserver01")),
            Some("fileserver01".to_string())
        );
    }

    #[test]
    fn effective_smb_target_prefers_explicit_server_for_unc() {
        // Finding 2: UNC-Pfad PLUS expliziter Override → Override gewinnt,
        // damit der User absichtlich gegen einen anderen Server testen kann.
        // Finding 2: UNC path PLUS explicit override → override wins, so
        // the user can deliberately test against a different server.
        assert_eq!(
            effective_smb_target(r"\\fs01\Daten", Some("fs02")),
            Some("fs02".to_string())
        );
    }

    #[test]
    fn effective_smb_target_falls_back_to_unc_server() {
        // Ohne expliziten Override aus dem UNC-Pfad ableiten.
        // Without an explicit override, derive from the UNC path.
        assert_eq!(
            effective_smb_target(r"\\fs01\Daten\sub", None),
            Some("fs01".to_string())
        );
        assert_eq!(
            effective_smb_target(r"\\?\UNC\fs01\Daten\sub", None),
            Some("fs01".to_string())
        );
    }

    #[test]
    fn effective_smb_target_returns_none_for_local_path_without_override() {
        // Lokaler Pfad ohne Override → kein SMB-Ziel → kein Share-Lookup.
        // Genau das verhindert den ursprünglichen `C:` als Server-Bug.
        // Local path without override → no SMB target → no share lookup.
        // This is exactly what prevents the original `C:` as server bug.
        assert_eq!(effective_smb_target(r"C:\Windows\SYSVOL", None), None);
        assert_eq!(effective_smb_target(r"C:\Windows\SYSVOL", Some("")), None);
    }

    // --- SmbAuditContext: Review-Runde 10 Finding 1 ---

    /// Reine UNC ohne explizite Flags → beide Komponenten aus dem Pfad.
    /// Das war der Hauptfall, der vor der Round-10-Korrektur nicht in
    /// `path_trustees` einfloss.
    /// Bare UNC without explicit flags → both fields from the path.
    /// This was the main case that didn't reach `path_trustees`
    /// before the round-10 fix.
    #[test]
    fn smb_audit_context_from_unc_alone() {
        let ctx = SmbAuditContext::resolve(r"\\fs01\data\folder\sub", None, None)
            .expect("UNC alone must yield both server and share");
        assert_eq!(ctx.server, "fs01");
        assert_eq!(ctx.share, "data");
    }

    /// Explizite Flags ueberschreiben die UNC-Komponenten — wichtig
    /// fuer Audit-Szenarien, in denen die Share-DACL auf einem anderen
    /// Server liegt als der Pfad selbst.
    /// Explicit flags override the UNC components — important for
    /// audit scenarios where the share DACL lives on a server
    /// different from the path itself.
    #[test]
    fn smb_audit_context_explicit_flags_override_unc() {
        let ctx = SmbAuditContext::resolve(
            r"\\fs01\data\folder",
            Some("dr01.corp.local"),
            Some("backup"),
        )
        .expect("explicit flags must yield a context");
        assert_eq!(ctx.server, "dr01.corp.local");
        assert_eq!(ctx.share, "backup");
    }

    /// Lokaler Pfad ohne Flags → kein SMB-Kontext (kein stillschweigendes
    /// `("C", "Windows")` aus `C:\Windows\…`).
    /// Local path without flags → no SMB context (no silent
    /// `("C", "Windows")` derived from `C:\Windows\…`).
    #[test]
    fn smb_audit_context_local_path_yields_none() {
        assert_eq!(
            SmbAuditContext::resolve(r"C:\Windows\SYSVOL", None, None),
            None
        );
    }

    /// Nur Server explizit, Pfad lokal, kein Share → `None`. Vorher haetten
    /// einzelne Helper an dieser Stelle einen Halb-Kontext gebaut, mit
    /// dem dann `get_share_dacl` mit leerem Share-Namen aufgerufen worden
    /// waere.
    /// Server only explicit, path local, no share → `None`. Previously
    /// individual helpers would have built a half-context here, leading
    /// to `get_share_dacl` calls with an empty share name.
    #[test]
    fn smb_audit_context_server_without_share_yields_none() {
        assert_eq!(
            SmbAuditContext::resolve(r"C:\data", Some("fs01"), None),
            None
        );
    }

    /// Mischung: Server explizit, Share aus UNC.
    /// Mix: server explicit, share from UNC.
    #[test]
    fn smb_audit_context_mixed_explicit_server_unc_share() {
        let ctx = SmbAuditContext::resolve(r"\\fs01\data\x", Some("fs02"), None)
            .expect("mix must yield a context");
        assert_eq!(ctx.server, "fs02");
        assert_eq!(ctx.share, "data");
    }

    /// Leere String-Flags zaehlen als „nicht gesetzt" — Defense gegen
    /// CLI-Frontends, die `Option<String>` immer als `Some("")`
    /// uebergeben statt `None`.
    /// Empty string flags count as "not set" — defence against CLI
    /// frontends that always hand over `Some("")` instead of `None`.
    #[test]
    fn smb_audit_context_empty_explicit_flags_are_treated_as_none() {
        let ctx = SmbAuditContext::resolve(r"\\fs01\data\x", Some(""), Some(""))
            .expect("empty explicit flags must fall back to UNC");
        assert_eq!(ctx.server, "fs01");
        assert_eq!(ctx.share, "data");
    }

    #[test]
    fn to_windows_api_path_is_idempotent() {
        // Walker baut FSO-Pfade auf Basis von `entry.path()`, welches das
        // Long-Path-Präfix vom Parent vererbt. Eine erneute Anwendung von
        // to_windows_api_path darf den Pfad nicht doppelt präfixieren.
        let once = to_windows_api_path(r"C:\Windows");
        let twice = to_windows_api_path(&once);
        assert_eq!(once, twice);

        let once_unc = to_windows_api_path(r"\\dc\share\folder");
        let twice_unc = to_windows_api_path(&once_unc);
        assert_eq!(once_unc, twice_unc);
    }
}
