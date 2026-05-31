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

/// Validates a user-supplied path as either a UNC path (\\server\share\...) or
/// an absolute local Windows path (C:\...). Returns the normalised path on success.
pub fn validate_path(input: &str) -> Result<NormalizedPath, CoreError> {
    let trimmed = input.trim();
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
