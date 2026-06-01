use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Typisierte SID — verhindert Verwechslung mit beliebigen Strings
/// Typed SID — prevents confusion with arbitrary strings
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sid(pub String);

/// Normalisierter, validierter Pfad
/// Normalized, validated path
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedPath(pub String);

/// Windows Access Mask (roher u32-Wert)
/// Windows Access Mask (raw u32 value)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMask(pub u32);

/// Art der Identität
/// Kind of identity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityKind {
    User,
    Group,
    Computer,
    WellKnown,
    Orphaned,
    Unknown,
}

/// Repräsentiert einen AD-Benutzer, eine Gruppe oder einen Computer
/// Represents an AD user, group, or computer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub sid: Sid,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub kind: IdentityKind,
    pub disabled: bool,
    /// userPrincipalName aus AD (z. B. `max.mustermann@testdomain.local`).
    /// Wird für Windows-NetAPI-Aufrufe wie `NetUserGetLocalGroups` bevorzugt,
    /// da das `DOMAIN\sAMAccountName`-Format zwingend den NetBIOS-Namen
    /// erwartet, den wir aus dem DN nicht zuverlässig ableiten können.
    /// userPrincipalName from AD (e.g. `max.mustermann@testdomain.local`).
    /// Preferred for Windows NetAPI calls like `NetUserGetLocalGroups`,
    /// since the `DOMAIN\sAMAccountName` form strictly requires the NetBIOS
    /// name which we cannot reliably derive from the DN.
    #[serde(default)]
    pub user_principal_name: Option<String>,
}

/// Zugriffskontext für die Berechtigungsberechnung.
/// Access context for permission evaluation.
///
/// Windows fügt dem Access-Token je nach Logon-Typ unterschiedliche
/// Well-Known-SIDs hinzu. Für eine korrekte AccessCheck-Nachbildung muss
/// die Engine wissen, ob sie einen lokalen oder einen remote-SMB-Zugriff
/// simuliert: ACEs auf `NETWORK` (S-1-5-2) wirken nur bei SMB; ACEs auf
/// `INTERACTIVE` (S-1-5-4) und `LOCAL` (S-1-2-0) wirken nur lokal.
///
/// Windows adds different well-known SIDs to the access token depending
/// on logon type. For a faithful AccessCheck reproduction the engine
/// needs to know whether to simulate a local or remote (SMB) access:
/// ACEs targeting `NETWORK` (S-1-5-2) only apply over SMB; ACEs
/// targeting `INTERACTIVE` (S-1-5-4) and `LOCAL` (S-1-2-0) only apply
/// to local logons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccessContext {
    /// Lokal interaktive Auswertung — `INTERACTIVE` und `LOCAL` werden
    /// implizit in den Token aufgenommen.
    /// Local interactive evaluation — `INTERACTIVE` and `LOCAL` are added
    /// to the token implicitly.
    LocalInteractive,
    /// Remote-SMB-Zugriff — `NETWORK` wird implizit in den Token aufgenommen.
    /// Remote SMB access — `NETWORK` is added to the token implicitly.
    RemoteSmb,
    /// Kein expliziter Kontext gesetzt — nur die universellen Well-Knowns
    /// (`Everyone`, `Authenticated Users`) wirken. Default für
    /// Rückwärtskompatibilität.
    /// No explicit context — only the universal well-knowns (`Everyone`,
    /// `Authenticated Users`) apply. Default for backwards compatibility.
    #[default]
    Unspecified,
}

impl AccessContext {
    /// Leitet den Kontext aus der Pfadform ab. UNC-Pfade — auch in der
    /// Long-Path-Form `\\?\UNC\server\share\…` — gelten als `RemoteSmb`;
    /// lokale Pfade (inkl. `\\?\C:\…`) gelten als `LocalInteractive`.
    /// Derives the context from the path shape. UNC paths — including the
    /// long-path form `\\?\UNC\server\share\…` — count as `RemoteSmb`;
    /// local paths (incl. `\\?\C:\…`) count as `LocalInteractive`.
    pub fn for_path(path: &str) -> Self {
        if let Some(rest) = path.strip_prefix(r"\\?\") {
            if rest.starts_with("UNC\\") || rest.starts_with("UNC/") {
                return Self::RemoteSmb;
            }
            return Self::LocalInteractive;
        }
        if path.starts_with(r"\\") {
            return Self::RemoteSmb;
        }
        Self::LocalInteractive
    }
}

/// Mitgliedschaft einer Identität in einer Gruppe
/// Membership of an identity in a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub member_sid: Sid,
    pub group_sid: Sid,
    /// true = direkt, false = über verschachtelte Gruppe / nested group
    pub direct: bool,
    /// Lesbarer Gruppenname, sofern der Resolver einen liefern konnte
    /// (z. B. `Domain Admins` aus LDAP/NetUserGetGroups oder
    /// `BUILTIN\Administrators` aus LookupAccountSidW). `None` bedeutet
    /// nicht „kein Name in der Welt", sondern „dieser Resolver hat keinen
    /// nachgereicht" — die Engine fällt dann auf die SID-Anzeige zurück.
    /// `#[serde(default)]` hält ältere Cache-Einträge ohne dieses Feld
    /// kompatibel.
    /// Human-readable group name when the resolver was able to provide
    /// one (e.g. `Domain Admins` from LDAP/NetUserGetGroups or
    /// `BUILTIN\Administrators` from LookupAccountSidW). `None` does not
    /// mean "no name exists" — it means "this resolver did not supply
    /// one" — and the engine falls back to displaying the SID.
    /// `#[serde(default)]` keeps older cache entries lacking this field
    /// compatible.
    #[serde(default)]
    pub group_name: Option<String>,
    /// Konkreter Mitgliedschafts-Pfad von `member_sid` zu `group_sid`
    /// (siehe [`MembershipPath`]). Vom Live-Resolver befüllt; der
    /// SQLite-Cache speichert ihn nicht zurück, weil er bei jedem Lauf
    /// neu rekonstruiert wird. `None` bedeutet „dieser Resolver hat
    /// keinen Pfad geliefert" — die Engine fällt dann auf die alte
    /// „direkt/transitiv"-Anzeige zurück. `#[serde(default)]` hält
    /// ältere Cache-Einträge kompatibel.
    /// Concrete membership path from `member_sid` to `group_sid` (see
    /// [`MembershipPath`]). Populated by the live resolver; the SQLite
    /// cache does not store it because it is reconstructed on every
    /// run. `None` means "this resolver did not supply a path" — the
    /// engine then falls back to the old "direct/transitive" display.
    /// `#[serde(default)]` keeps older cache entries compatible.
    #[serde(default)]
    pub path: Option<MembershipPath>,
}

/// Konkrete Mitgliedschafts-Kette von einer Identität zu einer Gruppe.
///
/// `nodes[0]` ist die Ausgangs-SID (Benutzer, Computer oder Gruppe),
/// `nodes[n-1]` die Zielgruppe. Zwischen-Indizes sind die verschachtelten
/// Gruppen in der Reihenfolge der direkten `member`-Edges.
///
/// `names` ist index-aligned zu `nodes` und enthält den Anzeigenamen
/// pro SID, sofern bekannt — die Engine kann daraus einen lesbaren
/// Berechtigungspfad bauen, ohne erneut zu serialisieren.
///
/// `complete` ist `true`, wenn die Kette vollständig aus konkreten
/// `member`-Edges rekonstruiert wurde. `false` bedeutet, dass nur die
/// transitive Zugehörigkeit feststeht (z. B. über
/// `LDAP_MATCHING_RULE_IN_CHAIN`), die exakte Zwischenstufen-Sequenz
/// aber nicht — typisch, wenn `memberOf` eines Zwischengruppen-Eintrags
/// vom Server abgeschnitten wurde.
///
/// Concrete membership chain from an identity to a group.
///
/// `nodes[0]` is the starting SID (user, computer or group), `nodes[n-1]`
/// is the target group. Intermediate indices are the nested groups in
/// direct `member`-edge order.
///
/// `names` is index-aligned with `nodes` and carries the display name
/// per SID when known — the engine can render a readable explanation
/// path without re-resolving.
///
/// `complete` is `true` when the chain was fully reconstructed from
/// concrete `member` edges. `false` means only the transitive
/// membership is established (e.g. via `LDAP_MATCHING_RULE_IN_CHAIN`)
/// but the exact intermediate sequence is not — typical when the
/// `memberOf` of an intermediate group entry was truncated by the
/// server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPath {
    pub nodes: Vec<Sid>,
    #[serde(default)]
    pub names: Vec<Option<String>>,
    pub source: MembershipPathSource,
    pub complete: bool,
}

/// Herkunftsquelle einer rekonstruierten Mitgliedschafts-Kette.
/// Source of a reconstructed membership chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipPathSource {
    /// Primäre AD-Gruppe (`primaryGroupID`) — eine Kante vom Benutzer
    /// direkt zur Primärgruppe, plus transitive Eltern als eigene
    /// Mitgliedschaften.
    /// Primary AD group (`primaryGroupID`) — a single edge from the user
    /// to the primary group, with transitive parents recorded as their
    /// own memberships.
    PrimaryGroup,
    /// Direkte oder verschachtelte Domänen-Gruppenmitgliedschaft, die
    /// über konkrete `member`-Edges rekonstruiert wurde.
    /// Direct or nested domain group membership reconstructed via
    /// concrete `member` edges.
    DomainGroup,
    /// Lokale Gruppe auf dem Zielserver (NetUserGetLocalGroups oder
    /// NetLocalGroupGetMembers).
    /// Local group on the target server (NetUserGetLocalGroups or
    /// NetLocalGroupGetMembers).
    LocalGroup,
    /// Die transitive Zugehörigkeit ist sicher (z. B. via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`), der konkrete Weg konnte aber
    /// nicht vollständig rekonstruiert werden. `complete` ist in diesem
    /// Fall `false`.
    /// Transitive membership is certain (e.g. via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`) but the concrete path could not
    /// be fully reconstructed. `complete` is `false` in this case.
    LdapMatchingRule,
}

/// Art des ACE
/// ACE type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AceKind {
    Allow,
    Deny,
}

/// Einzelner ACL-Eintrag
/// Single ACL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceEntry {
    pub kind: AceKind,
    pub sid: Sid,
    pub mask: AccessMask,
    pub inherited: bool,
    pub inheritance_flags: u32,
    pub propagation_flags: u32,
}

/// ACE-Typ, der vom Parser nicht vollständig interpretiert werden kann.
/// ACE type that cannot be fully interpreted by the parser.
///
/// Tritt bei Object-, Callback- oder herstellerspezifischen ACE-Typen auf.
/// Occurs with object, callback, or vendor-specific ACE types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedAce {
    /// Rohwert von ACE_HEADER.AceType.
    /// Raw value from ACE_HEADER.AceType.
    pub ace_type: u8,
    /// Rohwert von ACE_HEADER.AceFlags.
    /// Raw value from ACE_HEADER.AceFlags.
    pub flags: u8,
    /// Zugriffsmaske — bei Standard-ACE-Typen (0–15) liegt Mask direkt nach dem Header.
    /// Access mask — for standard ACE types (0–15) Mask is immediately after the header.
    pub mask: u32,
}

/// Dateisystemobjekt (Ordner oder Datei)
/// File system object (folder or file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemObject {
    pub path: NormalizedPath,
    pub is_directory: bool,
    pub owner_sid: Option<Sid>,
    pub dacl: Vec<AceEntry>,
    pub inheritance_disabled: bool,
    pub is_reparse_point: bool,
    /// ACEs, deren Typ vom Parser nicht unterstützt wird (Object-, Callback-ACEs usw.).
    /// ACEs whose type is not supported by the parser (object, callback ACEs, etc.).
    #[serde(default)]
    pub unsupported_aces: Vec<UnsupportedAce>,
    /// `true`, wenn die DACL des Objekts NULL ist. Eine NULL-DACL bedeutet
    /// fachlich „kein Zugriffsschutz" (Vollzugriff für alle) — abzugrenzen von
    /// einer leeren DACL (`dacl` leer aber `null_dacl == false`), die „kein
    /// Zugriff" bedeutet.
    /// `true` if the object's DACL is NULL. A NULL DACL means "no access
    /// control" (full access for everyone) — distinct from an empty DACL
    /// (`dacl` empty but `null_dacl == false`), which means "no access".
    #[serde(default)]
    pub null_dacl: bool,
}

/// SMB-Freigabe
/// SMB share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    pub unc_path: String,
    pub local_path: Option<NormalizedPath>,
    pub is_admin_share: bool,
}

/// Berechtigung auf einer Freigabe
/// Permission on a share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePermission {
    pub share_name: String,
    pub sid: Sid,
    pub mask: AccessMask,
    pub kind: AceKind,
}

/// Auswertungsstatus der Share-DACL für ein Ergebnis.
/// Evaluation status of the share DACL for a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShareEvalStatus {
    /// Kein SMB-Kontext angefragt — Ergebnis zeigt nur NTFS-Rechte (korrekt).
    /// No SMB context requested — result shows NTFS permissions only (correct).
    #[default]
    NotApplicable,
    /// Share-DACL erfolgreich gelesen und in die Berechnung eingeflossen.
    /// Share DACL successfully read and included in the calculation.
    Applied,
    /// Share-DACL ist NULL — über SMB gibt es keine Einschränkung; das
    /// Ergebnis entspricht damit der NTFS-Berechnung. Eigene Variante, um
    /// im Report nicht als Spezial-Share-Maske `0xFFFFFFFF` zu erscheinen.
    /// Share DACL is NULL — no SMB-side restriction; the result matches the
    /// NTFS computation. Dedicated variant so the report does not surface a
    /// fake "special" share mask `0xFFFFFFFF`.
    Unrestricted,
    /// Share-DACL-Lesen fehlgeschlagen — Ergebnis zeigt nur NTFS-Rechte (möglicherweise unvollständig).
    /// Share DACL read failed — result shows NTFS permissions only (potentially incomplete).
    ReadFailed(String),
}

/// Eingabezustand der Share-Seite für eine Berechtigungsauswertung.
/// Trägt sowohl den Status als auch die Maske im `Applied`-Fall — verhindert
/// die mehrdeutige Trennung zwischen "kein SMB-Kontext" und "Share-Lesen
/// fehlgeschlagen", die beide vorher als `None` aussahen.
///
/// Input state of the share side for a permission evaluation. Carries both
/// status and mask in the `Applied` case — prevents the ambiguous separation
/// between "no SMB context" and "share read failed", which both previously
/// looked like `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShareMaskStatus {
    /// Kein SMB-Kontext — Ergebnis ist ausschließlich die NTFS-Berechtigung.
    /// No SMB context — result is the NTFS permission only.
    #[default]
    NotApplicable,
    /// Share-DACL gelesen; `mask` ist die berechnete Share-Maske.
    /// Share DACL was read; `mask` is the computed share mask.
    Applied(AccessMask),
    /// Share hat eine NULL-DACL — fachlich "keine Beschränkung über SMB". Die
    /// effektive Berechnung muss dann ausschließlich aus NTFS folgen. Wird
    /// separat von `Applied(0xFFFFFFFF)` modelliert, um die Audit-Semantik
    /// nicht mit einer realen "Special-Access"-Maske zu verwechseln.
    /// Share has a NULL DACL — semantically "no restriction over SMB". The
    /// effective computation must then come from NTFS only. Modeled separately
    /// from `Applied(0xFFFFFFFF)` to avoid confusing audit semantics with a
    /// real "special access" mask.
    Unrestricted,
    /// Share-DACL-Lesen fehlgeschlagen — effective_mask ist unsicher und muss
    /// downstream als unvollständig behandelt werden.
    /// Share DACL read failed — effective_mask is uncertain and must be treated
    /// as incomplete downstream.
    ReadFailed(String),
}

/// Auswertungsstatus der lokalen Server-Gruppen-Auflösung für ein Ergebnis.
///
/// Die SIDs der lokalen Gruppen des Zielservers gehören zum Windows-Access-Token
/// und beeinflussen sowohl NTFS- als auch Share-Berechtigungen. Schlägt die
/// Auflösung fehl (Access denied, RPC-Fehler, Namensauflösungsproblem), fehlen
/// diese SIDs im Token — effektive Rechte sind dann potentiell zu niedrig.
///
/// Evaluation status of the local server group resolution for a result.
///
/// The target server's local-group SIDs belong to the Windows access token and
/// affect both NTFS and share evaluations. When resolution fails (access denied,
/// RPC errors, name lookup issues) those SIDs are missing from the token —
/// effective rights may then be too low.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LocalGroupEvalStatus {
    /// Lokale Gruppen wurden nicht angefragt (lokaler Pfad ohne Zielserver, oder
    /// Identität ohne brauchbaren Account-Namen).
    /// Local groups were not requested (local path without target server, or
    /// identity without a usable account name).
    #[default]
    NotQueried,
    /// Auflösung erfolgreich; SIDs sind im Token enthalten.
    /// Resolution succeeded; SIDs are included in the token.
    Applied,
    /// Auflösung fehlgeschlagen; Token ist unvollständig, Ergebnis muss
    /// downstream als unvollständig behandelt werden.
    /// Resolution failed; token is incomplete, result must be treated as
    /// incomplete downstream.
    NotAvailable(String),
}

/// Allow-ACE, der mindestens ein Bit zum NTFS-Ergebnis beigetragen hat.
/// Allow ACE that contributed at least one bit to the NTFS result.
///
/// `mask` enthält nur die Bits dieser ACE, die tatsächlich im finalen ntfs_raw enthalten sind
/// (ACE-Maske AND ntfs_raw), akkumuliert über alle ACEs derselben SID.
/// `mask` contains only the bits of this ACE that appear in the final ntfs_raw
/// (ACE mask AND ntfs_raw), accumulated across all ACEs of the same SID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributingAce {
    pub sid: Sid,
    pub mask: AccessMask,
}

/// Normalisierte effektive Berechtigung
/// Normalized effective permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePermission {
    pub identity: Identity,
    pub path: NormalizedPath,
    pub ntfs_mask: AccessMask,
    pub share_mask: Option<AccessMask>,
    /// Restriktivere Kombination aus NTFS und Share
    /// More restrictive combination of NTFS and share
    pub effective_mask: AccessMask,
    pub path_explanation: PermissionPath,
    /// Auswertungsstatus der Share-DACL — wird vom Aufrufer nach dem Engine-Call gesetzt.
    /// Share DACL evaluation status — set by the caller after the engine call.
    #[serde(default)]
    pub share_status: ShareEvalStatus,

    /// Auswertungsstatus der lokalen Server-Gruppen-Auflösung. `NotAvailable`
    /// markiert das Ergebnis als unvollständig — Risk Findings für diese
    /// Berechtigung sollten `incomplete = true` tragen.
    /// Evaluation status of the local server group resolution. `NotAvailable`
    /// marks the result as incomplete — risk findings derived from this
    /// permission should carry `incomplete = true`.
    #[serde(default)]
    pub local_group_status: LocalGroupEvalStatus,

    /// Allow-ACEs, die mindestens ein Bit zum NTFS-Ergebnis beigetragen haben, jeweils mit
    /// dem Teilmenge der tatsächlich beigetragenen Bits.
    /// Allow ACEs that contributed at least one bit to the NTFS result, each with the subset
    /// of bits actually contributed.
    #[serde(default)]
    pub contributing_sids: Vec<ContributingAce>,

    /// Anzahl der ACEs auf diesem Pfad, deren Typ vom Parser nicht ausgewertet werden konnte.
    /// Ist dieser Wert > 0, ist die DACL-Auswertung möglicherweise unvollständig.
    /// Number of ACEs on this path whose type the parser could not evaluate.
    /// When this value is > 0, the DACL evaluation is potentially incomplete.
    #[serde(default)]
    pub unsupported_ace_count: usize,

    /// DACL-Einträge, deren Trustee-SID zum Token-SID-Satz dieser Identität gehört
    /// (eigene SID oder eine Gruppen-SID). Strukturierte ACE-Herkunft für Risikoregeln —
    /// robuster als das Parsen des Erklärungstexts.
    /// DACL entries whose trustee SID belongs to this identity's token SID set
    /// (own SID or a group SID). Structured ACE origin for risk rules — more robust
    /// than parsing the explanation text.
    #[serde(default)]
    pub matched_aces: Vec<AceEntry>,

    /// Strukturierte Diagnose-Marker für diesen Pfad. Erfasst Befunde, die für
    /// einen Auditor relevant sind, aber außerhalb des reinen Recht-Ergebnisses
    /// liegen — z. B. eine nicht-kanonisch sortierte DACL, die deshalb von
    /// Windows in Stored-Order ausgewertet wird (Folge-Befund 3).
    /// Structured diagnostic markers for this path. Captures findings relevant
    /// to an auditor but outside the pure rights result — e.g. a non-canonical
    /// DACL ordering that Windows evaluates in stored order (follow-up
    /// finding 3).
    #[serde(default)]
    pub diagnostics: Vec<PermissionDiagnostic>,
}

/// Strukturierter Diagnose-Marker, der einer effektiven Berechtigung anhaftet.
/// Variante-tagged JSON-Serialisierung, damit zukünftige Marker einfach
/// ergänzt werden können, ohne Bestandsdaten zu brechen.
///
/// Structured diagnostic marker attached to an effective permission.
/// Variant-tagged JSON serialization so future markers can be added without
/// breaking persisted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum PermissionDiagnostic {
    /// Die DACL des Pfads folgt nicht der Windows-Kanonik
    /// (explizit-Deny → explizit-Allow → inherited-Deny → inherited-Allow).
    /// Die Engine wertet sie in Stored-Order aus — entspricht dem
    /// `AccessCheck`-Verhalten von Windows, kann sich aber von einer
    /// kanonisierten Erwartung unterscheiden. `at_index` ist der Index
    /// der ersten ACE, die die Ordnung bricht.
    ///
    /// The path's DACL is not in Windows-canonical order
    /// (explicit-deny → explicit-allow → inherited-deny → inherited-allow).
    /// The engine evaluates it in stored order — matches Windows
    /// `AccessCheck`, but may differ from canonicalized expectations.
    /// `at_index` is the index of the first ACE that breaks the order.
    NonCanonicalDaclOrder { at_index: usize },

    /// Auf der Share-DACL hat der Parser ACE-Typen nicht ausgewertet
    /// (z. B. Object-, Callback- oder herstellerspezifische ACEs). Die
    /// Share-Maske ist damit potenziell unvollständig — Risk-Findings
    /// für diese Berechtigung müssen `incomplete = true` tragen.
    /// `count` ist die Anzahl der ignorierten Share-ACEs.
    ///
    /// Das NTFS-Pendant (`unsupported_ace_count` auf
    /// `EffectivePermission`) gibt es schon länger; dieser Marker ist
    /// die spiegelbildliche Symmetrie für die Share-Seite
    /// (Folge-Befund 2 aus Review 2026-05-25).
    ///
    /// The share-side DACL parser skipped ACE types (e.g. object,
    /// callback or vendor-specific ACEs). The share mask is therefore
    /// potentially incomplete — risk findings for this permission must
    /// carry `incomplete = true`. `count` is the number of skipped
    /// share ACEs.
    ///
    /// The NTFS counterpart (`unsupported_ace_count` on
    /// `EffectivePermission`) has existed for a while; this marker is
    /// the mirror-image for the share side (follow-up finding 2 from
    /// the 2026-05-25 review).
    UnsupportedShareAces { count: usize },
}

/// Erklärbarer Berechtigungspfad
/// Explainable permission path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPath {
    pub steps: Vec<String>,
}

/// Scanergebnis einer einzelnen Ausführung
/// Scan result of a single run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub target: String,
    pub errors: Vec<ScanError>,
}

/// Fehler während eines Scans
/// Error during a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: Option<NormalizedPath>,
    pub message: String,
}

/// Risikobefund
/// Risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub rule_id: String,
    pub severity: RiskSeverity,
    pub description: String,
    pub affected_path: Option<NormalizedPath>,
    pub affected_identity: Option<Sid>,
    /// `true`, wenn die zugrundeliegende Berechtigungsauswertung unvollständig
    /// war (z. B. Share-DACL nicht lesbar). Konsumenten sollten den Befund dann
    /// vorsichtig interpretieren.
    /// `true` if the underlying permission evaluation was incomplete (e.g.
    /// share DACL not readable). Consumers should treat the finding cautiously.
    #[serde(default)]
    pub incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_context_default_is_unspecified() {
        assert_eq!(AccessContext::default(), AccessContext::Unspecified);
    }

    #[test]
    fn access_context_for_unc_path_is_remote_smb() {
        assert_eq!(
            AccessContext::for_path(r"\\server\share\folder"),
            AccessContext::RemoteSmb
        );
        assert_eq!(
            AccessContext::for_path(r"\\192.168.11.100\Shared"),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_long_path_unc_is_remote_smb() {
        // \\?\UNC\server\share\... — long-path-Form für UNC
        assert_eq!(
            AccessContext::for_path(r"\\?\UNC\server\share\folder"),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_local_path_is_local_interactive() {
        assert_eq!(
            AccessContext::for_path(r"C:\Windows"),
            AccessContext::LocalInteractive
        );
        assert_eq!(
            AccessContext::for_path(r"D:\Data\file.txt"),
            AccessContext::LocalInteractive
        );
    }

    #[test]
    fn access_context_for_long_path_local_is_local_interactive() {
        // \\?\C:\... — long-path-Form für lokalen Pfad
        assert_eq!(
            AccessContext::for_path(r"\\?\C:\very\long\path"),
            AccessContext::LocalInteractive
        );
    }
}
