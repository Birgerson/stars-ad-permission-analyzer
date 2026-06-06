// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

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

    /// Wie [`Self::for_path`], aber zwingt `RemoteSmb`, sobald ein expliziter
    /// SMB-Kontext angegeben wurde (`--smb-server` / `--share-name` in der CLI,
    /// die entsprechenden GUI-Felder). Das fixt Round-7-Finding 1: ein lokaler
    /// NTFS-Pfad, der mit explizitem SMB-Kontext analysiert wird, lieferte
    /// vorher `LocalInteractive` — `NETWORK` fehlte im Token, Share-DACL-ACEs
    /// auf `NETWORK`/`INTERACTIVE`/`LOCAL` wurden falsch aggregiert.
    ///
    /// Like [`Self::for_path`], but forces `RemoteSmb` as soon as an explicit
    /// SMB context is supplied (`--smb-server` / `--share-name` on the CLI,
    /// the corresponding GUI fields). This fixes round-7 finding 1: a local
    /// NTFS path analysed with an explicit SMB context previously produced
    /// `LocalInteractive` — `NETWORK` was missing from the token and share
    /// DACL ACEs targeting `NETWORK`/`INTERACTIVE`/`LOCAL` were aggregated
    /// incorrectly.
    pub fn for_path_with_smb(
        path: &str,
        smb_server: Option<&str>,
        share_name: Option<&str>,
    ) -> Self {
        let has_explicit_smb = smb_server.map(|s| !s.is_empty()).unwrap_or(false)
            || share_name.map(|s| !s.is_empty()).unwrap_or(false);
        if has_explicit_smb {
            return Self::RemoteSmb;
        }
        Self::for_path(path)
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

    /// Die Gruppen­auflösung läuft über den SAM/LSA-Fallback (ohne LDAP)
    /// und damit über `NetUserGetGroups`. Diese API liefert **nur direkte**
    /// globale Gruppen — verschachtelte Domain-Gruppen werden ohne LDAP
    /// nicht rekursiv aufgelöst, lokale Gruppen werden zusätzlich nur
    /// über bereits bekannte direkte Mitglieder als Vermittler verkettet.
    /// Der Token-SID-Satz kann deshalb unvollständig sein und ACEs auf
    /// tief verschachtelte Domain-Gruppen werden übersehen. Risk-Findings
    /// für diese Berechtigung müssen `incomplete = true` tragen.
    ///
    /// Schliesst ChatGPT-Code-Review 2026-06-04 Finding 6.
    ///
    /// Group resolution runs through the SAM/LSA fallback (no LDAP) and
    /// therefore through `NetUserGetGroups`. That API only returns
    /// **direct** global groups — nested domain groups are not resolved
    /// recursively without LDAP, and local groups are only mediated via
    /// already-known direct members. The token SID set can be incomplete
    /// and ACEs targeting deeply nested domain groups may be missed.
    /// Risk findings for this permission must carry `incomplete = true`.
    ///
    /// Closes ChatGPT code review 2026-06-04 finding 6.
    DomainGroupRecursionIncomplete,

    /// Die analysierte Identität ist im AD als deaktiviert markiert
    /// (`userAccountControl`-Bit `ACCOUNTDISABLE`, 0x0002). Die berechneten
    /// Rechte sind **ACL-theoretisch korrekt** — `disabled` Konten können
    /// sich aber normalerweise **nicht authentifizieren** und ueber SMB
    /// nicht zugreifen. Damit ein Audit-Leser dieses theoretische vs.
    /// reale Recht nicht verwechselt, taucht dieser Marker bei jedem
    /// Ergebnis einer deaktivierten Identität auf.
    ///
    /// Schliesst ChatGPT-Code-Review 2026-06-04 Finding 7.
    ///
    /// The analyzed identity is flagged as disabled in AD
    /// (`userAccountControl` bit `ACCOUNTDISABLE`, 0x0002). The computed
    /// rights are **ACL-theoretically correct** — but `disabled`
    /// accounts normally **cannot authenticate** and cannot access SMB.
    /// To prevent an audit reader from confusing this theoretical right
    /// with a real right, this marker appears on every result for a
    /// disabled identity.
    ///
    /// Closes ChatGPT code review 2026-06-04 finding 7.
    IdentityDisabled,

    /// Die analysierte Identität wurde per LSA (`LookupAccountNameW` für
    /// `DOMAIN\user`) eindeutig zu einer SID aufgelöst, **aber der
    /// konfigurierte LDAP-`base_dn` indexiert diese SID nicht** —
    /// typisch in Multi-Domain-Forests, bei Trust-Beziehungen oder
    /// AD-Migrationen. Die Identität ist **real**, aber die Domain-
    /// Gruppen-Rekursion läuft ohne LDAP — der Token-SID-Satz kann
    /// unvollständig sein und ACEs auf tief verschachtelte Domain-
    /// Gruppen werden übersehen. Risk-Findings für diese Berechtigung
    /// müssen `incomplete = true` tragen.
    ///
    /// Vor diesem Marker hätte `IdentityKind::Orphaned` gestanden — ein
    /// realer Benutzer aus einer Trusted Domain wäre damit fälschlich
    /// als verwaiste SID erschienen. Schließt
    /// ChatGPT-Code-Review 2026-06-04 Runde 2 Finding 1.
    ///
    /// The analyzed identity was unambiguously resolved to a SID via LSA
    /// (`LookupAccountNameW` for `DOMAIN\user`), **but the configured
    /// LDAP `base_dn` does not index that SID** — typical in
    /// multi-domain forests, trust relationships or AD migrations. The
    /// identity is **real**, but domain group recursion runs without
    /// LDAP — the token SID set can be incomplete and ACEs targeting
    /// deeply nested domain groups are missed. Risk findings for this
    /// permission must carry `incomplete = true`.
    ///
    /// Before this marker `IdentityKind::Orphaned` would have been used
    /// — a real user from a trusted domain would have been
    /// mis-classified as a stale SID. Closes ChatGPT code review
    /// 2026-06-04 round 2 finding 1.
    IdentityNotInConfiguredLdapBase,

    /// Die analysierte Identität wurde per LSA aufgelöst, die
    /// `userAccountControl`-Information (ob das Konto deaktiviert ist)
    /// konnte aber nicht ermittelt werden — typisch im SAM/LSA-Pfad
    /// ohne LDAP, wenn `NetUserGetInfo` für Nicht-Lokal-Konten oder mit
    /// `ERROR_ACCESS_DENIED` fehlschlägt. Die berechneten Rechte sind
    /// ACL-theoretisch korrekt, aber Stars kann hier nicht entscheiden,
    /// ob das Konto sich überhaupt authentifizieren kann. Der Marker ist
    /// kein Incompleteness-Trigger — er signalisiert nur eine
    /// Wissenslücke beim Account-Status.
    ///
    /// Schließt ChatGPT-Code-Review 2026-06-04 Runde 2 Finding 5.
    ///
    /// The analyzed identity was resolved via LSA, but its
    /// `userAccountControl` (whether the account is disabled) could not
    /// be determined — typical for the SAM/LSA path without LDAP when
    /// `NetUserGetInfo` fails for non-local accounts or with
    /// `ERROR_ACCESS_DENIED`. The computed rights are ACL-theoretically
    /// correct, but Stars cannot decide whether the account can
    /// authenticate at all. The marker is not an incompleteness trigger
    /// — it only signals a knowledge gap about the account state.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 2 finding 5.
    IdentityDisabledStatusUnknown,

    /// Der LDAP-Identity-Lookup ist mit einem technischen Fehler
    /// gescheitert (Bind-Fehler, Timeout, DC unerreichbar,
    /// Query-Fehler). Stars liefert eine Platzhalter-Identity zurück
    /// und rechnet die Berechtigung weiter — der Token-SID-Satz ist
    /// dabei aber strukturell unvollständig. Der Marker ist ein
    /// Incompleteness-Trigger; abgeleitete Risk-Findings werden als
    /// `incomplete = true` ausgewiesen.
    ///
    /// Schließt ChatGPT-Code-Review 2026-06-04 Runde 4 Finding 1.
    ///
    /// The LDAP identity lookup failed with a technical error (bind,
    /// timeout, DC unreachable, query error). Stars returns a
    /// placeholder identity and continues the evaluation — but the
    /// token SID set is structurally incomplete. This marker is an
    /// incompleteness trigger; derived risk findings are flagged
    /// `incomplete = true`.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 4 finding 1.
    IdentityLookupFailed { reason: String },

    /// Die rekursive Gruppenauflösung ist gescheitert oder wurde
    /// nicht ausgeführt (`GroupResolutionStatus::Failed` oder
    /// `GroupResolutionStatus::NotAttempted` in einem Cross-Domain-
    /// Szenario, in dem der LSA-Pfad keinen Gruppen-Crawl macht).
    /// ACEs auf Domain-Gruppen können dadurch im Befund fehlen — der
    /// Marker ist ein Incompleteness-Trigger.
    ///
    /// Schließt ChatGPT-Code-Review 2026-06-04 Runde 4 Finding 1.
    ///
    /// Recursive group resolution failed or was skipped. ACEs on
    /// domain groups may be missed — this marker is an incompleteness
    /// trigger.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 4 finding 1.
    GroupResolutionFailed { reason: String },
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

/// Schicht eines Trustee-Eintrags in der pfadzentrischen Sicht.
/// Layer of a trustee entry in the path-centric view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrusteeCategory {
    /// NTFS-DACL des Objekts.
    /// NTFS DACL of the object.
    Ntfs,
    /// SMB-Freigaben-DACL des umgebenden Shares.
    /// SMB share DACL of the surrounding share.
    Share,
}

/// Ein pfadzentrierter ACE-Eintrag mit raw-Daten — keine Display-
/// Formatierung. Render-Code (GUI / HTML / CSV) leitet daraus seine
/// jeweilige Darstellung ab. Beantwortet die Audit-Frage „wer hat
/// überhaupt Zugriff auf X?" identitätsfrei.
///
/// A path-centric ACE entry with raw data — no display formatting. Render
/// code (GUI / HTML / CSV) derives its own representation from this.
/// Answers the audit question "who can access X at all?" identity-free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTrustee {
    /// Trustee-SID — primäre technische Identität (vgl. AGENTS.md).
    /// Trustee SID — primary technical identity (cf. AGENTS.md).
    pub sid: Sid,
    /// Lesbarer Name (`DOMAIN\Name`) sofern aufgelöst. `None` heißt nicht
    /// „nicht existent", sondern „nicht aufgelöst" — Exporter sollten in
    /// dem Fall auf die SID-Anzeige zurückfallen.
    /// Readable name (`DOMAIN\Name`) when resolved. `None` does not mean
    /// "does not exist" — it means "not resolved". Exporters should fall
    /// back to the SID display in that case.
    #[serde(default)]
    pub display_name: Option<String>,
    pub kind: AceKind,
    pub mask: AccessMask,
    pub inherited: bool,
    pub inheritance_flags: u32,
    pub propagation_flags: u32,
    pub category: TrusteeCategory,
}

/// Eintrag in der pfadzentrierten Trustee-Liste — entweder ein echter
/// ACE oder ein Diagnose-Hinweis (zum Beispiel "Share-DACL konnte nicht
/// gelesen werden", "NULL DACL festgestellt"). Vor Review-Runde 10
/// wurden Diagnose-Hinweise als synthetische `PathTrustee`-Einträge
/// mit `kind = Allow` und leerer SID modelliert — das war für JSON-
/// Konsumenten irrefuehrend, weil ein Diagnose-Hinweis dort wie ein
/// realer Allow-ACE aussah. Mit dem Enum wird die Unterscheidung
/// typisiert und ist im JSON-Output via Tag (`"kind": "ace"` vs.
/// `"kind": "diagnostic"`) eindeutig.
///
/// Entry in the path-centric trustee list — either a real ACE or a
/// diagnostic hint (for example "share DACL could not be read",
/// "NULL DACL detected"). Before review round 10 diagnostic hints
/// were modelled as synthetic `PathTrustee` records with `kind = Allow`
/// and empty SID — misleading for JSON consumers because the
/// diagnostic looked like a real Allow ACE. With the enum the
/// distinction is typed and visible in the JSON output via the tag
/// (`"kind": "ace"` vs. `"kind": "diagnostic"`).
// Der Discriminator heisst bewusst `entry_kind`, NICHT `kind`. Grund:
// `PathTrustee` traegt ein Feld `kind: AceKind` (Allow/Deny). Ein
// internally-tagged Enum mit `tag = "kind"` wuerde diesen Feldnamen im
// JSON ueberschreiben (Serde wirft hier kein Compile-Error, sondern
// silently versetzt den Inhalt). Ein eigener Tag-Name vermeidet das.
// The discriminator is deliberately named `entry_kind`, NOT `kind`.
// Reason: `PathTrustee` carries a field `kind: AceKind` (Allow/Deny).
// An internally-tagged enum with `tag = "kind"` would silently
// overwrite that field name in JSON (Serde does not raise a compile
// error here). A dedicated tag name avoids the collision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entry_kind", rename_all = "snake_case")]
pub enum PathTrusteeEntry {
    /// Ein echter ACE aus der DACL.
    /// A real ACE from the DACL.
    Ace(PathTrustee),
    /// Ein Diagnose-Hinweis. `category` gibt an, welche Schicht
    /// (NTFS oder Share) gemeint ist; `message` enthaelt die fuer
    /// Auditoren lesbare Begruendung.
    /// A diagnostic hint. `category` says which layer (NTFS or share)
    /// it refers to; `message` carries the auditor-readable reason.
    Diagnostic {
        category: TrusteeCategory,
        message: String,
    },
}

impl PathTrusteeEntry {
    /// Hilfsfunktion: liefert die `TrusteeCategory` unabhaengig von der
    /// Variante. Render-Code muss damit nicht selbst matchen.
    /// Helper: returns the `TrusteeCategory` regardless of the variant.
    /// Render code does not need to match itself.
    pub fn category(&self) -> TrusteeCategory {
        match self {
            PathTrusteeEntry::Ace(ace) => ace.category,
            PathTrusteeEntry::Diagnostic { category, .. } => *category,
        }
    }

    /// Konstruktor fuer Diagnose-Hinweise.
    /// Constructor for diagnostic hints.
    pub fn diagnostic(category: TrusteeCategory, message: impl Into<String>) -> Self {
        PathTrusteeEntry::Diagnostic {
            category,
            message: message.into(),
        }
    }
}

/// Trustee-Auflistung pro Pfad: Pfad → Liste seiner ACEs und Diagnose-Hinweise.
/// Per-path trustee listing: path → list of its ACEs and diagnostic hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTrustees {
    pub path: NormalizedPath,
    pub trustees: Vec<PathTrusteeEntry>,
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

    // Round-7 Finding 1: ein lokaler Pfad mit explizitem SMB-Kontext muss
    // RemoteSmb liefern, damit NETWORK im Token landet und Share-DACL-ACEs
    // gegen NETWORK korrekt aggregiert werden.
    // Round-7 finding 1: a local path with an explicit SMB context must
    // yield RemoteSmb so NETWORK lands in the token and share DACL ACEs
    // targeting NETWORK are aggregated correctly.
    #[test]
    fn access_context_for_path_with_smb_forces_remote_when_smb_server_given() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\TestShare", Some("fs01"), None),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_forces_remote_when_share_name_given() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"D:\data", None, Some("Data")),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_keeps_unc_as_remote() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"\\server\share", None, None),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_keeps_local_when_no_smb_hint() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\Windows", None, None),
            AccessContext::LocalInteractive
        );
    }

    #[test]
    fn access_context_for_path_with_smb_ignores_empty_smb_hints() {
        // Empty-string SMB hints (e.g. an unfilled GUI field) must NOT
        // override the path-based default.
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\Windows", Some(""), Some("")),
            AccessContext::LocalInteractive
        );
    }
}
