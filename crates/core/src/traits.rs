use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::error::CoreError;
use crate::model::{
    AccessContext, EffectivePermission, FileSystemObject, GroupMembership, Identity,
    LocalGroupEvalStatus, PathTrustees, RiskFinding, ScanError, ShareMaskStatus, Sid,
};

pub struct ScanRequest {
    pub target: String,
}

/// Ergebnis eines Scans: rohe Dateisystemobjekte plus Fehler beim Lesen.
/// Die Berechnung effektiver Berechtigungen erfolgt anschließend im Evaluator —
/// der Scanner liefert nur die Eingabedaten.
/// Result of a scan: raw file system objects plus errors encountered while reading.
/// Effective permission computation happens afterwards in the evaluator — the
/// scanner only produces the input data.
pub struct ScanResult {
    pub objects: Vec<FileSystemObject>,
    pub errors: Vec<ScanError>,
}

pub struct PermissionEvaluationInput {
    pub identity: Identity,
    pub group_memberships: Vec<GroupMembership>,
    /// Das zu analysierende Dateisystemobjekt mit DACL und Owner.
    /// The file system object to analyze, including DACL and owner.
    pub file_system_object: FileSystemObject,
    /// Status der Share-Seite (kein SMB / angewendet mit Maske / fehlgeschlagen).
    /// Ersetzt das frühere `Option<AccessMask>` und macht „kein Kontext" von
    /// „Lesen fehlgeschlagen" eindeutig unterscheidbar.
    /// Status of the share side (no SMB / applied with mask / read failed).
    /// Replaces the former `Option<AccessMask>` and makes "no context"
    /// unambiguously distinguishable from "read failed".
    pub share_status: ShareMaskStatus,
    /// SIDs der lokalen Gruppen des Zielservers, in denen der Benutzer Mitglied
    /// ist (z. B. `BUILTIN\Administrators`). Sind diese SIDs leer, werden ACEs,
    /// die nur über lokale Server-Gruppen wirken, nicht erkannt.
    /// SIDs of local groups on the target server in which the user is a member
    /// (e.g. `BUILTIN\Administrators`). If this is empty, ACEs that only apply
    /// via local server groups are missed.
    pub local_group_sids: Vec<Sid>,
    /// Status der lokalen-Gruppen-Auflösung — `NotAvailable` markiert das
    /// Ergebnis als unvollständig (siehe [`LocalGroupEvalStatus`]). Der
    /// Aufrufer setzt diesen Wert, die Engine reicht ihn unverändert weiter.
    /// Status of the local-group resolution — `NotAvailable` marks the result
    /// as incomplete (see [`LocalGroupEvalStatus`]). The caller sets this; the
    /// engine forwards it unchanged.
    pub local_group_status: LocalGroupEvalStatus,
    /// Zugriffskontext (lokal interaktiv / remote SMB / nicht spezifiziert).
    /// Steuert, welche Well-Known-SIDs implizit in den Token aufgenommen
    /// werden (z. B. `NETWORK` für SMB, `INTERACTIVE` für lokal). Default
    /// (`Unspecified`) verhält sich wie vorher — nur `Everyone` und
    /// `Authenticated Users` werden ergänzt.
    /// Access context (local interactive / remote SMB / unspecified).
    /// Controls which well-known SIDs are added to the token implicitly
    /// (e.g. `NETWORK` for SMB, `INTERACTIVE` for local). The default
    /// (`Unspecified`) behaves as before — only `Everyone` and
    /// `Authenticated Users` are added.
    pub access_context: AccessContext,
    /// Anzahl Share-ACEs, die der Share-DACL-Parser nicht auswerten
    /// konnte (z. B. Object-, Callback- oder herstellerspezifische ACEs).
    /// Engine pusht bei >0 einen `PermissionDiagnostic::UnsupportedShareAces`
    /// in das Ergebnis; Risk-Findings dieser Berechtigung werden dann
    /// als `incomplete` markiert. Default 0 (keine).
    /// Number of share ACEs the share DACL parser could not interpret
    /// (e.g. object, callback or vendor-specific ACEs). When >0 the
    /// engine pushes a `PermissionDiagnostic::UnsupportedShareAces`
    /// into the result; risk findings derived from this permission are
    /// then flagged `incomplete`. Default 0 (none).
    pub unsupported_share_ace_count: usize,
    /// Optionale SID→Name-Übersetzungstabelle für die Erklärungstexte.
    /// Schlüssel ist der kanonische SID-String (gleich `Sid::0`), Wert
    /// der anzuzeigende Name (z. B. `Domain Admins` oder
    /// `BUILTIN\Administrators`). Die Engine schaut bei jeder SID, die in
    /// den `PermissionPath::steps` auftaucht (User, Gruppen, ACE-Trustees),
    /// in dieser Tabelle nach; ist die SID nicht enthalten oder die Tabelle
    /// leer, fällt sie auf die SID-Anzeige zurück. Default-leer hält
    /// bestehende Aufrufer unverändert kompatibel.
    /// Optional SID-to-name lookup table for the explanation text. The
    /// key is the canonical SID string (same as `Sid::0`), the value is
    /// the display name (e.g. `Domain Admins` or
    /// `BUILTIN\Administrators`). The engine consults this table for every
    /// SID that appears in `PermissionPath::steps` (user, groups, ACE
    /// trustees); when the SID is missing or the table is empty it falls
    /// back to showing the raw SID. Defaulting to empty keeps existing
    /// callers compatible.
    pub sid_names: BTreeMap<String, String>,
    /// `true`, wenn die Gruppen­auflösung über den SAM/LSA-Fallback
    /// (`NetUserGetGroups`) statt LDAP läuft. In diesem Fall sind
    /// **verschachtelte Domain-Gruppen nicht rekursiv aufgelöst** und der
    /// Token-SID-Satz kann unvollständig sein. Die Engine pusht dann einen
    /// `PermissionDiagnostic::DomainGroupRecursionIncomplete` ins Ergebnis,
    /// damit Audit-Konsumenten den Befund explizit als unvollständig
    /// behandeln. Default `false` (LDAP-Pfad) hält bestehende Aufrufer
    /// kompatibel. Schliesst Review-Befund 6.
    /// `true` when group resolution runs through the SAM/LSA fallback
    /// (`NetUserGetGroups`) instead of LDAP. In that case **nested domain
    /// groups are not recursively resolved** and the token SID set may be
    /// incomplete. The engine then pushes a
    /// `PermissionDiagnostic::DomainGroupRecursionIncomplete` into the
    /// result so audit consumers treat the finding as incomplete.
    /// Defaulting to `false` (LDAP path) keeps existing callers
    /// compatible. Closes review finding 6.
    pub group_resolution_via_sam_fallback: bool,
    /// `true`, wenn die Identitaet zwar per LSA aufgeloest werden konnte,
    /// der konfigurierte LDAP-`base_dn` die SID aber nicht indexiert (typisch
    /// in Multi-Domain-Forests). Die Engine pusht dann einen
    /// `PermissionDiagnostic::IdentityNotInConfiguredLdapBase`. Default
    /// `false`. Schliesst Review-Befund 2026-06-04 Runde 2 Finding 1.
    /// `true` when the identity was resolved via LSA but the configured
    /// LDAP `base_dn` does not index that SID (typical in multi-domain
    /// forests). The engine then pushes a
    /// `PermissionDiagnostic::IdentityNotInConfiguredLdapBase`. Default
    /// `false`. Closes review 2026-06-04 round 2 finding 1.
    pub identity_not_in_configured_ldap_base: bool,
    /// `true`, wenn `disabled` auf der Identitaet nicht zuverlaessig
    /// bestimmt werden konnte (z. B. SAM-Pfad ohne `NetUserGetInfo`).
    /// Default `false`. Schliesst Review-Befund 2026-06-04 Runde 2 Finding 5.
    /// `true` when the `disabled` flag on the identity could not be
    /// reliably determined (e.g. SAM path without `NetUserGetInfo`).
    /// Default `false`. Closes review 2026-06-04 round 2 finding 5.
    pub identity_disabled_status_unknown: bool,
    /// `Some(reason)`, wenn der LDAP-Identity-Lookup mit einem
    /// technischen Fehler gescheitert ist (Bind, Timeout, DC nicht
    /// erreichbar, Query-Fehler). Die Engine pusht dann einen
    /// `PermissionDiagnostic::IdentityLookupFailed { reason }`. Die
    /// Risk-Engine markiert abgeleitete Findings als
    /// `incomplete = true`. Default `None`. Schliesst
    /// Review-Befund 2026-06-04 Runde 4 Finding 1.
    /// `Some(reason)` when the LDAP identity lookup failed with a
    /// technical error. The engine pushes an `IdentityLookupFailed`
    /// marker; risk findings are flagged incomplete. Default `None`.
    pub identity_lookup_failure_reason: Option<String>,
    /// `Some(reason)`, wenn die rekursive Gruppenauflösung gescheitert
    /// ist oder bewusst nicht ausgeführt wurde, obwohl Gruppen für die
    /// korrekte Berechtigungsauswertung relevant gewesen wären. Die
    /// Engine pusht dann einen
    /// `PermissionDiagnostic::GroupResolutionFailed { reason }`. Die
    /// Risk-Engine markiert abgeleitete Findings als
    /// `incomplete = true`. Default `None`.
    /// `Some(reason)` when recursive group resolution failed or was
    /// deliberately skipped while groups would have mattered. Marker +
    /// risk-incomplete propagation.
    pub group_resolution_failure_reason: Option<String>,
}

pub struct RiskContext {
    pub findings: Vec<EffectivePermission>,
}

pub enum ExportTarget {
    File(std::path::PathBuf),
}

#[derive(Default)]
pub struct AnalysisResult {
    pub permissions: Vec<EffectivePermission>,
    pub risk_findings: Vec<RiskFinding>,
    /// Pfadzentrische Trustee-Auflistung (ACEs ohne Identitäts-Bezug).
    /// Wird vom Exporter genutzt, um die zweite Audit-Frage „wer hat
    /// überhaupt Zugriff?" pro Pfad mit zu rendern. Leer wenn der
    /// Aufrufer das nicht braucht — bricht keine bestehenden
    /// Konstruktionen.
    /// Path-centric trustee listing (ACEs without an identity context).
    /// Used by the exporter to render the second audit question "who has
    /// any access?" per path. Empty when the caller does not need it —
    /// does not break existing constructions.
    pub path_trustees: Vec<PathTrustees>,
}

/// Liest und analysiert Dateisystem-Objekte oder Freigaben.
/// Reads and analyzes file system objects or shares.
pub trait Scanner {
    fn scan(&self, request: ScanRequest) -> Result<ScanResult, CoreError>;
}

/// Löst SIDs zu Identitäten auf und ermittelt Gruppenmitgliedschaften via LDAP/AD.
/// Resolves SIDs to identities and determines group memberships via LDAP/AD.
///
/// Alle Methoden sind async, da AD-Abfragen I/O-gebunden sind.
/// All methods are async because AD queries are I/O-bound.
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Löst eine SID zu einer vollständigen Identität auf (Name, Domäne, Typ, Status).
    /// Resolves a SID to a full identity (name, domain, kind, status).
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError>;

    /// Ermittelt alle Gruppenmitgliedschaften rekursiv (direkt und transitiv).
    /// Determines all group memberships recursively (direct and transitive).
    async fn resolve_group_memberships(&self, sid: &Sid)
        -> Result<Vec<GroupMembership>, CoreError>;
}

/// Berechnet effektive Rechte aus Identität, Gruppen und ACL-Einträgen.
/// Calculates effective permissions from identity, groups, and ACL entries.
pub trait PermissionEvaluator {
    fn evaluate(&self, input: PermissionEvaluationInput) -> Result<EffectivePermission, CoreError>;
}

/// Bewertet Analyseergebnisse gegen eine einzelne Risikoregel.
/// Evaluates analysis results against a single risk rule.
pub trait RiskRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding>;
}

/// Exportiert Analyseergebnisse in ein Zielformat.
/// Exports analysis results to a target format.
pub trait Exporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError>;
}
