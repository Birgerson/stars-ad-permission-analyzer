// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Selective Authentication (ADR 0079, known limitation L4).
//!
//! When a trust uses Selective Authentication, an account of the trusted
//! domain may log on to a computer of this domain only if the computer's
//! object grants it the control access right **"Allowed to authenticate"**
//! (`68b1d179-0d15-4d4f-ab71-46152e79a7bc`) — otherwise Windows refuses the
//! logon (error 1935, measured in the lab 2026-10-17). The check is made for
//! the account's whole token: a group of the trusted domain, a domain-local
//! group of this domain reached through a Foreign Security Principal, and
//! Authenticated Users all count (measured).
//!
//! This module reads nothing itself: it evaluates the self-relative security
//! descriptor of the computer object (read by the resolver with the DACL
//! only) for a token. Every length is validated; an ACE it cannot read, or an
//! ACE for a SID whose presence is uncertain that would change the answer,
//! makes the answer **unknown** — never "allowed".

use std::collections::HashSet;

/// The control access right "Allowed to authenticate", in the binary GUID
/// layout of an object ACE (Data1–3 little-endian, Data4 as is).
pub const ALLOWED_TO_AUTHENTICATE: [u8; 16] = [
    0x79, 0xd1, 0xb1, 0x68, 0x15, 0x0d, 0x4f, 0x4d, 0xab, 0x71, 0x46, 0x15, 0x2e, 0x79, 0xa7, 0xbc,
];

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const INHERIT_ONLY_ACE: u8 = 0x08;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;
const GENERIC_ALL: u32 = 0x1000_0000;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// The answer for one token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedToAuthenticate {
    /// Granted; the SID of the deciding Allow ACE.
    Allowed { via: String },
    /// No ACE grants it, or a Deny decides.
    Denied,
    /// Not decidable, with the reason.
    Unknown { reason: String },
}

/// One ACE as far as this check needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ace {
    allow: bool,
    sid: String,
    /// The ACE grants / denies "Allowed to authenticate" (all extended rights,
    /// GENERIC_ALL, or this right's GUID).
    covers: bool,
    inherit_only: bool,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The SID that starts at `at` (and must end by `end`), as `S-1-…`.
fn sid_at(b: &[u8], at: usize, end: usize) -> Result<String, String> {
    let count = *b.get(at + 1).ok_or("SID truncated")? as usize;
    if count > 15 {
        return Err(format!("SID with {count} sub-authorities"));
    }
    let len = 8 + 4 * count;
    if at + len > end {
        return Err("SID runs past its ACE".to_owned());
    }
    crate::sid_util::bytes_to_sid_str(&b[at..at + len]).map_err(|e| e.to_string())
}

/// The ACEs of the DACL in a self-relative security descriptor; `Ok(None)`
/// for a NULL DACL (no DACL present: nothing restricts).
fn parse_dacl(sd: &[u8]) -> Result<Option<Vec<Ace>>, String> {
    if sd.len() < 20 {
        return Err(format!("security descriptor of {} bytes", sd.len()));
    }
    let control = u16_at(sd, 2).ok_or("control unreadable")?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err("security descriptor is not self-relative".to_owned());
    }
    let dacl_at = u32_at(sd, 16).ok_or("DACL offset unreadable")? as usize;
    if control & SE_DACL_PRESENT == 0 || dacl_at == 0 {
        return Ok(None);
    }
    let acl_size = u16_at(sd, dacl_at + 2).ok_or("DACL header truncated")? as usize;
    let ace_count = u16_at(sd, dacl_at + 4).ok_or("DACL header truncated")? as usize;
    let acl_end = dacl_at + acl_size;
    if acl_size < 8 || acl_end > sd.len() {
        return Err("DACL size runs past the descriptor".to_owned());
    }
    let mut aces = Vec::with_capacity(ace_count);
    let mut at = dacl_at + 8;
    for i in 0..ace_count {
        let kind = *sd.get(at).ok_or(format!("ACE {i} truncated"))?;
        let flags = *sd.get(at + 1).ok_or(format!("ACE {i} truncated"))?;
        let size = u16_at(sd, at + 2).ok_or(format!("ACE {i} truncated"))? as usize;
        let end = at + size;
        if size < 8 || end > acl_end {
            return Err(format!("ACE {i} has an invalid size"));
        }
        let inherit_only = flags & INHERIT_ONLY_ACE != 0;
        match kind {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => {
                let mask = u32_at(sd, at + 4).ok_or(format!("ACE {i} truncated"))?;
                let sid = sid_at(sd, at + 8, end).map_err(|e| format!("ACE {i}: {e}"))?;
                aces.push(Ace {
                    allow: kind == ACCESS_ALLOWED_ACE_TYPE,
                    sid,
                    covers: mask & (ADS_RIGHT_DS_CONTROL_ACCESS | GENERIC_ALL) != 0,
                    inherit_only,
                });
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
                let mask = u32_at(sd, at + 4).ok_or(format!("ACE {i} truncated"))?;
                let oflags = u32_at(sd, at + 8).ok_or(format!("ACE {i} truncated"))?;
                let mut p = at + 12;
                let object_type = if oflags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    let g: [u8; 16] = sd
                        .get(p..p + 16)
                        .ok_or(format!("ACE {i}: object type truncated"))?
                        .try_into()
                        .map_err(|_| format!("ACE {i}: object type unreadable"))?;
                    p += 16;
                    Some(g)
                } else {
                    None
                };
                if oflags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    p += 16;
                }
                let sid = sid_at(sd, p, end).map_err(|e| format!("ACE {i}: {e}"))?;
                let right = mask & (ADS_RIGHT_DS_CONTROL_ACCESS | GENERIC_ALL) != 0;
                aces.push(Ace {
                    allow: kind == ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                    sid,
                    covers: right && object_type.is_none_or(|g| g == ALLOWED_TO_AUTHENTICATE),
                    inherit_only,
                });
            }
            // Audit and label ACEs never grant or deny access.
            SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE => {}
            other => {
                return Err(format!(
                    "ACE {i} has type 0x{other:02X} (callback / conditional), which Stars \
                     does not evaluate"
                ))
            }
        }
        at = end;
    }
    Ok(Some(aces))
}

/// The first ACE (stored order, as the directory evaluates it) that decides
/// "Allowed to authenticate" for `token`; `None` when none applies.
fn first_decision<'a>(aces: &'a [Ace], token: &dyn Fn(&str) -> bool) -> Option<&'a Ace> {
    aces.iter()
        .filter(|a| !a.inherit_only && a.covers)
        .find(|a| token(&a.sid))
}

/// `true` for a SID that is certainly **not** in the token the check uses
/// for an account of a trusted domain (ADR 0079):
///
/// - builtin groups of this domain (`S-1-5-32-…`) — measured: neither
///   `Remote Desktop Users` nor `Administrators` (with its default ACE on the
///   computer object) let a member authenticate (lab 2026-10-17);
/// - `NETWORK` (S-1-5-2) — measured the same way;
/// - by definition never in the token of a user's logon: `SYSTEM`,
///   `LOCAL SERVICE`, `NETWORK SERVICE` (S-1-5-18/19/20), `Enterprise Domain
///   Controllers` (S-1-5-9, the forest's DC accounts only), `PRINCIPAL_SELF`
///   (S-1-5-10 — the object checked is the computer, not the account),
///   `CREATOR OWNER` / `CREATOR GROUP` (S-1-3-0/1, placeholders that no
///   token holds) and `ANONYMOUS LOGON` (S-1-5-7 — the logon is
///   authenticated).
pub fn certainly_absent_in_check(sid: &str) -> bool {
    sid.starts_with("S-1-5-32-")
        || matches!(
            sid,
            "S-1-5-2"
                | "S-1-5-18"
                | "S-1-5-19"
                | "S-1-5-20"
                | "S-1-5-9"
                | "S-1-5-10"
                | "S-1-3-0"
                | "S-1-3-1"
                | "S-1-5-7"
        )
}

/// `true` for a SID whose presence in the logon token the check cannot
/// know: listed in `uncertain`, or any SID that is not a domain account or
/// group SID (`S-1-5-21-…`), not in `certain` and not
/// [`certainly_absent_in_check`] — logon-type well-knowns,
/// authentication-assertion SIDs. A domain SID outside `certain` is
/// certainly absent: the account's domain groups are all known.
fn is_uncertain(sid: &str, certain: &HashSet<String>, uncertain: &HashSet<String>) -> bool {
    !certain.contains(sid)
        && (uncertain.contains(sid)
            || (!sid.starts_with("S-1-5-21-") && !certainly_absent_in_check(sid)))
}

/// Evaluates "Allowed to authenticate" in the self-relative security
/// descriptor `sd` for a token: `certain` SIDs are certainly in it,
/// `uncertain` SIDs — and every SID that is not a domain SID — may or may not
/// be. Every other domain SID is certainly absent. The answer is decided when
/// it is the same with and without the uncertain SIDs; otherwise unknown.
pub fn allowed_to_authenticate(
    sd: &[u8],
    certain: &HashSet<String>,
    uncertain: &HashSet<String>,
) -> AllowedToAuthenticate {
    let aces = match parse_dacl(sd) {
        Ok(Some(aces)) => aces,
        // A NULL DACL restricts nothing.
        Ok(None) => {
            return AllowedToAuthenticate::Allowed {
                via: "the object's NULL DACL (no restriction)".to_owned(),
            }
        }
        Err(reason) => {
            return AllowedToAuthenticate::Unknown {
                reason: format!("its permissions could not be evaluated: {reason}"),
            }
        }
    };
    let decide = |with_uncertain: bool| {
        let in_token = |s: &str| {
            certain.contains(s) || (with_uncertain && is_uncertain(s, certain, uncertain))
        };
        match first_decision(&aces, &in_token) {
            Some(a) if a.allow => AllowedToAuthenticate::Allowed { via: a.sid.clone() },
            _ => AllowedToAuthenticate::Denied,
        }
    };
    let without = decide(false);
    let with = decide(true);
    // The deciding SID may differ while the outcome is the same — then the
    // certain one is named.
    match (&without, &with) {
        (AllowedToAuthenticate::Allowed { .. }, AllowedToAuthenticate::Allowed { .. })
        | (AllowedToAuthenticate::Denied, AllowedToAuthenticate::Denied) => without,
        _ => {
            let sids: Vec<&str> = aces
                .iter()
                .filter(|a| !a.inherit_only && a.covers && is_uncertain(&a.sid, certain, uncertain))
                .map(|a| a.sid.as_str())
                .collect();
            AllowedToAuthenticate::Unknown {
                reason: format!(
                    "an ACE for {} decides it, and whether that SID is in the account's logon \
                     token is not known",
                    sids.join(", ")
                ),
            }
        }
    }
}

/// ADR 0079: a NetBIOS computer name as Windows allows it — 1–15
/// characters, no control characters, none of `\ / : * ? " < > | .` and
/// no space. The dot rule keeps an IP address or a DNS name from ever
/// passing as a computer name.
pub fn is_valid_netbios_computer_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=15).contains(&n)
        && !name
            .chars()
            .any(|c| c.is_control() || c == ' ' || "\\/:*?\"<>|.".contains(c))
}

/// ADR 0079 (L4): the Selective Authentication check of `resolution` on the
/// target server (`None` = this machine), or `None` when the account is not
/// of a trusted domain whose trust uses Selective Authentication — then
/// nothing is read and nothing changes.
///
/// The token checked is the one the lab showed counts: the account, its
/// `sIDHistory`, every group of its resolution (trusted-domain groups, this
/// domain's domain-local groups through FSPs, the organization SID),
/// Everyone and Authenticated Users. Builtin groups are left uncertain (not
/// measured). Read-only: one NetApi call, one LDAP search.
#[cfg(windows)]
pub async fn check_for_target(
    resource: &crate::resolver::LdapResolver,
    target_server: Option<&str>,
    resolution: &crate::principal::PrincipalResolution,
) -> Option<adpa_core::traits::SelectiveAuthenticationCheck> {
    use adpa_core::traits::SelectiveAuthenticationCheck as Check;
    let trusted = resolution.trusted_domain.as_ref()?;
    if !trusted.selective_authentication {
        return None;
    }
    let label = target_server.unwrap_or("this computer").to_owned();
    let name = match crate::local_account::server_netbios_name(target_server) {
        Ok(n) => n,
        Err(e) => {
            return Some(Check::Unknown {
                server: label.clone(),
                reason: format!("the computer name of {label} could not be read ({e})"),
            })
        }
    };
    let sd = match resource.computer_security_descriptor(&name).await {
        Ok(Some((_, Some(sd)))) => sd,
        Ok(Some((dn, None))) => {
            return Some(Check::Unknown {
                server: name,
                reason: format!("the permissions of its computer object {dn} could not be read"),
            })
        }
        Ok(None) => {
            return Some(Check::Unknown {
                reason: format!("there is no computer object {name}$ in the configured domain"),
                server: name,
            })
        }
        Err(e) => {
            return Some(Check::Unknown {
                server: name,
                reason: format!("its computer object could not be read ({e})"),
            })
        }
    };
    let mut certain: HashSet<String> = [
        resolution.sid.0.clone(),
        "S-1-1-0".to_owned(),
        "S-1-5-11".to_owned(),
    ]
    .into_iter()
    .collect();
    certain.extend(resolution.identity.sid_history.iter().map(|s| s.0.clone()));
    for m in &resolution.memberships {
        if !m.group_sid.0.starts_with("S-1-5-32-") {
            certain.insert(m.group_sid.0.clone());
        }
        certain.extend(m.group_sid_history.iter().map(|s| s.0.clone()));
    }
    let shown = |sid: &str| {
        let name = if sid == resolution.sid.0 {
            resolution.identity.name.clone()
        } else {
            match sid {
                "S-1-1-0" => Some("Everyone".to_owned()),
                "S-1-5-11" => Some("Authenticated Users".to_owned()),
                _ => resolution
                    .memberships
                    .iter()
                    .find(|m| m.group_sid.0 == sid)
                    .and_then(|m| m.group_name.clone()),
            }
        };
        match name {
            Some(n) => format!("{n} ({sid})"),
            None => sid.to_owned(),
        }
    };
    Some(
        match allowed_to_authenticate(&sd, &certain, &HashSet::new()) {
            AllowedToAuthenticate::Allowed { via } => Check::Allowed {
                server: name,
                via: if via.starts_with("S-") {
                    shown(&via)
                } else {
                    via
                },
            },
            AllowedToAuthenticate::Denied => Check::Denied { server: name },
            AllowedToAuthenticate::Unknown { reason } => Check::Unknown {
                server: name,
                reason,
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0079: an IP address or DNS name is never a computer name.
    #[test]
    fn netbios_computer_name_validation() {
        for ok in ["DC-01", "WIN-MONCCCT07FT", "A", "FS_01$X"] {
            assert!(is_valid_netbios_computer_name(ok), "{ok}");
        }
        for bad in [
            "",
            "192.168.11.147",
            "fs01.corp.test",
            "SIXTEEN-CHARS-XX",
            "A B",
            "A\\B",
            "A:B",
            "A\u{7}",
        ] {
            assert!(!is_valid_netbios_computer_name(bad), "{bad:?}");
        }
    }

    fn sid_bytes(s: &str) -> Vec<u8> {
        let parts: Vec<u64> = s.split('-').skip(1).map(|p| p.parse().unwrap()).collect();
        let (rev, auth, subs) = (parts[0] as u8, parts[1], &parts[2..]);
        let mut b = vec![rev, subs.len() as u8];
        b.extend_from_slice(&auth.to_be_bytes()[2..]);
        for s in subs {
            b.extend_from_slice(&(*s as u32).to_le_bytes());
        }
        b
    }

    fn ace(kind: u8, flags: u8, mask: u32, object: Option<[u8; 16]>, sid: &str) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        if kind == ACCESS_ALLOWED_OBJECT_ACE_TYPE || kind == ACCESS_DENIED_OBJECT_ACE_TYPE {
            body.extend_from_slice(&(if object.is_some() { 1u32 } else { 0 }).to_le_bytes());
            if let Some(g) = object {
                body.extend_from_slice(&g);
            }
        }
        body.extend(sid_bytes(sid));
        let mut a = vec![kind, flags];
        a.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
        a.extend(body);
        a
    }

    fn sd(aces: Vec<Vec<u8>>) -> Vec<u8> {
        let body: Vec<u8> = aces.iter().flatten().copied().collect();
        let mut acl = vec![4u8, 0];
        acl.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
        acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend(body);
        let mut s = vec![1u8, 0];
        s.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
        s.extend_from_slice(&[0; 12]); // owner, group, SACL
        s.extend_from_slice(&20u32.to_le_bytes()); // DACL right after the header
        s.extend(acl);
        s
    }

    const USER: &str = "S-1-5-21-9-9-9-1105";
    const PARTNERS: &str = "S-1-5-21-9-9-9-1110";
    const OTHER_RIGHT: [u8; 16] = [1; 16];

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Lab: "Allowed to authenticate" for the partner group lets its member in.
    #[test]
    fn an_object_ace_for_a_token_group_allows() {
        let d = sd(vec![ace(
            5,
            0,
            0x100,
            Some(ALLOWED_TO_AUTHENTICATE),
            PARTNERS,
        )]);
        assert_eq!(
            allowed_to_authenticate(&d, &set(&[USER, PARTNERS]), &set(&[])),
            AllowedToAuthenticate::Allowed {
                via: PARTNERS.to_owned()
            }
        );
    }

    /// Lab: without the right (or only another extended right) the logon is refused.
    #[test]
    fn no_grant_or_another_right_denies() {
        let d = sd(vec![
            ace(5, 0, 0x100, Some(OTHER_RIGHT), PARTNERS),
            ace(0, 0, 0x0002_0094, None, PARTNERS), // read only
        ]);
        assert_eq!(
            allowed_to_authenticate(&d, &set(&[USER, PARTNERS]), &set(&[])),
            AllowedToAuthenticate::Denied
        );
    }

    #[test]
    fn all_extended_rights_and_generic_all_cover_it() {
        for a in [
            ace(5, 0, 0x100, None, USER),
            ace(0, 0, 0x100, None, USER),
            ace(0, 0, GENERIC_ALL, None, USER),
        ] {
            assert!(matches!(
                allowed_to_authenticate(&sd(vec![a]), &set(&[USER]), &set(&[])),
                AllowedToAuthenticate::Allowed { .. }
            ));
        }
    }

    #[test]
    fn a_deny_first_wins_and_inherit_only_is_skipped() {
        let d = sd(vec![
            ace(
                5,
                INHERIT_ONLY_ACE,
                0x100,
                Some(ALLOWED_TO_AUTHENTICATE),
                USER,
            ),
            ace(6, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), PARTNERS),
            ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), USER),
        ]);
        assert_eq!(
            allowed_to_authenticate(&d, &set(&[USER, PARTNERS]), &set(&[])),
            AllowedToAuthenticate::Denied
        );
    }

    /// An ACE for a SID whose presence is uncertain is unknown — unless the
    /// answer is the same either way.
    #[test]
    fn an_uncertain_sid_that_decides_is_unknown() {
        let network = "S-1-5-2";
        let d = sd(vec![ace(
            5,
            0,
            0x100,
            Some(ALLOWED_TO_AUTHENTICATE),
            network,
        )]);
        assert!(matches!(
            allowed_to_authenticate(&d, &set(&[USER]), &set(&[network])),
            AllowedToAuthenticate::Unknown { .. }
        ));
        let d2 = sd(vec![
            ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), USER),
            ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), network),
        ]);
        assert_eq!(
            allowed_to_authenticate(&d2, &set(&[USER]), &set(&[network])),
            AllowedToAuthenticate::Allowed {
                via: USER.to_owned()
            }
        );
    }

    /// A well-known or builtin SID outside the certain token is uncertain on
    /// its own; a foreign domain SID outside it is certainly absent.
    #[test]
    fn well_knowns_are_uncertain_domain_sids_absent() {
        let interactive = "S-1-5-4";
        let d = sd(vec![ace(
            5,
            0,
            0x100,
            Some(ALLOWED_TO_AUTHENTICATE),
            interactive,
        )]);
        assert!(matches!(
            allowed_to_authenticate(&d, &set(&[USER]), &set(&[])),
            AllowedToAuthenticate::Unknown { .. }
        ));
        let stranger = "S-1-5-21-7-7-7-1234";
        let d2 = sd(vec![ace(
            5,
            0,
            0x100,
            Some(ALLOWED_TO_AUTHENTICATE),
            stranger,
        )]);
        assert_eq!(
            allowed_to_authenticate(&d2, &set(&[USER]), &set(&[])),
            AllowedToAuthenticate::Denied
        );
        // Authenticated Users in the certain token decides (lab: it counts).
        let au = "S-1-5-11";
        let d3 = sd(vec![ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), au)]);
        assert_eq!(
            allowed_to_authenticate(&d3, &set(&[USER, au]), &set(&[])),
            AllowedToAuthenticate::Allowed { via: au.to_owned() }
        );
    }

    /// ADR 0079 (lab 2026-10-17): builtin groups, NETWORK and the SIDs no
    /// user logon holds are certainly absent — the default computer-object
    /// ACEs for SYSTEM and Administrators therefore decide nothing for an
    /// account of a trusted domain.
    #[test]
    fn builtin_network_and_service_sids_are_certainly_absent() {
        for sid in [
            "S-1-5-32-544",
            "S-1-5-32-555",
            "S-1-5-2",
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-5-9",
            "S-1-5-10",
            "S-1-3-0",
            "S-1-3-1",
            "S-1-5-7",
        ] {
            assert!(certainly_absent_in_check(sid), "{sid}");
            let d = sd(vec![ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), sid)]);
            assert_eq!(
                allowed_to_authenticate(&d, &set(&[USER]), &set(&[])),
                AllowedToAuthenticate::Denied,
                "{sid}"
            );
        }
        for sid in ["S-1-5-4", "S-1-5-11", "S-1-1-0", "S-1-5-21-1-2-3-500"] {
            assert!(!certainly_absent_in_check(sid), "{sid}");
        }
        // The default pair on a DC's computer object: SYSTEM GenericAll,
        // Administrators with all extended rights — denied, not unknown.
        let d = sd(vec![
            ace(0, 0, GENERIC_ALL, None, "S-1-5-18"),
            ace(0, 0x10, 0x100, None, "S-1-5-32-544"),
        ]);
        assert_eq!(
            allowed_to_authenticate(&d, &set(&[USER]), &set(&[])),
            AllowedToAuthenticate::Denied
        );
    }

    #[test]
    fn damaged_or_unsupported_descriptors_are_unknown_never_allowed() {
        for bad in [
            vec![1u8, 0, 0],
            {
                let mut d = sd(vec![ace(5, 0, 0x100, Some(ALLOWED_TO_AUTHENTICATE), USER)]);
                d.truncate(d.len() - 3);
                d
            },
            sd(vec![{
                let mut a = ace(0, 0, 0x100, None, USER);
                a[0] = 0x0B; // callback ACE
                a
            }]),
        ] {
            assert!(matches!(
                allowed_to_authenticate(&bad, &set(&[USER]), &set(&[])),
                AllowedToAuthenticate::Unknown { .. }
            ));
        }
    }

    #[test]
    fn a_null_dacl_restricts_nothing() {
        let mut d = vec![1u8, 0];
        d.extend_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
        d.extend_from_slice(&[0; 16]);
        assert!(matches!(
            allowed_to_authenticate(&d, &set(&[USER]), &set(&[])),
            AllowedToAuthenticate::Allowed { .. }
        ));
    }
}
