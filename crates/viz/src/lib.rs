// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! viz — the permission graph (ADR 0077).
//!
//! [`permission_graph`] turns a finished [`EffectivePermission`] into a lane
//! layout: **account → token groups → NTFS ACEs → NTFS → share ACEs →
//! result**, read left to right like the explanation path. It is pure
//! presentation: every node and edge comes from the result's
//! [`PermissionTrace`](adpa_core::model::PermissionTrace) and its values —
//! no permission logic here.
//!
//! One layout, two renderings, so screen and report cannot drift apart:
//! [`GraphLayout::to_svg`] is the complete SVG the HTML report embeds;
//! the GUI draws [`GraphLayout::to_svg_shapes`] (boxes and edges only —
//! Slint's SVG renderer has no fonts) and puts [`GraphLayout::texts`] on
//! top as native text at the same coordinates.
//!
//! Colours carry one meaning each: green — an Allow decided bits; red — a
//! Deny decided bits; amber dashed — uncertain (counts only for certain
//! logons or session states); grey dashed — matched without effect,
//! inherit-only or not applied (deny-only).

use adpa_core::model::{
    AceEffect, AceKind, AceOutcome, EffectivePermission, ShareEvalStatus, TraceGroup,
    TraceGroupState, TraceLayer,
};
use permission_engine::{rights_label_compact, NormalizedRights};

const NODE_W: f64 = 250.0;
const NODE_H: f64 = 46.0;
const RESULT_H: f64 = 62.0;
const GAP_Y: f64 = 12.0;
const GAP_X: f64 = 70.0;
const MARGIN: f64 = 20.0;
const HEADER_H: f64 = 28.0;
const LEGEND_H: f64 = 40.0;
const TEXT_MAX: usize = 34;
/// Vertical distance between two routing tracks below the nodes.
const TRACK_GAP: f64 = 7.0;
/// Font size of every text in the graph, in px.
pub const FONT_SIZE: f64 = 12.0;

const C_TEXT: &str = "#1f2937";
const C_MUTED: &str = "#6b7280";
const C_BORDER: &str = "#9ca3af";
const C_BG: &str = "#ffffff";
const C_NODE: &str = "#f8fafc";
const C_GREEN: &str = "#15803d";
const C_RED: &str = "#b91c1c";
const C_AMBER: &str = "#b45309";
const C_GREY: &str = "#9ca3af";

/// How an edge or a node border is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    Plain,
    Granted,
    Denied,
    Uncertain,
    Inactive,
}

impl Look {
    fn colour(self) -> &'static str {
        match self {
            Look::Plain => C_BORDER,
            Look::Granted => C_GREEN,
            Look::Denied => C_RED,
            Look::Uncertain => C_AMBER,
            Look::Inactive => C_GREY,
        }
    }
    fn dash(self) -> &'static str {
        if matches!(self, Look::Uncertain | Look::Inactive) {
            " stroke-dasharray=\"5 4\""
        } else {
            ""
        }
    }
    fn width(self) -> f64 {
        match self {
            Look::Granted | Look::Denied => 2.0,
            _ => 1.2,
        }
    }
}

/// The role of a text line, which decides its colour and weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextStyle {
    /// Lane header.
    Heading,
    /// First line of a node.
    Primary,
    /// Further node lines and the legend.
    Secondary,
}

impl TextStyle {
    /// The fixed colour of this text (the graph has a fixed light canvas).
    pub fn colour(self) -> &'static str {
        match self {
            TextStyle::Primary => C_TEXT,
            _ => C_MUTED,
        }
    }
    /// Whether this text is bold.
    pub fn bold(self) -> bool {
        !matches!(self, TextStyle::Secondary)
    }
}

/// One text line; `baseline` is the y of its baseline, as in SVG.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphText {
    pub x: f64,
    pub baseline: f64,
    pub text: String,
    pub style: TextStyle,
}

#[derive(Debug, Clone)]
struct Node {
    col: usize,
    x: f64,
    y: f64,
    h: f64,
    lines: Vec<String>,
    /// The full text, shown as a tooltip in the SVG.
    title: String,
    look: Look,
}

#[derive(Debug, Clone)]
struct Edge {
    from: usize,
    to: usize,
    look: Look,
    /// For an edge that skips a lane: its routing track below the nodes,
    /// so it never crosses a node it does not connect (ADR 0077).
    track: Option<usize>,
}

/// The laid-out permission graph of one result.
#[derive(Debug, Clone)]
pub struct GraphLayout {
    pub width: f64,
    pub height: f64,
    /// Every text of the graph — lane headers, node lines, legend.
    pub texts: Vec<GraphText>,
    title: String,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// (x, y, look) of each legend swatch.
    legend: Vec<(f64, f64, Look)>,
    /// y of the first routing track.
    track_y0: f64,
}

fn effect_look(ace: &AceOutcome) -> Look {
    match (&ace.effect, ace.kind) {
        (AceEffect::Decided { .. }, AceKind::Allow) => Look::Granted,
        (AceEffect::Decided { .. }, AceKind::Deny) => Look::Denied,
        (AceEffect::Uncertain { .. }, _) => Look::Uncertain,
        _ => Look::Inactive,
    }
}

fn effect_text(ace: &AceOutcome) -> String {
    match &ace.effect {
        AceEffect::Decided { bits } => {
            let verb = if ace.kind == AceKind::Allow {
                "grants"
            } else {
                "denies"
            };
            format!("{verb} {}", NormalizedRights::new(*bits).display_name())
        }
        AceEffect::NoEffect => "no effective bits".to_owned(),
        AceEffect::InheritOnly => "inherit-only — not on this object".to_owned(),
        AceEffect::Uncertain { .. } => "UNCERTAIN".to_owned(),
        AceEffect::NotApplied { .. } => "not applied (deny-only)".to_owned(),
    }
}

fn group_look(g: &TraceGroup) -> Look {
    match g.state {
        TraceGroupState::Uncertain => Look::Uncertain,
        TraceGroupState::DenyOnly => Look::Inactive,
        _ => Look::Plain,
    }
}

fn shorten(s: &str) -> String {
    if s.chars().count() <= TEXT_MAX {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(TEXT_MAX - 1).collect();
        format!("{cut}…")
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The trustee without its SID suffix, for the first node line.
fn short_name(display: &str) -> &str {
    match display.rfind(" (S-") {
        Some(i) => &display[..i],
        None => display,
    }
}

/// The permission graph of one result, or `None` when the result carries
/// no trace (no ACE on the object, or a result stored before ADR 0077).
pub fn permission_graph(p: &EffectivePermission) -> Option<GraphLayout> {
    if p.trace.is_empty() {
        return None;
    }
    let share_applied = matches!(p.share_status, ShareEvalStatus::Applied);
    let lanes: Vec<&str> = if share_applied {
        vec![
            "Account",
            "Token groups",
            "NTFS ACEs",
            "NTFS",
            "Share ACEs",
            "Result",
        ]
    } else {
        vec!["Account", "Token groups", "NTFS ACEs", "NTFS", "Result"]
    };
    let lane_x = |i: usize| MARGIN + i as f64 * (NODE_W + GAP_X);
    let shown = |a: &AceOutcome| a.layer == TraceLayer::Ntfs || share_applied;

    let mut nodes: Vec<Node> = Vec::new();
    let mut columns: Vec<Vec<usize>> = vec![Vec::new(); lanes.len()];
    let mut push = |nodes: &mut Vec<Node>,
                    col: usize,
                    lines: Vec<String>,
                    title: String,
                    look: Look,
                    h: f64| {
        nodes.push(Node {
            col,
            x: lane_x(col),
            y: 0.0,
            h,
            lines,
            title,
            look,
        });
        columns[col].push(nodes.len() - 1);
        nodes.len() - 1
    };

    let account = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
    let account_node = push(
        &mut nodes,
        0,
        vec![shorten(account), shorten(&p.identity.sid.0)],
        format!("{account} ({})", p.identity.sid.0),
        Look::Plain,
        NODE_H,
    );

    // An ACE that names the account itself gets its own pass-through node
    // in the group lane — otherwise its edge would cross the lane and look
    // as if it came through a group.
    let direct_node = if p
        .trace
        .aces
        .iter()
        .any(|a| shown(a) && a.sid == p.identity.sid)
    {
        Some(push(
            &mut nodes,
            1,
            vec![
                "the account itself".to_owned(),
                "ACE names the account directly".to_owned(),
            ],
            format!("An ACE names {account} directly — no group involved"),
            Look::Plain,
            NODE_H,
        ))
    } else {
        None
    };

    let mut group_nodes: Vec<(String, usize, Look)> = Vec::new();
    for g in &p.trace.groups {
        let state = match g.state {
            TraceGroupState::Member => "",
            TraceGroupState::DenyOnly => " · deny-only",
            TraceGroupState::Uncertain => " · uncertain",
            TraceGroupState::Implicit => " · implicit",
        };
        let decisive = if g.decisive { " · decisive" } else { "" };
        let idx = push(
            &mut nodes,
            1,
            vec![
                shorten(short_name(&g.display)),
                shorten(&format!("{}{state}{decisive}", g.route)),
            ],
            format!("{} — {}{state}{decisive}", g.display, g.route),
            group_look(g),
            NODE_H,
        );
        group_nodes.push((g.sid.0.clone(), idx, group_look(g)));
    }
    if p.trace.other_groups > 0 {
        push(
            &mut nodes,
            1,
            vec![
                format!("+{} further groups", p.trace.other_groups),
                "no ACE on this object".to_owned(),
            ],
            format!(
                "{} further memberships — no ACE on this object names them",
                p.trace.other_groups
            ),
            Look::Inactive,
            NODE_H,
        );
    }

    let ace_line = |a: &AceOutcome| {
        let kind = if a.kind == AceKind::Allow {
            "Allow"
        } else {
            "Deny"
        };
        let scope = if a.inherited { " (inherited)" } else { "" };
        format!(
            "{kind} {}{scope}",
            NormalizedRights::new(permission_engine::mask::expand_generic_rights(a.mask.0))
                .display_name()
        )
    };
    let mut ace_nodes: Vec<(usize, &AceOutcome)> = Vec::new();
    for a in p.trace.aces.iter().filter(|a| shown(a)) {
        let col = if a.layer == TraceLayer::Ntfs { 2 } else { 4 };
        let reason = match &a.effect {
            AceEffect::Uncertain { reason } | AceEffect::NotApplied { reason } => {
                format!(" — {reason}")
            }
            _ => String::new(),
        };
        let idx = push(
            &mut nodes,
            col,
            vec![
                shorten(&ace_line(a)),
                shorten(short_name(&a.trustee)),
                shorten(&effect_text(a)),
            ],
            format!(
                "{} for {} → {}{reason}",
                ace_line(a),
                a.trustee,
                effect_text(a)
            ),
            effect_look(a),
            RESULT_H,
        );
        ace_nodes.push((idx, a));
    }

    // An empty ACE lane says so — an empty column would leave the admin
    // guessing why the layer grants nothing.
    let ace_lanes: &[(usize, TraceLayer, &str)] = if share_applied {
        &[
            (2, TraceLayer::Ntfs, "NTFS"),
            (4, TraceLayer::Share, "share"),
        ]
    } else {
        &[(2, TraceLayer::Ntfs, "NTFS")]
    };
    for (col, layer, name) in ace_lanes {
        if !ace_nodes.iter().any(|(_, a)| a.layer == *layer) {
            push(
                &mut nodes,
                *col,
                vec![
                    "no ACE reaches the account".to_owned(),
                    "see the permission path".to_owned(),
                ],
                format!(
                    "No {name} ACE names the account or a group in its token — the permission path explains why (for example an ACE only for interactive logons)"
                ),
                Look::Inactive,
                NODE_H,
            );
        }
    }

    let ntfs_label = rights_label_compact(p.ntfs_mask.0, p.ntfs_determinable());
    let ntfs_node = push(
        &mut nodes,
        3,
        vec!["NTFS".to_owned(), shorten(&ntfs_label)],
        format!("NTFS: {ntfs_label} (0x{:08X})", p.ntfs_mask.0),
        if p.ntfs_determinable() {
            Look::Plain
        } else {
            Look::Uncertain
        },
        NODE_H,
    );
    let effective = rights_label_compact(p.effective_mask.0, p.effective_determinable());
    let detail = match (&p.share_status, p.share_mask) {
        (ShareEvalStatus::Applied, Some(share)) => format!(
            "share {}",
            rights_label_compact(share.0, p.share_determinable())
        ),
        (ShareEvalStatus::ReadFailed(_), _) => "share not determinable".to_owned(),
        (ShareEvalStatus::Unrestricted, _) => "share unrestricted (NULL DACL)".to_owned(),
        _ => "no SMB share".to_owned(),
    };
    let result_node = push(
        &mut nodes,
        lanes.len() - 1,
        vec![
            "Effective".to_owned(),
            shorten(&effective),
            shorten(&detail),
        ],
        format!(
            "Effective: {effective} (0x{:08X}) — {detail}",
            p.effective_mask.0
        ),
        if p.effective_determinable() {
            Look::Plain
        } else {
            Look::Uncertain
        },
        RESULT_H,
    );

    // Vertical placement: every column centred on the tallest one.
    let col_h = |col: &Vec<usize>, nodes: &Vec<Node>| {
        col.iter().map(|i| nodes[*i].h).sum::<f64>() + GAP_Y * (col.len().saturating_sub(1)) as f64
    };
    let max_h = columns.iter().map(|c| col_h(c, &nodes)).fold(0.0, f64::max);
    for col in &columns {
        let mut y = MARGIN + HEADER_H + (max_h - col_h(col, &nodes)) / 2.0;
        for i in col {
            nodes[*i].y = y;
            y += nodes[*i].h + GAP_Y;
        }
    }

    // Edges.
    let mut edges: Vec<Edge> = Vec::new();
    if let Some(d) = direct_node {
        edges.push(Edge {
            from: account_node,
            to: d,
            look: Look::Plain,
            track: None,
        });
    }
    for (_, idx, look) in &group_nodes {
        edges.push(Edge {
            from: account_node,
            to: *idx,
            look: *look,
            track: None,
        });
    }
    for (idx, a) in &ace_nodes {
        let source = if a.sid == p.identity.sid {
            direct_node
        } else {
            group_nodes
                .iter()
                .find(|(sid, _, _)| sid == &a.sid.0)
                .map(|(_, i, _)| *i)
        };
        if let Some(src) = source {
            edges.push(Edge {
                from: src,
                to: *idx,
                look: effect_look(a),
                track: None,
            });
        }
        let target = if a.layer == TraceLayer::Ntfs {
            ntfs_node
        } else {
            result_node
        };
        edges.push(Edge {
            from: *idx,
            to: target,
            look: effect_look(a),
            track: None,
        });
    }
    edges.push(Edge {
        from: ntfs_node,
        to: result_node,
        look: Look::Plain,
        track: None,
    });

    // Edges that skip a lane (group → share ACE, NTFS → result past the
    // share lane) run on their own track below all nodes.
    let mut tracks = 0;
    for e in &mut edges {
        if nodes[e.to].col > nodes[e.from].col + 1 {
            e.track = Some(tracks);
            tracks += 1;
        }
    }
    let track_y0 = MARGIN + HEADER_H + max_h + TRACK_GAP;
    let tracks_h = if tracks > 0 {
        TRACK_GAP * (tracks + 1) as f64
    } else {
        0.0
    };

    // Texts and legend.
    let width = MARGIN * 2.0 + lanes.len() as f64 * NODE_W + (lanes.len() - 1) as f64 * GAP_X;
    let height = MARGIN * 2.0 + HEADER_H + max_h + tracks_h + LEGEND_H;
    let mut texts: Vec<GraphText> = lanes
        .iter()
        .enumerate()
        .map(|(i, name)| GraphText {
            x: lane_x(i),
            baseline: MARGIN + 14.0,
            text: (*name).to_owned(),
            style: TextStyle::Heading,
        })
        .collect();
    for n in &nodes {
        for (k, line) in n.lines.iter().enumerate() {
            texts.push(GraphText {
                x: n.x + 10.0,
                baseline: n.y + 18.0 + k as f64 * 16.0,
                text: line.clone(),
                style: if k == 0 {
                    TextStyle::Primary
                } else {
                    TextStyle::Secondary
                },
            });
        }
    }
    let ly = height - MARGIN - 14.0;
    let mut legend = Vec::new();
    let mut lx = MARGIN;
    for (look, text) in [
        (Look::Granted, "Allow decided bits"),
        (Look::Denied, "Deny decided bits"),
        (Look::Uncertain, "uncertain (logon / session)"),
        (Look::Inactive, "no effect · inherit-only · deny-only"),
    ] {
        legend.push((lx, ly, look));
        texts.push(GraphText {
            x: lx + 34.0,
            baseline: ly + 4.0,
            text: text.to_owned(),
            style: TextStyle::Secondary,
        });
        lx += 34.0 + text.chars().count() as f64 * 6.4 + 28.0;
    }

    Some(GraphLayout {
        width,
        height,
        texts,
        title: format!("Permission graph — {}", p.path.0),
        nodes,
        edges,
        legend,
        track_y0,
    })
}

impl GraphLayout {
    /// The complete SVG — shapes, texts and `<title>` tooltips; every text
    /// is XML-escaped.
    pub fn to_svg(&self) -> String {
        self.render(true)
    }

    /// Boxes, edges and legend swatches only, for a renderer that draws
    /// [`GraphLayout::texts`] itself.
    pub fn to_svg_shapes(&self) -> String {
        self.render(false)
    }

    fn render(&self, with_text: bool) -> String {
        let (width, height) = (self.width, self.height);
        let mut s = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" viewBox=\"0 0 {width:.0} {height:.0}\" font-family=\"Segoe UI, Arial, sans-serif\" font-size=\"{FONT_SIZE:.0}\">"
        );
        if with_text {
            s.push_str(&format!("<title>{}</title>", esc(&self.title)));
        }
        s.push_str(&format!(
            "<rect width=\"100%\" height=\"100%\" fill=\"{C_BG}\"/>"
        ));
        for e in &self.edges {
            let (a, b) = (&self.nodes[e.from], &self.nodes[e.to]);
            let (x1, y1) = (a.x + NODE_W, a.y + a.h / 2.0);
            let (x2, y2) = (b.x, b.y + b.h / 2.0);
            let d = match e.track {
                // Down into the gap after the source lane, along the track
                // below the nodes, up in the gap before the target lane.
                Some(t) => {
                    let ty = self.track_y0 + t as f64 * TRACK_GAP;
                    let (xa, xb) = (x1 + GAP_X, x2 - GAP_X);
                    let (ma, mb) = (x1 + GAP_X / 2.0, x2 - GAP_X / 2.0);
                    format!(
                        "M{x1:.1},{y1:.1} C{ma:.1},{y1:.1} {ma:.1},{ty:.1} {xa:.1},{ty:.1} L{xb:.1},{ty:.1} C{mb:.1},{ty:.1} {mb:.1},{y2:.1} {x2:.1},{y2:.1}"
                    )
                }
                None => {
                    let mid = (x1 + x2) / 2.0;
                    format!("M{x1:.1},{y1:.1} C{mid:.1},{y1:.1} {mid:.1},{y2:.1} {x2:.1},{y2:.1}")
                }
            };
            s.push_str(&format!(
                "<path d=\"{d}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{:.1}\"{}/>",
                e.look.colour(),
                e.look.width(),
                e.look.dash()
            ));
        }
        for n in &self.nodes {
            s.push_str("<g>");
            if with_text {
                s.push_str(&format!("<title>{}</title>", esc(&n.title)));
            }
            s.push_str(&format!(
                "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{NODE_W:.0}\" height=\"{:.1}\" rx=\"6\" fill=\"{C_NODE}\" stroke=\"{}\" stroke-width=\"{:.1}\"{}/></g>",
                n.x,
                n.y,
                n.h,
                n.look.colour(),
                n.look.width(),
                n.look.dash()
            ));
        }
        for (x, y, look) in &self.legend {
            s.push_str(&format!(
                "<line x1=\"{x:.1}\" y1=\"{y:.1}\" x2=\"{:.1}\" y2=\"{y:.1}\" stroke=\"{}\" stroke-width=\"{:.1}\"{}/>",
                x + 28.0,
                look.colour(),
                look.width(),
                look.dash()
            ));
        }
        if with_text {
            for t in &self.texts {
                let weight = if t.style.bold() {
                    " font-weight=\"600\""
                } else {
                    ""
                };
                s.push_str(&format!(
                    "<text x=\"{:.1}\" y=\"{:.1}\" fill=\"{}\"{weight}>{}</text>",
                    t.x,
                    t.baseline,
                    t.style.colour(),
                    esc(&t.text)
                ));
            }
        }
        s.push_str("</svg>");
        s
    }
}

/// The complete permission graph SVG of one result (see
/// [`permission_graph`]).
pub fn permission_graph_svg(p: &EffectivePermission) -> Option<String> {
    permission_graph(p).map(|g| g.to_svg())
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{
        AccessMask, Identity, IdentityKind, LocalGroupEvalStatus, NormalizedPath, PermissionPath,
        PermissionTrace, Sid,
    };

    const USER: &str = "S-1-5-21-1-2-3-1000";

    fn result(trace: PermissionTrace, share: Option<u32>) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid(USER.into()),
                name: Some("alice".into()),
                domain: None,
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            path: NormalizedPath(r"\\fs\Data$\Finance <x>".into()),
            ntfs_mask: AccessMask(0x0013_01BF),
            share_mask: share.map(AccessMask),
            effective_mask: AccessMask(share.unwrap_or(0x0013_01BF) & 0x0013_01BF),
            path_explanation: PermissionPath { steps: vec![] },
            share_status: if share.is_some() {
                ShareEvalStatus::Applied
            } else {
                ShareEvalStatus::NotApplicable
            },
            local_group_status: LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
            trace,
        }
    }

    fn ace(layer: TraceLayer, kind: AceKind, sid: &str, effect: AceEffect) -> AceOutcome {
        AceOutcome {
            layer,
            kind,
            sid: Sid(sid.into()),
            trustee: format!("G {sid} ({sid})"),
            mask: AccessMask(0x0013_01BF),
            inherited: true,
            effect,
        }
    }

    fn group(sid: &str, name: &str, state: TraceGroupState) -> TraceGroup {
        TraceGroup {
            sid: Sid(sid.into()),
            display: format!("{name} ({sid})"),
            route: "direct".into(),
            state,
            decisive: true,
        }
    }

    fn trace() -> PermissionTrace {
        PermissionTrace {
            aces: vec![
                ace(
                    TraceLayer::Ntfs,
                    AceKind::Allow,
                    "S-1-5-21-1-2-3-2001",
                    AceEffect::Decided { bits: 0x0013_01BF },
                ),
                ace(
                    TraceLayer::Ntfs,
                    AceKind::Deny,
                    "S-1-5-21-1-2-3-2002",
                    AceEffect::Decided { bits: 0x2 },
                ),
                ace(
                    TraceLayer::Ntfs,
                    AceKind::Allow,
                    "S-1-5-32-544",
                    AceEffect::Uncertain {
                        reason: "UAC".into(),
                    },
                ),
                ace(
                    TraceLayer::Share,
                    AceKind::Allow,
                    "S-1-1-0",
                    AceEffect::Decided { bits: 0x0012_00A9 },
                ),
            ],
            groups: vec![
                group("S-1-5-21-1-2-3-2001", "Finance", TraceGroupState::Member),
                group("S-1-5-21-1-2-3-2002", "Temps", TraceGroupState::Member),
                group("S-1-5-32-544", "Administrators", TraceGroupState::DenyOnly),
                group("S-1-1-0", "Everyone", TraceGroupState::Implicit),
            ],
            other_groups: 57,
        }
    }

    fn has_text(g: &GraphLayout, t: &str) -> bool {
        g.texts.iter().any(|x| x.text == t)
    }

    #[test]
    fn no_trace_no_graph() {
        assert!(permission_graph(&result(PermissionTrace::default(), None)).is_none());
    }

    #[test]
    fn graph_has_the_lanes_nodes_and_colours_of_the_trace() {
        let p = result(trace(), Some(0x0012_00A9));
        let g = permission_graph(&p).unwrap();
        for lane in [
            "Account",
            "Token groups",
            "NTFS ACEs",
            "NTFS",
            "Share ACEs",
            "Result",
        ] {
            assert!(has_text(&g, lane), "{lane}");
        }
        assert!(has_text(&g, "Finance") && has_text(&g, "+57 further groups"));
        // account→4 groups, 4 ACEs with source and target each, NTFS→result
        assert_eq!(g.edges.len(), 4 + 4 * 2 + 1);
        let svg = g.to_svg();
        assert!(svg.contains(C_GREEN) && svg.contains(C_RED) && svg.contains(C_AMBER));
        assert!(svg.contains("deny-only"));
        assert!(svg.contains("&lt;x&gt;"), "the path is escaped");
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
    }

    /// An ACE on the account itself is routed through its own node in the
    /// group lane, never through a group node.
    #[test]
    fn direct_ace_has_its_own_node_in_the_group_lane() {
        let t = PermissionTrace {
            aces: vec![ace(
                TraceLayer::Ntfs,
                AceKind::Allow,
                USER,
                AceEffect::Decided { bits: 0x0013_01BF },
            )],
            groups: vec![],
            other_groups: 3,
        };
        let g = permission_graph(&result(t, None)).unwrap();
        assert!(has_text(&g, "the account itself"));
        // account→direct, direct→ACE, ACE→NTFS, NTFS→result
        assert_eq!(g.edges.len(), 4);
        let direct = g
            .nodes
            .iter()
            .position(|n| n.lines[0] == "the account itself")
            .unwrap();
        let ace = g
            .nodes
            .iter()
            .position(|n| n.lines[0].starts_with("Allow"))
            .unwrap();
        assert!(g.edges.iter().any(|e| e.from == direct && e.to == ace));
        assert!(!g.edges.iter().any(|e| e.from == 0 && e.to == ace));
    }

    /// An edge that skips a lane never runs straight through the lanes in
    /// between — it is routed on its own track below every node.
    #[test]
    fn lane_skipping_edges_run_below_the_nodes() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let bottom = g.nodes.iter().map(|n| n.y + n.h).fold(0.0, f64::max);
        let mut tracks: Vec<usize> = Vec::new();
        for e in &g.edges {
            let skips = g.nodes[e.to].col > g.nodes[e.from].col + 1;
            assert_eq!(skips, e.track.is_some());
            if let Some(t) = e.track {
                assert!(!tracks.contains(&t), "one track per edge");
                tracks.push(t);
            }
        }
        // Everyone → share ACE, and NTFS → result past the share lane.
        assert_eq!(tracks.len(), 2);
        assert!(g.track_y0 > bottom);
        assert!(g.track_y0 + 2.0 * TRACK_GAP < g.height - LEGEND_H);
    }

    /// A lane without any ACE for the account carries an explicit node.
    #[test]
    fn empty_ace_lane_says_so() {
        let t = PermissionTrace {
            aces: vec![ace(
                TraceLayer::Share,
                AceKind::Allow,
                "S-1-1-0",
                AceEffect::Decided { bits: 0x0012_00A9 },
            )],
            groups: vec![group("S-1-1-0", "Everyone", TraceGroupState::Implicit)],
            other_groups: 0,
        };
        let g = permission_graph(&result(t, Some(0x0012_00A9))).unwrap();
        let empty: Vec<&Node> = g
            .nodes
            .iter()
            .filter(|n| n.lines[0] == "no ACE reaches the account")
            .collect();
        assert_eq!(empty.len(), 1, "only the NTFS lane is empty");
        assert_eq!(empty[0].col, 2);
        assert_eq!(empty[0].look, Look::Inactive);
    }

    #[test]
    fn without_share_there_is_no_share_lane() {
        let g = permission_graph(&result(trace(), None)).unwrap();
        assert!(!has_text(&g, "Share ACEs"));
        assert!(has_text(&g, "no SMB share"));
        assert!(g.nodes.iter().all(|n| n.x < lane_count_x(5)));
    }

    fn lane_count_x(lanes: usize) -> f64 {
        MARGIN + lanes as f64 * (NODE_W + GAP_X)
    }

    #[test]
    fn shapes_svg_has_no_text_but_the_same_shapes() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let shapes = g.to_svg_shapes();
        assert!(!shapes.contains("<text") && !shapes.contains("<title"));
        let full = g.to_svg();
        assert_eq!(
            shapes.matches("<path ").count(),
            full.matches("<path ").count()
        );
        assert_eq!(
            shapes.matches("<rect ").count(),
            full.matches("<rect ").count()
        );
    }

    #[test]
    fn output_is_deterministic() {
        let a = permission_graph_svg(&result(trace(), Some(0x0012_00A9)));
        let b = permission_graph_svg(&result(trace(), Some(0x0012_00A9)));
        assert_eq!(a, b);
    }
}
