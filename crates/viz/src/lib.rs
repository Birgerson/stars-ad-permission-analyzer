// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! viz — the permission graph (ADR 0077, layout v2 ADR 0081).
//!
//! [`permission_graph`] turns a finished [`EffectivePermission`] into a
//! layout read left to right like the explanation path: **account → token
//! groups → ACEs → result per layer → (logon) → effective result**. The ACE
//! and layer columns carry two bands — NTFS on top, the share below — so
//! `effective = NTFS ∩ share` is visible as two inputs of one result node,
//! and every edge connects neighbouring columns (none crosses a box). It is
//! pure presentation: every node and edge comes from the result's
//! [`PermissionTrace`](adpa_core::model::PermissionTrace), its values and
//! markers — no permission logic here; the limiting side uses the engine's
//! own rule ([`permission_engine::limiting_side`]).
//!
//! One layout, two renderings, so screen and report cannot drift apart:
//! [`GraphLayout::to_svg_with`] is the complete SVG (the HTML report);
//! the GUI draws [`GraphLayout::to_svg_shapes_with`] (boxes and edges only —
//! Slint's SVG renderer has no fonts) and puts [`GraphLayout::texts`] on
//! top as native text at the same coordinates. Both come in a light and a
//! dark palette.
//!
//! Colours carry one meaning each: green — an Allow decided bits; red, as a
//! double line — a Deny decided bits; amber dashed — uncertain (counts only
//! for certain logons or session states); grey dashed — matched without
//! effect, inherit-only or not applied (deny-only); slate — the result of a
//! layer flowing into the effective right. A thick line is on the decisive
//! route.

use adpa_core::model::{
    AceEffect, AceKind, AceOutcome, EffectivePermission, IdentityKind, PermissionDiagnostic,
    ShareEvalStatus, TraceGroup, TraceGroupState, TraceLayer,
};
use permission_engine::mask::expand_generic_rights;
use permission_engine::{limiting_side, LimitingSide, NormalizedRights};

const NODE_W: f64 = 270.0;
const GAP_Y: f64 = 12.0;
const GAP_X: f64 = 60.0;
const MARGIN: f64 = 20.0;
const HEADER_H: f64 = 28.0;
const CAPTION_H: f64 = 26.0;
/// Room between the NTFS band and the share band (incl. the band headers).
const BAND_GAP: f64 = 38.0;
const FIRST_BASELINE: f64 = 18.0;
const LINE_H: f64 = 16.0;
const BOTTOM_PAD: f64 = 12.0;
const TEXT_PAD: f64 = 10.0;
/// Average advance of one character at [`FONT_SIZE`] — used to fit texts
/// into a box instead of cutting them off. The graph is drawn in Arial (the
/// GUI's font, ADR 0083); measured at 12 px, mixed text needs 5–6 px per
/// character, a capitals-only rights label such as `RX+WA,WEA,DC,DE,WDAC,WO`
/// about 7.8 px, so such a label can still overrun a box edge.
const CHAR_W: f64 = 6.7;
const LEGEND_ROW_H: f64 = 22.0;
const LEGEND_SWATCH: f64 = 28.0;
/// The report scales a graph down to this share of its width, not further.
const MIN_SCALE: f64 = 0.8;
/// Font size of every text in the graph, in px.
pub const FONT_SIZE: f64 = 12.0;

/// How many characters fit into one line of a box.
fn max_chars() -> usize {
    ((NODE_W - 2.0 * TEXT_PAD) / CHAR_W) as usize
}

/// The colours of one theme.
struct Palette {
    bg: &'static str,
    node: &'static str,
    text: &'static str,
    muted: &'static str,
    border: &'static str,
    green: &'static str,
    red: &'static str,
    amber: &'static str,
    grey: &'static str,
    value: &'static str,
}

const LIGHT: Palette = Palette {
    bg: "#ffffff",
    node: "#f8fafc",
    text: "#1f2937",
    muted: "#6b7280",
    border: "#9ca3af",
    green: "#15803d",
    red: "#b91c1c",
    amber: "#b45309",
    grey: "#9ca3af",
    value: "#475569",
};

const DARK: Palette = Palette {
    bg: "#161b26",
    node: "#1f2633",
    text: "#e5e7eb",
    muted: "#9ca3af",
    border: "#4b5563",
    green: "#22c55e",
    red: "#f87171",
    amber: "#f59e0b",
    grey: "#6b7280",
    value: "#cbd5e1",
};

fn palette(dark: bool) -> &'static Palette {
    if dark {
        &DARK
    } else {
        &LIGHT
    }
}

/// How an edge or a node border is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    Plain,
    Granted,
    Denied,
    Uncertain,
    Inactive,
    /// The result of a layer flowing into the effective right.
    Value,
}

impl Look {
    fn colour(self, p: &Palette) -> &'static str {
        match self {
            Look::Plain => p.border,
            Look::Granted => p.green,
            Look::Denied => p.red,
            Look::Uncertain => p.amber,
            Look::Inactive => p.grey,
            Look::Value => p.value,
        }
    }
    fn dash(self) -> &'static str {
        if matches!(self, Look::Uncertain | Look::Inactive) {
            " stroke-dasharray=\"5 4\""
        } else {
            ""
        }
    }
    fn width(self, strong: bool) -> f64 {
        let base = match self {
            Look::Granted | Look::Denied => 2.0,
            Look::Value => 1.6,
            _ => 1.2,
        };
        if strong {
            base + 1.2
        } else {
            base
        }
    }
}

/// The role of a text line, which decides its colour and weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextStyle {
    /// Column header and caption.
    Heading,
    /// First line of a node.
    Primary,
    /// Further node lines and the legend.
    Secondary,
    /// A line that deserves attention (not determinable, no SYNCHRONIZE).
    Caution,
    /// A line that changes the answer (logon refused).
    Alert,
}

impl TextStyle {
    /// The colour of this text in the light palette.
    pub fn colour(self) -> &'static str {
        self.colour_in(false)
    }
    /// The colour of this text in the light or the dark palette.
    pub fn colour_in(self, dark: bool) -> &'static str {
        let p = palette(dark);
        match self {
            TextStyle::Primary => p.text,
            TextStyle::Heading | TextStyle::Secondary => p.muted,
            TextStyle::Caution => p.amber,
            TextStyle::Alert => p.red,
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
    /// The box this line belongs to (an index into
    /// [`GraphLayout::node_boxes`]); `None` for caption, headers and legend.
    pub node: Option<usize>,
}

/// One box of the graph as a frontend sees it — for a click target and its
/// full text.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeBox {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    /// The complete text of the box (the SVG tooltip).
    pub title: String,
}

#[derive(Debug, Clone)]
struct Node {
    col: usize,
    x: f64,
    y: f64,
    h: f64,
    lines: Vec<(String, TextStyle)>,
    /// The full text, shown as a tooltip in the SVG.
    title: String,
    look: Look,
}

#[derive(Debug, Clone)]
struct Edge {
    from: usize,
    to: usize,
    look: Look,
    /// On the decisive route: drawn thicker.
    strong: bool,
}

#[derive(Debug, Clone)]
struct LegendItem {
    x: f64,
    y: f64,
    look: Look,
    strong: bool,
}

/// The laid-out permission graph of one result.
#[derive(Debug, Clone)]
pub struct GraphLayout {
    pub width: f64,
    pub height: f64,
    /// Every text of the graph — caption, headers, node lines, legend.
    pub texts: Vec<GraphText>,
    /// `name (SID)` of every membership no ACE on this object names — for a
    /// frontend that lists them next to the graph.
    pub further_groups: Vec<String>,
    title: String,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    legend: Vec<LegendItem>,
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

/// [`effect_text`] after `prefix`, in box lines: decided bits as
/// [`rights_lines`] puts them (none cut off), any other effect in one or
/// two lines.
fn effect_lines(prefix: &str, ace: &AceOutcome) -> Vec<String> {
    match &ace.effect {
        AceEffect::Decided { bits } => {
            let verb = if ace.kind == AceKind::Allow {
                "grants "
            } else {
                "denies "
            };
            rights_lines(&format!("{prefix}{verb}"), *bits)
        }
        AceEffect::InheritOnly => wrap2(&format!("{prefix}inherit-only — not on this object")),
        AceEffect::Uncertain { reason } => wrap2(&format!("{prefix}UNCERTAIN — {reason}")),
        _ => wrap2(&format!("{prefix}{}", effect_text(ace))),
    }
}

fn group_look(g: &TraceGroup) -> Look {
    match g.state {
        TraceGroupState::Uncertain => Look::Uncertain,
        TraceGroupState::DenyOnly => Look::Inactive,
        _ => Look::Plain,
    }
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Cuts at the end — for routes and reasons, whose start matters most.
fn fit(s: &str) -> String {
    let max = max_chars();
    if chars(s) <= max {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

/// Where a text longer than a box line breaks: after a comma or at a space,
/// never in the first half of the line; without either, at the box edge.
fn break_index(text: &[char]) -> usize {
    let max = max_chars();
    (max / 2..=max)
        .rev()
        .find(|&i| text[i - 1] == ',' || text[i] == ' ')
        .unwrap_or(max)
}

/// At most `max_lines` lines instead of a cut: the text breaks as
/// [`break_index`] says; only a last line that is still too long is cut
/// (the full text stays in the tooltip and the GUI detail).
fn wrap_lines(s: &str, max_lines: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut rest: Vec<char> = s.chars().collect();
    while rest.len() > max_chars() && lines.len() + 1 < max_lines {
        let cut = break_index(&rest);
        let line: String = rest[..cut].iter().collect();
        lines.push(line.trim_end().to_owned());
        rest = rest[cut..]
            .iter()
            .copied()
            .skip_while(|c| *c == ' ')
            .collect();
    }
    let last: String = rest.into_iter().collect();
    if !last.is_empty() || lines.is_empty() {
        lines.push(fit(&last));
    }
    lines
}

/// One or two lines — for routes and ACE reasons.
fn wrap2(s: &str) -> Vec<String> {
    wrap_lines(s, 2)
}

/// Lines of the reason why a layer or the logon is not determinable — the
/// core message of its box.
const REASON_LINES: usize = 4;

/// As many lines as the text needs, nothing cut — for rights, where every
/// bit counts.
fn wrap_all(s: &str) -> Vec<String> {
    wrap_lines(s, usize::MAX)
}

/// Keeps the start and the end — for identifiers whose tail matters.
fn fit_middle(s: &str) -> String {
    fit_middle_to(s, max_chars())
}

/// [`fit_middle`] into `max` characters.
fn fit_middle_to(s: &str, max: usize) -> String {
    if chars(s) <= max {
        return s.to_owned();
    }
    let head = (max - 1) / 2;
    let tail = max - 1 - head;
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(chars(s) - tail).collect();
    format!("{start}…{end}")
}

/// An account or group name: when it does not fit, the domain goes first
/// (`…\name`), then the middle.
fn fit_name(s: &str) -> String {
    if chars(s) <= max_chars() {
        return s.to_owned();
    }
    if let Some(i) = s.find('\\') {
        // "…\" takes two characters; the name keeps its start and its end.
        return format!("…\\{}", fit_middle_to(&s[i + 1..], max_chars() - 2));
    }
    fit_middle(s)
}

/// A SID keeps its authority prefix and its RID: `S-1-5-21-…-16182`.
fn fit_sid(sid: &str) -> String {
    if chars(sid) <= max_chars() {
        return sid.to_owned();
    }
    match (sid.starts_with("S-1-5-21-"), sid.rfind('-')) {
        (true, Some(i)) => format!("S-1-5-21-…{}", &sid[i..]),
        _ => fit_middle(sid),
    }
}

/// Every domain account or group SID in `s` as `S-1-5-21-…-RID`, as
/// [`fit_sid`] writes it — for box lines; the full text stays in the
/// tooltip and the GUI detail.
fn shorten_sids(s: &str) -> String {
    const PREFIX: &str = "S-1-5-21-";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(PREFIX) {
        out.push_str(&rest[..i]);
        out.push_str(PREFIX);
        let tail = &rest[i + PREFIX.len()..];
        let len = tail
            .find(|c: char| !(c.is_ascii_digit() || c == '-'))
            .unwrap_or(tail.len());
        let sid = tail[..len].trim_end_matches('-');
        let parts: Vec<&str> = sid.split('-').collect();
        match parts.as_slice() {
            // Domain identifier (three sub-authorities) and a RID.
            [.., rid] if parts.len() >= 4 && parts.iter().all(|p| !p.is_empty()) => {
                out.push_str("…-");
                out.push_str(rid);
            }
            _ => out.push_str(sid),
        }
        rest = &tail[sid.len()..];
    }
    out.push_str(rest);
    out
}

/// `prefix` + the rights, in as many box lines as needed — no bit is ever
/// cut off: the long form when it fits one line, else the icacls short form
/// (`(WD,AD,WA,WEA,S)`), which names every bit as well — after `prefix` when
/// it fits there, on a line of its own when it fits that, else broken after
/// a comma.
fn rights_lines(prefix: &str, mask: u32) -> Vec<String> {
    let rights = NormalizedRights::new(mask);
    let long = format!("{prefix}{}", rights.display_name());
    if chars(&long) <= max_chars() {
        return vec![long];
    }
    let label = rights.label();
    let short = format!("{prefix}{label}");
    let head = prefix.trim_end();
    if chars(&short) > max_chars() && !head.is_empty() && chars(&label) <= max_chars() {
        return vec![head.to_owned(), label];
    }
    wrap_all(&short)
}

/// The value lines of a result node: the right, or — when it is not
/// determinable — the verdict and the known data.
fn value_lines(mask: u32, determinable: bool) -> Vec<(String, TextStyle)> {
    let mut lines = Vec::new();
    let prefix = if determinable {
        ""
    } else {
        lines.push(("NOT DETERMINABLE".to_owned(), TextStyle::Caution));
        "known data: "
    };
    lines.extend(
        rights_lines(prefix, mask)
            .into_iter()
            .map(|l| (l, TextStyle::Secondary)),
    );
    lines
}

fn node_h(lines: usize) -> f64 {
    FIRST_BASELINE + lines.saturating_sub(1) as f64 * LINE_H + BOTTOM_PAD
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

fn kind_label(kind: &IdentityKind) -> &'static str {
    match kind {
        IdentityKind::User => "user",
        IdentityKind::Group => "group",
        IdentityKind::Computer => "computer",
        IdentityKind::WellKnown => "well-known",
        IdentityKind::ForeignSecurityPrincipal => "foreign principal",
        IdentityKind::Orphaned => "orphaned SID",
        IdentityKind::Unknown => "unknown kind",
    }
}

/// How much of the token the graph draws, and whether it carries a caption.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GraphOptions {
    /// `false` (default): the memberships no ACE names are one box
    /// "+N further groups" (their names in its tooltip). `true`: each of them
    /// gets its own grey dashed box.
    pub all_groups: bool,
    /// A caption line (account and path) at the top — for a graph saved on
    /// its own; the report row and the GUI tab show both already.
    pub caption: bool,
}

/// How a layout is rendered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderOptions {
    /// The dark palette (the HTML report, the GUI in dark mode).
    pub dark: bool,
    /// A node whose edges stay bright while the rest is faded (GUI click).
    pub highlight: Option<usize>,
    /// Scale with the available width (down to [`MIN_SCALE`]) — the report.
    pub responsive: bool,
}

/// How many names the "+N further groups" tooltip lists before it says
/// how many more there are.
const TOOLTIP_NAMES: usize = 40;

/// The permission graph of one result, or `None` when the result carries
/// no trace (no ACE on the object, or a result stored before ADR 0077).
pub fn permission_graph(p: &EffectivePermission) -> Option<GraphLayout> {
    permission_graph_with(p, GraphOptions::default())
}

/// The lines of one box: text and style.
type NodeLines = Vec<(String, TextStyle)>;

/// The Selective Authentication marker as a logon node (ADR 0079): look,
/// lines, full text.
fn logon_node(p: &EffectivePermission) -> Option<(Look, NodeLines, String)> {
    p.diagnostics.iter().find_map(|d| {
        let (look, first, last) = match d {
            PermissionDiagnostic::SelectiveAuthenticationAllowed { via, .. } => (
                Look::Granted,
                ("Logon allowed".to_owned(), TextStyle::Primary),
                format!("via {via}"),
            ),
            PermissionDiagnostic::SelectiveAuthenticationDenied { server } => (
                Look::Denied,
                ("Logon refused".to_owned(), TextStyle::Alert),
                format!("not \"Allowed to authenticate\" on {server}"),
            ),
            PermissionDiagnostic::SelectiveAuthenticationUnknown { reason, .. } => (
                Look::Uncertain,
                ("Logon not determinable".to_owned(), TextStyle::Caution),
                reason.clone(),
            ),
            _ => return None,
        };
        let mut lines = vec![
            first,
            ("Selective Authentication".to_owned(), TextStyle::Secondary),
        ];
        lines.extend(
            wrap_lines(&shorten_sids(&last), REASON_LINES)
                .into_iter()
                .map(|l| (l, TextStyle::Secondary)),
        );
        Some((look, lines, d.summary()))
    })
}

/// [`permission_graph`] with options.
pub fn permission_graph_with(p: &EffectivePermission, opts: GraphOptions) -> Option<GraphLayout> {
    if p.trace.is_empty() {
        return None;
    }
    let share_ctx = !matches!(p.share_status, ShareEvalStatus::NotApplicable);
    let share_applied = matches!(p.share_status, ShareEvalStatus::Applied);
    let logon = logon_node(p);
    let logon_refused = matches!(logon, Some((Look::Denied, _, _)));
    // ADR 0079 addendum: an undeterminable logon whose range collapses — the
    // permissions grant nothing, so No access either way.
    let logon_without_effect = p.diagnostics.iter().any(|d| {
        matches!(
            d,
            PermissionDiagnostic::SelectiveAuthenticationUnknown {
                affects_result: false,
                ..
            }
        )
    });
    let result_col = if logon.is_some() { 5 } else { 4 };
    let ncols = result_col + 1;
    let col_x = |c: usize| MARGIN + c as f64 * (NODE_W + GAP_X);
    let top0 = MARGIN + if opts.caption { CAPTION_H } else { 0.0 };
    let top = top0 + HEADER_H;
    let shown = |a: &AceOutcome| a.layer == TraceLayer::Ntfs || share_applied;

    let mut nodes: Vec<Node> = Vec::new();
    let push = |nodes: &mut Vec<Node>,
                col: usize,
                lines: Vec<(String, TextStyle)>,
                title: String,
                look: Look| {
        let h = node_h(lines.len());
        nodes.push(Node {
            col,
            x: col_x(col),
            y: 0.0,
            h,
            lines,
            title,
            look,
        });
        nodes.len() - 1
    };
    let primary = |s: String| (s, TextStyle::Primary);
    let secondary = |s: String| (s, TextStyle::Secondary);

    // Account.
    let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
    let account = match &p.identity.domain {
        Some(d) if !name.contains('\\') && !d.is_empty() => format!("{d}\\{name}"),
        _ => name.to_owned(),
    };
    let disabled = if p.identity.disabled {
        " · disabled"
    } else {
        ""
    };
    let account_node = push(
        &mut nodes,
        0,
        vec![
            primary(fit_name(&account)),
            secondary(fit(&format!(
                "{} · {}{disabled}",
                kind_label(&p.identity.kind),
                fit_sid(&p.identity.sid.0)
            ))),
        ],
        format!(
            "{account} ({}) — {}{disabled}",
            p.identity.sid.0,
            kind_label(&p.identity.kind)
        ),
        Look::Plain,
    );

    // Token groups. An ACE that names the account itself gets its own
    // pass-through node, so its edge never looks as if it came through a
    // group.
    let direct_decided = p.trace.aces.iter().any(|a| {
        shown(a) && a.sid == p.identity.sid && matches!(a.effect, AceEffect::Decided { .. })
    });
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
                primary("the account itself".to_owned()),
                secondary("ACE names the account directly".to_owned()),
            ],
            format!("An ACE names {account} directly — no group involved"),
            Look::Plain,
        ))
    } else {
        None
    };
    let mut group_nodes: Vec<(String, usize, Look, bool)> = Vec::new();
    for g in &p.trace.groups {
        let state = match g.state {
            TraceGroupState::Member => "",
            TraceGroupState::DenyOnly => " · deny-only",
            TraceGroupState::Uncertain => " · uncertain",
            TraceGroupState::Implicit => " · implicit",
        };
        let decisive = if g.decisive { " · decisive" } else { "" };
        let mut lines = vec![primary(fit_name(short_name(&g.display)))];
        lines.extend(
            wrap2(&format!("{}{state}{decisive}", g.route))
                .into_iter()
                .map(secondary),
        );
        let idx = push(
            &mut nodes,
            1,
            lines,
            format!("{} — {}{state}{decisive}", g.display, g.route),
            group_look(g),
        );
        group_nodes.push((g.sid.0.clone(), idx, group_look(g), g.decisive));
    }
    // The memberships no ACE names: one box each, or one summary box that
    // names them in its tooltip. A result stored before the names existed
    // (`other` empty, only the count) keeps the summary box.
    let further_groups: Vec<String> = p.trace.other.iter().map(|g| g.display.clone()).collect();
    let drawn_individually = if opts.all_groups {
        p.trace.other.len()
    } else {
        0
    };
    if opts.all_groups {
        for g in &p.trace.other {
            let state = match g.state {
                TraceGroupState::DenyOnly => " · deny-only",
                TraceGroupState::Uncertain => " · uncertain",
                _ => "",
            };
            let mut lines = vec![primary(fit_name(short_name(&g.display)))];
            lines.extend(
                wrap2(&format!("{}{state} · no ACE here", g.route))
                    .into_iter()
                    .map(secondary),
            );
            let idx = push(
                &mut nodes,
                1,
                lines,
                format!(
                    "{} — {}{state} — no ACE on this object names it",
                    g.display, g.route
                ),
                Look::Inactive,
            );
            group_nodes.push((g.sid.0.clone(), idx, Look::Inactive, false));
        }
    }
    let summarised = p.trace.other_groups.saturating_sub(drawn_individually);
    if summarised > 0 {
        let mut title =
            format!("{summarised} further memberships — no ACE on this object names them");
        if !opts.all_groups && !further_groups.is_empty() {
            let listed: Vec<&str> = further_groups
                .iter()
                .take(TOOLTIP_NAMES)
                .map(String::as_str)
                .collect();
            title.push_str(": ");
            title.push_str(&listed.join(", "));
            if further_groups.len() > TOOLTIP_NAMES {
                title.push_str(&format!(
                    " … and {} more",
                    further_groups.len() - TOOLTIP_NAMES
                ));
            }
        }
        push(
            &mut nodes,
            1,
            vec![
                primary(format!("+{summarised} further groups")),
                secondary("no ACE on this object".to_owned()),
            ],
            title,
            Look::Inactive,
        );
    }

    // ACEs, in two bands of one column: NTFS on top, the share below.
    let ace_title = |a: &AceOutcome| {
        let kind = if a.kind == AceKind::Allow {
            "Allow"
        } else {
            "Deny"
        };
        let scope = if a.inherited { " (inherited)" } else { "" };
        format!(
            "{kind} {}{scope}",
            NormalizedRights::new(expand_generic_rights(a.mask.0)).display_name()
        )
    };
    let mut ace_nodes: Vec<(usize, &AceOutcome)> = Vec::new();
    let mut ntfs_aces: Vec<usize> = Vec::new();
    let mut share_aces: Vec<usize> = Vec::new();
    for a in p.trace.aces.iter().filter(|a| shown(a)) {
        let kind = if a.kind == AceKind::Allow {
            "Allow "
        } else {
            "Deny "
        };
        let scope = if a.inherited {
            "inherited · "
        } else {
            "explicit · "
        };
        let reason = match &a.effect {
            AceEffect::Uncertain { reason } | AceEffect::NotApplied { reason } => {
                format!(" — {reason}")
            }
            _ => String::new(),
        };
        let mut lines: NodeLines = rights_lines(kind, expand_generic_rights(a.mask.0))
            .into_iter()
            .map(primary)
            .collect();
        lines.push(secondary(fit_name(short_name(&a.trustee))));
        lines.extend(effect_lines(scope, a).into_iter().map(secondary));
        let idx = push(
            &mut nodes,
            2,
            lines,
            format!(
                "{} for {} → {}{reason}",
                ace_title(a),
                a.trustee,
                effect_text(a)
            ),
            effect_look(a),
        );
        ace_nodes.push((idx, a));
        if a.layer == TraceLayer::Ntfs {
            ntfs_aces.push(idx);
        } else {
            share_aces.push(idx);
        }
    }
    // An empty ACE band says so — an empty band would leave the admin
    // guessing why the layer grants nothing.
    let empty_band = |nodes: &mut Vec<Node>, name: &str| {
        push(
            nodes,
            2,
            vec![
                primary("no ACE reaches the account".to_owned()),
                secondary("see the permission path".to_owned()),
            ],
            format!(
                "No {name} ACE names the account or a group in its token — the permission path explains why (for example an ACE only for interactive logons)"
            ),
            Look::Inactive,
        )
    };
    if ntfs_aces.is_empty() {
        ntfs_aces.push(empty_band(&mut nodes, "NTFS"));
    }
    if share_applied && share_aces.is_empty() {
        share_aces.push(empty_band(&mut nodes, "share"));
    }

    // Results per layer.
    let mut ntfs_lines = vec![primary("NTFS".to_owned())];
    ntfs_lines.extend(value_lines(p.ntfs_mask.0, p.ntfs_determinable()));
    let ntfs_node = push(
        &mut nodes,
        3,
        ntfs_lines,
        format!(
            "NTFS: {} (0x{:08X})",
            permission_engine::rights_label_compact(p.ntfs_mask.0, p.ntfs_determinable()),
            p.ntfs_mask.0
        ),
        if p.ntfs_determinable() {
            Look::Plain
        } else {
            Look::Uncertain
        },
    );
    let share_node = if share_ctx {
        let mut lines = vec![primary("Share".to_owned())];
        let (title, look) = match (&p.share_status, p.share_mask) {
            (ShareEvalStatus::Applied, Some(m)) => {
                lines.extend(value_lines(m.0, p.share_determinable()));
                (
                    format!(
                        "Share: {} (0x{:08X})",
                        permission_engine::rights_label_compact(m.0, p.share_determinable()),
                        m.0
                    ),
                    if p.share_determinable() {
                        Look::Plain
                    } else {
                        Look::Uncertain
                    },
                )
            }
            (ShareEvalStatus::Unrestricted, _) => {
                lines.push(secondary("no restriction (NULL DACL)".to_owned()));
                (
                    "Share: NULL DACL — the share does not restrict, NTFS decides".to_owned(),
                    Look::Plain,
                )
            }
            (ShareEvalStatus::ReadFailed(reason), _) => {
                lines.push(("NOT DETERMINABLE".to_owned(), TextStyle::Caution));
                lines.extend(wrap_lines(reason, REASON_LINES).into_iter().map(secondary));
                (
                    format!("Share: not determinable — {reason}"),
                    Look::Uncertain,
                )
            }
            _ => {
                lines.push(("NOT DETERMINABLE".to_owned(), TextStyle::Caution));
                ("Share: not determinable".to_owned(), Look::Uncertain)
            }
        };
        Some(push(&mut nodes, 3, lines, title, look))
    } else {
        None
    };

    // Logon (Selective Authentication, ADR 0079).
    let logon_idx = logon
        .as_ref()
        .map(|(look, lines, title)| push(&mut nodes, 4, lines.clone(), title.clone(), *look));

    // The effective right.
    let limit = match (&p.share_status, p.share_mask) {
        (ShareEvalStatus::Applied, Some(share)) => Some(limiting_side(p.ntfs_mask.0, share.0)),
        _ => None,
    };
    let mut eff_lines = vec![primary("Effective".to_owned())];
    if logon_refused {
        eff_lines.push(("No access".to_owned(), TextStyle::Alert));
        eff_lines.push(secondary("logon refused before any ACE".to_owned()));
    } else {
        eff_lines.extend(value_lines(p.effective_mask.0, p.effective_determinable()));
        let detail = match (&p.share_status, limit) {
            (_, Some(LimitingSide::Share)) => "limited by the share",
            (_, Some(LimitingSide::Ntfs)) => "limited by NTFS",
            (_, Some(LimitingSide::Neither)) => "NTFS and share agree",
            (ShareEvalStatus::Unrestricted, _) => "share unrestricted — NTFS decides",
            (ShareEvalStatus::ReadFailed(_), _) => "share not determinable",
            _ => "no SMB share — NTFS decides",
        };
        eff_lines.push(secondary(detail.to_owned()));
        if matches!(logon, Some((Look::Uncertain, _, _))) {
            eff_lines.push(if logon_without_effect {
                // ADR 0079 addendum: nothing granted — exact either way.
                secondary("whatever the logon decides".to_owned())
            } else {
                ("logon not determinable".to_owned(), TextStyle::Caution)
            });
        }
    }
    let sync = p
        .diagnostics
        .iter()
        .find(|d| matches!(d, PermissionDiagnostic::SynchronizeNotGranted { .. }));
    if sync.is_some() {
        eff_lines.extend(
            wrap2("no SYNCHRONIZE: Explorer and most programs get \"access denied\"")
                .into_iter()
                .map(|l| (l, TextStyle::Caution)),
        );
    }
    let mut eff_title = format!(
        "Effective: {} (0x{:08X})",
        permission_engine::rights_label_compact(p.effective_mask.0, p.effective_determinable()),
        p.effective_mask.0
    );
    if let Some((_, _, summary)) = &logon {
        eff_title.push_str(" — ");
        eff_title.push_str(summary);
    }
    if let Some(d) = sync {
        eff_title.push_str(" — ");
        eff_title.push_str(&d.summary());
    }
    let result_node = push(
        &mut nodes,
        result_col,
        eff_lines,
        eff_title,
        if p.effective_determinable() {
            Look::Plain
        } else {
            Look::Uncertain
        },
    );

    // Vertical placement.
    let stack_h = |idxs: &[usize], nodes: &[Node]| {
        idxs.iter().map(|i| nodes[*i].h).sum::<f64>() + GAP_Y * idxs.len().saturating_sub(1) as f64
    };
    let place = |idxs: &[usize], y0: f64, nodes: &mut Vec<Node>| {
        let mut y = y0;
        for i in idxs {
            nodes[*i].y = y;
            y += nodes[*i].h + GAP_Y;
        }
    };
    let group_col: Vec<usize> = (0..nodes.len()).filter(|i| nodes[*i].col == 1).collect();
    let ntfs_band_h = stack_h(&ntfs_aces, &nodes).max(nodes[ntfs_node].h);
    let share_band_h = match share_node {
        Some(s) => stack_h(&share_aces, &nodes).max(nodes[s].h),
        None => 0.0,
    };
    let aces_h = ntfs_band_h
        + if share_node.is_some() {
            BAND_GAP + share_band_h
        } else {
            0.0
        };
    let groups_h = stack_h(&group_col, &nodes);
    let content_h = aces_h
        .max(groups_h)
        .max(nodes[account_node].h)
        .max(nodes[result_node].h);
    let centred = |h: f64| {
        if opts.all_groups {
            top
        } else {
            top + (content_h - h) / 2.0
        }
    };
    let aces_top = centred(aces_h);
    let ntfs_stack_h = stack_h(&ntfs_aces, &nodes);
    place(
        &ntfs_aces,
        aces_top + (ntfs_band_h - ntfs_stack_h) / 2.0,
        &mut nodes,
    );
    nodes[ntfs_node].y = aces_top + (ntfs_band_h - nodes[ntfs_node].h) / 2.0;
    let share_top = aces_top + ntfs_band_h + BAND_GAP;
    if let Some(s) = share_node {
        let share_stack_h = stack_h(&share_aces, &nodes);
        place(
            &share_aces,
            share_top + (share_band_h - share_stack_h) / 2.0,
            &mut nodes,
        );
        nodes[s].y = share_top + (share_band_h - nodes[s].h) / 2.0;
    }
    place(&group_col, centred(groups_h), &mut nodes);
    nodes[account_node].y = centred(nodes[account_node].h);
    let centre = |i: usize, nodes: &[Node]| nodes[i].y + nodes[i].h / 2.0;
    let mid = match share_node {
        Some(s) => (centre(ntfs_node, &nodes) + centre(s, &nodes)) / 2.0,
        None => centre(ntfs_node, &nodes),
    };
    for i in [Some(result_node), logon_idx].into_iter().flatten() {
        nodes[i].y = mid - nodes[i].h / 2.0;
    }

    // Edges — every one between neighbouring columns.
    let mut edges: Vec<Edge> = Vec::new();
    if let Some(d) = direct_node {
        edges.push(Edge {
            from: account_node,
            to: d,
            look: Look::Plain,
            strong: direct_decided,
        });
    }
    for (_, idx, look, decisive) in &group_nodes {
        edges.push(Edge {
            from: account_node,
            to: *idx,
            look: *look,
            strong: *decisive,
        });
    }
    for (idx, a) in &ace_nodes {
        let decided = matches!(a.effect, AceEffect::Decided { .. });
        let source = if a.sid == p.identity.sid {
            direct_node.map(|d| (d, true))
        } else {
            group_nodes
                .iter()
                .find(|(sid, _, _, _)| sid == &a.sid.0)
                .map(|(_, i, _, decisive)| (*i, *decisive))
        };
        if let Some((src, decisive)) = source {
            edges.push(Edge {
                from: src,
                to: *idx,
                look: effect_look(a),
                strong: decided && decisive,
            });
        }
        edges.push(Edge {
            from: *idx,
            to: if a.layer == TraceLayer::Ntfs {
                ntfs_node
            } else {
                share_node.unwrap_or(ntfs_node)
            },
            look: effect_look(a),
            strong: decided,
        });
    }
    let into_result = logon_idx.unwrap_or(result_node);
    edges.push(Edge {
        from: ntfs_node,
        to: into_result,
        look: Look::Value,
        strong: matches!(limit, None | Some(LimitingSide::Ntfs)),
    });
    if let Some(s) = share_node {
        edges.push(Edge {
            from: s,
            to: into_result,
            look: Look::Value,
            strong: matches!(limit, Some(LimitingSide::Share)),
        });
    }
    if let (Some(l), Some((look, _, _))) = (logon_idx, &logon) {
        // An undeterminable logon that cannot change the result has no effect
        // on it: grey dashed, like every other line without effect.
        let (look, strong) = if logon_without_effect {
            (Look::Inactive, false)
        } else {
            (*look, true)
        };
        edges.push(Edge {
            from: l,
            to: result_node,
            look,
            strong,
        });
    }

    // Texts: caption, headers, node lines.
    let width = MARGIN * 2.0 + ncols as f64 * NODE_W + (ncols - 1) as f64 * GAP_X;
    let mut texts: Vec<GraphText> = Vec::new();
    if opts.caption {
        let caption = format!("{account} on {}", p.path.0);
        let room = ((width - 2.0 * MARGIN) / CHAR_W) as usize;
        let caption = if chars(&caption) > room {
            let cut: String = caption.chars().take(room.saturating_sub(1)).collect();
            format!("{cut}…")
        } else {
            caption
        };
        texts.push(GraphText {
            x: MARGIN,
            baseline: MARGIN + 16.0,
            text: caption,
            style: TextStyle::Primary,
            node: None,
        });
    }
    let mut headers: Vec<(usize, &str, f64)> = vec![
        (0, "Account", top0 + 14.0),
        (1, "Token groups", top0 + 14.0),
        (2, "NTFS ACEs", top0 + 14.0),
        (3, "NTFS", top0 + 14.0),
        (result_col, "Result", top0 + 14.0),
    ];
    if logon_idx.is_some() {
        headers.push((4, "Logon", top0 + 14.0));
    }
    if share_node.is_some() {
        let band_header = share_top - 12.0;
        if share_applied {
            headers.push((2, "Share ACEs", band_header));
        }
        headers.push((3, "Share", band_header));
    }
    for (col, name, baseline) in headers {
        texts.push(GraphText {
            x: col_x(col),
            baseline,
            text: name.to_owned(),
            style: TextStyle::Heading,
            node: None,
        });
    }
    for (i, n) in nodes.iter().enumerate() {
        for (k, (line, style)) in n.lines.iter().enumerate() {
            texts.push(GraphText {
                x: n.x + TEXT_PAD,
                baseline: n.y + FIRST_BASELINE + k as f64 * LINE_H,
                text: line.clone(),
                style: *style,
                node: Some(i),
            });
        }
    }

    // Legend, wrapped into rows that fit the width.
    let content_bottom = nodes.iter().map(|n| n.y + n.h).fold(top, f64::max);
    let mut legend = Vec::new();
    let mut lx = MARGIN;
    let mut ly = content_bottom + 26.0;
    for (look, strong, text) in [
        (Look::Granted, false, "Allow decided bits"),
        (Look::Denied, false, "Deny decided bits"),
        (Look::Uncertain, false, "uncertain (logon / session)"),
        (
            Look::Inactive,
            false,
            "no effect · inherit-only · deny-only",
        ),
        (Look::Value, false, "result of a layer"),
        (Look::Plain, true, "thick: decisive route"),
    ] {
        let item_w = LEGEND_SWATCH + 6.0 + chars(text) as f64 * 6.4 + 28.0;
        if lx + item_w > width - MARGIN && lx > MARGIN {
            lx = MARGIN;
            ly += LEGEND_ROW_H;
        }
        legend.push(LegendItem {
            x: lx,
            y: ly,
            look,
            strong,
        });
        texts.push(GraphText {
            x: lx + LEGEND_SWATCH + 6.0,
            baseline: ly + 4.0,
            text: text.to_owned(),
            style: TextStyle::Secondary,
            node: None,
        });
        lx += item_w;
    }
    let height = ly + 14.0 + MARGIN;

    Some(GraphLayout {
        width,
        height,
        texts,
        further_groups,
        title: format!("Permission graph — {account} on {}", p.path.0),
        nodes,
        edges,
        legend,
    })
}

impl GraphLayout {
    /// The complete SVG in the light palette — shapes, texts and `<title>`
    /// tooltips; every text is XML-escaped.
    pub fn to_svg(&self) -> String {
        self.render(true, &RenderOptions::default())
    }

    /// The complete SVG with render options.
    pub fn to_svg_with(&self, opts: &RenderOptions) -> String {
        self.render(true, opts)
    }

    /// Boxes, edges and legend swatches only (light palette), for a
    /// renderer that draws [`GraphLayout::texts`] itself.
    pub fn to_svg_shapes(&self) -> String {
        self.render(false, &RenderOptions::default())
    }

    /// [`GraphLayout::to_svg_shapes`] with render options.
    pub fn to_svg_shapes_with(&self, opts: &RenderOptions) -> String {
        self.render(false, opts)
    }

    /// Which boxes stay bright while `highlight` is selected: the box, every
    /// box it is reached from and every box it leads to — all routes through
    /// it. Without a selection, or with an index that is no box, all of them.
    /// Edges connect neighbouring columns only, so an edge between two bright
    /// boxes always lies on such a route.
    pub fn route_nodes(&self, highlight: Option<usize>) -> Vec<bool> {
        let n = self.nodes.len();
        let Some(start) = highlight.filter(|h| *h < n) else {
            return vec![true; n];
        };
        let walk = |forward: bool| {
            let mut seen = vec![false; n];
            seen[start] = true;
            let mut stack = vec![start];
            while let Some(i) = stack.pop() {
                for e in &self.edges {
                    let (from, to) = if forward {
                        (e.from, e.to)
                    } else {
                        (e.to, e.from)
                    };
                    if from == i && !seen[to] {
                        seen[to] = true;
                        stack.push(to);
                    }
                }
            }
            seen
        };
        let (up, down) = (walk(false), walk(true));
        up.iter().zip(&down).map(|(a, b)| *a || *b).collect()
    }

    /// Every box with its full text, in drawing order — for click targets.
    pub fn node_boxes(&self) -> Vec<NodeBox> {
        self.nodes
            .iter()
            .map(|n| NodeBox {
                x: n.x,
                y: n.y,
                w: NODE_W,
                h: n.h,
                title: n.title.clone(),
            })
            .collect()
    }

    fn render(&self, with_text: bool, opts: &RenderOptions) -> String {
        let pal = palette(opts.dark);
        let (width, height) = (self.width, self.height);
        let style = if opts.responsive {
            format!(
                " style=\"width:100%;height:auto;max-width:{width:.0}px;min-width:{:.0}px\"",
                width * MIN_SCALE
            )
        } else {
            String::new()
        };
        let mut s = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" viewBox=\"0 0 {width:.0} {height:.0}\"{style} font-family=\"Arial, sans-serif\" font-size=\"{FONT_SIZE:.0}\">"
        );
        if with_text {
            s.push_str(&format!("<title>{}</title>", esc(&self.title)));
        }
        s.push_str(&format!(
            "<rect width=\"100%\" height=\"100%\" fill=\"{}\"/>",
            pal.bg
        ));
        // With a highlighted node, every route through it stays bright and
        // thick; everything else fades.
        let lit = self.route_nodes(opts.highlight);
        let highlighting = opts.highlight.is_some_and(|h| h < self.nodes.len());
        let fade = |hot: bool| if hot { "" } else { " opacity=\"0.25\"" };
        for e in &self.edges {
            let (a, b) = (&self.nodes[e.from], &self.nodes[e.to]);
            let (x1, y1) = (a.x + NODE_W, a.y + a.h / 2.0);
            let (x2, y2) = (b.x, b.y + b.h / 2.0);
            let mid = (x1 + x2) / 2.0;
            let d = format!("M{x1:.1},{y1:.1} C{mid:.1},{y1:.1} {mid:.1},{y2:.1} {x2:.1},{y2:.1}");
            let hot = lit[e.from] && lit[e.to];
            let w = e.look.width(e.strong || (hot && highlighting));
            line(&mut s, &d, e.look, w, pal, fade(hot));
        }
        for (i, n) in self.nodes.iter().enumerate() {
            s.push_str("<g>");
            if with_text {
                s.push_str(&format!("<title>{}</title>", esc(&n.title)));
            }
            let selected = opts.highlight == Some(i);
            s.push_str(&format!(
                "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{NODE_W:.0}\" height=\"{:.1}\" rx=\"6\" fill=\"{}\" stroke=\"{}\" stroke-width=\"{:.1}\"{}{}/></g>",
                n.x,
                n.y,
                n.h,
                pal.node,
                n.look.colour(pal),
                n.look.width(false) + if selected { 1.6 } else { 0.0 },
                n.look.dash(),
                fade(lit[i])
            ));
        }
        for item in &self.legend {
            let d = format!(
                "M{:.1},{:.1} L{:.1},{:.1}",
                item.x,
                item.y,
                item.x + LEGEND_SWATCH,
                item.y
            );
            line(&mut s, &d, item.look, item.look.width(item.strong), pal, "");
        }
        if with_text {
            for t in &self.texts {
                let weight = if t.style.bold() {
                    " font-weight=\"600\""
                } else {
                    ""
                };
                let hot = t.node.is_none_or(|i| lit.get(i).copied().unwrap_or(true));
                s.push_str(&format!(
                    "<text x=\"{:.1}\" y=\"{:.1}\" fill=\"{}\"{weight}{}>{}</text>",
                    t.x,
                    t.baseline,
                    t.style.colour_in(opts.dark),
                    fade(hot),
                    esc(&t.text)
                ));
            }
        }
        s.push_str("</svg>");
        s
    }
}

/// One line of an edge or a legend swatch. A Deny is a double line (a
/// bright core over the red stroke), so it reads apart from an Allow without
/// colour as well.
fn line(s: &mut String, d: &str, look: Look, w: f64, pal: &Palette, fade: &str) {
    if look == Look::Denied {
        s.push_str(&format!(
            "<path d=\"{d}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{:.1}\"{fade}/>",
            look.colour(pal),
            w + 1.6
        ));
        s.push_str(&format!(
            "<path d=\"{d}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{:.1}\"{fade}/>",
            pal.bg,
            (w - 0.6).max(1.0)
        ));
    } else {
        s.push_str(&format!(
            "<path d=\"{d}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{w:.1}\"{}{fade}/>",
            look.colour(pal),
            look.dash()
        ));
    }
}

/// The complete permission graph SVG of one result (see
/// [`permission_graph`]), light palette.
pub fn permission_graph_svg(p: &EffectivePermission) -> Option<String> {
    permission_graph(p).map(|g| g.to_svg())
}

/// [`permission_graph_svg`] with render options (the report: dark,
/// responsive).
pub fn permission_graph_svg_with(p: &EffectivePermission, opts: &RenderOptions) -> Option<String> {
    permission_graph(p).map(|g| g.to_svg_with(opts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{
        AccessMask, Identity, IdentityKind, LocalGroupEvalStatus, NormalizedPath, PermissionPath,
        PermissionTrace, Sid, SynchronizeGap,
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
            other: Default::default(),
        }
    }

    fn has_text(g: &GraphLayout, t: &str) -> bool {
        g.texts.iter().any(|x| x.text == t)
    }

    fn node_with(g: &GraphLayout, first: &str) -> usize {
        g.nodes
            .iter()
            .position(|n| n.lines[0].0 == first)
            .unwrap_or_else(|| panic!("no node {first}"))
    }

    #[test]
    fn no_trace_no_graph() {
        assert!(permission_graph(&result(PermissionTrace::default(), None)).is_none());
    }

    #[test]
    fn graph_has_the_columns_bands_nodes_and_colours_of_the_trace() {
        let p = result(trace(), Some(0x0012_00A9));
        let g = permission_graph(&p).unwrap();
        for header in [
            "Account",
            "Token groups",
            "NTFS ACEs",
            "NTFS",
            "Share ACEs",
            "Share",
            "Result",
        ] {
            assert!(has_text(&g, header), "{header}");
        }
        assert!(has_text(&g, "Finance") && has_text(&g, "+57 further groups"));
        // account→4 groups, 4 ACEs with source and target each, NTFS and
        // share → effective.
        assert_eq!(g.edges.len(), 4 + 4 * 2 + 2);
        let svg = g.to_svg();
        assert!(svg.contains(LIGHT.green) && svg.contains(LIGHT.red) && svg.contains(LIGHT.amber));
        assert!(svg.contains(LIGHT.value), "layer results flow in slate");
        assert!(svg.contains("deny-only"));
        assert!(svg.contains("&lt;x&gt;"), "the path is escaped");
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
    }

    /// ADR 0081: every edge connects neighbouring columns, so no edge can
    /// run through a box it does not connect — there are no detours.
    #[test]
    fn every_edge_connects_neighbouring_columns() {
        for share in [None, Some(0x0012_00A9)] {
            let g = permission_graph(&result(trace(), share)).unwrap();
            for e in &g.edges {
                assert_eq!(
                    g.nodes[e.to].col,
                    g.nodes[e.from].col + 1,
                    "{} → {}",
                    g.nodes[e.from].title,
                    g.nodes[e.to].title
                );
            }
        }
    }

    /// The share band lies below the NTFS band, and the effective right sits
    /// between the two layer results.
    #[test]
    fn the_share_band_lies_below_the_ntfs_band() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let bottom_ntfs = g
            .nodes
            .iter()
            .filter(|n| n.col == 2 && n.title.contains("S-1-5-21") || n.title.contains("S-1-5-32"))
            .filter(|n| n.col == 2)
            .map(|n| n.y + n.h)
            .fold(0.0, f64::max);
        let share_ace = &g.nodes[g
            .nodes
            .iter()
            .position(|n| n.col == 2 && n.title.contains("S-1-1-0"))
            .unwrap()];
        assert!(share_ace.y > bottom_ntfs);
        let ntfs = &g.nodes[node_with(&g, "NTFS")];
        let share = &g.nodes[node_with(&g, "Share")];
        let eff = &g.nodes[node_with(&g, "Effective")];
        assert!(share.y > ntfs.y + ntfs.h);
        let mid = (ntfs.y + ntfs.h / 2.0 + share.y + share.h / 2.0) / 2.0;
        assert!((eff.y + eff.h / 2.0 - mid).abs() < 0.01);
    }

    /// An ACE on the account itself is routed through its own node in the
    /// group column, never through a group node.
    #[test]
    fn direct_ace_has_its_own_node_in_the_group_column() {
        let t = PermissionTrace {
            aces: vec![ace(
                TraceLayer::Ntfs,
                AceKind::Allow,
                USER,
                AceEffect::Decided { bits: 0x0013_01BF },
            )],
            groups: vec![],
            other_groups: 3,
            other: Default::default(),
        };
        let g = permission_graph(&result(t, None)).unwrap();
        // account→direct, direct→ACE, ACE→NTFS, NTFS→effective
        assert_eq!(g.edges.len(), 4);
        let direct = node_with(&g, "the account itself");
        let ace = g
            .nodes
            .iter()
            .position(|n| n.lines[0].0.starts_with("Allow"))
            .unwrap();
        assert!(g
            .edges
            .iter()
            .any(|e| e.from == direct && e.to == ace && e.strong));
        assert!(!g.edges.iter().any(|e| e.from == 0 && e.to == ace));
    }

    /// A band without any ACE for the account carries an explicit node.
    #[test]
    fn empty_ace_band_says_so() {
        let t = PermissionTrace {
            aces: vec![ace(
                TraceLayer::Share,
                AceKind::Allow,
                "S-1-1-0",
                AceEffect::Decided { bits: 0x0012_00A9 },
            )],
            groups: vec![group("S-1-1-0", "Everyone", TraceGroupState::Implicit)],
            other_groups: 0,
            other: Default::default(),
        };
        let g = permission_graph(&result(t, Some(0x0012_00A9))).unwrap();
        let empty: Vec<&Node> = g
            .nodes
            .iter()
            .filter(|n| n.lines[0].0 == "no ACE reaches the account")
            .collect();
        assert_eq!(empty.len(), 1, "only the NTFS band is empty");
        assert_eq!(empty[0].col, 2);
        assert_eq!(empty[0].look, Look::Inactive);
    }

    fn with_other_groups() -> PermissionTrace {
        let mut t = trace();
        t.other_groups = 2;
        t.other = vec![
            group("S-1-5-21-1-2-3-3001", "Idle A", TraceGroupState::Member),
            group("S-1-5-21-1-2-3-3002", "Idle B <&>", TraceGroupState::Member),
        ];
        t
    }

    /// Default view: one summary box whose tooltip names the groups.
    #[test]
    fn further_groups_are_named_in_the_summary_tooltip() {
        let g = permission_graph(&result(with_other_groups(), None)).unwrap();
        assert!(has_text(&g, "+2 further groups"));
        assert_eq!(g.further_groups.len(), 2);
        let svg = g.to_svg();
        assert!(svg.contains("Idle A (S-1-5-21-1-2-3-3001)"));
        assert!(svg.contains("Idle B &lt;&amp;&gt;"), "names are escaped");
    }

    /// "Show all groups": each one its own grey box, linked to the account,
    /// and no summary box left; account, groups and ACEs start at the top.
    #[test]
    fn all_groups_draws_each_membership() {
        let g = permission_graph_with(
            &result(with_other_groups(), None),
            GraphOptions {
                all_groups: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!g.texts.iter().any(|t| t.text.contains("further groups")));
        for name in ["Idle A", "Idle B <&>"] {
            let i = node_with(&g, name);
            assert_eq!(g.nodes[i].look, Look::Inactive);
            assert!(g.edges.iter().any(|e| e.from == 0 && e.to == i));
        }
        let first_y = |col: usize| {
            g.nodes
                .iter()
                .filter(|n| n.col == col)
                .map(|n| n.y)
                .fold(f64::MAX, f64::min)
        };
        for col in 0..3 {
            assert_eq!(first_y(col), MARGIN + HEADER_H, "column {col}");
        }
    }

    /// The default view stays centred.
    #[test]
    fn default_view_stays_centred() {
        let g = permission_graph(&result(with_other_groups(), None)).unwrap();
        let account = g.nodes.iter().find(|n| n.col == 0).unwrap();
        assert!(account.y > MARGIN + HEADER_H, "account centred");
    }

    /// A result stored before the names existed keeps its summary box.
    #[test]
    fn a_count_without_names_stays_a_summary() {
        let mut t = trace();
        t.other_groups = 5;
        let g = permission_graph_with(
            &result(t, None),
            GraphOptions {
                all_groups: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(has_text(&g, "+5 further groups"));
    }

    #[test]
    fn without_share_there_is_no_share_band() {
        let g = permission_graph(&result(trace(), None)).unwrap();
        assert!(!has_text(&g, "Share ACEs") && !has_text(&g, "Share"));
        assert!(has_text(&g, "no SMB share — NTFS decides"));
        assert!(g.nodes.iter().all(|n| n.col <= 4));
    }

    /// The limiting side is named and its edge drawn thick — the engine's
    /// own rule.
    #[test]
    fn the_limiting_side_is_named_and_drawn_thick() {
        let cases = [
            (0x0013_01BF, 0x0012_00A9, "limited by the share", true),
            (0x0012_00A9, 0x001F_01FF, "limited by NTFS", false),
            (0x0012_00A9, 0x0012_00A9, "NTFS and share agree", false),
        ];
        for (ntfs, share, text, share_thick) in cases {
            let mut p = result(trace(), Some(share));
            p.ntfs_mask = AccessMask(ntfs);
            p.effective_mask = AccessMask(ntfs & share);
            let g = permission_graph(&p).unwrap();
            assert!(has_text(&g, text), "{text}");
            let eff = node_with(&g, "Effective");
            let (n, s) = (node_with(&g, "NTFS"), node_with(&g, "Share"));
            let edge = |from: usize| {
                g.edges
                    .iter()
                    .find(|e| e.from == from && e.to == eff)
                    .unwrap()
            };
            assert_eq!(edge(s).strong, share_thick, "{text}");
            assert_eq!(edge(n).strong, text == "limited by NTFS", "{text}");
            assert_eq!(edge(n).look, Look::Value);
        }
    }

    /// ADR 0079: a refused logon is its own red node before the result,
    /// which says No access — never green lines into a refused logon
    /// without the reason.
    #[test]
    fn a_refused_logon_is_its_own_node_before_the_result() {
        let mut p = result(trace(), Some(0x0012_00A9));
        p.effective_mask = AccessMask(0);
        p.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationDenied {
                server: "FS01".into(),
            });
        let g = permission_graph(&p).unwrap();
        assert!(has_text(&g, "Logon"), "the logon column has a header");
        let logon = node_with(&g, "Logon refused");
        assert_eq!(g.nodes[logon].look, Look::Denied);
        assert!(g.nodes[logon].title.contains("Selective Authentication"));
        let eff = node_with(&g, "Effective");
        assert!(g.nodes[eff]
            .lines
            .iter()
            .any(|(l, s)| l == "No access" && *s == TextStyle::Alert));
        assert!(g
            .edges
            .iter()
            .any(|e| e.from == logon && e.to == eff && e.look == Look::Denied));
        // NTFS and share flow into the logon node, not past it.
        assert!(!g.edges.iter().any(|e| e.to == eff && e.look == Look::Value));

        let mut q = result(trace(), Some(0x0012_00A9));
        q.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationUnknown {
                server: "FS01".into(),
                reason: "no read access".into(),
                affects_result: true,
            });
        let g = permission_graph(&q).unwrap();
        let logon = node_with(&g, "Logon not determinable");
        assert_eq!(g.nodes[logon].look, Look::Uncertain);
        assert!(has_text(&g, "logon not determinable"));
        let eff = node_with(&g, "Effective");
        assert!(g
            .edges
            .iter()
            .any(|e| e.from == logon && e.to == eff && e.look == Look::Uncertain && e.strong));

        // ADR 0079 addendum: the permissions grant nothing — the logon box
        // stays amber, but its line has no effect and the result is exact.
        let mut n = result(trace(), Some(0x0012_00A9));
        n.ntfs_mask = AccessMask(0);
        n.effective_mask = AccessMask(0);
        n.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationUnknown {
                server: "FS01".into(),
                reason: "no read access".into(),
                affects_result: false,
            });
        let g = permission_graph(&n).unwrap();
        let logon = node_with(&g, "Logon not determinable");
        assert_eq!(g.nodes[logon].look, Look::Uncertain);
        let eff = node_with(&g, "Effective");
        let lines: Vec<&str> = g.nodes[eff].lines.iter().map(|(l, _)| l.as_str()).collect();
        assert!(lines.contains(&"No access"), "{lines:?}");
        assert!(lines.contains(&"whatever the logon decides"), "{lines:?}");
        assert!(!lines.contains(&"NOT DETERMINABLE") && !lines.contains(&"logon not determinable"));
        assert!(g
            .edges
            .iter()
            .any(|e| e.from == logon && e.to == eff && e.look == Look::Inactive && !e.strong));

        let mut r = result(trace(), Some(0x0012_00A9));
        r.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationAllowed {
                server: "FS01".into(),
                via: "GG_Partners".into(),
            });
        let g = permission_graph(&r).unwrap();
        assert_eq!(g.nodes[node_with(&g, "Logon allowed")].look, Look::Granted);
        assert!(has_text(&g, "via GG_Partners"));
        // Without a logon marker there is no logon column.
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        assert!(!has_text(&g, "Logon"));
    }

    /// ADR 0080: the result node says why Explorer fails.
    #[test]
    fn a_missing_synchronize_is_named_on_the_result() {
        let mut p = result(trace(), None);
        p.diagnostics
            .push(PermissionDiagnostic::SynchronizeNotGranted {
                cause: SynchronizeGap::DeniedByNtfsAce,
                certain: true,
            });
        let g = permission_graph(&p).unwrap();
        let eff = &g.nodes[node_with(&g, "Effective")];
        assert!(eff
            .lines
            .iter()
            .any(|(l, s)| l.contains("no SYNCHRONIZE") && *s == TextStyle::Caution));
        assert!(eff.title.contains("SYNCHRONIZE"));
    }

    /// No line of a box is longer than a box line holds: long names lose the
    /// domain first, a SID keeps its RID, rights fall back to the short form.
    #[test]
    fn texts_fit_their_boxes() {
        let mut t = trace();
        t.aces[1].mask = AccessMask(0x0010_0116);
        t.aces[1].effect = AceEffect::Decided { bits: 0x0010_0116 };
        // A long name with a multi-byte character, a long nested route.
        t.groups[0].display =
            "NT AUTHORITY\\Authenticated Users — a very long name (S-1-5-11)".into();
        t.groups[1].route = "via alice → GG_Department_Finance_Munich → DL_Project".into();
        let mut p = result(t, Some(0x0012_00A9));
        p.identity.sid = Sid("S-1-5-21-1025961329-1437379190-2506159458-16182".into());
        p.identity.domain = Some("corp.example.test".into());
        // The marker lines of the logon and the result box as well.
        p.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationDenied {
                server: "FILESERVER-0815".into(),
            });
        p.diagnostics
            .push(PermissionDiagnostic::SynchronizeNotGranted {
                cause: SynchronizeGap::DeniedByNtfsAce,
                certain: true,
            });
        let g = permission_graph(&p).unwrap();
        for n in &g.nodes {
            for (line, _) in &n.lines {
                assert!(chars(line) <= max_chars(), "{line} ({})", chars(line));
            }
        }
        assert!(has_text(&g, "Deny (WD,AD,WA,WEA,S)"), "short rights form");
        assert!(g.texts.iter().any(|t| t.text.contains("S-1-5-21-…-16182")));
        assert!(g
            .texts
            .iter()
            .any(|t| t.text.starts_with("…\\Authenticated") && t.text.ends_with("long name")));
    }

    /// A long second line breaks into two lines instead of being cut —
    /// nothing is lost, and a short one stays one line.
    #[test]
    fn long_second_lines_wrap_instead_of_being_cut() {
        let s = "inherited · grants (X,RD,RA,REA,DE,RC,WD,AD,WA,WEA,DC)";
        let w = wrap2(s);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w
            .iter()
            .all(|l| chars(l) <= max_chars() && !l.contains('…')));
        assert_eq!(
            format!("{}{}", w[0], w[1]).replace(' ', ""),
            s.replace(' ', "")
        );
        assert_eq!(
            wrap2("explicit · grants Modify"),
            vec!["explicit · grants Modify"]
        );
    }

    /// The reason why the logon is not determinable is the message of its
    /// box: it shows in full, over up to four lines.
    #[test]
    fn a_logon_reason_shows_in_full() {
        // The lab case: "Allowed to authenticate" only for INTERACTIVE.
        let reason = "an ACE for S-1-5-4 decides it, and whether that SID is in the account's logon token is not known";
        let mut p = result(trace(), Some(0x0012_00A9));
        p.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationUnknown {
                server: "FS01".into(),
                reason: reason.into(),
                affects_result: true,
            });
        let g = permission_graph(&p).unwrap();
        let logon = &g.nodes[node_with(&g, "Logon not determinable")];
        let shown: Vec<&str> = logon.lines[2..].iter().map(|(l, _)| l.as_str()).collect();
        assert!(shown.len() > 2 && shown.len() <= REASON_LINES, "{shown:?}");
        assert_eq!(shown.join(" "), reason);
        assert!(shown.iter().all(|l| chars(l) <= max_chars()));
    }

    /// A domain SID in a logon line keeps its RID instead of breaking in
    /// the middle of the number; other SIDs and texts stay as they are.
    #[test]
    fn sids_in_logon_lines_keep_their_rid() {
        assert_eq!(
            shorten_sids("GG_ExtPartners (S-1-5-21-1667335488-272840759-1416816776-1110)"),
            "GG_ExtPartners (S-1-5-21-…-1110)"
        );
        assert_eq!(
            shorten_sids("an ACE for S-1-5-18, S-1-5-21-1-2-3-500 decides it"),
            "an ACE for S-1-5-18, S-1-5-21-…-500 decides it"
        );
        // A domain identifier without a RID, and text without a SID.
        assert_eq!(shorten_sids("S-1-5-21-1-2-3"), "S-1-5-21-1-2-3");
        assert_eq!(shorten_sids("no SID here"), "no SID here");
        let mut p = result(trace(), Some(0x0012_00A9));
        p.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationAllowed {
                server: "FS01".into(),
                via: "GG_ExtPartners (S-1-5-21-1667335488-272840759-1416816776-1110)".into(),
            });
        let g = permission_graph(&p).unwrap();
        assert!(has_text(&g, "via GG_ExtPartners (S-1-5-21-…-1110)"));
        let logon = &g.nodes[node_with(&g, "Logon allowed")];
        assert!(
            logon.title.contains("1416816776-1110"),
            "the full SID stays"
        );
    }

    /// Rights are never cut: a short form that does not fit after its prefix
    /// moves to a line of its own, a longer one breaks after a comma — every
    /// bit stays visible in the box.
    #[test]
    fn long_rights_wrap_without_losing_a_bit() {
        // Read & Execute + Delete without SYNCHRONIZE (lab SyncTest S1).
        assert_eq!(
            rights_lines("inherited · grants ", 0x0003_00A9),
            vec!["inherited · grants", "(X,RD,RA,REA,DE,RC)"]
        );
        assert_eq!(rights_lines("", 0x0013_01BF), vec!["Modify"]);
        // Full Control without SYNCHRONIZE: a 43-character short form.
        const FULL_NO_SYNC: u32 = 0x000F_01FF;
        let label = "(X,RD,RA,REA,WD,AD,WA,WEA,DC,DE,RC,WDAC,WO)";
        assert_eq!(
            rights_lines("Deny ", FULL_NO_SYNC).concat(),
            format!("Deny {label}")
        );
        assert_eq!(rights_lines("", FULL_NO_SYNC).concat(), label);

        let mut t = trace();
        t.aces[1].mask = AccessMask(FULL_NO_SYNC);
        t.aces[1].effect = AceEffect::Decided { bits: FULL_NO_SYNC };
        let mut p = result(t, None);
        p.ntfs_mask = AccessMask(FULL_NO_SYNC);
        p.effective_mask = AccessMask(FULL_NO_SYNC);
        let g = permission_graph(&p).unwrap();
        for n in &g.nodes {
            for (line, _) in &n.lines {
                assert!(chars(line) <= max_chars(), "{line} ({})", chars(line));
            }
        }
        assert!(!g.texts.iter().any(|t| t.text.contains('…')), "nothing cut");
        let deny = g
            .nodes
            .iter()
            .find(|n| n.lines[0].0.starts_with("Deny"))
            .unwrap();
        assert_eq!(
            format!("{}{}", deny.lines[0].0, deny.lines[1].0),
            format!("Deny {label}")
        );
        assert_eq!(deny.lines[1].1, TextStyle::Primary, "the header continues");
        let eff = &g.nodes[node_with(&g, "Effective")];
        let value: String = eff.lines[1..3].iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(value, label);
    }

    /// Dark palette: the report and the GUI in dark mode.
    #[test]
    fn dark_palette_replaces_the_light_one() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let dark = g.to_svg_with(&RenderOptions {
            dark: true,
            ..Default::default()
        });
        assert!(dark.contains(DARK.bg) && dark.contains(DARK.green));
        assert!(!dark.contains(LIGHT.bg) && !dark.contains(LIGHT.green));
        assert_eq!(TextStyle::Primary.colour_in(true), DARK.text);
    }

    /// A click lights every route through the box — what it is reached from
    /// and what it leads to; boxes, edges and texts off those routes fade.
    #[test]
    fn highlight_lights_every_route_through_the_box() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let finance = node_with(&g, "Finance");
        let lit = g.route_nodes(Some(finance));
        for on in ["alice", "Finance", "NTFS", "Effective"] {
            assert!(lit[node_with(&g, on)], "{on} is on the route");
        }
        for off in ["Temps", "Everyone", "Share"] {
            assert!(!lit[node_with(&g, off)], "{off} is off the route");
        }
        let aces: Vec<usize> = (0..g.nodes.len())
            .filter(|i| g.nodes[*i].col == 2)
            .collect();
        let lit_aces: Vec<usize> = aces.iter().copied().filter(|i| lit[*i]).collect();
        assert_eq!(lit_aces.len(), 1, "only the ACE of Finance");
        assert!(g.nodes[lit_aces[0]].title.contains("2001"));

        let full = g.to_svg_with(&RenderOptions {
            highlight: Some(finance),
            ..Default::default()
        });
        assert!(
            full.contains("opacity=\"0.25\">Temps</text>"),
            "texts fade too"
        );
        assert!(full.contains(">Finance</text>") && !full.contains("opacity=\"0.25\">Finance<"));
        // No selection, or an index that is no box: nothing fades.
        assert!(g.route_nodes(None).iter().all(|b| *b));
        assert!(g.route_nodes(Some(9_999)).iter().all(|b| *b));
        let invalid = g.to_svg_shapes_with(&RenderOptions {
            highlight: Some(9_999),
            ..Default::default()
        });
        assert_eq!(invalid, g.to_svg_shapes());
        assert!(!g.to_svg_shapes().contains("opacity="));
    }

    /// A Deny is a double line: two strokes per Deny edge.
    #[test]
    fn a_deny_is_a_double_line() {
        let g = permission_graph(&result(trace(), None)).unwrap();
        let denies = g.edges.iter().filter(|e| e.look == Look::Denied).count();
        let shapes = g.to_svg_shapes();
        let red = shapes.matches(&format!("stroke=\"{}\"", LIGHT.red)).count();
        // edges + the red node border + the legend swatch
        assert_eq!(red, denies + 1 + 1);
        assert!(shapes.matches(&format!("stroke=\"{}\"", LIGHT.bg)).count() > denies);
    }

    /// The caption names account and path — for a graph saved on its own.
    #[test]
    fn caption_option_adds_account_and_path() {
        let p = result(trace(), None);
        let plain = permission_graph(&p).unwrap();
        let with = permission_graph_with(
            &p,
            GraphOptions {
                caption: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(with
            .texts
            .iter()
            .any(|t| t.text == r"alice on \\fs\Data$\Finance <x>"));
        assert!(with.height > plain.height);
    }

    #[test]
    fn responsive_only_when_asked() {
        let g = permission_graph(&result(trace(), None)).unwrap();
        assert!(!g.to_svg().contains("style="));
        let r = g.to_svg_with(&RenderOptions {
            responsive: true,
            ..Default::default()
        });
        assert!(r.contains("width:100%") && r.contains("min-width:"));
    }

    #[test]
    fn node_boxes_carry_every_box_and_its_full_text() {
        let g = permission_graph(&result(trace(), Some(0x0012_00A9))).unwrap();
        let boxes = g.node_boxes();
        assert_eq!(boxes.len(), g.nodes.len());
        assert!(boxes.iter().all(|b| !b.title.is_empty() && b.w == NODE_W));
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
