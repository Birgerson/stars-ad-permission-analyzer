// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Graph tab (`ui/tabs/graph.slint`): the Analyze result as a permission
//! graph (ADR 0077, 0081) — drawn, clickable and savable as SVG.

use std::cell::RefCell;

use adpa_core::model::EffectivePermission;
use slint::ComponentHandle;

use crate::{GraphNodeVm, GraphState, GraphTextVm, MainWindow};

thread_local! {
    /// The result the Graph tab shows, so "Show all groups" can redraw it.
    static GRAPH_RESULT: RefCell<Option<EffectivePermission>> = const { RefCell::new(None) };
}

pub fn wire(ui: &MainWindow) {
    // "Show all groups": redraw the same result in the other layout.
    {
        let weak = ui.as_weak();
        ui.global::<GraphState>().on_toggle_all_groups(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            // Another layout: the selected box no longer exists.
            ui.global::<GraphState>().set_selected(-1);
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            if let Some(perm) = perm {
                draw(&ui, &perm);
            }
        });
    }

    // ADR 0081: a click selects a box (its full text, every route through
    // it bright); a second click on it clears the selection.
    {
        let weak = ui.as_weak();
        ui.global::<GraphState>().on_node_clicked(move |index| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let selected = if ui.global::<GraphState>().get_selected() == index {
                -1
            } else {
                index
            };
            ui.global::<GraphState>().set_selected(selected);
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            if let Some(perm) = perm {
                draw(&ui, &perm);
            }
        });
    }

    // "Save as SVG" (ADR 0081): the graph with its caption, as in the report.
    {
        let weak = ui.as_weak();
        ui.global::<GraphState>().on_save_svg(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            let outcome = match perm {
                None => Err("There is no graph to save — run an analysis first.".to_owned()),
                Some(perm) => {
                    let opts = viz::GraphOptions {
                        all_groups: ui.global::<GraphState>().get_all_groups(),
                        caption: true,
                    };
                    match viz::permission_graph_with(&perm, opts) {
                        Some(graph) => save_svg(
                            ui.global::<GraphState>().get_save_path().as_str(),
                            &graph.to_svg_with(&viz::RenderOptions::default()),
                        ),
                        None => Err("This result has no graph to save.".to_owned()),
                    }
                }
            };
            match outcome {
                Ok(msg) => {
                    ui.global::<GraphState>().set_save_error(false);
                    ui.global::<GraphState>().set_save_status(msg.into());
                }
                Err(msg) => {
                    ui.global::<GraphState>().set_save_error(true);
                    ui.global::<GraphState>().set_save_status(msg.into());
                }
            }
        });
    }
}

/// ADR 0077: the Graph tab shows the permission graph of this result —
/// the layout from `viz`, the same one the HTML report embeds as SVG. The
/// shapes come as a text-free SVG and the texts are drawn natively on top,
/// at the layout's coordinates. No graph is drawn for a result without a
/// trace; a render failure is said, not hidden.
pub fn show(ui: &MainWindow, perm: &EffectivePermission) {
    GRAPH_RESULT.with(|g| *g.borrow_mut() = Some(perm.clone()));
    // A new result: nothing selected, no stale save message.
    ui.global::<GraphState>().set_selected(-1);
    ui.global::<GraphState>().set_save_status("".into());
    draw(ui, perm);
}

/// ADR 0077: no graph shown, with the reason why.
pub fn clear(ui: &MainWindow, caption: &str) {
    GRAPH_RESULT.with(|g| *g.borrow_mut() = None);
    ui.global::<GraphState>().set_further_groups("".into());
    ui.global::<GraphState>().set_has_graph(false);
    ui.global::<GraphState>().set_image(slint::Image::default());
    ui.global::<GraphState>()
        .set_image_dark(slint::Image::default());
    ui.global::<GraphState>().set_texts(slint::ModelRc::new(
        slint::VecModel::<GraphTextVm>::default(),
    ));
    ui.global::<GraphState>().set_nodes(slint::ModelRc::new(
        slint::VecModel::<GraphNodeVm>::default(),
    ));
    ui.global::<GraphState>().set_selected(-1);
    ui.global::<GraphState>().set_detail("".into());
    ui.global::<GraphState>().set_caption(caption.into());
}

/// The memberships no ACE on this object names, for the line under the
/// graph — empty when there are none.
fn further_groups_text(groups: &[String]) -> String {
    if groups.is_empty() {
        return String::new();
    }
    // Names only — the SIDs are in the boxes ("Show all groups"), the
    // Analyze path and the Groups tab.
    let names: Vec<&str> = groups
        .iter()
        .map(|g| match g.rfind(" (S-") {
            Some(i) => &g[..i],
            None => g.as_str(),
        })
        .collect();
    format!(
        "Further groups of the account — no ACE on this object names them, so they do not change this result ({}): {}",
        names.len(),
        names.join(" · ")
    )
}

/// `#rrggbb` → a Slint colour (the graph palette is fixed hex).
fn hex_colour(hex: &str) -> slint::Color {
    let v = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0x00_80_80_80);
    slint::Color::from_rgb_u8((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// ADR 0081: writes a saved permission graph — the path validated like a
/// report export (existing directory, `.svg` only), never overwriting a file
/// (`create_new` also covers a file created between check and write).
fn save_svg(path: &str, svg: &str) -> Result<String, String> {
    use std::io::Write as _;
    use validation::export_path::{validate_svg_export_path, ExportPathStatus};
    let status = validate_svg_export_path(path).map_err(|e| format!("Invalid file: {e}"))?;
    if let ExportPathStatus::Exists(p) = &status {
        return Err(format!(
            "Target file already exists: {}. Pick a different name or delete the file first.",
            p.0.display()
        ));
    }
    let target = status.path().0.clone();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| format!("Could not create {}: {e}", target.display()))?;
    file.write_all(svg.as_bytes())
        .map_err(|e| format!("Could not write {}: {e}", target.display()))?;
    Ok(format!("Graph saved: {}", target.display()))
}

/// Draws `perm` with the current "Show all groups" setting and selection —
/// the shapes in both palettes (Slint picks by `Theme.dark`), the texts with
/// both colours, and every box as a click target (ADR 0081).
fn draw(ui: &MainWindow, perm: &EffectivePermission) {
    let opts = viz::GraphOptions {
        all_groups: ui.global::<GraphState>().get_all_groups(),
        caption: false,
    };
    let Some(graph) = viz::permission_graph_with(perm, opts) else {
        clear(
            ui,
            "No graph for this result: no ACE on this object reaches the account or its groups. The permission path in the Analyze tab explains the result (for example a missing or empty DACL).",
        );
        return;
    };
    let boxes = graph.node_boxes();
    let selected = usize::try_from(ui.global::<GraphState>().get_selected())
        .ok()
        .filter(|i| *i < boxes.len());
    let render = |dark: bool| viz::RenderOptions {
        dark,
        highlight: selected,
        responsive: false,
    };
    let light =
        slint::Image::load_from_svg_data(graph.to_svg_shapes_with(&render(false)).as_bytes());
    let dark = slint::Image::load_from_svg_data(graph.to_svg_shapes_with(&render(true)).as_bytes());
    match (light, dark) {
        (Ok(light), Ok(dark)) => {
            ui.global::<GraphState>().set_image(light);
            ui.global::<GraphState>().set_image_dark(dark);
            let lit = graph.route_nodes(selected);
            let texts: Vec<GraphTextVm> = graph
                .texts
                .iter()
                .map(|t| GraphTextVm {
                    x: t.x as f32,
                    // Baseline (SVG) to the top of the text box: one font
                    // size up is close enough for 12 px Segoe UI.
                    y: (t.baseline - viz::FONT_SIZE) as f32,
                    text: t.text.as_str().into(),
                    bold: t.style.bold(),
                    color_light: hex_colour(t.style.colour_in(false)),
                    color_dark: hex_colour(t.style.colour_in(true)),
                    faded: t.node.is_some_and(|i| !lit.get(i).copied().unwrap_or(true)),
                })
                .collect();
            ui.global::<GraphState>()
                .set_texts(slint::ModelRc::new(slint::VecModel::from(texts)));
            let nodes: Vec<GraphNodeVm> = boxes
                .iter()
                .enumerate()
                .map(|(i, b)| GraphNodeVm {
                    x: b.x as f32,
                    y: b.y as f32,
                    w: b.w as f32,
                    h: b.h as f32,
                    index: i32::try_from(i).unwrap_or(i32::MAX),
                })
                .collect();
            ui.global::<GraphState>()
                .set_nodes(slint::ModelRc::new(slint::VecModel::from(nodes)));
            ui.global::<GraphState>()
                .set_selected(selected.map_or(-1, |i| i32::try_from(i).unwrap_or(-1)));
            ui.global::<GraphState>().set_detail(
                selected
                    .map(|i| boxes[i].title.clone())
                    .unwrap_or_default()
                    .into(),
            );
            // The list is for the compact view; with every group drawn it
            // would only repeat the boxes.
            let further = if opts.all_groups {
                String::new()
            } else {
                further_groups_text(&graph.further_groups)
            };
            ui.global::<GraphState>().set_further_groups(further.into());
            ui.global::<GraphState>().set_has_graph(true);
            ui.global::<GraphState>().set_caption(
                format!(
                    "Permission graph — {} on {}",
                    perm.identity
                        .name
                        .as_deref()
                        .unwrap_or(&perm.identity.sid.0),
                    perm.path.0
                )
                .into(),
            );
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!("permission graph could not be rendered: {e}");
            clear(
                ui,
                "The graph could not be rendered; the permission path in the Analyze tab is complete. The HTML report embeds the graph as well.",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::save_svg;

    /// ADR 0081: a saved graph never overwrites a file, and only `.svg`
    /// is accepted.
    #[test]
    fn save_svg_writes_new_files_only() {
        let dir = std::env::temp_dir();
        let target = dir.join(format!("adpa-graph-{}.svg", uuid::Uuid::new_v4()));
        let path = target.to_str().unwrap();
        let msg = save_svg(path, "<svg/>").unwrap();
        assert!(msg.starts_with("Graph saved"), "{msg}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "<svg/>");
        let again = save_svg(path, "<svg>other</svg>").unwrap_err();
        assert!(again.contains("already exists"), "{again}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "<svg/>",
            "unchanged"
        );
        let _ = std::fs::remove_file(&target);
        let wrong = dir.join("adpa-graph.html");
        assert!(save_svg(wrong.to_str().unwrap(), "<svg/>").is_err());
    }
}
