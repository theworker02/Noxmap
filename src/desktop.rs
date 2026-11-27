#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText, Stroke};
use noxmap::scanner::{PortResult, PortState, parse_ports, top_tcp_ports};
use noxmap::storage::SnapshotStore;
use noxmap::{ScanOptions, ScanPolicy, Scanner};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "Noxmap",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1180.0, 760.0]),
            ..Default::default()
        },
        Box::new(|creation| {
            configure_theme(&creation.egui_ctx);
            Ok(Box::new(NoxmapDesktop::default()))
        }),
    )
}

fn configure_theme(context: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(14, 19, 28);
    visuals.window_fill = Color32::from_rgb(22, 29, 40);
    visuals.extreme_bg_color = Color32::from_rgb(9, 13, 20);
    visuals.faint_bg_color = Color32::from_rgb(28, 37, 50);
    visuals.selection.bg_fill = Color32::from_rgb(31, 106, 208);
    visuals.widgets.active.bg_fill = Color32::from_rgb(40, 123, 231);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 55, 75);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(25, 34, 47);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(56, 71, 91));
    visuals.window_stroke = Stroke::new(1.0, Color32::from_rgb(46, 61, 80));
    context.set_visuals(visuals);
}

struct NoxmapDesktop {
    target: String,
    port_spec: String,
    use_fast_profile: bool,
    allow_public: bool,
    identify_services: bool,
    result: Option<noxmap::ScanSnapshot>,
    history: Vec<noxmap::ScanSnapshot>,
    message: Option<String>,
}

impl Default for NoxmapDesktop {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".into(),
            port_spec: "22,80,443,8080".into(),
            use_fast_profile: false,
            allow_public: false,
            identify_services: true,
            result: None,
            history: Vec::new(),
            message: None,
        }
    }
}

impl NoxmapDesktop {
    fn scan(&mut self) {
        let ports = if self.use_fast_profile {
            top_tcp_ports(100)
        } else {
            parse_ports(&self.port_spec)
        };
        let ports = match ports {
            Ok(ports) => ports,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        let policy = ScanPolicy {
            allow_public: self.allow_public,
            ..ScanPolicy::default()
        };
        let options = ScanOptions {
            ports,
            identify_services: self.identify_services,
            ..ScanOptions::default()
        };
        match Scanner::new(policy).scan(self.target.trim(), &options) {
            Ok(snapshot) => {
                let attempts = snapshot.ports.len();
                let target = snapshot.target.clone();
                match SnapshotStore::open(".noxmap").and_then(|store| {
                    store.append(&snapshot)?;
                    store.history(&target)
                }) {
                    Ok(history) => {
                        self.history = history;
                        self.message = Some(format!(
                            "Completed {attempts} TCP connection attempts and saved this local snapshot."
                        ));
                    }
                    Err(error) => {
                        self.message = Some(format!(
                            "Completed {attempts} TCP connection attempts, but could not save local history: {error}"
                        ));
                    }
                }
                self.result = Some(snapshot);
            }
            Err(error) => self.message = Some(error),
        }
    }

    fn load_history(&mut self) {
        let target = self.target.trim();
        if target.is_empty() {
            self.message = Some("Enter a target before loading local history.".into());
            return;
        }
        match SnapshotStore::open(".noxmap").and_then(|store| store.history(target)) {
            Ok(history) => {
                let count = history.len();
                self.history = history;
                self.message = Some(format!("Loaded {count} local snapshots for {target}."));
            }
            Err(error) => self.message = Some(format!("Could not load local history: {error}")),
        }
    }
}

impl eframe::App for NoxmapDesktop {
    fn update(&mut self, context: &egui::Context, _: &mut eframe::Frame) {
        egui::TopBottomPanel::top("app-header")
            .frame(header_frame())
            .show(context, |ui| {
                ui.add_space(7.0);
                ui.horizontal(|ui| {
                    draw_mark(ui);
                    ui.heading(RichText::new("Noxmap").size(25.0).strong());
                    ui.separator();
                    ui.label(RichText::new("Network inventory desktop").color(Color32::LIGHT_GRAY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        status_badge(ui, "LOCAL-FIRST", Color32::from_rgb(119, 186, 255));
                    });
                });
                ui.add_space(7.0);
            });
        egui::SidePanel::left("navigation")
            .resizable(false)
            .default_width(212.0)
            .frame(sidebar_frame())
            .show(context, |ui| {
                draw_navigation(ui);
            });

        egui::CentralPanel::default().show(context, |ui| {
            ui.add_space(14.0);
            ui.heading(RichText::new("Scan workspace").size(25.0));
            ui.label(
                RichText::new("Inventory the systems you are authorized to assess.")
                    .color(Color32::GRAY),
            );
            ui.add_space(14.0);
            draw_scan_configuration(ui, self);
            ui.add_space(14.0);
            draw_results(ui, self);
            ui.add_space(14.0);
            draw_history(ui, self);
        });
    }
}

fn draw_navigation(ui: &mut egui::Ui) {
    ui.add_space(18.0);
    ui.label(
        RichText::new("WORKSPACE")
            .small()
            .strong()
            .color(Color32::GRAY),
    );
    ui.add_space(8.0);
    egui::Frame::default()
        .fill(Color32::from_rgb(25, 75, 145))
        .show(ui, |ui| {
            ui.add_sized(
                [165.0, 30.0],
                egui::Label::new(RichText::new("◉  Scan workspace").strong()),
            );
        });
    ui.add_space(22.0);
    ui.label(
        RichText::new("AVAILABLE NOW")
            .small()
            .strong()
            .color(Color32::GRAY),
    );
    ui.add_space(8.0);
    for item in [
        "TCP connect inventory",
        "Service identification",
        "Bounded fast profile",
        "Local scan history",
    ] {
        ui.label(RichText::new(item).color(Color32::LIGHT_GRAY));
        ui.add_space(4.0);
    }
    ui.add_space(18.0);
    ui.separator();
    ui.add_space(10.0);
    ui.label(RichText::new("Scope guardrails").strong());
    ui.label(RichText::new("Public targets require an explicit acknowledgement. No stealth or packet-forging modes are exposed here.").small().color(Color32::GRAY));
    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        ui.label(
            RichText::new("Noxmap desktop · early access")
                .small()
                .color(Color32::GRAY),
        );
    });
}

fn draw_scan_configuration(ui: &mut egui::Ui, app: &mut NoxmapDesktop) {
    panel_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Scan configuration").size(18.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_sized(
                        [126.0, 34.0],
                        egui::Button::new(RichText::new("Start scan").strong()),
                    )
                    .clicked()
                {
                    app.scan();
                }
                if ui.button("Load history").clicked() {
                    app.load_history();
                }
            });
        });
        ui.label(
            RichText::new("The desktop client uses the same bounded TCP scanner as the CLI.")
                .small()
                .color(Color32::GRAY),
        );
        ui.add_space(14.0);
        ui.columns(2, |columns| {
            columns[0].label(
                RichText::new("TARGET")
                    .small()
                    .strong()
                    .color(Color32::GRAY),
            );
            columns[0].add_sized(
                [300.0, 34.0],
                egui::TextEdit::singleline(&mut app.target).hint_text("hostname or IP address"),
            );
            columns[0].label(
                RichText::new("Hostname, IP address, or permitted local target.")
                    .small()
                    .color(Color32::GRAY),
            );
            columns[1].label(
                RichText::new("TCP PORTS")
                    .small()
                    .strong()
                    .color(Color32::GRAY),
            );
            columns[1].add_enabled_ui(!app.use_fast_profile, |ui| {
                ui.add_sized(
                    [300.0, 34.0],
                    egui::TextEdit::singleline(&mut app.port_spec)
                        .hint_text("22,80,443 or 8000-8100"),
                );
            });
            columns[1].label(
                RichText::new("Comma-separated ports and inclusive ranges.")
                    .small()
                    .color(Color32::GRAY),
            );
        });
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut app.use_fast_profile,
                "Fast profile · 100 curated TCP ports",
            );
            ui.checkbox(&mut app.identify_services, "Identify services");
            ui.checkbox(&mut app.allow_public, "Authorized public target");
        });
    });
}

fn draw_history(ui: &mut egui::Ui, app: &NoxmapDesktop) {
    panel_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Recent local snapshots").size(18.0).strong());
            ui.label(
                RichText::new("Stored only in .noxmap on this machine")
                    .small()
                    .color(Color32::GRAY),
            );
        });
        if app.history.is_empty() {
            ui.label(
                RichText::new("No snapshots loaded for the current target.")
                    .small()
                    .color(Color32::GRAY),
            );
            return;
        }
        egui::Grid::new("snapshot-history")
            .striped(true)
            .min_col_width(120.0)
            .spacing([18.0, 7.0])
            .show(ui, |ui| {
                ui.strong("CAPTURED");
                ui.strong("TARGET");
                ui.strong("OPEN");
                ui.strong("PORTS");
                ui.end_row();
                for snapshot in app.history.iter().rev().take(4) {
                    ui.label(snapshot_age(snapshot.scanned_at_unix_ms));
                    ui.label(&snapshot.target);
                    ui.label(count_state(snapshot, &PortState::Open).to_string());
                    ui.label(snapshot.ports.len().to_string());
                    ui.end_row();
                }
            });
    });
}

fn snapshot_age(scanned_at_unix_ms: u128) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(scanned_at_unix_ms, |duration| duration.as_millis());
    let elapsed_seconds = now.saturating_sub(scanned_at_unix_ms) / 1_000;
    match elapsed_seconds {
        0..=59 => "just now".into(),
        60..=3_599 => format!("{}m ago", elapsed_seconds / 60),
        3_600..=86_399 => format!("{}h ago", elapsed_seconds / 3_600),
        _ => format!("{}d ago", elapsed_seconds / 86_400),
    }
}

fn draw_results(ui: &mut egui::Ui, app: &NoxmapDesktop) {
    panel_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Port results").size(18.0).strong());
            if let Some(snapshot) = &app.result {
                ui.label(
                    RichText::new(snapshot.target.as_str())
                        .small()
                        .color(Color32::GRAY),
                );
            }
        });
        if let Some(message) = &app.message {
            ui.label(
                RichText::new(message)
                    .small()
                    .color(Color32::from_rgb(132, 196, 255)),
            );
        } else {
            ui.label(
                RichText::new("No scan has run in this desktop session.")
                    .small()
                    .color(Color32::GRAY),
            );
        }
        if let Some(snapshot) = &app.result {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                metric_card(
                    ui,
                    "SCANNED",
                    snapshot.ports.len().to_string(),
                    Color32::from_rgb(124, 178, 255),
                );
                metric_card(
                    ui,
                    "OPEN",
                    count_state(snapshot, &PortState::Open).to_string(),
                    Color32::from_rgb(87, 210, 143),
                );
                metric_card(
                    ui,
                    "CLOSED",
                    count_state(snapshot, &PortState::Closed).to_string(),
                    Color32::from_rgb(167, 180, 199),
                );
                metric_card(
                    ui,
                    "OTHER",
                    (snapshot.ports.len()
                        - count_state(snapshot, &PortState::Open)
                        - count_state(snapshot, &PortState::Closed))
                    .to_string(),
                    Color32::from_rgb(246, 183, 95),
                );
            });
        }
        ui.add_space(12.0);
        egui::ScrollArea::vertical()
            .max_height(330.0)
            .show(ui, |ui| {
                egui::Grid::new("port-results")
                    .striped(true)
                    .min_col_width(110.0)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        ui.strong("PORT");
                        ui.strong("PROTOCOL");
                        ui.strong("STATE");
                        ui.strong("SERVICE");
                        ui.strong("EVIDENCE");
                        ui.end_row();
                        if let Some(snapshot) = &app.result {
                            for port in &snapshot.ports {
                                draw_port_row(ui, port);
                            }
                        } else {
                            ui.label(
                                RichText::new("Run a scan to see port results.")
                                    .color(Color32::GRAY),
                            );
                            ui.end_row();
                        }
                    });
            });
    });
}

fn draw_port_row(ui: &mut egui::Ui, port: &PortResult) {
    ui.label(port.port.to_string());
    ui.label("TCP");
    let color = match port.state {
        PortState::Open => Color32::from_rgb(104, 211, 145),
        PortState::Closed => Color32::from_rgb(160, 174, 192),
        PortState::Filtered | PortState::Unreachable | PortState::Unresolved => {
            Color32::from_rgb(246, 173, 85)
        }
    };
    ui.colored_label(color, format!("{:?}", port.state).to_lowercase());
    ui.label(
        port.service
            .as_ref()
            .map_or("unknown", |service| &service.name),
    );
    ui.label(
        port.service
            .as_ref()
            .map_or("", |service| &service.evidence),
    );
    ui.end_row();
}

fn header_frame() -> egui::Frame {
    egui::Frame::default().fill(Color32::from_rgb(16, 22, 31))
}

fn sidebar_frame() -> egui::Frame {
    egui::Frame::default().fill(Color32::from_rgb(12, 17, 25))
}

fn panel_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(Color32::from_rgb(22, 30, 42))
        .stroke(Stroke::new(1.0, Color32::from_rgb(49, 65, 86)))
        .inner_margin(egui::Margin::same(16))
}

fn draw_mark(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    let blue = Color32::from_rgb(65, 152, 255);
    painter.circle_stroke(center, 10.0, Stroke::new(2.0, blue));
    painter.line_segment(
        [rect.left_center(), rect.right_center()],
        Stroke::new(2.0, blue),
    );
    painter.line_segment(
        [rect.center_top(), rect.center_bottom()],
        Stroke::new(2.0, blue),
    );
    painter.circle_filled(center, 3.0, blue);
}

fn status_badge(ui: &mut egui::Ui, label: &str, color: Color32) {
    egui::Frame::default()
        .fill(Color32::from_rgb(24, 43, 68))
        .show(ui, |ui| {
            ui.label(RichText::new(label).small().strong().color(color));
        });
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: String, color: Color32) {
    egui::Frame::default()
        .fill(Color32::from_rgb(17, 24, 34))
        .show(ui, |ui| {
            ui.set_min_width(104.0);
            ui.label(RichText::new(label).small().strong().color(Color32::GRAY));
            ui.label(RichText::new(value).size(22.0).strong().color(color));
        });
}

fn count_state(snapshot: &noxmap::ScanSnapshot, state: &PortState) -> usize {
    snapshot
        .ports
        .iter()
        .filter(|port| &port.state == state)
        .count()
}

#[cfg(test)]
mod tests {
    use super::snapshot_age;

    #[test]
    fn formats_snapshot_age_with_compact_units() {
        assert_eq!(snapshot_age(u128::MAX), "just now");
    }
}

