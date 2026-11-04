//! Warden desktop entry point.

mod app;
mod i18n;
mod theme;

use app::WardenApp;

fn main() -> eframe::Result {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Warden")
            .with_app_id("warden")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 600.0])
            .with_icon(theme::icon()),
        ..Default::default()
    };

    eframe::run_native(
        "Warden",
        options,
        Box::new(|cc| Ok(Box::new(WardenApp::new(cc)))),
    )
}
