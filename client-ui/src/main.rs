//! ModelLock buyer desktop UI entry (real core on Windows, mock preview elsewhere).

use eframe::egui;
use modelock_client_ui::app::{App, AppCore};
#[cfg(windows)]
mod core_real;
#[cfg(not(windows))]
use modelock_client_ui::core_mock::MockCore;

fn make_core() -> Box<dyn AppCore> {
    #[cfg(windows)]
    {
        Box::new(core_real::RealCore::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(MockCore::new())
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ui(ctx);
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 660.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ModelLock",
        options,
        Box::new(|_cc| Ok(Box::new(App::new(make_core())))),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
