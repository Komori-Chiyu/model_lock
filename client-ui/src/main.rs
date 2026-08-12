//! ModelLock buyer desktop UI entry (real core on Windows, mock preview elsewhere).
//! GUI app: no console window in release builds.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use modelock_client_ui::app::{App, AppCore};
use modelock_client_ui::logo;
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

/// Load a CJK font from the system so Chinese text renders (egui's built-in
/// fonts are Latin-only). Appended as a fallback family, so Latin stays on
/// the default font. No-op when no candidate file exists (e.g. Linux preview).
fn install_cjk_fonts(ctx: &egui::Context) {
    #[cfg(windows)]
    let candidates: [&str; 5] = [
        "C:\\Windows\\Fonts\\msyh.ttc", // 微软雅黑
        "C:\\Windows\\Fonts\\msyh.ttf",
        "C:\\Windows\\Fonts\\simhei.ttf", // 黑体
        "C:\\Windows\\Fonts\\simsun.ttc", // 宋体
        "C:\\Windows\\Fonts\\Deng.ttf",   // 等线
    ];
    #[cfg(not(windows))]
    let candidates: [&str; 0] = [];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .push("cjk".to_owned());
            }
            ctx.set_fonts(fonts);
            log::info!("loaded CJK font from {path}");
            return;
        }
    }
    log::warn!("no CJK font found; Chinese text may render as boxes");
}

/// Wrapper to implement `eframe::App` for the library `App` (orphan rule).
struct GuiApp(App);

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.0.ui(ctx);
    }
}

/// Single-instance guard: if another ModelLock client is already running,
/// tell the user and exit. The mutex handle is deliberately leaked — it must
/// stay alive for the whole process and is released by the OS on exit.
#[cfg(windows)]
fn ensure_single_instance() -> bool {
    use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::synchapi::CreateMutexW;
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    unsafe {
        let name = wide("ModelLockClientSingleton");
        let handle = CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr());
        if handle.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            let title = wide("星零集模型锁");
            let msg = wide("星零集模型锁 已经在运行中。");
            winapi::um::winuser::MessageBoxW(std::ptr::null_mut(), msg.as_ptr(), title.as_ptr(), 0);
            return false;
        }
        std::mem::forget(handle);
    }
    true
}

#[cfg(not(windows))]
fn ensure_single_instance() -> bool {
    true
}

fn main() -> anyhow::Result<()> {
    if !ensure_single_instance() {
        return Ok(());
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([960.0, 660.0])
        .with_title("星零集模型锁");
    if let Some(icon) = logo::icon_data() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "星零集模型锁",
        options,
        Box::new(|cc| {
            install_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(GuiApp(App::new(make_core()))))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
