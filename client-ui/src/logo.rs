//! Load the app logo (docs/logo.png) for the UI texture and window icon.
//! Installed layout: logo.png sits next to the exe; dev layout: repo docs/.

use eframe::egui;

const LOGO_TEXTURE_NAME: &str = "model_lock_logo";

/// Locate logo.png: next to the exe (installed) or ../../../docs (cargo run:
/// target/{debug,release} is three levels under the repo root).
fn logo_bytes() -> Option<Vec<u8>> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for cand in [
        exe_dir.join("logo.png"),
        exe_dir.join("../../../docs/logo.png"),
    ] {
        if let Ok(bytes) = std::fs::read(&cand) {
            log::info!("logo loaded from {}", cand.display());
            return Some(bytes);
        }
    }
    log::warn!("logo.png not found (exe dir or ../../../docs)");
    None
}

/// Decode logo.png into an egui texture for on-screen display.
pub fn load_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let img = image::load_from_memory(&logo_bytes()?).ok()?.to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
    Some(ctx.load_texture(LOGO_TEXTURE_NAME, color, egui::TextureOptions::LINEAR))
}

/// Decode logo.png into window-icon data (downscaled; icons are small).
pub fn icon_data() -> Option<egui::IconData> {
    let img = image::load_from_memory(&logo_bytes()?)
        .ok()?
        .resize(256, 256, image::imageops::FilterType::Triangle)
        .to_rgba8();
    Some(egui::IconData {
        rgba: img.as_raw().clone(),
        width: img.width(),
        height: img.height(),
    })
}
