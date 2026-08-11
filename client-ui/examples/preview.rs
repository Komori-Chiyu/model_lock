//! Headless UI preview: renders the buyer UI pages to PNGs with a tiny software
//! rasterizer (no GPU / display required).

use eframe::egui::{self, epaint, Pos2};
use modelock_client_ui::app::{App, Page};
use modelock_client_ui::core_mock::MockCore;

const W: usize = 960;
const H: usize = 660;

/// Sample the font atlas (one float coverage per texel).
fn sample(px: &[f32], w: usize, h: usize, u: f32, v: f32) -> f32 {
    if px.is_empty() || w == 0 || h == 0 {
        return 1.0;
    }
    let x = ((u.clamp(0.0, 1.0)) * (w - 1) as f32).round() as usize;
    let y = ((v.clamp(0.0, 1.0)) * (h - 1) as f32).round() as usize;
    let i = y * w + x;
    if i >= px.len() {
        return 0.0;
    }
    px[i].clamp(0.0, 1.0)
}

fn raster_tri(
    buf: &mut [u8],
    w: usize,
    h: usize,
    v0: &epaint::Vertex,
    v1: &epaint::Vertex,
    v2: &epaint::Vertex,
    atlas: &[f32],
    aw: usize,
    ah: usize,
) {
    let a = v0.pos;
    let b = v1.pos;
    let c = v2.pos;
    let det = (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
    if det.abs() < 1e-6 {
        return;
    }
    let x0 = a.x.min(b.x).min(c.x).floor().max(0.0) as usize;
    let x1 = (a.x.max(b.x).max(c.x).ceil() as usize).min(w);
    let y0 = a.y.min(b.y).min(c.y).floor().max(0.0) as usize;
    let y1 = (a.y.max(b.y).max(c.y).ceil() as usize).min(h);
    for y in y0..y1 {
        for x in x0..x1 {
            let p = Pos2::new(x as f32 + 0.5, y as f32 + 0.5);
            let pa = Pos2::new(p.x - a.x, p.y - a.y);
            let ba = Pos2::new(b.x - a.x, b.y - a.y);
            let ca = Pos2::new(c.x - a.x, c.y - a.y);
            // p = a + u*ba + v*ca
            let u = (pa.x * ca.y - pa.y * ca.x) / det;
            let v = (ba.x * pa.y - ba.y * pa.x) / det;
            let ww = 1.0 - u - v;
            if u < 0.0 || v < 0.0 || ww < 0.0 {
                continue;
            }
            let uv = Pos2::new(
                u * v0.uv.x + v * v1.uv.x + ww * v2.uv.x,
                u * v0.uv.y + v * v1.uv.y + ww * v2.uv.y,
            );
            let ca = (u * v0.color.a() as f32 + v * v1.color.a() as f32 + ww * v2.color.a() as f32)
                / 255.0;
            let cr = (u * v0.color.r() as f32 + v * v1.color.r() as f32 + ww * v2.color.r() as f32)
                / 255.0;
            let cg = (u * v0.color.g() as f32 + v * v1.color.g() as f32 + ww * v2.color.g() as f32)
                / 255.0;
            let cb = (u * v0.color.b() as f32 + v * v1.color.b() as f32 + ww * v2.color.b() as f32)
                / 255.0;
            let cov = sample(atlas, aw, ah, uv.x, uv.y);
            let idx = (y * w + x) * 4;
            let bg_r = buf[idx] as f32;
            let bg_g = buf[idx + 1] as f32;
            let bg_b = buf[idx + 2] as f32;
            let a_eff = (ca * cov).clamp(0.0, 1.0);
            buf[idx] = (cr * 255.0 * a_eff + bg_r * (1.0 - a_eff)).round() as u8;
            buf[idx + 1] = (cg * 255.0 * a_eff + bg_g * (1.0 - a_eff)).round() as u8;
            buf[idx + 2] = (cb * 255.0 * a_eff + bg_b * (1.0 - a_eff)).round() as u8;
        }
    }
}

fn snapshot(page: Page, name: &str, dir: &str) -> anyhow::Result<()> {
    let mut app = App::new(Box::new(MockCore::new()));
    app.set_page(page);

    let mut ctx = egui::Context::default();
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(Pos2::ZERO, egui::vec2(W as f32, H as f32))),
        ..Default::default()
    };
    let output = ctx.run(input, |ctx| app.ui(ctx));
    let clipped = ctx.tessellate(output.shapes, output.pixels_per_point);

    let atlas = ctx.fonts(|f| f.texture_atlas());
    let font_image = atlas.lock().image().clone();
    let aw = font_image.size[0];
    let ah = font_image.size[1];

    let mut buf = vec![0u8; W * H * 4];
    for i in 0..W * H {
        buf[i * 4 + 0] = 255;
        buf[i * 4 + 1] = 250;
        buf[i * 4 + 2] = 252;
        buf[i * 4 + 3] = 255;
    }
    for clip in &clipped {
        let epaint::Primitive::Mesh(mesh) = &clip.primitive else {
            continue;
        };
        for tri in mesh.indices.chunks_exact(3) {
            let i0 = tri[0] as usize;
            let i1 = tri[1] as usize;
            let i2 = tri[2] as usize;
            raster_tri(
                &mut buf,
                W,
                H,
                &mesh.vertices[i0],
                &mesh.vertices[i1],
                &mesh.vertices[i2],
                &font_image.pixels,
                aw,
                ah,
            );
        }
    }
    let path = format!("{dir}/{name}.png");
    image::save_buffer(&path, &buf, W as u32, H as u32, image::ColorType::Rgba8)?;
    println!("saved {path}");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    std::fs::create_dir_all(&dir)?;
    snapshot(Page::Library, "buyer_library", &dir)?;
    snapshot(Page::Trust, "buyer_trust", &dir)?;
    snapshot(Page::Settings, "buyer_settings", &dir)?;
    println!("done");
    Ok(())
}
