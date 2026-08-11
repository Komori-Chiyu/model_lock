//! ModelLock buyer UI (core-agnostic; real core on Windows, mock on Linux preview).

use eframe::egui;
use std::path::Path;

const PINK: egui::Color32 = egui::Color32::from_rgb(255, 205, 220);
const PURPLE: egui::Color32 = egui::Color32::from_rgb(190, 170, 240);
const TEXT_DARK: egui::Color32 = egui::Color32::from_rgb(70, 60, 80);
const OK_GREEN: egui::Color32 = egui::Color32::from_rgb(120, 190, 150);

#[derive(PartialEq, Clone, Copy)]
pub enum Page {
    Library,
    Trust,
    Settings,
}

#[derive(Clone)]
pub struct ModelEntry {
    pub model_id: String,
    pub expires_at: Option<String>,
    pub note: String,
    pub vkit_path: String,
}

pub trait AppCore {
    fn list_models(&self) -> Vec<ModelEntry>;
    fn is_trusted(&self) -> bool;
    fn init_device(&self, path: &Path) -> Result<String, String>;
    fn trust_author(&self, path: &Path) -> Result<String, String>;
    fn verify_and_accept(&self, path: &Path, code: Option<&str>) -> Result<ModelEntry, String>;
    fn mount(&mut self, path: &Path, kill_vts: bool) -> Result<(), String>;
    fn unmount(&mut self);
    fn is_mounted(&self) -> bool;
    fn mounted_model(&self) -> Option<String>;
    fn remove_model(&self, model_id: &str) -> Result<(), String>;
}

pub struct App {
    core: Box<dyn AppCore>,
    page: Page,
    models: Vec<ModelEntry>,
    trusted: bool,
    author_key_id: String,
    kill_vts: bool,
    pending_vkit: Option<String>,
    pending_code: String,
    mounted_model: Option<String>,
    messages: Vec<String>,
}

impl App {
    pub fn new(core: Box<dyn AppCore>) -> Self {
        let models = core.list_models();
        let trusted = core.is_trusted();
        let mounted_model = core.mounted_model();
        Self {
            core,
            page: Page::Library,
            models,
            trusted,
            author_key_id: String::new(),
            kill_vts: false,
            pending_vkit: None,
            pending_code: String::new(),
            mounted_model,
            messages: Vec::new(),
        }
    }

    pub fn set_page(&mut self, page: Page) {
        self.page = page;
    }

    fn log(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        log::info!("{m}");
        self.messages.push(m);
        if self.messages.len() > 200 {
            self.messages.drain(..100);
        }
    }

    fn refresh_models(&mut self) {
        self.models = self.core.list_models();
    }

    fn do_export_vreq(&mut self) {
        match rfd::FileDialog::new().set_file_name("授权请求.vreq").save_file() {
            Some(path) => match self.core.init_device(&path) {
                Ok(kid) => self.log(format!("已导出授权请求 key_id={}", &kid[..8.min(kid.len())])),
                Err(e) => self.log(format!("导出失败: {e}")),
            },
            None => {}
        }
    }

    fn do_trust_author(&mut self) {
        match rfd::FileDialog::new()
            .add_filter("author.spki", &["spki", "txt"])
            .pick_file()
        {
            Some(path) => match self.core.trust_author(&path) {
                Ok(kid) => {
                    self.trusted = true;
                    self.author_key_id = kid.clone();
                    self.log(format!("已信任作者密钥 {}", &kid[..8.min(kid.len())]));
                }
                Err(e) => self.log(format!("信任失败: {e}")),
            },
            None => {}
        }
    }

    fn do_pick_vkit(&mut self) {
        match rfd::FileDialog::new().add_filter("vkit", &["vkit"]).pick_file() {
            Some(path) => {
                self.pending_vkit = Some(path.display().to_string());
                self.pending_code.clear();
            }
            None => {}
        }
    }

    fn do_mount(&mut self) {
        let Some(path) = self.pending_vkit.clone() else {
            self.log("请先选择 .vkit 文件");
            return;
        };
        if self.core.is_mounted() {
            self.log("已有模型挂载中，请先卸载");
            return;
        }
        if !self.trusted {
            self.log("请先在「信任作者」页导入作者公钥");
            self.page = Page::Trust;
            return;
        }
        let code = if self.pending_code.trim().is_empty() {
            None
        } else {
            Some(self.pending_code.trim().to_string())
        };
        let path_p = std::path::PathBuf::from(&path);
        match self.core.verify_and_accept(&path_p, code.as_deref()) {
            Ok(entry) => match self.core.mount(&path_p, self.kill_vts) {
                Ok(()) => {
                    self.log(format!("已挂载 {}", entry.model_id));
                    self.refresh_models();
                }
                Err(e) => self.log(format!("挂载失败: {e}")),
            },
            Err(e) => self.log(format!("授权校验失败: {e}")),
        }
    }

    fn do_unmount(&mut self) {
        self.core.unmount();
        self.log("正在卸载…（VTS 保持运行）");
    }

    fn do_mount_existing(&mut self, model_id: &str) {
        let Some(entry) = self.models.iter().find(|m| m.model_id == model_id).cloned() else {
            return;
        };
        let path = std::path::PathBuf::from(&entry.vkit_path);
        if !path.exists() {
            self.log(format!("找不到模型文件: {}", entry.vkit_path));
            return;
        }
        if self.core.is_mounted() {
            self.log("已有模型挂载中，请先卸载");
            return;
        }
        match self.core.mount(&path, self.kill_vts) {
            Ok(()) => self.log(format!("已挂载 {}", entry.model_id)),
            Err(e) => self.log(format!("挂载失败: {e}")),
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        self.mounted_model = self.core.mounted_model();

        let mut visuals = egui::Visuals::light();
        visuals.panel_fill = egui::Color32::from_rgb(255, 250, 252);
        visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
        visuals.selection.bg_fill = PINK;
        visuals.override_text_color = Some(TEXT_DARK);
        ctx.set_visuals(visuals);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🐱 ModelLock");
                ui.label("买家端 · demo");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match &self.mounted_model {
                        Some(m) => {
                            ui.colored_label(OK_GREEN, format!("● {m} 挂载中"));
                            if ui.button("卸载").clicked() {
                                self.do_unmount();
                            }
                        }
                        None => {
                            ui.colored_label(egui::Color32::GRAY, "○ 未挂载");
                        }
                    }
                });
            });
            ui.add_space(6.0);
        });

        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.add_space(10.0);
            let items = [
                (Page::Library, "📚 我的模型"),
                (Page::Trust, "🔑 信任作者"),
                (Page::Settings, "⚙️ 设置"),
            ];
            for (page, label) in items {
                if ui.selectable_label(self.page == page, label).clicked() {
                    self.page = page;
                }
                ui.add_space(4.0);
            }
            ui.add_space(20.0);
            ui.label("消息");
            ui.separator();
            egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                for m in self.messages.iter().rev().take(30) {
                    ui.label(
                        egui::RichText::new(m).size(11.0).color(egui::Color32::from_rgb(120, 110, 130)),
                    );
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Library => self.ui_library(ui),
            Page::Trust => self.ui_trust(ui),
            Page::Settings => self.ui_settings(ui),
        });
    }

    fn ui_library(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("我的模型");
        ui.label("将画师发来的 .vkit 加入并输入激活码，一键挂载给 VTube Studio。");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button("＋ 添加 .vkit").clicked() {
                self.do_pick_vkit();
            }
            if ui.button("刷新列表").clicked() {
                self.refresh_models();
            }
        });

        let pending = self.pending_vkit.clone();
        if let Some(path) = &pending {
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new("待挂载").strong().color(PURPLE));
                ui.label(path);
                ui.horizontal(|ui| {
                    ui.label("激活码：");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pending_code)
                            .hint_text("首次使用输入，之后自动记住")
                            .desired_width(220.0),
                    );
                    if ui.button("🚀 挂载").clicked() {
                        self.do_mount();
                    }
                });
            });
        }

        ui.add_space(10.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.models.is_empty() {
                ui.label("还没有已授权的模型，先「添加 .vkit」吧～");
                return;
            }
            for m in self.models.clone() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&m.model_id).strong());
                        let exp = m.expires_at.clone().unwrap_or_else(|| "永久".to_string());
                        ui.label(format!("有效期: {exp}"));
                        if !m.note.is_empty() {
                            ui.label(format!("备注: {}", m.note));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("移除").clicked() {
                                let _ = self.core.remove_model(&m.model_id);
                                self.refresh_models();
                            }
                            if ui.button("挂载").clicked() {
                                self.do_mount_existing(&m.model_id);
                            }
                        });
                    });
                    ui.label(
                        egui::RichText::new(&m.vkit_path)
                            .size(11.0)
                            .color(egui::Color32::from_rgb(140, 130, 150)),
                    );
                });
                ui.add_space(6.0);
            }
        });
    }

    fn ui_trust(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("信任作者");
        ui.label("第一次使用需要两步：① 导出你的授权请求发给画师；② 导入画师返回的作者公钥。");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("① 设备身份").strong().color(PURPLE));
            ui.label("生成设备密钥（私钥不可导出）并导出 .vreq 请求文件。");
            if ui.button("📤 导出授权请求 .vreq").clicked() {
                self.do_export_vreq();
            }
        });

        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("② 作者公钥").strong().color(PURPLE));
            match self.trusted {
                true => {
                    ui.colored_label(OK_GREEN, "✓ 已信任作者");
                    if !self.author_key_id.is_empty() {
                        ui.label(format!("作者密钥 ID: {}", self.author_key_id));
                    }
                }
                false => {
                    ui.colored_label(egui::Color32::from_rgb(230, 150, 120), "✗ 尚未信任任何作者");
                }
            }
            if ui.button("🔑 导入作者公钥 author.spki").clicked() {
                self.do_trust_author();
            }
        });
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("设置");
        ui.add_space(6.0);
        ui.checkbox(&mut self.kill_vts, "卸载时同时关闭 VTube Studio");
        ui.label("默认关闭：卸载只移除虚拟盘，VTS 继续运行。");
        ui.add_space(10.0);
        ui.separator();
        ui.label("关于：ModelLock 买家端 demo v0.1");
        ui.label("完全离线授权 · 一人一码 · 模型绑定本机密钥");
    }
}
