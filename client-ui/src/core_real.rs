//! Real core (Windows only): delegates to modelock-client.

use std::path::Path;

use modelock_client::{self as core, MountConfig, MountHandle};

use modelock_client_ui::app::{AppCore, ModelEntry};

pub struct RealCore {
    handle: Option<MountHandle>,
    mounted: Option<String>,
}

impl RealCore {
    pub fn new() -> Self {
        Self {
            handle: None,
            mounted: None,
        }
    }
}

fn to_entry(m: core::auth::AcceptedLicense) -> ModelEntry {
    ModelEntry {
        model_id: m.model_id,
        expires_at: m.expires_at,
        note: m.note,
        vkit_path: m.vkit_path,
    }
}

impl AppCore for RealCore {
    fn list_models(&self) -> Vec<ModelEntry> {
        core::list_models().unwrap_or_default().into_iter().map(to_entry).collect()
    }

    fn is_trusted(&self) -> bool {
        core::is_author_trusted().unwrap_or(false)
    }

    fn init_device(&self, path: &Path) -> Result<String, String> {
        core::init_device(path).map(|i| i.key_id).map_err(|e| format!("{e:#}"))
    }

    fn trust_author(&self, path: &Path) -> Result<String, String> {
        core::trust_author_file(path).map_err(|e| format!("{e:#}"))
    }

    fn verify_and_accept(&self, path: &Path, code: Option<&str>) -> Result<ModelEntry, String> {
        core::verify_and_accept(path, code).map(to_entry).map_err(|e| format!("{e:#}"))
    }

    fn mount(&mut self, path: &Path, kill_vts: bool) -> Result<(), String> {
        let cfg = MountConfig {
            kill_vts_on_unmount: kill_vts,
            ..Default::default()
        };
        let handle = core::mount_model(path, None, &cfg).map_err(|e| format!("{e:#}"))?;
        self.mounted = Some(core::list_models().unwrap_or_default().first().map(|m| m.model_id.clone()).unwrap_or_else(|| "model".to_string()));
        self.handle = Some(handle);
        Ok(())
    }

    fn unmount(&mut self) {
        if let Some(mut h) = self.handle.take() {
            h.stop();
        }
        self.mounted = None;
    }

    fn is_mounted(&self) -> bool {
        self.handle.as_ref().map(|h| h.is_running()).unwrap_or(false)
    }

    fn mounted_model(&self) -> Option<String> {
        self.mounted.clone()
    }

    fn remove_model(&self, model_id: &str) -> Result<(), String> {
        core::remove_model(model_id).map_err(|e| format!("{e:#}"))
    }
}
