//! Mock core for UI preview / non-Windows builds.

use std::path::Path;

use crate::app::{AppCore, ModelEntry};

pub struct MockCore {
    mounted: Option<String>,
    models: Vec<ModelEntry>,
}

impl MockCore {
    pub fn new() -> Self {
        Self {
            mounted: Some("小樱".to_string()),
            models: vec![
                ModelEntry {
                    model_id: "小樱".to_string(),
                    expires_at: Some("2027-12-31".to_string()),
                    note: "阿花".to_string(),
                    vkit_path: r"D:\models\小樱-阿花.vkit".to_string(),
                },
                ModelEntry {
                    model_id: "初音".to_string(),
                    expires_at: None,
                    note: "阿花".to_string(),
                    vkit_path: r"D:\models\初音-阿花.vkit".to_string(),
                },
            ],
        }
    }
}

impl AppCore for MockCore {
    fn list_models(&self) -> Vec<ModelEntry> {
        self.models.clone()
    }

    fn is_trusted(&self) -> bool {
        true
    }

    fn init_device(&self, _path: &Path) -> Result<String, String> {
        Ok("c047d12e3f4a5b6c".to_string())
    }

    fn trust_author(&self, _path: &Path) -> Result<String, String> {
        Ok("aabbccdd11223344".to_string())
    }

    fn verify_and_accept(&self, _path: &Path, _code: Option<&str>) -> Result<ModelEntry, String> {
        Ok(self.models[0].clone())
    }

    fn mount(&mut self, _path: &Path, _kill_vts: bool) -> Result<(), String> {
        self.mounted = Some(self.models[0].model_id.clone());
        Ok(())
    }

    fn unmount(&mut self) {
        self.mounted = None;
    }

    fn is_mounted(&self) -> bool {
        self.mounted.is_some()
    }

    fn mounted_model(&self) -> Option<String> {
        self.mounted.clone()
    }

    fn remove_model(&self, _model_id: &str) -> Result<(), String> {
        Ok(())
    }
}
