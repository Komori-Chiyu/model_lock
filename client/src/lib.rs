//! ModelLock buyer core library (shared by the CLI and the desktop UI).

pub mod auth;
pub mod device_key;
pub mod util;
pub mod vfs;
pub mod vkit;
pub mod vts;

use anyhow::{bail, Context, Result};
use dokan::{FileSystemMounter, MountFlags, MountOptions};
use rsa::pkcs8::DecodePublicKey;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use widestring::U16CString;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchMode {
    Steam,
    NoSteam,
}

#[derive(Clone, Debug)]
pub struct MountConfig {
    pub vts_override: Option<PathBuf>,
    pub launch_mode: LaunchMode,
    pub kill_vts_on_unmount: bool,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            vts_override: None,
            launch_mode: LaunchMode::Steam,
            kill_vts_on_unmount: false,
        }
    }
}

pub struct DeviceInfo {
    pub key_id: String,
    pub spki_b64: String,
}

pub fn init_device(vreq_out: &Path) -> Result<DeviceInfo> {
    let key = device_key::open_or_create()?;
    device_key::write_vreq(&key, vreq_out)?;
    Ok(DeviceInfo {
        key_id: key.key_id.clone(),
        spki_b64: util::b64e(&key.spki_der),
    })
}

pub fn trust_author_file(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    let b64 = text.trim();
    let der = util::b64d(b64).context("author key file must contain base64 DER SPKI")?;
    rsa::RsaPublicKey::from_public_key_der(&der).context("not a valid RSA public key")?;
    let mut state = auth::load_state()?.unwrap_or_default();
    state.author_spki_b64 = util::b64e(&der);
    auth::save_state(&state)?;
    Ok(device_key::key_id_of_spki(&der))
}

pub fn is_author_trusted() -> Result<bool> {
    Ok(!auth::load_state()?.unwrap_or_default().author_spki_b64.is_empty())
}

pub fn list_models() -> Result<Vec<auth::AcceptedLicense>> {
    Ok(auth::load_state()?.unwrap_or_default().accepted_licenses)
}

pub fn remove_model(model_id: &str) -> Result<()> {
    let mut state = auth::load_state()?.unwrap_or_default();
    state.accepted_licenses.retain(|m| m.model_id != model_id);
    auth::save_state(&state)
}

fn sanitize_model_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let clean = clean.trim_matches('_');
    if clean.is_empty() {
        "model".to_string()
    } else {
        clean.to_string()
    }
}

pub struct MountHandle {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl MountHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }

    pub fn wait(mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| anyhow::anyhow!("mount worker panicked"))?;
        }
        Ok(())
    }
}

/// Verify the offline license and remember the model (idempotent).
pub fn verify_and_accept(vkit_path: &Path, code: Option<&str>) -> Result<auth::AcceptedLicense> {
    let mut state = auth::load_state()?.unwrap_or_default();
    let key = device_key::open_or_create()?;
    let pkg = Arc::new(vkit::Package::open(vkit_path, &key)?);
    let lic = pkg
        .header
        .license
        .clone()
        .context("package has no offline license")?;
    let spki_b64 = state.author_spki_b64.clone();
    if spki_b64.is_empty() {
        bail!("trust the artist key first (trust-author)");
    }
    let author_spki = util::b64d(&spki_b64)?;
    let cached = auth::is_license_accepted(&state, &pkg.header.model_id, &lic.code_hash);
    let code = if cached {
        None
    } else {
        Some(code.context("this package requires an activation code")?)
    };
    vkit::verify_package_license(&pkg.header, &author_spki, &key.key_id, code)?;
    if code.is_some() {
        auth::accept_license(
            &mut state,
            &pkg.header.model_id,
            &lic.code_hash,
            &vkit_path.display().to_string(),
            lic.expires_at.clone(),
            &lic.note,
        )?;
        state = auth::load_state()?.unwrap_or_default();
    }
    Ok(state
        .accepted_licenses
        .iter()
        .find(|m| m.model_id == pkg.header.model_id && m.code_hash == lic.code_hash)
        .cloned()
        .unwrap_or_else(|| auth::AcceptedLicense {
            model_id: pkg.header.model_id.clone(),
            code_hash: lic.code_hash.clone(),
            vkit_path: vkit_path.display().to_string(),
            expires_at: lic.expires_at.clone(),
            note: lic.note.clone(),
        }))
}

/// Mount a model: verify license, mount the Dokan volume, launch VTS through
/// Steam and authorize it. Unmount with `MountHandle::stop` + `wait`.
pub fn mount_model(vkit_path: &Path, code: Option<&str>, cfg: &MountConfig) -> Result<MountHandle> {
    let mut state = auth::load_state()?.unwrap_or_default();
    let key = device_key::open_or_create()?;
    let pkg = Arc::new(vkit::Package::open(vkit_path, &key)?);
    log::info!(
        "package {}: {} files, {} bytes protected",
        pkg.header.model_id,
        pkg.header.files.len(),
        pkg.total_protected_bytes()
    );

    if let Some(lic) = &pkg.header.license {
        let spki_b64 = state.author_spki_b64.clone();
        if spki_b64.is_empty() {
            bail!("trust the artist key first (trust-author)");
        }
        let author_spki = util::b64d(&spki_b64)?;
        let cached = auth::is_license_accepted(&state, &pkg.header.model_id, &lic.code_hash);
        let code = if cached {
            None
        } else {
            Some(code.context("this package requires an activation code")?)
        };
        vkit::verify_package_license(&pkg.header, &author_spki, &key.key_id, code)?;
        if code.is_some() {
            auth::accept_license(
                &mut state,
                &pkg.header.model_id,
                &lic.code_hash,
                &vkit_path.display().to_string(),
                lic.expires_at.clone(),
                &lic.note,
            )?;
        }
        println!("offline license OK (model {})", pkg.header.model_id);
    } else {
        log::warn!("package has no offline license; skipping activation check");
    }

    let vts_exe = match &cfg.vts_override {
        Some(p) => p.clone(),
        None => vts::find_vts()?,
    };
    let model_id = sanitize_model_id(&pkg.header.model_id);
    let mount_point = vts_exe
        .parent()
        .context("VTS exe has no parent directory")?
        .join("VTube Studio_Data")
        .join("StreamingAssets")
        .join("Live2DModels")
        .join(&model_id);
    if mount_point.exists() {
        let non_empty = std::fs::read_dir(&mount_point)?.next().is_some();
        if non_empty {
            bail!("mount directory already exists and is not empty: {}", mount_point.display());
        }
        std::fs::remove_dir(&mount_point)?;
    }
    std::fs::create_dir_all(&mount_point)?;

    let fs = Arc::new(vfs::ModelFs::new(pkg));
    let mount_point_str = mount_point.to_string_lossy().to_string();
    let mount_point_w = U16CString::from_str(&mount_point_str)?;

    let mount_fs = fs.clone();
    let mount_mp = mount_point_w.clone();
    let dokan_thread = std::thread::spawn(move || {
        dokan::init();
        let options = MountOptions {
            single_thread: false,
            flags: MountFlags::ALT_STREAM,
            ..Default::default()
        };
        let mut mounter = FileSystemMounter::new(&*mount_fs, &mount_mp, &options);
        match mounter.mount() {
            Ok(_volume) => log::info!("volume unmounted"),
            Err(e) => log::error!("Dokan mount failed: {e}"),
        }
        dokan::shutdown();
    });
    std::thread::sleep(std::time::Duration::from_millis(1500));
    log::info!("volume mounted");

    let vts_proc = match cfg.launch_mode {
        LaunchMode::NoSteam => {
            log::warn!("launching VTS with -nosteam (dev mode)");
            vts::launch_vts_nosteam(&vts_exe, cfg.kill_vts_on_unmount)?
        }
        LaunchMode::Steam => {
            let existing = vts::collect_vts_pids();
            vts::request_steam_launch()?;
            println!(
                "launching VTube Studio via Steam (app {}), waiting...",
                vts::STEAM_APPID
            );
            let found = vts::wait_for_steam_vts(&existing, 120)?;
            vts::adopt_vts(found.pid, found.handle, cfg.kill_vts_on_unmount)?
        }
    };
    let auth_handle = vts::duplicate_handle(vts_proc.process_handle)?;
    fs.authorize_vts(vts_proc.pid, auth_handle);
    println!("mounted model '{model_id}' (VTS pid={})", vts_proc.pid);

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let mount_mp2 = mount_point_w.clone();
    let worker = std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !vts::process_alive(vts_proc.process_handle) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        fs.deauthorize();
        unsafe {
            winapi::um::handleapi::CloseHandle(auth_handle);
            let _ = dokan::unmount(&mount_mp2);
        }
        let _ = dokan_thread.join();
        let _ = std::fs::remove_dir(&mount_point);
        drop(vts_proc); // kills VTS only when configured
    });

    Ok(MountHandle {
        stop,
        worker: Some(worker),
    })
}
