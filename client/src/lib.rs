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

/// Trusted date sources: any HTTPS response's `Date` header carries the
/// server's UTC time, and TLS makes the response tamper-resistant. Several
/// well-known hosts are tried because any single one may be unreachable.
const TIME_SOURCES: [&str; 3] = [
    "https://www.baidu.com/",
    "https://www.qq.com/",
    "https://www.apple.com.cn/",
];

/// Parse an RFC 7231 date ("Tue, 11 Aug 2026 14:30:00 GMT") into YYYY-MM-DD.
fn parse_http_date(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: u32 = parts[1].trim_end_matches(',').parse().ok()?;
    let month = match parts[2].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: u32 = parts[3].parse().ok()?;
    if !(1..=31).contains(&day) || year < 2000 || year > 2100 {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Fetch the trusted current date (UTC, YYYY-MM-DD) from the network. The
/// system clock is never used for expiry decisions — it can be changed to
/// dodge expiry, while a TLS-fetched Date header cannot.
pub fn fetch_network_date() -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let mut last_err: Option<String> = None;
    for url in TIME_SOURCES {
        match agent.get(url).call() {
            Ok(resp) => {
                if let Some(date) = resp.header("date").and_then(parse_http_date) {
                    log::info!("network date from {url}: {date}");
                    return Ok(date);
                }
                last_err = Some(format!("{url}: no usable Date header"));
            }
            Err(e) => {
                log::warn!("time source {url} failed: {e}");
                last_err = Some(format!("{url}: {e}"));
            }
        }
    }
    bail!(
        "无法获取网络时间(过期校验依赖联网时间): {}",
        last_err.unwrap_or_default()
    )
}

/// Record that a license was verified today (network date). As a backstop
/// against a misbehaving time source, refuse if the date ever goes backwards.
fn record_verification_date(state: &mut auth::ClientState, today: &str) -> Result<()> {
    if let Some(last) = state.last_verified_date.as_deref().filter(|s| !s.is_empty()) {
        if today < last {
            bail!("日期异常:从 {last} 倒退到了 {today},请检查网络时间源");
        }
    }
    state.last_verified_date = Some(today.to_string());
    auth::save_state(state)
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
    let today = fetch_network_date()?;
    vkit::verify_package_license(&pkg.header, &author_spki, &key.key_id, code, &today)?;
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
    record_verification_date(&mut state, &today)?;
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
        let today = fetch_network_date()?;
        vkit::verify_package_license(&pkg.header, &author_spki, &key.key_id, code, &today)?;
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
        record_verification_date(&mut state, &today)?;
        println!("offline license OK (model {}, network date {today})", pkg.header.model_id);
    } else {
        log::warn!("package has no offline license; skipping activation check");
    }

    // Steam mode pre-checks BEFORE touching the mount point: a running
    // "VTube Studio.exe" (real or look-alike) must be closed by the user, and
    // Steam must be up. Only the VTS instance we launch through Steam right
    // now is ever authorized to read the volume.
    let existing_pids = if cfg.launch_mode == LaunchMode::Steam {
        let existing = vts::collect_vts_pids();
        if !existing.is_empty() {
            bail!(
                "VTube Studio 正在运行（pid {:?}），请先关闭它再挂载",
                existing.iter().collect::<Vec<_>>()
            );
        }
        if !vts::steam_running() {
            bail!("Steam 尚未运行，请先打开 Steam 再挂载");
        }
        Some(existing)
    } else {
        None
    };

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
    let mount_point_str = mount_point.to_string_lossy().to_string();
    let mount_point_w = U16CString::from_str(&mount_point_str)?;

    // Clean up the previous mount before creating ours. A stale Dokan volume
    // (left behind by a hard-killed client) can own this directory: metadata
    // reports it as gone while create_dir_all fails with ERROR_ALREADY_EXISTS
    // (os error 183). Metadata is therefore not a reliable signal — drive the
    // cleanup by actions instead: unmount, try to rebuild the mount point,
    // and retry while the driver finishes detaching the stale volume.
    let mut created = false;
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..10 {
        let _ = dokan::unmount(&mount_point_w);
        // Ignore read/remove errors here: a stale volume can make them fail
        // even though the directory is empty. Only a real non-empty conflict
        // (a genuine model directory) aborts.
        let non_empty = std::fs::read_dir(&mount_point)
            .ok()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if non_empty {
            bail!("mount directory already exists and is not empty: {}", mount_point.display());
        }
        let _ = std::fs::remove_dir(&mount_point);
        match std::fs::create_dir_all(&mount_point) {
            Ok(()) => {
                log::info!("mount point ready (attempt {attempt})");
                created = true;
                break;
            }
            Err(e) => {
                log::warn!("mount point create attempt {attempt} failed: {e}");
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
    if !created {
        return Err(last_err.map(anyhow::Error::from).unwrap_or_else(|| {
            anyhow::anyhow!("cannot create mount point {}", mount_point.display())
        }))
        .with_context(|| {
            format!(
                "stale virtual volume at {} did not detach; close other ModelLock clients and retry, or reboot",
                mount_point.display()
            )
        });
    }

    let fs = Arc::new(vfs::ModelFs::new(pkg));

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
            let existing = existing_pids.unwrap_or_default();
            vts::request_steam_launch()?;
            println!(
                "launching VTube Studio via Steam (app {}), waiting...",
                vts::STEAM_APPID
            );
            let found = vts::wait_for_steam_vts(&existing, 120)?;
            vts::adopt_vts(found.pid, found.handle, cfg.kill_vts_on_unmount)?
        }
    };
    // Handles are raw pointers and therefore not Send: convert them to usize
    // and let the worker own them. VtsProcess is forgotten (no Drop) so it
    // does not close handles or kill VTS behind our back.
    let vts_pid = vts_proc.pid;
    let vts_handle = vts_proc.process_handle as usize;
    let vts_thread = vts_proc.thread_handle as usize;
    std::mem::forget(vts_proc);

    let auth_handle =
        vts::duplicate_handle(vts_handle as winapi::um::winnt::HANDLE)? as usize;
    fs.authorize_vts(vts_pid, auth_handle as winapi::um::winnt::HANDLE);
    println!("mounted model '{model_id}' (VTS pid={vts_pid})");

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let mount_mp2 = mount_point_w.clone();
    let kill = cfg.kill_vts_on_unmount;
    let worker = std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !vts::process_alive(vts_handle as winapi::um::winnt::HANDLE) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        fs.deauthorize();
        unsafe {
            winapi::um::handleapi::CloseHandle(auth_handle as winapi::um::winnt::HANDLE);
            let _ = dokan::unmount(&mount_mp2);
        }
        let _ = dokan_thread.join();
        let _ = std::fs::remove_dir(&mount_point);
        if kill {
            vts::kill_vts(vts_handle as winapi::um::winnt::HANDLE);
        }
        unsafe {
            winapi::um::handleapi::CloseHandle(vts_handle as winapi::um::winnt::HANDLE);
            if vts_thread != 0 {
                winapi::um::handleapi::CloseHandle(vts_thread as winapi::um::winnt::HANDLE);
            }
        }
    });

    Ok(MountHandle {
        stop,
        worker: Some(worker),
    })
}
