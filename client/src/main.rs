//! ModelLock buyer client.
//!
//! Subcommands:
//!   init      --vreq-out <file>          create the device key and export .vreq
//!   activate  --server <url> --code <c>  activate the code for this device
//!   mount     --vkit <file> [--vts <exe>] [--server <url>]
//!                                         mount the model and launch VTS

mod auth;
mod device_key;
mod util;
mod vfs;
mod vkit;
mod vts;

use anyhow::{bail, Context, Result};
use dokan::{FileSystemMounter, MountFlags, MountOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use widestring::U16CString;

use crate::auth::ClientState;

fn usage() {
    eprintln!(
        "modelock-client\n\
         \n\
         init      --vreq-out <file>\n\
         activate  --server <url> --code <CODE>\n\
         mount     --vkit <file.vkit> [--vts <VTube Studio.exe>] [--server <url>]"
    );
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn cmd_init(args: &[String]) -> Result<()> {
    let out = arg_value(args, "--vreq-out").context("--vreq-out is required")?;
    let key = device_key::open_or_create()?;
    device_key::write_vreq(&key, std::path::Path::new(&out))?;
    println!("key_id={}", key.key_id);
    println!("wrote request file: {out}");
    Ok(())
}

fn cmd_activate(args: &[String]) -> Result<()> {
    let server = arg_value(args, "--server").context("--server is required")?;
    let code = arg_value(args, "--code").context("--code is required")?;
    let key = device_key::open_or_create()?;
    let state = auth::activate(&server, &code, &key)?;
    auth::save_state(&state)?;
    println!("activated: model bound to device {}", state.device_id);
    Ok(())
}

fn ensure_valid_token(state: &mut ClientState) -> Result<()> {
    match auth::check_status(state) {
        Ok(_) => Ok(()),
        Err(_) => {
            let token = auth::refresh_token(state)?;
            state.token = token;
            auth::save_state(state)?;
            Ok(())
        }
    }
}

fn sanitize_model_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_');
    if clean.is_empty() {
        "model".to_string()
    } else {
        clean.to_string()
    }
}

fn cmd_mount(args: &[String]) -> Result<()> {
    let vkit_path = arg_value(args, "--vkit").context("--vkit is required")?;
    let vts_override = arg_value(args, "--vts");
    let server_override = arg_value(args, "--server");

    let mut state = auth::load_state()?.context("not activated; run `activate` first")?;
    if let Some(server) = server_override {
        state.server = server;
    }
    ensure_valid_token(&mut state)?;

    let key = device_key::open_or_create()?;
    let pkg = Arc::new(vkit::Package::open(std::path::Path::new(&vkit_path), &key)?);
    log::info!(
        "package {}: {} files, {} bytes protected",
        pkg.header.model_id,
        pkg.header.files.len(),
        pkg.total_protected_bytes()
    );

    let vts_exe = match vts_override {
        Some(p) => PathBuf::from(p),
        None => vts::find_vts()?,
    };
    log::info!("VTS executable: {}", vts_exe.display());

    // Mount point: VTS model directory (created before VTS starts).
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
    log::info!("mount point: {}", mount_point.display());

    let fs = vfs::ModelFs::new(pkg);
    let mount_point_str = mount_point.to_string_lossy().to_string();
    let mount_point_w = U16CString::from_str(&mount_point_str)?;

    unsafe { dokan::init() };
    let options = MountOptions {
        single_thread: false,
        flags: MountFlags::ALT_STREAM,
        ..Default::default()
    };
    let mut mounter = FileSystemMounter::new(&fs, &mount_point_w, &options);
    let file_system = mounter
        .mount()
        .map_err(|e| anyhow::anyhow!("Dokan mount failed: {e}"))?;
    log::info!("volume mounted");

    // Launch VTS inside a kill-on-close job, then authorize its PID+handle.
    let vts_proc = vts::launch_vts(&vts_exe, &[])?;
    let auth_handle = vts::duplicate_handle(vts_proc.process_handle)?;
    fs.authorize_vts(vts_proc.pid, auth_handle);
    println!(
        "mounted model '{}' and launched VTS (pid={}); press Ctrl+C or close VTS to unmount",
        model_id, vts_proc.pid
    );

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .context("failed to install Ctrl+C handler")?;
    }

    while !stop.load(Ordering::SeqCst) && vts::process_alive(vts_proc.process_handle) {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    log::info!("unmounting");
    fs.deauthorize();
    unsafe {
        winapi::um::handleapi::CloseHandle(auth_handle);
        let _ = dokan::unmount(&mount_point_w);
    }
    drop(file_system);
    let _ = std::fs::remove_dir(&mount_point);
    unsafe { dokan::shutdown() };
    log::info!("done");
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        bail!("missing subcommand");
    }
    match args[1].as_str() {
        "init" => cmd_init(&args[2..]),
        "activate" => cmd_activate(&args[2..]),
        "mount" => cmd_mount(&args[2..]),
        other => {
            usage();
            bail!("unknown subcommand: {other}")
        }
    }
}
