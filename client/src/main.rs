//! ModelLock buyer client CLI (uses the shared core library).

use anyhow::{bail, Context, Result};
use modelock_client::{self as core, LaunchMode, MountConfig};
use std::path::PathBuf;

fn usage() {
    eprintln!(
        "modelock-client\n\
         \n\
         init          --vreq-out <file>\n\
         trust-author  --file author.spki\n\
         mount         --vkit <file.vkit> [--code <CODE>] [--vts <VTube Studio.exe>]\n\
                       [--launch-mode steam|nosteam] [--kill-vts]\n\
         models        (list accepted models)\n\
         activate      --server <url> --code <CODE>   (legacy online)"
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
    let info = core::init_device(std::path::Path::new(&out))?;
    println!("key_id={}", info.key_id);
    println!("wrote request file: {out}");
    Ok(())
}

fn cmd_trust_author(args: &[String]) -> Result<()> {
    let file = arg_value(args, "--file").context("--file is required")?;
    let key_id = core::trust_author_file(std::path::Path::new(&file))?;
    println!("trusted artist key: {key_id}");
    Ok(())
}

fn cmd_models(_args: &[String]) -> Result<()> {
    for m in core::list_models()? {
        let exp = m.expires_at.clone().unwrap_or_else(|| "-".to_string());
        println!("{} | code={} | expires={} | {}", m.model_id, &m.code_hash[..8.min(m.code_hash.len())], exp, m.vkit_path);
    }
    Ok(())
}

fn cmd_activate(args: &[String]) -> Result<()> {
    let server = arg_value(args, "--server").context("--server is required")?;
    let code = arg_value(args, "--code").context("--code is required")?;
    let key = core::device_key::open_or_create()?;
    let state = core::auth::activate(&server, &code, &key)?;
    core::auth::save_state(&state)?;
    println!("activated: model bound to device {}", state.device_id);
    Ok(())
}

fn cmd_mount(args: &[String]) -> Result<()> {
    let vkit_path = arg_value(args, "--vkit").context("--vkit is required")?;
    let code_arg = arg_value(args, "--code");
    let vts_override = arg_value(args, "--vts").map(PathBuf::from);
    let launch_mode = match arg_value(args, "--launch-mode").as_deref() {
        Some("nosteam") => LaunchMode::NoSteam,
        _ => LaunchMode::Steam,
    };
    let kill_vts = args.iter().any(|a| a == "--kill-vts");
    let cfg = MountConfig {
        vts_override,
        launch_mode,
        kill_vts_on_unmount: kill_vts,
    };

    let mut handle = core::mount_model(std::path::Path::new(&vkit_path), code_arg.as_deref(), &cfg)?;
    println!("mounted; press Ctrl+C to unmount (VTS will keep running)");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, std::sync::atomic::Ordering::SeqCst))
            .context("failed to install Ctrl+C handler")?;
    }
    while !stop.load(std::sync::atomic::Ordering::SeqCst) && handle.is_running() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    handle.stop();
    handle.wait()?;
    println!("unmounted");
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
        "trust-author" => cmd_trust_author(&args[2..]),
        "activate" => cmd_activate(&args[2..]),
        "mount" => cmd_mount(&args[2..]),
        "models" => cmd_models(&args[2..]),
        other => {
            usage();
            bail!("unknown subcommand: {other}")
        }
    }
}
