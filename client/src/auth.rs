//! Activation-server client, device fingerprint, and local state.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::device_key::DeviceKey;
use crate::util;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ClientState {
    pub server: String,
    pub token: String,
    pub device_id: String,
}

pub fn utcnow_iso() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

pub fn state_path() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(base.join("ModelLock").join("state.json"))
}

pub fn load_state() -> Result<Option<ClientState>> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw).ok())
}

pub fn save_state(state: &ClientState) -> Result<()> {
    let path = state_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

/// Collect a multi-source device fingerprint (best-effort on Windows).
pub fn collect_hwid() -> String {
    let mut parts = Vec::new();
    if let Ok(guid) = read_machine_guid() {
        parts.push(format!("guid={guid}"));
    }
    if let Ok(name) = read_computer_name() {
        parts.push(format!("host={name}"));
    }
    if let Ok(serial) = read_volume_serial() {
        parts.push(format!("vol={serial}"));
    }
    hex::encode(Sha256::digest(parts.join("|").as_bytes()))
}

fn read_machine_guid() -> std::io::Result<String> {
    use winapi::shared::minwindef::HKEY;
    use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ};
    unsafe {
        let subkey = util::to_utf16_c(r"SOFTWARE\Microsoft\Cryptography");
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let name = util::to_utf16_c("MachineGuid");
        let mut buf = [0u16; 64];
        let mut len = (buf.len() * 2) as u32;
        let ret = RegQueryValueExW(
            hkey,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        );
        RegCloseKey(hkey);
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let used = (len as usize) / 2;
        Ok(util::from_utf16(&buf[..used.min(buf.len())]).trim_end_matches('\0').to_string())
    }
}

fn read_computer_name() -> std::io::Result<String> {
    use winapi::um::sysinfoapi::{GetComputerNameW, COMPUTER_NAME_FORMAT};
    unsafe {
        let mut buf = [0u16; 64];
        let mut len = buf.len() as u32;
        if GetComputerNameW(buf.as_mut_ptr(), &mut len) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(util::from_utf16(&buf[..len as usize]))
    }
}

fn read_volume_serial() -> std::io::Result<String> {
    use winapi::um::fileapi::GetVolumeInformationW;
    unsafe {
        let root = util::to_utf16_c("C:\\");
        let mut serial: u32 = 0;
        if GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(format!("{serial:08X}"))
    }
}

fn post_json(server: &str, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let url = format!("{}/{}", server.trim_end_matches('/'), path);
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .with_context(|| format!("POST {url} failed"))?;
    let value: serde_json::Value = resp.into_json().context("invalid JSON response")?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let code = value.get("code").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
        let msg = value.get("message").and_then(|v| v.as_str()).unwrap_or("");
        bail!("server error {code}: {msg}");
    }
    Ok(value)
}

pub fn activate(server: &str, code: &str, key: &DeviceKey) -> Result<ClientState> {
    let device_id = collect_hwid();
    let body = serde_json::json!({
        "code": code,
        "device_id": device_id,
        "pubkey_spki": util::b64e(&key.spki_der),
        "hwids": {"machine_guid": read_machine_guid().unwrap_or_default()},
    });
    let out = post_json(server, "api/activate", body)?;
    let token = out
        .get("token")
        .and_then(|v| v.as_str())
        .context("server did not return a token")?
        .to_string();
    Ok(ClientState {
        server: server.to_string(),
        token,
        device_id,
    })
}

pub fn refresh_token(state: &ClientState) -> Result<String> {
    let out = post_json(&state.server, "api/refresh", serde_json::json!({"token": state.token}))?;
    out.get("token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context("server did not return a token")
}

pub fn check_status(state: &ClientState) -> Result<serde_json::Value> {
    post_json(&state.server, "api/status", serde_json::json!({"token": state.token}))
}
