//! VTube Studio discovery, Steam launch, monitoring and lifecycle.
//!
//! Requirements enforced by the lock client:
//!   * The model volume is mounted BEFORE VTS starts.
//!   * VTS must be launched THROUGH Steam (`steam.exe -applaunch 1325860`,
//!     appid 1325860 = VTube Studio).  Starting VTS manually (double click or
//!     `-nosteam`) is not authorized.
//!   * The client monitors for a NEW VTube Studio.exe process and only
//!     authorizes it when its parent process image is steam.exe (i.e. it was
//!     actually spawned by Steam, not by explorer or a wrapper).
//!   * Authorization = PID + held process handle (GetProcessId re-check), so
//!     PID reuse cannot impersonate the authorized instance.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};
use winapi::shared::minwindef::{BOOL, DWORD, FALSE};
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::handleapi::{CloseHandle, DuplicateHandle, INVALID_HANDLE_VALUE};
use winapi::um::jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject};
use winapi::um::processthreadsapi::{
    CreateProcessW, GetCurrentProcess, GetProcessId, OpenProcess, ResumeThread, TerminateProcess,
    PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, QueryFullProcessImageNameW, WAIT_OBJECT_0,
};
use winapi::um::winnt::{
    HANDLE, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE,
    DUPLICATE_SAME_ACCESS,
};
use winapi::um::winnt::KEY_READ;
use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER};

pub const VTS_EXE: &str = "VTube Studio.exe";
pub const STEAM_APPID: &str = "1325860";

fn reg_read_string(hive: winapi::shared::minwindef::HKEY, subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let sk = widestring::U16CString::from_str(subkey).ok()?;
        let mut hkey: winapi::shared::minwindef::HKEY = ptr::null_mut();
        if RegOpenKeyExW(hive, sk.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let name = widestring::U16CString::from_str(value).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let ret = RegQueryValueExW(
            hkey,
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        );
        RegCloseKey(hkey);
        if ret != 0 {
            return None;
        }
        let used = (len as usize) / 2;
        Some(
            widestring::U16Str::from_slice(&buf[..used.min(buf.len())])
                .to_string_lossy()
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}

fn process_snapshot() -> Option<winapi::um::winnt::HANDLE> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(snap)
        }
    }
}

fn process_image(snap: winapi::um::winnt::HANDLE, pid: u32) -> Option<String> {
    unsafe {
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            return None;
        }
        loop {
            if entry.th32ProcessID == pid {
                return Some(
                    widestring::U16Str::from_slice(&entry.szExeFile)
                        .to_string_lossy()
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            if Process32NextW(snap, &mut entry) == 0 {
                return None;
            }
        }
    }
}

/// Return the parent PID of a process (th32ParentProcessID).
fn process_parent_pid(snap: winapi::um::winnt::HANDLE, pid: u32) -> Option<u32> {
    unsafe {
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            return None;
        }
        loop {
            if entry.th32ProcessID == pid {
                return Some(entry.th32ParentProcessID);
            }
            if Process32NextW(snap, &mut entry) == 0 {
                return None;
            }
        }
    }
}


/// Full path of a process image via QueryFullProcessImageNameW.
fn pid_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(
            widestring::U16Str::from_slice(&buf[..(len as usize).min(buf.len())])
                .to_string_lossy()
                .to_string(),
        )
    }
}

/// True when the direct parent of `pid` is steam.exe (case-insensitive).
pub fn parent_is_steam(pid: u32) -> bool {
    let Some(snap) = process_snapshot() else {
        return false;
    };
    let result = (|| {
        let parent = process_parent_pid(snap, pid)?;
        let image = process_image(snap, parent)?;
        Some(image.eq_ignore_ascii_case("steam.exe"))
    })();
    unsafe { CloseHandle(snap) };
    result.unwrap_or(false)
}

/// Snapshot of currently running VTS PIDs (used to detect NEW instances).
pub fn collect_vts_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    let Some(snap) = process_snapshot() else {
        return pids;
    };
    unsafe {
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let name = widestring::U16Str::from_slice(&entry.szExeFile)
                    .to_string_lossy()
                    .trim_end_matches('\0')
                    .to_string();
                if name.eq_ignore_ascii_case(VTS_EXE) {
                    pids.insert(entry.th32ProcessID);
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    pids
}

/// Locate steam.exe via the Steam registry key (with fallbacks).
pub fn steam_exe_path() -> Option<PathBuf> {
    if let Some(steam_dir) =
        reg_read_string(HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath").map(PathBuf::from)
    {
        let candidate = steam_dir.join("steam.exe");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    for fallback in [
        r"C:\Program Files (x86)\Steam\steam.exe",
        r"C:\Program Files\Steam\steam.exe",
    ] {
        let p = PathBuf::from(fallback);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Ask Steam to launch VTube Studio (`steam.exe -applaunch 1325860`).
pub fn request_steam_launch() -> Result<()> {
    let steam = steam_exe_path().context("steam.exe not found; is Steam installed?")?;
    let cmd = format!("\"{}\" -applaunch {}", steam.display(), STEAM_APPID);
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().collect();
    cmd_w.push(0);
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
            CREATE_NEW_PROCESS_GROUP,
            ptr::null_mut(),
            ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        bail!("failed to launch steam.exe: {}", std::io::Error::last_os_error());
    }
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    log::info!("requested Steam launch of VTube Studio (app {})", STEAM_APPID);
    Ok(())
}

pub struct FoundVts {
    pub pid: u32,
    pub handle: HANDLE,
}

/// Poll for a NEW VTS process whose parent is steam.exe.
///
/// `existing` is the PID set captured before requesting the Steam launch.
/// Instances that were already running (including manually started ones) are
/// never authorized.
pub fn wait_for_steam_vts(existing: &HashSet<u32>, timeout_secs: u64) -> Result<FoundVts> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let now_pids = collect_vts_pids();
        for pid in &now_pids {
            if existing.contains(pid) {
                continue;
            }
            if !parent_is_steam(*pid) {
                log::warn!("ignoring VTS pid {pid}: parent is not steam.exe");
                continue;
            }
            let handle = authorize_pid(*pid)?;
            let verified = unsafe { GetProcessId(handle) } == *pid;
            if !verified {
                unsafe { CloseHandle(handle) };
                continue;
            }
            log::info!("authorized Steam-launched VTS pid={pid}");
            return Ok(FoundVts { pid: *pid, handle });
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for Steam to launch VTube Studio");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Locate `VTube Studio.exe` (used for the nosteam fallback mode only).
pub fn find_vts() -> Result<PathBuf> {
    let snap_opt = process_snapshot();
    if let Some(snap) = snap_opt {
        unsafe {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let name = widestring::U16Str::from_slice(&entry.szExeFile)
                        .to_string_lossy()
                        .trim_end_matches('\0')
                        .to_string();
                    if name.eq_ignore_ascii_case(VTS_EXE) {
                        if let Some(path) = pid_exe_path(entry.th32ProcessID) {
                            CloseHandle(snap);
                            return Ok(PathBuf::from(path));
                        }
                    }
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
    }
    if let Some(steam) = reg_read_string(HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath")
        .map(PathBuf::from)
    {
        let mut libraries = vec![steam.clone()];
        libraries.extend(vdf_library_paths(&steam.join("steamapps").join("libraryfolders.vdf")));
        for lib in libraries {
            let candidate = lib
                .join("steamapps")
                .join("common")
                .join("VTube Studio")
                .join(VTS_EXE);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    bail!("VTube Studio not found; start it once or pass --vts")
}

fn vdf_library_paths(vdf: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string(vdf) {
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('"') {
                if let Some(first_end) = rest.find('"') {
                    let rest = &rest[first_end + 1..];
                    if let Some(rest) = rest.trim_start().strip_prefix('"') {
                        if let Some(second_end) = rest.rfind('"') {
                            out.push(PathBuf::from(&rest[..second_end]));
                        }
                    }
                }
            }
        }
    }
    out
}

pub struct VtsProcess {
    pub pid: u32,
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    job_handle: HANDLE,
    kill_on_drop: bool,
}

impl Drop for VtsProcess {
    fn drop(&mut self) {
        unsafe {
            if self.kill_on_drop {
                if !self.job_handle.is_null() {
                    // Closing the kill-job terminates the process tree.
                    CloseHandle(self.job_handle);
                } else {
                    TerminateProcess(self.process_handle, 1);
                }
            } else if !self.job_handle.is_null() {
                // Behavior B: leave VTS running; release handles only.
                CloseHandle(self.job_handle);
            }
            if !self.process_handle.is_null() {
                CloseHandle(self.process_handle);
            }
            if !self.thread_handle.is_null() {
                CloseHandle(self.thread_handle);
            }
        }
    }
}

fn create_kill_job() -> Result<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
        if job.is_null() {
            bail!("CreateJobObjectW failed: {}", std::io::Error::last_os_error());
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ret = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ret == 0 {
            CloseHandle(job);
            bail!("SetInformationJobObject failed: {}", std::io::Error::last_os_error());
        }
        Ok(job)
    }
}

/// Adopt an already-running (Steam-launched) VTS process.  Tries to put it in
/// a kill-on-close job; when Steam already placed it in a job, falls back to
/// TerminateProcess on cleanup.
pub fn adopt_vts(pid: u32, handle: HANDLE, kill_on_drop: bool) -> Result<VtsProcess> {
    if !kill_on_drop {
        return Ok(VtsProcess {
            pid,
            process_handle: handle,
            thread_handle: ptr::null_mut(),
            job_handle: ptr::null_mut(),
            kill_on_drop: false,
        });
    }
    let job = create_kill_job()?;
    let assigned = unsafe { AssignProcessToJobObject(job, handle) };
    if assigned == 0 {
        log::warn!("could not assign VTS pid {pid} to job (Steam job?); will use TerminateProcess");
        unsafe { CloseHandle(job) };
        Ok(VtsProcess {
            pid,
            process_handle: handle,
            thread_handle: ptr::null_mut(),
            job_handle: ptr::null_mut(),
            kill_on_drop: true,
        })
    } else {
        Ok(VtsProcess {
            pid,
            process_handle: handle,
            thread_handle: ptr::null_mut(),
            job_handle: job,
            kill_on_drop: true,
        })
    }
}

/// Launch VTS directly with `-nosteam` (kept for dev/test only; the default
/// and supported mode is the Steam launch).
pub fn launch_vts_nosteam(exe: &Path, kill_on_drop: bool) -> Result<VtsProcess> {
    let cmd = format!("\"{}\" -nosteam", exe.display());
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().collect();
    cmd_w.push(0);
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            ptr::null_mut(),
            ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        bail!("CreateProcessW failed: {}", std::io::Error::last_os_error());
    }
    if kill_on_drop {
        let job = create_kill_job()?;
        let assign = unsafe { AssignProcessToJobObject(job, pi.hProcess) };
        if assign == 0 {
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(job);
            }
            bail!("AssignProcessToJobObject failed: {}", std::io::Error::last_os_error());
        }
        unsafe { ResumeThread(pi.hThread) };
        Ok(VtsProcess {
            pid: pi.dwProcessId,
            process_handle: pi.hProcess,
            thread_handle: pi.hThread,
            job_handle: job,
            kill_on_drop: true,
        })
    } else {
        unsafe { ResumeThread(pi.hThread) };
        Ok(VtsProcess {
            pid: pi.dwProcessId,
            process_handle: pi.hProcess,
            thread_handle: pi.hThread,
            job_handle: ptr::null_mut(),
            kill_on_drop: false,
        })
    }
}

/// Open a handle to a PID for authorization checks (prevents PID reuse).
pub fn authorize_pid(pid: u32) -> Result<HANDLE> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if handle.is_null() {
            bail!("OpenProcess({pid}) failed: {}", std::io::Error::last_os_error());
        }
        Ok(handle)
    }
}

pub fn wait_for_exit(handle: HANDLE, timeout_ms: u32) -> bool {
    unsafe { WaitForSingleObject(handle, timeout_ms) == WAIT_OBJECT_0 }
}

pub fn kill_vts(handle: HANDLE) {
    unsafe { TerminateProcess(handle, 1); }
}

pub fn process_alive(handle: HANDLE) -> bool {
    unsafe { WaitForSingleObject(handle, 0) != WAIT_OBJECT_0 }
}

/// Duplicate a process handle (keeps a stable identity across the session).
pub fn duplicate_handle(handle: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut dup: HANDLE = ptr::null_mut();
        if DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut dup,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            bail!("DuplicateHandle failed: {}", std::io::Error::last_os_error());
        }
        Ok(dup)
    }
}

#[allow(dead_code)]
fn _vts_consts() -> (DWORD, BOOL) {
    (ERROR_SUCCESS as DWORD, FALSE)
}
