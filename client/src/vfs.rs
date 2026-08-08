//! Dokan read-only virtual file system that serves decrypted .vkit blocks.
//!
//! Security model:
//!   * Every open/read/enumeration first checks that the requestor PID equals
//!     the VTS instance this client launched, AND that the stored process
//!     handle still refers to that PID.  PID reuse is therefore not enough.
//!   * Read budgets: per-block reread suppression and a whole-volume output
//!     fuse, so bulk extraction tools cannot drain the package.
//!   * Decrypted blocks are cached in memory only (bounded), never written to
//!     disk.

use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileTimeOperation,
    FillDataResult, FindData, FindStreamData, MountOptions, OperationInfo, OperationResult,
    VolumeInfo,
};
use dokan_sys::win32::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use widestring::{U16CStr, U16CString, U16String};
use winapi::shared::ntstatus::*;
use winapi::um::winnt::{self, HANDLE};

use crate::vkit::Package;

pub const PER_FILE_BLOCK_FACTOR: u64 = 8;
pub const VOLUME_FUSE_FACTOR: u64 = 3;

pub struct AuthorizedVts {
    pub pid: u32,
    pub handle: HANDLE,
}

struct Budgets {
    per_block: Mutex<HashMap<(usize, u64), u64>>,
    volume_read: Mutex<u64>,
    volume_fuse: u64,
    sticky: AtomicBool,
}

impl Budgets {
    fn new(total_protected: u64) -> Self {
        Self {
            per_block: Mutex::new(HashMap::new()),
            volume_read: Mutex::new(0),
            volume_fuse: total_protected.saturating_mul(VOLUME_FUSE_FACTOR),
            sticky: AtomicBool::new(false),
        }
    }

    /// Returns Err(STATUS_DATA_ERROR) when a file's reread budget is exceeded,
    /// or Err(STATUS_ACCESS_DENIED) when the volume fuse has tripped.
    fn charge(&self, file_idx: usize, block_idx: u64, block_count: u64, bytes: u64) -> OperationResult<()> {
        if self.sticky.load(Ordering::Relaxed) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mut per = self.per_block.lock().unwrap();
        let key = (file_idx, block_idx);
        let count = per.entry(key).or_insert(0);
        *count += 1;
        let limit = block_count.saturating_mul(PER_FILE_BLOCK_FACTOR);
        if *count > limit {
            return Err(STATUS_DATA_ERROR);
        }
        let mut total = self.volume_read.lock().unwrap();
        *total = total.saturating_add(bytes);
        if *total > self.volume_fuse {
            self.sticky.store(true, Ordering::Relaxed);
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }
}

fn default_security_descriptor() -> &'static Vec<u8> {
    static SD: OnceLock<Vec<u8>> = OnceLock::new();
    SD.get_or_init(|| unsafe {
        let sddl = widestring::U16CString::from_str("D:(A;;GA;;;WD)").unwrap();
        let mut sd: *mut winnt::SECURITY_DESCRIPTOR = std::ptr::null_mut();
        if winapi::um::securitybaseapi::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            winnt::SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Vec::new();
        }
        let len = winapi::um::securitybaseapi::GetSecurityDescriptorLength(sd);
        let mut out = vec![0u8; len];
        std::ptr::copy_nonoverlapping(sd as *const u8, out.as_mut_ptr(), len);
        winapi::um::winbase::LocalFree(sd as winapi::um::winnt::HLOCAL);
        out
    })
}

pub struct ModelFs {
    pkg: Arc<Package>,
    auth: RwLock<Option<AuthorizedVts>>,
    budgets: Budgets,
}

impl ModelFs {
    pub fn new(pkg: Arc<Package>) -> Self {
        let total = pkg.total_protected_bytes();
        Self {
            pkg,
            auth: RwLock::new(None),
            budgets: Budgets::new(total),
        }
    }

    pub fn authorize_vts(&self, pid: u32, handle: HANDLE) {
        *self.auth.write().unwrap() = Some(AuthorizedVts { pid, handle });
    }

    pub fn deauthorize(&self) {
        *self.auth.write().unwrap() = None;
    }

    fn check_authorized(&self, pid: u32) -> bool {
        let guard = self.auth.read().unwrap();
        match guard.as_ref() {
            None => false,
            Some(a) => {
                if a.pid != pid || a.handle.is_null() {
                    return false;
                }
                unsafe { winapi::um::processthreadsapi::GetProcessId(a.handle) } == pid
            }
        }
    }

    fn normalize(path: &str) -> String {
        path.trim_start_matches('\\').trim_start_matches('/').to_string()
    }

    fn is_dir(&self, path: &str) -> bool {
        if path.is_empty() {
            return true;
        }
        let prefix = format!("{}/", path);
        self.pkg
            .header
            .files
            .iter()
            .any(|f| f.path.to_lowercase().starts_with(&prefix.to_lowercase()))
    }
}

pub struct Context {
    pub path: U16String,
    pub file_idx: Option<usize>,
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for ModelFs {
    type Context = Context;

    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &dokan::IO_SECURITY_CONTEXT,
        _desired_access: winnt::ACCESS_MASK,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        if !self.check_authorized(info.pid()) {
            return Err(STATUS_ACCESS_DENIED);
        }
        if create_disposition != FILE_OPEN && create_disposition != FILE_OPEN_IF {
            return Err(STATUS_ACCESS_DENIED); // read-only volume
        }
        let path = Self::normalize(&file_name.to_string_lossy());
        if path.is_empty() {
            return Ok(CreateFileInfo {
                context: Context { path: U16String::from_str(""), file_idx: None },
                is_dir: true,
                new_file_created: false,
            });
        }
        if let Some(idx) = self.pkg.find_file(&path) {
            let _ = idx;
        }
        let file_idx = self.pkg.header.files.iter().position(|f| f.path.eq_ignore_ascii_case(&path));
        if let Some(file_idx) = file_idx {
            if create_options & FILE_DIRECTORY_FILE > 0 {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
            return Ok(CreateFileInfo {
                context: Context {
                    path: U16String::from_str(&path),
                    file_idx: Some(file_idx),
                },
                is_dir: false,
                new_file_created: false,
            });
        }
        if self.is_dir(&path) {
            if create_options & FILE_NON_DIRECTORY_FILE > 0 {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            return Ok(CreateFileInfo {
                context: Context { path: U16String::from_str(&path), file_idx: None },
                is_dir: true,
                new_file_created: false,
            });
        }
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
    }

    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if !self.check_authorized(info.pid()) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let file_idx = context.file_idx.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        let file = &self.pkg.header.files[file_idx];
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let offset = offset as u64;
        if offset >= file.size {
            return Ok(0);
        }
        let block_size = self.pkg.header.block_size.max(1);
        let block_idx = offset / block_size;
        self.budgets.charge(
            file_idx,
            block_idx,
            file.blocks.len() as u64,
            buffer.len() as u64,
        )?;
        let data = self.pkg.read_range(file_idx, offset, buffer.len() as u64)?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len() as u32)
    }

    fn write_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _buffer: &[u8],
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<u32> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        match context.file_idx {
            Some(idx) => {
                let file = &self.pkg.header.files[idx];
                Ok(FileInfo {
                    attributes: winnt::FILE_ATTRIBUTE_ARCHIVE,
                    creation_time: std::time::SystemTime::now(),
                    last_access_time: std::time::SystemTime::now(),
                    last_write_time: std::time::SystemTime::now(),
                    file_size: file.size,
                    number_of_links: 1,
                    file_index: idx as u64 + 1,
                })
            }
            None => Ok(FileInfo {
                attributes: winnt::FILE_ATTRIBUTE_DIRECTORY,
                creation_time: std::time::SystemTime::now(),
                last_access_time: std::time::SystemTime::now(),
                last_write_time: std::time::SystemTime::now(),
                file_size: 0,
                number_of_links: 1,
                file_index: 0,
            }),
        }
    }

    fn find_files(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if !self.check_authorized(info.pid()) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let prefix = context.path.to_string_lossy();
        let prefix_parts: Vec<&str> = if prefix.is_empty() {
            Vec::new()
        } else {
            prefix.split('/').collect()
        };
        let mut children: HashMap<String, (bool, u64)> = HashMap::new();
        for (idx, file) in self.pkg.header.files.iter().enumerate() {
            let parts: Vec<&str> = file.path.split('/').collect();
            if parts.len() <= prefix_parts.len() {
                continue;
            }
            if prefix_parts.iter().zip(parts.iter()).any(|(a, b)| !a.eq_ignore_ascii_case(b)) {
                continue;
            }
            let name = parts[prefix_parts.len()];
            let is_file = parts.len() == prefix_parts.len() + 1
                && file.path.eq_ignore_ascii_case(&format!("{}{}{}", prefix, if prefix.is_empty() { "" } else { "/" }, name));
            children
                .entry(name.to_string())
                .and_modify(|e| {
                    if !is_file {
                        e.0 = false;
                    }
                })
                .or_insert((is_file, if is_file { file.size } else { 0 }));
            let _ = idx;
        }
        for (name, (is_file, size)) in children {
            let mut attrs = if is_file {
                winnt::FILE_ATTRIBUTE_ARCHIVE
            } else {
                winnt::FILE_ATTRIBUTE_DIRECTORY
            };
            if attrs == 0 {
                attrs = winnt::FILE_ATTRIBUTE_NORMAL;
            }
            let result = fill_find_data(&FindData {
                attributes: attrs,
                creation_time: std::time::SystemTime::now(),
                last_access_time: std::time::SystemTime::now(),
                last_write_time: std::time::SystemTime::now(),
                file_size: size,
                file_name: U16CString::from_str(&name).unwrap(),
            });
            if let Err(dokan::FillDataError::BufferFull) = result {
                return Err(STATUS_BUFFER_OVERFLOW);
            }
        }
        Ok(())
    }

    fn set_file_attributes(
        &'h self,
        _file_name: &U16CStr,
        _file_attributes: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn set_file_time(
        &'h self,
        _file_name: &U16CStr,
        _creation_time: FileTimeOperation,
        _last_access_time: FileTimeOperation,
        _last_write_time: FileTimeOperation,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn delete_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn delete_directory(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn move_file(
        &'h self,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_end_of_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_allocation_size(
        &'h self,
        _file_name: &U16CStr,
        _alloc_size: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        Ok(DiskSpaceInfo {
            byte_count: 1024 * 1024 * 1024,
            free_byte_count: 512 * 1024 * 1024,
            available_byte_count: 512 * 1024 * 1024,
        })
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<VolumeInfo> {
        Ok(VolumeInfo {
            name: U16CString::from_str("ModelLock").unwrap(),
            serial_number: 0,
            max_component_length: 255,
            fs_flags: winnt::FILE_CASE_PRESERVED_NAMES
                | winnt::FILE_UNICODE_ON_DISK
                | winnt::FILE_PERSISTENT_ACLS,
            fs_name: U16CString::from_str("NTFS").unwrap(),
        })
    }

    fn mounted(
        &'h self,
        mount_point: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<()> {
        log::info!("mounted at {}", mount_point.to_string_lossy());
        Ok(())
    }

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        log::info!("unmounted");
        Ok(())
    }

    fn get_file_security(
        &'h self,
        _file_name: &U16CStr,
        _security_information: u32,
        security_descriptor: *mut winnt::SECURITY_DESCRIPTOR,
        buffer_length: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<u32> {
        let sd = default_security_descriptor();
        if sd.is_empty() {
            return Err(STATUS_INTERNAL_ERROR);
        }
        let needed = sd.len() as u32;
        if buffer_length < needed {
            return Ok(needed);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(sd.as_ptr(), security_descriptor as *mut u8, sd.len());
        }
        Ok(needed)
    }

    fn set_file_security(
        &'h self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: *mut winnt::SECURITY_DESCRIPTOR,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn find_streams(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_stream_data: impl FnMut(&FindStreamData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if let Some(idx) = context.file_idx {
            let file = &self.pkg.header.files[idx];
            fill_find_stream_data(&FindStreamData {
                size: file.size as i64,
                name: U16CString::from_str("::$DATA").unwrap(),
            });
        }
        Ok(())
    }
}

#[allow(dead_code)]
