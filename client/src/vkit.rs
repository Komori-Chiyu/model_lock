//! Read a .vkit package and decrypt blocks on demand.
//!
//! Layout (v1, little-endian):
//!   prefix: u32 magic "VKIT" | u32 version | u64 header_len | u64 data_len
//!   header: UTF-8 JSON (see Header below)
//!   data:   per-file block ciphertexts (AES-256-GCM, 12-byte nonce, 16-byte tag)
//!
//! AAD for each block is `b"VKIT1" || path_utf8 || block_index_le_u64`, so
//! blocks cannot be reordered or swapped between files.

use anyhow::{bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::RwLock;

use crate::device_key::{unwrap_cek, DeviceKey};
use crate::util;

pub const BLOCK_SIZE: u64 = 1024 * 1024;
pub const CACHE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Deserialize, Clone, Debug)]
pub struct BlockMeta {
    pub i: u64,
    pub n: String, // base64 nonce (12 bytes)
    pub t: String, // base64 tag (16 bytes)
    pub l: u64,    // plaintext length
}

#[derive(Deserialize, Clone, Debug)]
pub struct FileMeta {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub blocks: Vec<BlockMeta>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Recipient {
    pub key_id: String,
    pub algorithm: String,
    pub wrapped_cek: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Header {
    pub magic: String,
    pub version: u32,
    pub model_id: String,
    pub block_size: u64,
    pub recipients: Vec<Recipient>,
    pub files: Vec<FileMeta>,
    #[serde(default)]
    pub note: String,
}

pub fn open_header(path: &Path) -> Result<(Header, u64)> {
    let mut fh = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut prefix = [0u8; 24];
    fh.read_exact(&mut prefix)?;
    if &prefix[..4] != b"VKIT" {
        bail!("not a VKIT package");
    }
    let version = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
    let header_len = u64::from_le_bytes(prefix[8..16].try_into().unwrap());
    let data_len = u64::from_le_bytes(prefix[16..24].try_into().unwrap());
    if version != 1 {
        bail!("unsupported VKIT version {version}");
    }
    if header_len > 64 * 1024 * 1024 {
        bail!("header too large");
    }
    let mut raw = vec![0u8; header_len as usize];
    fh.read_exact(&mut raw)?;
    let header: Header = serde_json::from_slice(&raw).context("invalid header JSON")?;
    if header.magic != "VKIT" {
        bail!("header magic mismatch");
    }
    let data_start = 24 + header_len;
    let end = fh.seek(SeekFrom::End(0))?;
    if data_start + data_len != end {
        bail!("data length mismatch");
    }
    Ok((header, data_start))
}

pub struct Package {
    pub header: Header,
    pub cek: Vec<u8>,
    file: File,
    data_start: u64,
    cipher: LessSafeKey,
    cache: RwLock<Cache>,
    file_index: HashMap<String, usize>,
}

struct Cache {
    blocks: HashMap<(usize, u64), Vec<u8>>,
    bytes: usize,
}

impl Package {
    pub fn open(path: &Path, key: &DeviceKey) -> Result<Self> {
        let (header, data_start) = open_header(path)?;
        let recipient = header
            .recipients
            .iter()
            .find(|r| r.key_id.eq_ignore_ascii_case(&key.key_id))
            .context("package is not encrypted for this device key")?;
        let wrapped = util::b64d(&recipient.wrapped_cek)
            .context("invalid wrapped_cek encoding")?;
        let cek = unwrap_cek(key, &wrapped).context("failed to unwrap content key")?;
        if cek.len() != 32 {
            bail!("unexpected CEK length {}", cek.len());
        }
        let unbound = UnboundKey::new(&AES_256_GCM, &cek).map_err(|_| anyhow::anyhow!("bad CEK"))?;
        let file_index = header
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.path.to_lowercase(), i))
            .collect();
        Ok(Self {
            header,
            cek,
            file: File::open(path)?,
            data_start,
            cipher: LessSafeKey::new(unbound),
            cache: RwLock::new(Cache {
                blocks: HashMap::new(),
                bytes: 0,
            }),
            file_index,
        })
    }

    pub fn find_file(&self, path: &str) -> Option<&FileMeta> {
        self.file_index
            .get(&path.to_lowercase())
            .map(|i| &self.header.files[*i])
    }

    pub fn find_model3(&self) -> Option<&FileMeta> {
        self.header
            .files
            .iter()
            .find(|f| f.path.to_lowercase().ends_with(".model3.json"))
    }

    pub fn total_protected_bytes(&self) -> u64 {
        self.header.files.iter().map(|f| f.size).sum()
    }

    fn block_aad(path: &str, idx: u64) -> Vec<u8> {
        let mut aad = b"VKIT1".to_vec();
        aad.extend(path.as_bytes());
        aad.extend(idx.to_le_bytes());
        aad
    }

    fn read_block(&self, file: &FileMeta, block: &BlockMeta) -> Result<Vec<u8>> {
        // Compute absolute offset of this block's ciphertext.
        let mut offset = self.data_start + file.offset;
        for prev in &file.blocks {
            if prev.i == block.i {
                break;
            }
            offset += prev.l + 16;
        }
        let ct_len = (block.l + 16) as usize;
        let mut buf = vec![0u8; ct_len];
        {
            let mut fh = &self.file;
            fh.seek(SeekFrom::Start(offset))?;
            fh.read_exact(&mut buf)?;
        }
        let nonce = Nonce::assume_unique_for_key(
            util::b64d(&block.n)?.try_into().map_err(|_| anyhow::anyhow!("bad nonce"))?,
        );
        let aad = Aad::from(Self::block_aad(&file.path, block.i));
        let plain = self
            .cipher
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|_| anyhow::anyhow!("block {} authentication failed", block.i))?;
        Ok(plain.to_vec())
    }

    fn cached_block(&self, file_idx: usize, block: &BlockMeta) -> Result<Vec<u8>> {
        {
            let cache = self.cache.read().unwrap();
            if let Some(data) = cache.blocks.get(&(file_idx, block.i)) {
                return Ok(data.clone());
            }
        }
        let file = &self.header.files[file_idx];
        let data = self.read_block(file, block)?;
        {
            let mut cache = self.cache.write().unwrap();
            if cache.bytes + data.len() > CACHE_LIMIT {
                cache.blocks.clear();
                cache.bytes = 0;
            }
            cache.blocks.insert((file_idx, block.i), data.clone());
            cache.bytes += data.len();
        }
        Ok(data)
    }

    /// Read [offset, offset+len) from a file (clamped to file size).
    pub fn read_range(&self, file_idx: usize, offset: u64, len: u64) -> Result<Vec<u8>> {
        let file = &self.header.files[file_idx];
        if offset >= file.size {
            return Ok(Vec::new());
        }
        let end = (offset + len).min(file.size);
        let block_size = self.header.block_size.max(1);
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            let block_idx = pos / block_size;
            let block = file
                .blocks
                .iter()
                .find(|b| b.i == block_idx)
                .context("block index missing")?;
            let data = self.cached_block(file_idx, block)?;
            let within = (pos % block_size) as usize;
            let take = ((end - pos) as usize).min(data.len() - within);
            out.extend_from_slice(&data[within..within + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    pub fn read_all(&self, file_idx: usize) -> Result<Vec<u8>> {
        let file = &self.header.files[file_idx];
        self.read_range(file_idx, 0, file.size)
    }
}
