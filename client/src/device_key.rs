//! Windows CNG device key management.
//!
//! The buyer's RSA-2048 key pair lives in the per-user key storage provider
//! (KSP) as a NON-EXPORTABLE key.  The private key never leaves the KSP: CEK
//! unwrapping is done in place with NCryptDecrypt.  The public half is
//! exported as a BCRYPT_RSAPUBLIC_BLOB and re-encoded into a DER
//! SubjectPublicKeyInfo so the artist-side packager (Python) can wrap content
//! keys for this buyer.
//!
//! winapi 0.3 only declares a subset of NCrypt; the functions used here are
//! declared locally with the same signatures as ncrypt.h.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::ptr;
use winapi::ctypes::c_void;
use winapi::shared::bcrypt::BCRYPT_OAEP_PADDING_INFO;
use winapi::shared::ntdef::LPCWSTR;
use winapi::shared::winerror::NTE_EXISTS;
use winapi::um::ncrypt::{
    NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty, NCRYPT_KEY_HANDLE,
    NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, SECURITY_STATUS,
};

use crate::util;

const KEY_NAME: &str = "ModelLockDeviceKey";
const NCRYPT_DECRYPT_FLAG: u32 = 0x0000_0004;
const NCRYPT_ALLOW_EXPORT_NONE: u32 = 0;

extern "system" {
    fn NCryptCreatePersistedKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pszAlgId: LPCWSTR,
        pszKeyName: LPCWSTR,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> SECURITY_STATUS;
    fn NCryptFinalizeKey(hKey: NCRYPT_KEY_HANDLE, dwFlags: u32) -> SECURITY_STATUS;
    fn NCryptOpenKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pszKeyName: LPCWSTR,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> SECURITY_STATUS;
    fn NCryptExportKey(
        hKey: NCRYPT_KEY_HANDLE,
        hExportKey: NCRYPT_KEY_HANDLE,
        pszBlobType: LPCWSTR,
        pParameterList: *mut c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> SECURITY_STATUS;
    fn NCryptDecrypt(
        hKey: NCRYPT_KEY_HANDLE,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *mut c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> SECURITY_STATUS;
}

pub struct DeviceKey {
    pub key_handle: NCRYPT_KEY_HANDLE,
    pub key_id: String,
    pub spki_der: Vec<u8>,
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.key_handle);
        }
    }
}

fn wide(s: &str) -> widestring::U16CString {
    widestring::U16CString::from_str(s).expect("no interior NUL")
}

fn nerr(status: i32, what: &str) -> Result<()> {
    if status < 0 {
        bail!("{what}: NTSTATUS {status:#x}");
    }
    Ok(())
}

/// Get (or create) the persisted, non-exportable RSA-2048 key in the KSP.
pub fn open_or_create() -> Result<DeviceKey> {
    unsafe {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        let prov_name = wide("Microsoft Software Key Storage Provider");
        nerr(
            NCryptOpenStorageProvider(&mut provider, prov_name.as_ptr(), 0),
            "NCryptOpenStorageProvider",
        )?;

        let mut key: NCRYPT_KEY_HANDLE = 0;
        let alg = wide("RSA");
        let name = wide(KEY_NAME);
        let status = NCryptCreatePersistedKey(
            provider,
            &mut key,
            alg.as_ptr(),
            name.as_ptr(),
            0,
            0,
        );
        if status == 0 {
            // New key: force 2048-bit RSA.
            let size: u32 = 2048;
            let len_prop = wide("Length");
            nerr(
                NCryptSetProperty(
                    key,
                    len_prop.as_ptr(),
                    &size as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as u32,
                    0,
                ),
                "NCryptSetProperty(Length)",
            )?;
            // Only allow decryption with this key.
            let usage: u32 = NCRYPT_DECRYPT_FLAG;
            let usage_prop = wide("Key Usage");
            nerr(
                NCryptSetProperty(
                    key,
                    usage_prop.as_ptr(),
                    &usage as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as u32,
                    0,
                ),
                "NCryptSetProperty(Key Usage)",
            )?;
            // Forbid export: no flag bits set.
            let no_export: u32 = NCRYPT_ALLOW_EXPORT_NONE;
            let export_prop = wide("Export Policy");
            nerr(
                NCryptSetProperty(
                    key,
                    export_prop.as_ptr(),
                    &no_export as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as u32,
                    0,
                ),
                "NCryptSetProperty(Export Policy)",
            )?;
            nerr(NCryptFinalizeKey(key, 0), "NCryptFinalizeKey")?;
        } else if status == NTE_EXISTS {
            nerr(
                NCryptOpenKey(provider, &mut key, name.as_ptr(), 0, 0),
                "NCryptOpenKey",
            )?;
        } else {
            bail!("NCryptCreatePersistedKey: NTSTATUS {status:#x}");
        }
        NCryptFreeObject(provider);

        let (spki_der, key_id) = export_public_spki(key)?;
        Ok(DeviceKey {
            key_handle: key,
            key_id,
            spki_der,
        })
    }
}

/// Export the public half as BCRYPT_RSAPUBLIC_BLOB, then re-encode to DER SPKI.
fn export_public_spki(key: NCRYPT_KEY_HANDLE) -> Result<(Vec<u8>, String)> {
    unsafe {
        let blob_type = wide("RSAPUBLICBLOB");
        // First call asks for the buffer size.
        let mut size: u32 = 0;
        let status = NCryptExportKey(
            key,
            0,
            blob_type.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut size,
            0,
        );
        if status != 0 {
            bail!("NCryptExportKey(size): NTSTATUS {status:#x}");
        }
        let mut blob = vec![0u8; size as usize];
        let mut written: u32 = 0;
        nerr(
            NCryptExportKey(
                key,
                0,
                blob_type.as_ptr(),
                ptr::null_mut(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut written,
                0,
            ),
            "NCryptExportKey",
        )?;
        blob.truncate(written as usize);
        let (n, e) = parse_rsa_public_blob(&blob)?;
        let spki = build_spki(&n, &e)?;
        let key_id = hex::encode(&Sha256::digest(&spki)[..16]);
        Ok((spki, key_id))
    }
}

/// BCRYPT_RSAPUBLIC_BLOB: Magic("RSA1") + BitLength + cbPublicExp + cbModulus +
/// cbPrime1 + cbPrime2, followed by little-endian public exponent and modulus.
fn parse_rsa_public_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Magic(4) + BitLength(4) + cbPublicExp(4) + cbModulus(4) + cbPrime1(4) + cbPrime2(4)
    const HEADER: usize = 24;
    if blob.len() < HEADER + 8 {
        bail!("public key blob too small");
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != winapi::shared::bcrypt::BCRYPT_RSAPUBLIC_MAGIC {
        bail!("not a BCRYPT_RSAPUBLIC_BLOB");
    }
    let exp_len = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let mod_len = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    if blob.len() != HEADER + exp_len + mod_len {
        bail!("public key blob length mismatch");
    }
    let body = &blob[HEADER..];
    let exp = body[..exp_len].iter().rev().cloned().collect::<Vec<_>>();
    let modulus = body[exp_len..].iter().rev().cloned().collect::<Vec<_>>();
    Ok((strip_leading_zeros(&modulus), strip_leading_zeros(&exp)))
}

fn strip_leading_zeros(v: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    v[i..].to_vec()
}

// ---------- minimal DER encoder ----------

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut tmp = n;
        let mut len_bytes = Vec::new();
        while tmp > 0 {
            len_bytes.insert(0, (tmp & 0xff) as u8);
            tmp >>= 8;
        }
        let mut out = vec![0x80u8 | (len_bytes.len() as u8)];
        out.extend(len_bytes);
        out
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend(content);
    out
}

fn der_positive_integer(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    der_tlv(0x02, &v)
}

fn der_oid_rsa() -> Vec<u8> {
    // 1.2.840.113549.1.1.1
    der_tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
}

/// Build SubjectPublicKeyInfo from modulus/exponent big-endian bytes.
fn build_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let rsa_pub = der_tlv(
        0x30,
        &[
            der_positive_integer(modulus),
            der_positive_integer(exponent),
        ]
        .concat(),
    );
    let alg = der_tlv(0x30, &[der_oid_rsa(), vec![0x05, 0x00]].concat());
    let mut bit_string = vec![0x00];
    bit_string.extend(rsa_pub);
    let bit_string = der_tlv(0x03, &bit_string);
    Ok(der_tlv(0x30, &[alg, bit_string].concat()))
}

/// Unwrap the package CEK using the KSP private key (OAEP-SHA256).
pub fn unwrap_cek(key: &DeviceKey, wrapped: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let sha256 = wide("SHA256");
        let padding = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: sha256.as_ptr(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut size: u32 = 0;
        let status = NCryptDecrypt(
            key.key_handle,
            wrapped.as_ptr(),
            wrapped.len() as u32,
            &padding as *const _ as *mut c_void,
            ptr::null_mut(),
            0,
            &mut size,
            NCRYPT_SILENT_FLAG,
        );
        if status != 0 {
            bail!("NCryptDecrypt(size): NTSTATUS {status:#x}");
        }
        let mut out = vec![0u8; size as usize];
        let mut written: u32 = 0;
        nerr(
            NCryptDecrypt(
                key.key_handle,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                &padding as *const _ as *mut c_void,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut written,
                NCRYPT_SILENT_FLAG,
            ),
            "NCryptDecrypt",
        )?;
        out.truncate(written as usize);
        Ok(out)
    }
}

/// Serialize the buyer request file (.vreq) for the artist.
pub fn write_vreq(key: &DeviceKey, path: &std::path::Path) -> Result<()> {
    let doc = serde_json::json!({
        "magic": "VREQ",
        "version": 1,
        "algorithm": "RSA-2048",
        "key_id": key.key_id,
        "spki": util::b64e(&key.spki_der),
        "created_at": crate::auth::utcnow_iso(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

pub fn key_id_of_spki(spki_der: &[u8]) -> String {
    hex::encode(&Sha256::digest(spki_der)[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_integer_roundtrip() {
        let n = vec![0x01, 0x02, 0x03];
        let enc = der_positive_integer(&n);
        assert_eq!(enc[0], 0x02);
        assert_eq!(enc[1], n.len() as u8);
        assert_eq!(&enc[2..], &n[..]);
    }

    #[test]
    fn strip_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), vec![1, 2]);
        assert_eq!(strip_leading_zeros(&[0]), vec![0]);
    }
}
