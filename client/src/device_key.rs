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
use winapi::shared::ntdef::LPCWSTR;
use winapi::shared::winerror::NTE_EXISTS;
use winapi::um::ncrypt::{
    NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty, NCRYPT_KEY_HANDLE,
    NCRYPT_PROV_HANDLE, SECURITY_STATUS,
};

use crate::util;

const KEY_NAME: &str = "ModelLockDeviceKey8";
const NCRYPT_ALLOW_DECRYPT_FLAG: u32 = 0x0000_0001;
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
                    &size as *const u32 as *mut u8,
                    std::mem::size_of::<u32>() as u32,
                    0,
                ),
                "NCryptSetProperty(Length)",
            )?;
            // Don't set key usage restriction - allow all usages (default).
            // Setting NCRYPT_ALLOW_DECRYPT_FLAG may interfere with OAEP in some CNG versions.
            // Forbid export: no flag bits set.
            let no_export: u32 = NCRYPT_ALLOW_EXPORT_NONE;
            let export_prop = wide("Export Policy");
            nerr(
                NCryptSetProperty(
                    key,
                    export_prop.as_ptr(),
                    &no_export as *const u32 as *mut u8,
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
        log::debug!("BCRYPT blob: {} bytes, mod_len={}, exp_len={}", blob.len(), n.len(), e.len());
        log::debug!("SPKI DER: {} bytes, key_id={}", spki.len(), key_id);
        log::debug!("Modulus[..8]={:02x?}", &n[..8.min(n.len())]);
        log::debug!("Exponent={:02x?}", &e[..]);
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
    // BCRYPT_RSAPUBLIC_BLOB: PublicExponent and Modulus are stored in
    // little-endian.  Reverse byte order to obtain big-endian for DER.
    let exp_raw = &body[..exp_len];
    let mod_raw = &body[exp_len..exp_len + mod_len];
    // Verify blob structure: exponent first, then modulus.
    log::debug!(
        "BCRYPT blob total={} exp_ofs=0 exp_len={} mod_ofs={} mod_len={}",
        blob.len(), exp_len, exp_len, mod_len
    );
    // Treat as little-endian: reverse each field.
    let exp: Vec<u8> = exp_raw.iter().rev().cloned().collect();
    let modulus: Vec<u8> = mod_raw.iter().rev().cloned().collect();
    // Verify the modulus is odd (RSA requirement).
    if !modulus.is_empty() && modulus[modulus.len() - 1] % 2 == 0 {
        log::warn!(
            "BCRYPT modulus appears even (last byte={:#04x}); trying without reversal",
            modulus[modulus.len() - 1]
        );
        // Maybe the blob is already big-endian. Use raw bytes.
        let modulus = mod_raw.to_vec();
        // Check again
        if !modulus.is_empty() && modulus[modulus.len() - 1] % 2 == 0 {
            bail!("BCRYPT modulus is even in both LE and BE interpretations");
        }
        log::debug!("Modulus looks valid in native (BE) byte order");
        Ok((modulus, strip_leading_zeros(&exp)))
    } else {
        Ok((modulus, strip_leading_zeros(&exp)))
    }
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

/// Unwrap the package CEK using the KSP private key.
///
/// Does raw RSA decryption (NCryptDecrypt with flags=0, the only mode that
/// works on this Windows build), then strips OAEP-SHA256 padding manually.
pub fn unwrap_cek(key: &DeviceKey, wrapped: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        // Raw RSA decryption (flags=0, no padding info).
        // Explicit padding flags (0x02, 0x04) all return NTE_INVALID_PARAMETER.
        let mut raw = vec![0u8; 256];
        let mut written: u32 = 0;
        nerr(
            NCryptDecrypt(
                key.key_handle,
                wrapped.as_ptr(),
                wrapped.len() as u32,
                std::ptr::null_mut(),
                raw.as_mut_ptr(),
                raw.len() as u32,
                &mut written,
                0,
            ),
            "NCryptDecrypt(raw)",
        )?;
        raw.truncate(written as usize);

        // Manual OAEP-SHA256 unpadding (RFC 8017 §7.1.2).
        oaep_sha256_decode(&raw)
    }
}

/// Manual OAEP-SHA256 decoding.
///
/// EME-OAEP decoding as specified in RFC 8017 §7.1.2:
///   EM = 0x00 || maskedSeed || maskedDB
///   seed = MGF1(maskedDB, hLen) XOR maskedSeed
///   DB  = MGF1(seed, hLen) XOR maskedDB
///   DB  = lHash' || PS || 0x01 || M
/// where lHash' = SHA256(label), PS = zero bytes.
fn oaep_sha256_decode(em: &[u8]) -> Result<Vec<u8>> {
    let hlen: usize = 32; // SHA-256 output length
    if em.len() < 2 * hlen + 2 {
        bail!("OAEP: encoded message too short ({} bytes)", em.len());
    }
    if em[0] != 0x00 {
        bail!("OAEP: invalid first byte {:#04x}", em[0]);
    }

    let masked_seed = &em[1..1 + hlen];
    let masked_db = &em[1 + hlen..];

    // seedMask = MGF1(maskedDB, hLen)
    let seed_mask = mgf1_sha256(masked_db, hlen);
    // seed = maskedSeed XOR seedMask
    let mut seed = vec![0u8; hlen];
    for i in 0..hlen {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    // dbMask = MGF1(seed, maskedDB.len)
    let db_mask = mgf1_sha256(&seed, masked_db.len());

    // DB = maskedDB XOR dbMask
    let mut db = vec![0u8; masked_db.len()];
    for i in 0..db.len() {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Verify lHash = SHA256("") (empty label)
    let lhash = {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, b"");
        hasher.finalize()
    };
    if &db[..hlen] != lhash.as_slice() {
        log::debug!("OAEP lHash expected: {}", hex::encode(lhash.as_slice()));
        log::debug!("OAEP lHash got:      {}", hex::encode(&db[..hlen]));
        log::debug!("OAEP masked_db first 32: {}", hex::encode(&masked_db[..32.min(masked_db.len())]));
        log::debug!("OAEP seed first 16: {}", hex::encode(&seed[..16]));
        log::debug!("OAEP db_mask first 16: {}", hex::encode(&db_mask[..16]));
        bail!("OAEP: label hash mismatch (wrong key or parameters)");
    }

    // Find 0x01 separator after zero padding
    let payload_start = db[hlen..]
        .iter()
        .position(|&b| b == 0x01)
        .map(|p| hlen + p + 1)
        .ok_or_else(|| anyhow::anyhow!("OAEP: payload separator not found"))?;

    Ok(db[payload_start..].to_vec())
}

/// MGF1 with SHA-256.
fn mgf1_sha256(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, seed);
        Digest::update(&mut hasher, &counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
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

    #[test]
    fn test_mgf1() {
        // Test vector from RFC 8017 or verify against known Python output
        let seed = hex::decode("f6637a87b95697358a24cfa324eb54b5").unwrap();
        let result = mgf1_sha256(&seed, 223);
        // Compare with Python's MGF1 output
        assert_eq!(
            hex::encode(&result[..16]),
            "88592a2296f1f5b39960f6064471148b",
            "MGF1 first 16 bytes should match Python"
        );
    }
}
