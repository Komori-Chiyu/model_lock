//! Small shared helpers (UTF-16 conversion, hex/base64, path rules).

use anyhow::{bail, Result};
use widestring::{U16CString, U16String};

pub fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

pub fn to_utf16_c(s: &str) -> U16CString {
    U16CString::from_str(s).expect("no interior NUL")
}

pub fn from_utf16(data: &[u16]) -> String {
    U16String::from_slice(data).to_string_lossy()
}

pub fn b64e(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64d(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(text)?)
}

/// Validate one package-relative POSIX path (mirror of the Python packager).
pub fn validate_relative_path(path: &str) -> Result<String> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        bail!("path must be relative");
    }
    if path.chars().any(|c| (c as u32) < 32 || (c as u32) == 127) {
        bail!("path contains control character");
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        bail!("path contains empty component");
    }
    for part in &parts {
        if *part == "." || *part == ".." {
            bail!("path contains '.' or '..'");
        }
        if part.chars().any(|c| "\\/:*?\"<>|".contains(c)) {
            bail!("path component contains forbidden character");
        }
        if part.encode_utf16().count() > 255 {
            bail!("path component too long");
        }
    }
    if path.encode_utf16().count() > 4096 {
        bail!("path too long");
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        assert!(validate_relative_path("a/b/c.json").is_ok());
        assert!(validate_relative_path("../x").is_err());
        assert!(validate_relative_path("a\\b").is_err());
        assert!(validate_relative_path("a:b").is_err());
        assert!(validate_relative_path("a//b").is_err());
        assert!(validate_relative_path("/abs").is_err());
    }
}
