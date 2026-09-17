use anyhow::{Context, Result};
use p12::PFX;
use std::path::Path;

/// Builds a password-protected PKCS12 keystore containing `leaf_key` +
/// `leaf_cert_der`, with `ca_cert_der` bundled in as the trust chain, and
/// writes it to `path`.
///
/// Uses the pure-Rust `p12` crate (PBE-SHA1-3DES for the key, matching the
/// classic PKCS12 encryption that both OpenSSL (`-legacy`) and every JRE's
/// SunJSSE keystore loader understand) rather than shelling out to OpenSSL.
pub fn write_keystore(
    leaf_cert_der: &[u8],
    leaf_key_der: &[u8],
    ca_cert_der: &[u8],
    password: &str,
    alias: &str,
    path: &Path,
) -> Result<()> {
    let pfx = PFX::new_with_cas(
        leaf_cert_der,
        leaf_key_der,
        &[ca_cert_der],
        password,
        alias,
    )
    .context("failed to build PKCS12 keystore")?;
    std::fs::write(path, pfx.to_der())
        .with_context(|| format!("failed to write keystore to {:?}", path))
}
