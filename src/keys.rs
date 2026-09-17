use anyhow::{Context, Result};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use std::path::Path;

/// Generates a new RSA-2048 key pair and imports it into an [`rcgen::KeyPair`].
///
/// `rcgen`'s default `ring` backend cannot *generate* RSA keys (ring has no RSA
/// keygen support), so the raw key material comes from the pure-Rust `rsa`
/// crate and is imported into rcgen via its PKCS#8 DER constructor, which
/// `ring` can sign with just fine.
pub fn generate_rsa_keypair() -> Result<rcgen::KeyPair> {
    let mut rng = rand::rngs::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).context("failed to generate RSA-2048 key")?;
    let pkcs8_der = private_key
        .to_pkcs8_der()
        .context("failed to encode RSA key as PKCS#8")?;
    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec());
    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)
        .context("failed to import generated RSA key into rcgen")
}

pub fn write_key_pem(key: &rcgen::KeyPair, path: &Path) -> Result<()> {
    let pem = key.serialize_pem();
    std::fs::write(path, pem).with_context(|| format!("failed to write key to {:?}", path))
}

/// Reads back a key pair previously written by [`write_key_pem`] (always a
/// PKCS#8 "PRIVATE KEY" PEM, since that's what `rcgen::KeyPair::serialize_pem`
/// produces).
pub fn read_key_pem(path: &Path) -> Result<rcgen::KeyPair> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key from {:?}", path))?;
    rcgen::KeyPair::from_pem(&pem).with_context(|| format!("failed to parse key at {:?}", path))
}
