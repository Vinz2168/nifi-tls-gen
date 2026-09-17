use crate::{cert, dn::DnTemplate, keys};
use anyhow::{Context, Result};
use rcgen::KeyPair;
use std::path::Path;

/// A loaded or freshly generated CA. `key` is consumed by
/// [`rcgen::Issuer::from_ca_cert_der`] (it isn't `Clone`), so callers build
/// the `Issuer` once from `ca.key` and keep using `ca.cert_der` afterwards to
/// embed the CA certificate in each node's keystore/truststore.
pub struct Ca {
    pub cert_der: Vec<u8>,
    pub key: KeyPair,
}

/// Loads the CA from `<ca_dir>/ca.key` + `ca.crt` if present, otherwise
/// generates a fresh self-signed CA and writes both files.
pub fn load_or_create(ca_dir: &Path, ca_name: &str, dn_template: &DnTemplate) -> Result<Ca> {
    let key_path = ca_dir.join("ca.key");
    let cert_path = ca_dir.join("ca.crt");

    if key_path.exists() {
        let key = keys::read_key_pem(&key_path)?;
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("CA key exists but {:?} is missing", cert_path))?;
        let cert_der = pem::parse(&cert_pem)
            .context("failed to parse existing ca.crt")?
            .into_contents();
        return Ok(Ca { cert_der, key });
    }

    std::fs::create_dir_all(ca_dir)
        .with_context(|| format!("failed to create CA directory {:?}", ca_dir))?;

    let key = keys::generate_rsa_keypair()?;
    let params = cert::ca_params(dn_template.build(ca_name));
    let cert = cert::self_sign_ca(&params, &key)?;

    keys::write_key_pem(&key, &key_path)?;
    std::fs::write(&cert_path, cert.pem())
        .with_context(|| format!("failed to write {:?}", cert_path))?;

    Ok(Ca {
        cert_der: cert.der().to_vec(),
        key,
    })
}
