use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: u32 = 0xFEED_FEED;
const VERSION: u32 = 2;
const TRUSTED_CERT_TAG: u32 = 2;
const MIGHTY_APHRODITE: &[u8] = b"Mighty Aphrodite";

pub struct TrustedCertEntry<'a> {
    pub alias: &'a str,
    pub cert_der: &'a [u8],
}

/// Hand-rolled writer for the JKS ("Java KeyStore") binary format, producing
/// a truststore that holds only trusted-certificate entries (no private
/// keys) — the subset `sun.security.provider.JavaKeyStore` needs for a
/// NiFi truststore. Layout: `0xFEEDFEED` magic, format version (2), entry
/// count, then per entry a tag (2 = trusted cert), a `writeUTF`-encoded
/// alias, an 8-byte timestamp, the cert type string "X.509", the DER length,
/// and the DER bytes; finally a SHA-1 keyed hash over the whole body for
/// tamper detection. Verified against a real JDK's `keytool -list` in
/// `tests/jks_roundtrip.rs`.
pub fn write_truststore(entries: &[TrustedCertEntry], password: &str, path: &Path) -> Result<()> {
    let body = encode_body(entries)?;
    let digest = keyed_hash(password, &body);

    let mut out = body;
    out.extend_from_slice(&digest);

    std::fs::write(path, out)
        .with_context(|| format!("failed to write truststore to {:?}", path))
}

fn encode_body(entries: &[TrustedCertEntry]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&MAGIC.to_be_bytes());
    body.extend_from_slice(&VERSION.to_be_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    for entry in entries {
        body.extend_from_slice(&TRUSTED_CERT_TAG.to_be_bytes());
        write_utf(&mut body, entry.alias)?;
        body.extend_from_slice(&now_millis.to_be_bytes());
        write_utf(&mut body, "X.509")?;
        body.extend_from_slice(&(entry.cert_der.len() as u32).to_be_bytes());
        body.extend_from_slice(entry.cert_der);
    }
    Ok(body)
}

/// Reproduces `sun.security.provider.JavaKeyStore`'s integrity hash:
/// `SHA-1(UTF-16BE(password) || "Mighty Aphrodite" || <keystore body>)`.
///
/// This is sometimes described as XOR-ing the salt phrase with the password;
/// the real JDK source (and this implementation, confirmed by round-tripping
/// through a real `keytool -list`) concatenates them instead.
fn keyed_hash(password: &str, body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for unit in password.encode_utf16() {
        hasher.update(unit.to_be_bytes());
    }
    hasher.update(MIGHTY_APHRODITE);
    hasher.update(body);
    hasher.finalize().into()
}

/// Writes a string using Java's `DataOutputStream.writeUTF` "modified UTF-8"
/// encoding: a 2-byte big-endian length prefix (of the encoded bytes, not
/// characters) followed by the bytes, with NUL encoded as 0xC0 0x80 and each
/// UTF-16 code unit (including lone surrogate halves of an astral character)
/// encoded independently, matching the JDK exactly.
fn write_utf(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let mut encoded = Vec::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007F => encoded.push(unit as u8),
            0x0000 | 0x0080..=0x07FF => {
                encoded.push(0xC0 | ((unit >> 6) as u8 & 0x1F));
                encoded.push(0x80 | (unit as u8 & 0x3F));
            }
            _ => {
                encoded.push(0xE0 | ((unit >> 12) as u8 & 0x0F));
                encoded.push(0x80 | ((unit >> 6) as u8 & 0x3F));
                encoded.push(0x80 | (unit as u8 & 0x3F));
            }
        }
    }
    if encoded.len() > u16::MAX as usize {
        bail!("string {s:?} is too long to encode in a JKS UTF field");
    }
    out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    out.extend_from_slice(&encoded);
    Ok(())
}
