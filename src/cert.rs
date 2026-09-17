use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose,
    Issuer, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

/// NiFi's own `tls-toolkit` defaults to 825 days; the spec for this tool asks
/// for a flat 10-year validity instead.
const VALIDITY_DAYS: i64 = 365 * 10;

/// Builds params for a self-signed CA certificate with the given subject DN.
pub fn ca_params(dn: DistinguishedName) -> CertificateParams {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Back-date slightly to tolerate clock skew between this machine and the
    // nodes that will validate the chain.
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    params
}

/// Builds params for a leaf (node) certificate, with `host` set as both the
/// `CN` (via `dn`) and as its sole Subject Alternative Name entry. `host` is
/// classified as an IP-address SAN or a DNS-name SAN automatically.
pub fn leaf_params(dn: DistinguishedName, host: &str) -> Result<CertificateParams> {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.subject_alt_names = vec![host_san(host)?];
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    Ok(params)
}

fn host_san(host: &str) -> Result<SanType> {
    Ok(match IpAddr::from_str(host) {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(
            host.to_string()
                .try_into()
                .with_context(|| format!("{host:?} is not a valid DNS name or IP address"))?,
        ),
    })
}

pub fn self_sign_ca(params: &CertificateParams, key: &KeyPair) -> Result<Certificate> {
    params
        .self_signed(key)
        .context("failed to self-sign CA certificate")
}

pub fn issue_leaf(
    params: &CertificateParams,
    leaf_key: &KeyPair,
    issuer: &Issuer<'_, KeyPair>,
) -> Result<Certificate> {
    params
        .signed_by(leaf_key, issuer)
        .context("failed to sign leaf certificate with CA")
}
