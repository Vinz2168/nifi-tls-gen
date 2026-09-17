use anyhow::{bail, Result};
use rcgen::{DistinguishedName, DnType};

/// A parsed `--dn` template.
///
/// The `CN` component (if any) is discarded: every certificate this tool
/// issues gets its own explicit `CN` (the CA name for the CA cert, the
/// hostname for each node cert), matching how NiFi's own `tls-toolkit`
/// combines a `dnPrefix` ("CN=") + per-entity name + `dnSuffix` (e.g.
/// ", OU=NIFI") into one subject DN. The remaining RDNs (O, OU, L, ST, C, or
/// custom OIDs) are kept in the order they were given and reused for every
/// certificate.
pub struct DnTemplate {
    extra_rdns: Vec<(DnType, String)>,
}

impl DnTemplate {
    pub fn parse(dn: &str) -> Result<Self> {
        let mut extra_rdns = Vec::new();
        for part in dn.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((key, value)) = part.split_once('=') else {
                bail!("invalid DN component {part:?} in --dn {dn:?} (expected KEY=value)");
            };
            let key = key.trim();
            let value = value.trim();
            let dn_type = match key.to_ascii_uppercase().as_str() {
                "CN" => continue, // overridden per-certificate
                "O" | "ORGANIZATIONNAME" => DnType::OrganizationName,
                "OU" | "ORGANIZATIONALUNITNAME" => DnType::OrganizationalUnitName,
                "L" | "LOCALITYNAME" => DnType::LocalityName,
                "ST" | "S" | "STATEORPROVINCENAME" => DnType::StateOrProvinceName,
                "C" | "COUNTRYNAME" => DnType::CountryName,
                other => bail!("unsupported DN attribute {other:?} in --dn {dn:?}"),
            };
            extra_rdns.push((dn_type, value.to_string()));
        }
        Ok(Self { extra_rdns })
    }

    /// Builds a full subject DN for the given entity name (CA name or hostname).
    pub fn build(&self, common_name: &str) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        for (ty, value) in &self.extra_rdns {
            dn.push(ty.clone(), value.as_str());
        }
        dn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cn_only() {
        let tmpl = DnTemplate::parse("CN=admin").unwrap();
        let dn = tmpl.build("node1.example.com");
        assert_eq!(
            dn.get(&DnType::CommonName),
            Some(&"node1.example.com".into())
        );
    }

    #[test]
    fn full_dn_keeps_extra_rdns() {
        let tmpl = DnTemplate::parse("CN=nifi-registry-admin, OU=NIFI").unwrap();
        let dn = tmpl.build("ca.nifi");
        assert_eq!(dn.get(&DnType::CommonName), Some(&"ca.nifi".into()));
        assert_eq!(
            dn.get(&DnType::OrganizationalUnitName),
            Some(&"NIFI".into())
        );
    }

    #[test]
    fn rejects_unknown_attribute() {
        assert!(DnTemplate::parse("CN=x, ZZ=y").is_err());
    }
}
