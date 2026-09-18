mod ca;
mod cert;
mod dn;
mod jks;
mod keys;
mod pkcs12;
mod properties;

use anyhow::{Context, Result};
use clap::Parser;
use dn::DnTemplate;
use rcgen::Issuer;
use std::path::PathBuf;

/// Generates a self-signed CA plus per-hostname PKCS12 keystores and JKS
/// truststores for Apache NiFi, replacing the cert-generation part of
/// `tls-toolkit.sh standalone` without requiring a JVM.
#[derive(Parser)]
#[command(name = "nifi-tls-gen")]
struct Cli {
    /// Comma-separated list of hostnames or IPs to issue node certificates for.
    ///
    /// Same flag name and short form as tls-toolkit's `-n`/`--hostnames`.
    #[arg(long, short = 'n', value_delimiter = ',', required = true)]
    hostnames: Vec<String>,

    /// DN template, e.g. "CN=admin" or "CN=nifi-registry-admin, OU=NIFI". The
    /// CN is ignored (each certificate gets its own CN); any other RDNs
    /// (O, OU, L, ST, C) are reused on every certificate this tool issues.
    ///
    /// Plays the same role as tls-toolkit's `--nifiDnSuffix` (accepted here
    /// as an alias): the non-CN part of the DN, reused for every
    /// certificate. tls-toolkit's separate `--nifiDnPrefix` isn't supported
    /// — this tool always uses a literal `CN=` prefix.
    #[arg(long, visible_alias = "nifiDnSuffix")]
    dn: String,

    /// Common Name for the CA certificate.
    ///
    /// Same role as tls-toolkit's `-c`/`--certificateAuthorityHostname`
    /// (accepted here as an alias).
    #[arg(long, short = 'c', visible_alias = "certificateAuthorityHostname")]
    ca_name: String,

    /// Directory to write ca/ and one directory per hostname into.
    ///
    /// Same flag as tls-toolkit's `-o`/`--outputDirectory` (accepted here as
    /// an alias).
    #[arg(long, short = 'o', visible_alias = "outputDirectory")]
    out_dir: PathBuf,

    /// Password shared by the keystore, the key inside it, and the truststore.
    ///
    /// Same role as tls-toolkit's `-S`/`--keyStorePassword` (accepted here
    /// as an alias). Unlike tls-toolkit, this tool always uses one shared
    /// password for the keystore, its key, and the truststore — there's no
    /// equivalent of tls-toolkit's separate `-K`/`--keyPassword` or
    /// `-P`/`--trustStorePassword`.
    #[arg(long, short = 'S', visible_alias = "keyStorePassword")]
    keystore_password: String,

    /// Path to a complete, real `nifi.properties` file for the target NiFi
    /// version (e.g. generated once by a real `tls-toolkit.sh` run, or
    /// copied from an existing installation's conf/nifi.properties). Each
    /// host's output nifi.properties is this template with the 7 security
    /// keys merged in; every other line is kept byte-for-byte identical.
    /// There is no default or embedded template — the correct one depends
    /// on the target NiFi version, so the caller must always supply it.
    ///
    /// Same flag as tls-toolkit's `-f`/`--nifiPropertiesFile` (accepted here
    /// as an alias), except that flag is optional upstream (an embedded
    /// template is used if omitted) and is required here.
    #[arg(long, short = 'f', visible_alias = "nifiPropertiesFile")]
    base_properties: PathBuf,

    /// Regenerate a node's keystore/truststore/properties even if they already exist.
    ///
    /// Same flag as tls-toolkit's `-O`/`--isOverwrite` (accepted here as an
    /// alias).
    #[arg(long, short = 'O', visible_alias = "isOverwrite")]
    force: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let dn_template = DnTemplate::parse(&cli.dn)?;

    let base_properties = std::fs::read_to_string(&cli.base_properties).with_context(|| {
        format!(
            "failed to read --base-properties template {:?}",
            cli.base_properties
        )
    })?;

    std::fs::create_dir_all(&cli.out_dir)
        .with_context(|| format!("failed to create output directory {:?}", cli.out_dir))?;

    let ca_dir = cli.out_dir.join("ca");
    let ca = ca::load_or_create(&ca_dir, &cli.ca_name, &dn_template)
        .context("failed to load or create CA")?;
    let ca_cert_der = ca.cert_der.clone();
    let issuer = Issuer::from_ca_cert_der(&ca.cert_der.clone().into(), ca.key)
        .context("failed to build issuer from CA certificate")?;

    for host in &cli.hostnames {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        process_host(host, &ca_cert_der, &issuer, &dn_template, &base_properties, &cli)?;
    }

    Ok(())
}

fn process_host(
    host: &str,
    ca_cert_der: &[u8],
    issuer: &Issuer<'_, rcgen::KeyPair>,
    dn_template: &DnTemplate,
    base_properties: &str,
    cli: &Cli,
) -> Result<()> {
    let host_dir = cli.out_dir.join(host);
    let keystore_path = host_dir.join("keystore.p12");

    if keystore_path.exists() && !cli.force {
        println!("{host}: skipped (keystore.p12 already exists, use --force to regenerate)");
        return Ok(());
    }

    std::fs::create_dir_all(&host_dir)
        .with_context(|| format!("failed to create directory {:?}", host_dir))?;

    let leaf_key =
        keys::generate_rsa_keypair().with_context(|| format!("{host}: failed to generate key"))?;
    let leaf_params = cert::leaf_params(dn_template.build(host), host)
        .with_context(|| format!("{host}: failed to build certificate params"))?;
    let leaf_cert = cert::issue_leaf(&leaf_params, &leaf_key, issuer)
        .with_context(|| format!("{host}: failed to issue certificate"))?;

    pkcs12::write_keystore(
        leaf_cert.der(),
        &leaf_key.serialize_der(),
        ca_cert_der,
        &cli.keystore_password,
        host,
        &keystore_path,
    )
    .with_context(|| format!("{host}: failed to write keystore"))?;

    let truststore_path = host_dir.join("truststore.jks");
    jks::write_truststore(
        &[jks::TrustedCertEntry {
            alias: &cli.ca_name,
            cert_der: ca_cert_der,
        }],
        &cli.keystore_password,
        &truststore_path,
    )
    .with_context(|| format!("{host}: failed to write truststore"))?;

    properties::write_properties(
        base_properties,
        &cli.keystore_password,
        &host_dir.join("nifi.properties"),
    )
    .with_context(|| format!("{host}: failed to write nifi.properties"))?;

    println!("{host}: OK -> {}", host_dir.display());
    Ok(())
}
