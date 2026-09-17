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
    #[arg(long, value_delimiter = ',', required = true)]
    hostnames: Vec<String>,

    /// DN template, e.g. "CN=admin" or "CN=nifi-registry-admin, OU=NIFI". The
    /// CN is ignored (each certificate gets its own CN); any other RDNs
    /// (O, OU, L, ST, C) are reused on every certificate this tool issues.
    #[arg(long)]
    dn: String,

    /// Common Name for the CA certificate.
    #[arg(long)]
    ca_name: String,

    /// Directory to write ca/ and one directory per hostname into.
    #[arg(long)]
    out_dir: PathBuf,

    /// Password shared by the keystore, the key inside it, and the truststore.
    #[arg(long)]
    keystore_password: String,

    /// Regenerate a node's keystore/truststore/properties even if they already exist.
    #[arg(long)]
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
        process_host(host, &ca_cert_der, &issuer, &dn_template, &cli)?;
    }

    Ok(())
}

fn process_host(
    host: &str,
    ca_cert_der: &[u8],
    issuer: &Issuer<'_, rcgen::KeyPair>,
    dn_template: &DnTemplate,
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

    properties::write_properties(&cli.keystore_password, &host_dir.join("nifi.properties"))
        .with_context(|| format!("{host}: failed to write nifi.properties"))?;

    println!("{host}: OK -> {}", host_dir.display());
    Ok(())
}
