//! End-to-end tests that drive the compiled `nifi-tls-gen` binary the same
//! way a user would, then check the results with independent tools
//! (`openssl`, real JDK `keytool`) rather than re-parsing our own output.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A minimal stand-in for a real `nifi.properties` template, with a couple
/// of unrelated properties, a comment, and a blank line, plus a couple of
/// the 7 security keys already present (with stale values) to exercise the
/// in-place merge through the CLI, not just `properties::merge` directly.
const FAKE_TEMPLATE: &str = "\
# fake nifi.properties template for tests
nifi.flow.configuration.file=./conf/flow.json.gz

nifi.security.keystoreType=JKS
nifi.web.https.port=8443
";

fn write_fake_template(dir: &Path) -> PathBuf {
    let path = dir.join("nifi.properties.template");
    std::fs::write(&path, FAKE_TEMPLATE).unwrap();
    path
}

fn run_generator(out_dir: &Path, hostnames: &str, base_properties: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_nifi-tls-gen"))
        .args([
            "--hostnames",
            hostnames,
            "--dn",
            "CN=admin, OU=NIFI",
            "--ca-name",
            "ca.nifi",
            "--out-dir",
        ])
        .arg(out_dir)
        .args(["--keystore-password", "changeit123", "--base-properties"])
        .arg(base_properties)
        .status()
        .expect("failed to run nifi-tls-gen binary");
    assert!(status.success(), "nifi-tls-gen exited with {status}");
}

fn tool_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("-help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// (a) Generates a CA + 2 hosts, then verifies via `openssl pkcs12 -info` +
/// `openssl verify` that each keystore's cert chain validates against the
/// generated CA.
#[test]
fn keystores_validate_against_ca_with_openssl() {
    if !tool_available("openssl") {
        eprintln!("SKIP: `openssl` not found on PATH, cannot verify PKCS12 chains");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let template = write_fake_template(dir.path());
    run_generator(dir.path(), "hosta.example.com,hostb.example.com", &template);

    let ca_crt = dir.path().join("ca/ca.crt");
    assert!(ca_crt.exists());

    for host in ["hosta.example.com", "hostb.example.com"] {
        let keystore = dir.path().join(host).join("keystore.p12");
        assert!(keystore.exists(), "missing keystore for {host}");

        // Modern OpenSSL (3.x) needs -legacy to read the classic
        // PBE-SHA1-3DES/RC2 PKCS12 encryption that both it and every JRE
        // have always supported; older OpenSSL builds understand it without
        // the flag and simply ignore -legacy if it's a no-op there.
        let info = Command::new("openssl")
            .args([
                "pkcs12",
                "-legacy",
                "-in",
            ])
            .arg(&keystore)
            .args(["-info", "-noout", "-passin", "pass:changeit123"])
            .output()
            .expect("failed to run openssl pkcs12 -info");
        assert!(
            info.status.success(),
            "openssl pkcs12 -info failed for {host}: {}",
            String::from_utf8_lossy(&info.stderr)
        );

        let extract = Command::new("openssl")
            .args(["pkcs12", "-legacy", "-in"])
            .arg(&keystore)
            .args(["-clcerts", "-nokeys", "-passin", "pass:changeit123"])
            .output()
            .expect("failed to extract leaf cert");
        assert!(extract.status.success());

        let leaf_pem = dir.path().join(format!("{host}.pem"));
        std::fs::write(&leaf_pem, &extract.stdout).unwrap();

        let verify = Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(&ca_crt)
            .arg(&leaf_pem)
            .output()
            .expect("failed to run openssl verify");
        assert!(
            verify.status.success(),
            "certificate chain for {host} did not validate against the generated CA: {}",
            String::from_utf8_lossy(&verify.stdout)
        );
    }
}

/// (b) Verifies the hand-rolled truststore.jks can be read back by a real
/// JVM's `keytool -list`. Skips gracefully if no JDK is on PATH.
#[test]
fn truststore_jks_is_readable_by_real_keytool() {
    if !tool_available("keytool") {
        eprintln!("SKIP: `keytool` not found on PATH, cannot validate JKS against a real JVM");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let template = write_fake_template(dir.path());
    run_generator(dir.path(), "hostc.example.com", &template);

    let truststore = dir.path().join("hostc.example.com/truststore.jks");
    assert!(truststore.exists());

    let output = Command::new("keytool")
        .args(["-list", "-keystore"])
        .arg(&truststore)
        .args(["-storetype", "JKS", "-storepass", "changeit123"])
        .output()
        .expect("failed to run keytool -list");
    assert!(
        output.status.success(),
        "real JDK keytool could not read our hand-rolled JKS truststore: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ca.nifi"),
        "expected the CA alias 'ca.nifi' in keytool output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("1 entry") || stdout.contains("1 entries"),
        "expected exactly one trusted-cert entry, got:\n{stdout}"
    );
}

/// (c) Verifies nifi.properties is the base template with the 7 security
/// keys merged in: correct values, and every other template line preserved
/// byte-for-byte and in order (one already present and rewritten, JKS ->
/// PKCS12; the other 6 appended at the end since FAKE_TEMPLATE doesn't have
/// them).
#[test]
fn nifi_properties_merges_into_base_template() {
    let dir = tempfile::tempdir().unwrap();
    let template = write_fake_template(dir.path());
    run_generator(dir.path(), "hostd.example.com", &template);

    let contents =
        std::fs::read_to_string(dir.path().join("hostd.example.com/nifi.properties")).unwrap();
    let lines: Vec<&str> = contents.lines().collect();

    assert_eq!(
        lines,
        vec![
            "# fake nifi.properties template for tests",
            "nifi.flow.configuration.file=./conf/flow.json.gz",
            "",
            "nifi.security.keystoreType=PKCS12",
            "nifi.web.https.port=8443",
            "nifi.security.keystore=./keystore.p12",
            "nifi.security.keystorePasswd=changeit123",
            "nifi.security.keyPasswd=changeit123",
            "nifi.security.truststore=./truststore.jks",
            "nifi.security.truststoreType=JKS",
            "nifi.security.truststorePasswd=changeit123",
        ],
        "unexpected merged nifi.properties:\n{contents}"
    );

    // regex_search with '^nifi\.security\.keyPasswd=(.+)$' in multiline mode
    // needs each property on its own line with no surrounding whitespace.
    for line in &lines {
        assert_eq!(line.trim(), *line, "line has surrounding whitespace: {line:?}");
        assert!(!line.contains('"'), "line should not be quoted: {line:?}");
    }
}

/// `--base-properties` is required: no embedded/default template, since the
/// correct one depends on the target NiFi version.
#[test]
fn base_properties_flag_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nifi-tls-gen"))
        .args([
            "--hostnames",
            "hoste.example.com",
            "--dn",
            "OU=NIFI",
            "--ca-name",
            "ca.nifi",
            "--out-dir",
        ])
        .arg(dir.path())
        .args(["--keystore-password", "changeit123"])
        .output()
        .expect("failed to run nifi-tls-gen binary");

    assert!(
        !output.status.success(),
        "expected failure when --base-properties is omitted"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("base-properties") || stderr.contains("base_properties"),
        "expected the error to mention the missing --base-properties flag, got:\n{stderr}"
    );
}
