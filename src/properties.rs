use anyhow::{Context, Result};
use std::path::Path;

/// The 7 security keys this tool owns, in the order they're appended when
/// missing from a template.
const SECURITY_KEYS: [&str; 7] = [
    "nifi.security.keystore",
    "nifi.security.keystoreType",
    "nifi.security.keystorePasswd",
    "nifi.security.keyPasswd",
    "nifi.security.truststore",
    "nifi.security.truststoreType",
    "nifi.security.truststorePasswd",
];

fn security_values(password: &str) -> [String; 7] {
    [
        "./keystore.p12".to_string(),
        "PKCS12".to_string(),
        password.to_string(),
        password.to_string(),
        "./truststore.jks".to_string(),
        "JKS".to_string(),
        password.to_string(),
    ]
}

/// Reads a base `nifi.properties` template (a complete, real properties file
/// for the target NiFi version) and returns its content with this tool's 7
/// security keys merged in: an existing `key=value` line for one of them is
/// rewritten in place with the generated value, and a key with no existing
/// line is appended at the end. Every other line — other properties,
/// comments, blank lines — is kept byte-for-byte identical and in its
/// original order.
///
/// This is deliberately a line-level find/replace/append rather than a
/// generic `key=value` parser: administrators diff the generated file
/// against the template, so preserving the order and formatting of
/// untouched lines exactly is a hard requirement, not a nicety.
pub fn merge(template: &str, password: &str) -> String {
    let values = security_values(password);
    let mut found = [false; 7];
    let mut out_lines: Vec<String> = Vec::new();

    for line in template.lines() {
        let after_indent = line.trim_start();
        let matched = SECURITY_KEYS.iter().enumerate().find_map(|(i, key)| {
            after_indent
                .strip_prefix(key)
                .filter(|rest| rest.starts_with('='))
                .map(|_| i)
        });

        match matched {
            Some(i) if !found[i] => {
                found[i] = true;
                out_lines.push(format!("{}={}", SECURITY_KEYS[i], values[i]));
            }
            Some(i) => {
                eprintln!(
                    "warning: duplicate `{}=` line in base properties template, \
                     keeping the first occurrence and leaving this one unchanged",
                    SECURITY_KEYS[i]
                );
                out_lines.push(line.to_string());
            }
            None => out_lines.push(line.to_string()),
        }
    }

    for (i, key) in SECURITY_KEYS.iter().enumerate() {
        if !found[i] {
            out_lines.push(format!("{key}={}", values[i]));
        }
    }

    let mut contents = out_lines.join("\n");
    contents.push('\n');
    contents
}

/// Merges [`merge`]'s output into `out_path`.
pub fn write_properties(template: &str, password: &str, out_path: &Path) -> Result<()> {
    std::fs::write(out_path, merge(template, password))
        .with_context(|| format!("failed to write nifi.properties to {:?}", out_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_keys_in_place_and_preserves_everything_else() {
        // All 7 keys present, scattered, mixed with non-security properties,
        // a comment, and a blank line — some already have a value (to be
        // overwritten), one is empty (to be filled in).
        let template = "\
# NiFi properties
nifi.flow.configuration.file=./conf/flow.json.gz

nifi.security.truststoreType=JKS
nifi.cluster.is.node=false
nifi.security.keystorePasswd=
# a comment about the keystore
nifi.security.keystore=/old/path/keystore.p12
nifi.security.keystoreType=JKS
nifi.web.https.port=8443
nifi.security.keyPasswd=oldpass
nifi.security.truststore=/old/path/truststore.jks
nifi.security.truststorePasswd=oldpass
";
        let out = merge(template, "s3cret");
        let out_lines: Vec<&str> = out.lines().collect();
        let in_lines: Vec<&str> = template.lines().collect();

        // All 7 keys are already present in this template, so line count
        // must be unchanged; nothing gets appended.
        assert_eq!(out_lines.len(), in_lines.len());

        assert_eq!(
            out_lines,
            vec![
                "# NiFi properties",
                "nifi.flow.configuration.file=./conf/flow.json.gz",
                "",
                "nifi.security.truststoreType=JKS",
                "nifi.cluster.is.node=false",
                "nifi.security.keystorePasswd=s3cret",
                "# a comment about the keystore",
                "nifi.security.keystore=./keystore.p12",
                "nifi.security.keystoreType=PKCS12",
                "nifi.web.https.port=8443",
                "nifi.security.keyPasswd=s3cret",
                "nifi.security.truststore=./truststore.jks",
                "nifi.security.truststorePasswd=s3cret",
            ]
        );
    }

    #[test]
    fn appends_all_keys_when_none_present() {
        let template = "\
# a template with no security keys at all
nifi.flow.configuration.file=./conf/flow.json.gz
nifi.web.https.port=8443
";
        let out = merge(template, "s3cret");
        let out_lines: Vec<&str> = out.lines().collect();
        let in_lines: Vec<&str> = template.lines().collect();

        assert_eq!(out_lines.len(), in_lines.len() + SECURITY_KEYS.len());
        assert_eq!(&out_lines[..in_lines.len()], in_lines.as_slice());

        let expected_appended = [
            "nifi.security.keystore=./keystore.p12",
            "nifi.security.keystoreType=PKCS12",
            "nifi.security.keystorePasswd=s3cret",
            "nifi.security.keyPasswd=s3cret",
            "nifi.security.truststore=./truststore.jks",
            "nifi.security.truststoreType=JKS",
            "nifi.security.truststorePasswd=s3cret",
        ];
        assert_eq!(&out_lines[in_lines.len()..], expected_appended.as_slice());
    }

    #[test]
    fn duplicate_key_keeps_first_and_leaves_second_untouched() {
        // All 7 keys present so nothing gets appended, isolating just the
        // duplicate-handling behavior for `keystoreType`.
        let template = "\
nifi.security.keystoreType=JKS
nifi.security.keystoreType=SOME_STALE_DUPLICATE_VALUE
nifi.security.keystore=./keystore.p12
nifi.security.keystorePasswd=x
nifi.security.keyPasswd=x
nifi.security.truststore=./truststore.jks
nifi.security.truststoreType=JKS
nifi.security.truststorePasswd=x
";
        let out = merge(template, "s3cret");
        let out_lines: Vec<&str> = out.lines().collect();
        // First occurrence rewritten with the generated value; the
        // duplicate second occurrence is left completely untouched.
        assert_eq!(out_lines[0], "nifi.security.keystoreType=PKCS12");
        assert_eq!(
            out_lines[1],
            "nifi.security.keystoreType=SOME_STALE_DUPLICATE_VALUE"
        );
        assert_eq!(out_lines.len(), template.lines().count());
    }

    #[test]
    fn tolerates_leading_whitespace_on_matched_keys() {
        let template = "  nifi.security.keystoreType=JKS\n";
        let out = merge(template, "s3cret");
        assert_eq!(
            out.lines().next(),
            Some("nifi.security.keystoreType=PKCS12")
        );
    }
}
