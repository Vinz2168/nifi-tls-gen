use anyhow::{Context, Result};
use std::path::Path;

/// Writes the small subset of `nifi.properties` that downstream Ansible tasks
/// read back with `regex_search('^nifi\.security\.keyPasswd=(.+)$', multiline=True)`-
/// style patterns: one `key=value` pair per line, no quoting, no surrounding
/// whitespace, no sections.
pub fn write_properties(password: &str, path: &Path) -> Result<()> {
    let contents = format!(
        "nifi.security.keystore=./keystore.p12\n\
         nifi.security.keystoreType=PKCS12\n\
         nifi.security.keystorePasswd={password}\n\
         nifi.security.keyPasswd={password}\n\
         nifi.security.truststore=./truststore.jks\n\
         nifi.security.truststoreType=JKS\n\
         nifi.security.truststorePasswd={password}\n"
    );
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write nifi.properties to {:?}", path))
}
