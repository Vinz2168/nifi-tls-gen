# nifi-tls-gen

Generates the certificate material Apache NiFi's `tls-toolkit.sh standalone`
would generate — a CA, and per-node PKCS12 keystores + JKS truststores +
a `nifi.properties` with the security properties filled in — without needing
a JVM at generation time. NiFi itself still runs on Java on the target nodes;
only the *generation* step runs JVM-free, which is what makes this usable
inside a JVM-less Ansible Execution Environment container.

## CLI

```
nifi-tls-gen \
  --hostnames <comma-separated hostnames/IPs> \
  --dn "<DN template, e.g. 'CN=admin' or 'CN=nifi-registry-admin, OU=NIFI'>" \
  --ca-name <CA common name, e.g. ca.nifi> \
  --out-dir <output directory> \
  --keystore-password <password> \
  --base-properties <path to a template nifi.properties> \
  [--force]
```

| Flag                  | Short | tls-toolkit alias | Required | Meaning                                                                                                    |
|------------------------|:---:|-----------------------------|:--------:|-------------------------------------------------------------------------------------------------------------|
| `--hostnames`          | `-n` | `--hostnames` | yes      | Comma-separated hostnames or IP addresses; one node cert is issued per entry.                               |
| `--dn`                 | | `--nifiDnSuffix` | yes      | DN template. Its `CN` is ignored — every certificate gets an explicit `CN` (see below) — and any other RDNs (`O`, `OU`, `L`, `ST`, `C`) are kept and reused on every certificate issued. |
| `--ca-name`            | `-c` | `--certificateAuthorityHostname` | yes      | Common Name for the CA certificate (and the alias used for it in every truststore). |
| `--out-dir`            | `-o` | `--outputDirectory` | yes      | Output directory (created if missing). |
| `--keystore-password`  | `-S` | `--keyStorePassword` | yes      | Shared password for the keystore, the private key inside it, and the truststore. |
| `--base-properties`    | `-f` | `--nifiPropertiesFile` | yes      | Path to a complete, real `nifi.properties` file for the target NiFi version. See [nifi.properties generation](#nifiproperties-generation) below. |
| `--force`              | `-O` | `--isOverwrite` | no       | Regenerate a node's `keystore.p12`/`truststore.jks`/`nifi.properties` even if `keystore.p12` already exists. |

### tls-toolkit CLI compatibility

The short flags and the "tls-toolkit alias" long names above are accepted
as exact synonyms for their `nifi-tls-gen` counterparts — same flag,
same behavior — for anyone whose fingers already know `tls-toolkit.sh
standalone`'s options (from `TlsToolkitStandaloneCommandLine`/
`BaseTlsToolkitCommandLine` in NiFi's own — now removed — `nifi-toolkit-tls`
module). This is **compatibility for existing functionality only, not new
functionality**: only flags this tool already implements got an alias.
tls-toolkit options with no equivalent here are deliberately **not**
accepted at all, so a typo doesn't silently do something unexpected:

- `-K`/`--keyPassword`, `-P`/`--trustStorePassword` — this tool always uses
  one shared password (`--keystore-password`/`-S`) for the keystore, its
  key, and the truststore; there's no per-store password.
- `-T`/`--keyStoreType`, `-a`/`--keyAlgorithm`, `-k`/`--keySize`,
  `-s`/`--signingAlgorithm`, `-d`/`--days` — always PKCS12 keystore / JKS
  truststore, RSA-2048, SHA256withRSA, 10-year validity; not configurable.
- `--nifiDnPrefix` — the CN prefix is always the literal `CN=`.
- `-C`/`--clientCertDn`, `-B`/`--clientCertPassword`,
  `-G`/`--globalPortSequence`, `--subjectAlternativeNames`,
  `--additionalCACertificate`, `--splitKeystore`, `-g`/
  `--differentKeyAndKeystorePasswords` — no equivalent feature.
- `-f`/`--nifiPropertiesFile` is **required** here (no embedded default
  template — see below), where it's optional upstream.

(As of NiFi 2.x, `tls-toolkit.sh` itself no longer ships at all — the
`nifi-toolkit-tls` module was removed from NiFi's `main` branch and only
exists on the legacy `support/nifi-1.x` branch — which is the whole reason
this tool exists.)

### Example

```sh
nifi-tls-gen \
  --hostnames nifi-1.internal,nifi-2.internal,10.0.0.5 \
  --dn "CN=admin, OU=NIFI" \
  --ca-name ca.nifi \
  --out-dir ./tls \
  --keystore-password changeit123 \
  --base-properties ./templates/nifi.properties.2.11.0
```

### Output structure

```
<out-dir>/
  ca/
    ca.crt
    ca.key
  nifi-1.internal/
    keystore.p12
    truststore.jks
    nifi.properties
  nifi-2.internal/
    keystore.p12
    truststore.jks
    nifi.properties
  10.0.0.5/
    keystore.p12
    truststore.jks
    nifi.properties
```

### `nifi.properties` generation

> **Breaking change**: earlier versions of this tool wrote a minimal
> `nifi.properties` from scratch, containing only the 7 security keys below
> and nothing else. That behavior is gone. `--base-properties` is now
> **required**, and each host's `nifi.properties` is that template merged
> with the 7 security keys, not a from-scratch file.

`--base-properties` must point to a complete, valid `nifi.properties` file
for the target NiFi version — generate one once with a real
`tls-toolkit.sh standalone` run, or copy `conf/nifi.properties` out of an
existing NiFi installation of the same version, and check it into the
consuming project's repo. There's no default or embedded template: the
right one depends on the NiFi version, so the caller always supplies it
explicitly.

For each host, the tool reads that template and, for exactly these 7 keys:

```
nifi.security.keystore=./keystore.p12
nifi.security.keystoreType=PKCS12
nifi.security.keystorePasswd=<password>
nifi.security.keyPasswd=<password>
nifi.security.truststore=./truststore.jks
nifi.security.truststoreType=JKS
nifi.security.truststorePasswd=<password>
```

rewrites the line in place if a `key=` line for it already exists anywhere
in the template (whatever its current value), or appends a new `key=value`
line at the end if it doesn't. **Every other line — every other property,
every comment, every blank line — is preserved byte-for-byte and in its
original order.** This is implemented as a line-level find/replace/append
over the template's raw text (`src/properties.rs::merge`), deliberately not
a generic `key=value` parser that could reorder or reformat things: this
file gets diffed by administrators against the template, so preserving
unrelated lines exactly is a hard requirement.

If one of the 7 keys appears more than once in the template (not valid
NiFi config, but handled defensively), only the first occurrence is
rewritten; later ones are left untouched and a warning is printed to
stderr.

### DN construction

Real `tls-toolkit` builds each certificate's subject as `dnPrefix + <name> +
dnSuffix` (default `dnPrefix = "CN="`, `dnSuffix = ", OU=NIFI"`). This tool
follows the same idea from a single `--dn` template: it parses out any
non-`CN` RDNs and reuses them as the suffix, and substitutes the entity's own
name as `CN`:

- CA certificate: `CN=<--ca-name>` + the template's other RDNs.
- Each node certificate: `CN=<hostname>` + the template's other RDNs.

Each node certificate's SAN list has exactly one entry, `<hostname>`,
classified automatically as an IP-address SAN (if it parses as an IPv4/IPv6
address) or a DNS-name SAN otherwise.

### Idempotency

- If `<out-dir>/ca/ca.key` exists, that CA is loaded and reused (its private
  key and `ca.crt` are never touched again) instead of generating a new one.
- If `<out-dir>/<hostname>/keystore.p12` exists, that host's key, cert,
  keystore, truststore, and `nifi.properties` are all skipped, unless
  `--force` is passed.

## Design choices / deviations from a literal `tls-toolkit` port

- **Validity**: 10 years (3650 days) for both the CA and every node cert, per
  this tool's spec. Upstream `tls-toolkit` defaults to 825 days.
- **Key algorithm**: RSA-2048 (matches upstream's own default: `RSA` /
  `2048` / `SHA256withRSA`).

### Certificate generation: `rcgen`

Certs are built with [`rcgen`](https://docs.rs/rcgen) 0.14, signed with
`SHA256withRSA`, backed by `ring`. `ring` cannot *generate* RSA keys (it has
no RSA keygen support at all — see
[briansmith/ring#219](https://github.com/briansmith/ring/issues/219)), so
RSA-2048 key material is generated with the pure-Rust
[`rsa`](https://docs.rs/rsa) crate, PKCS#8-DER-encoded, and imported into
`rcgen::KeyPair::from_pkcs8_der_and_sign_algo` — which `ring` *can* sign
with. No native RSA-generation library (OpenSSL, aws-lc) is linked in.

### PKCS12 keystore: the `p12` crate

`keystore.p12` is built with the pure-Rust [`p12`](https://crates.io/crates/p12)
crate (`PFX::new_with_cas`), not by shelling out to `openssl pkcs12`. It uses
the classic PBE-SHA1-3KeyTripleDES (key) / PBE-SHA1-40BitRC2 (certs)
PKCS12 encryption — the scheme every JRE's `SunJSSE`/`PKCS12` keystore
provider has supported since forever, and the one real `tls-toolkit` itself
produces via Java's own `KeyStore.store()`. This was verified end-to-end
against a real JDK 26 `keytool -list -v` (see `tests/integration.rs`,
`keystores_validate_against_ca_with_openssl` and the manual check below) and
against `openssl pkcs12 -info`. Note that **OpenSSL 3.x needs the `-legacy`
flag** to read this scheme (it moved legacy PKCS12 ciphers into an optional
provider); that only matters if you inspect the file with the `openssl` CLI
directly — Java reads it natively either way, which is what actually matters
for NiFi.

### JKS truststore: hand-rolled writer, verified against a real JVM

`truststore.jks` needed to be **real JKS**, not PKCS12-renamed — NiFi's own
docs call out BouncyCastle/Oracle JSSE PKCS12-truststore compatibility
issues and recommend JKS. The Rust JKS crates available on crates.io at the
time of writing (`jks`, `rust-jks`, and similar) are either read-only,
abandoned, or don't implement the trusted-cert-entry + integrity-hash write
path correctly, so this tool hand-rolls the writer in `src/jks.rs` instead of
depending on one of them. It implements only the subset of the format
`sun.security.provider.JavaKeyStore` needs to read a truststore (no private
key entries):

```
u4  MAGIC (0xFEEDFEED)
u4  VERSION (2)
u4  entry count
for each entry:
    u4     tag (2 = trusted cert entry)
    utf    alias            (2-byte length + Java "modified UTF-8" bytes)
    i8     timestamp (millis since epoch)
    utf    cert type ("X.509")
    u4     cert DER length
    bytes  cert DER
20 bytes  SHA-1 keyed hash over everything above
```

The integrity hash is `SHA-1(UTF-16BE(password) || "Mighty Aphrodite" ||
<everything from MAGIC through the last entry>)`. **This concatenates the
password and the salt phrase, it does not XOR them** — that was double
checked against real output, and against `sun.security.provider.JavaKeyStore`'s
`getPreKeyedHash`/`engineStore` behavior, since an XOR-based implementation
produces a file real `keytool` rejects with a "Keystore was tampered with,
or password was incorrect" error.

**Validation**: `tests/integration.rs::truststore_jks_is_readable_by_real_keytool`
generates a truststore and runs the real JDK's `keytool -list -keystore
truststore.jks -storetype JKS` against it, asserting success and that the CA
alias shows up. It skips (with a clear message) if no JDK is on `PATH`. This
was also checked manually:

```sh
$ keytool -list -v -keystore <out>/<host>/truststore.jks -storetype JKS -storepass <password>
Keystore type: JKS
Keystore provider: SUN
Your keystore contains 1 entry
Alias name: ca.nifi
Entry type: trustedCertEntry
Owner: OU=NIFI, CN=ca.nifi
...
```

against JDK 26 (`java -version` → `26.0.1`).

## Building

```sh
cargo build --release
```

Produces `target/release/nifi-tls-gen`.

### musl / minimal-container builds (x86_64 Linux)

Nothing in the dependency tree links against system OpenSSL — certificate
crypto is `ring` (which officially supports musl targets, including
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) plus the
pure-Rust `rsa`/`p12` crates. On Linux, a static musl binary builds with:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

**Cross-compiling from macOS** (or any non-Linux host): rustup's musl target
needs a musl C toolchain to build `ring`'s few C/assembly files, which isn't
available outside Linux. The reliable way is building inside a Linux
container — critically, an **x86_64** one, not whatever the host's native
arch is, since `ring`'s C code is architecture-specific
(cross-arch-in-container silently fails with a confusing
`cc1: error: unrecognized command-line option '-m64'` from a mismatched
`musl-gcc` if you don't pin the platform):

```sh
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work rust:latest bash -c '
  apt-get update -qq && apt-get install -y -qq musl-tools musl-dev
  rustup target add x86_64-unknown-linux-musl
  cargo build --release --target x86_64-unknown-linux-musl
'
```

Produces `target/x86_64-unknown-linux-musl/release/nifi-tls-gen` — a static
`ELF 64-bit ... x86-64 ... static-pie linked` binary. This was verified by
actually running that binary (not just compiling it) inside two separate
minimal `--platform linux/amd64` containers with nothing else installed:
`alpine:3.20` (musl libc) and `debian:12-slim` (glibc) — both ran it and
produced correct output with zero extra runtime dependencies, which is the
target scenario (a JVM-less Ansible Execution Environment container).

If cross-compiling like this fails in your environment, fall back to a
regular `x86_64-unknown-linux-gnu` build and ensure `libc` is present in the
container, which every mainstream base image has anyway.

## Testing

```sh
cargo test --release
```

- `src/dn.rs` unit tests cover `--dn` template parsing.
- `src/properties.rs` unit tests cover the template-merge logic directly:
  replacing all 7 keys in place (scattered through a template mixed with
  comments/blanks/other properties) with no line-count change, appending
  all 7 when none are present, leaving a duplicate key's second occurrence
  untouched, and tolerating leading whitespace on a matched key.
- `tests/integration.rs` drives the actual compiled binary end-to-end:
  - `keystores_validate_against_ca_with_openssl`: generates a CA + 2 hosts,
    shells out to `openssl pkcs12 -info` / `openssl verify` to confirm each
    keystore's cert chain validates against the generated CA. Skips if
    `openssl` isn't on `PATH`.
  - `truststore_jks_is_readable_by_real_keytool`: confirms the hand-rolled
    JKS writer round-trips through a real JDK's `keytool -list`. Skips if no
    JDK is on `PATH`.
  - `nifi_properties_merges_into_base_template`: runs the CLI against a fake
    template with some of the 7 keys already present and others missing,
    and asserts the exact resulting line sequence — matched keys rewritten
    in place, missing ones appended, everything else preserved verbatim, no
    surrounding whitespace on any property line (needed by the Ansible
    `regex_search('^nifi\.security\.keyPasswd=(.+)$', multiline=True)`
    pattern that reads this file back downstream).
  - `base_properties_flag_is_required`: confirms the CLI fails clearly when
    `--base-properties` is omitted.
  - `tls_toolkit_compatible_aliases_work`: runs the binary using only
    tls-toolkit's flag names/short forms (`-n`, `--nifiDnSuffix`, `-c`,
    `-o`, `-S`, `-f`, `-O`) and confirms they behave exactly like the
    canonical flags, including `-O` regenerating an existing host.

  This was also checked against a real, complete 378-line
  `nifi.properties` pulled from the `apache/nifi:2.11.0` Docker image: after
  merging, `diff` against the original shows only the 7 targeted lines
  changed, same line count, everything else untouched.
