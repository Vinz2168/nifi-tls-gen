# NiFi 2.11 3-node cluster — local Docker Compose smoke test

Validates `nifi-tls-gen`'s output end-to-end against a real Apache NiFi
2.11.0 cluster: CA + 3 node certs + 1 admin client cert, a hand-mounted
`authorizers.xml`, and `docker-compose.yml` wiring up `zookeeper` + `nifi-1`
+ `nifi-2` + `nifi-3` with mutual TLS.

## Regenerate the certs

```sh
cd /Users/vincenzo.lombardo/nifi-keytool-rust
cargo build --release
./target/release/nifi-tls-gen \
  --hostnames nifi-1,nifi-2,nifi-3,admin \
  --dn "OU=NIFI" \
  --ca-name ca.nifi \
  --out-dir docker/tls \
  --keystore-password nifiClusterPw1
```

`admin` is generated the same way as a node (server+client EKU, DNS SAN
`admin`) — that's fine, its `keystore.p12` is usable directly as a browser
or `curl` client certificate.

## Bring the cluster up

```sh
cd docker
docker compose up -d
```

Takes about a minute per node (flow election waits up to `NIFI_ELECTION_MAX_WAIT`
= 1 min). Watch it with `docker logs -f nifi-1` — look for `Cluster State
changed from Not Clustered to Clustered`.

- UI: https://localhost:8443/nifi (nifi-1), :8444 (nifi-2), :8445 (nifi-3)
- Import `tls/admin/keystore.p12` (password `nifiClusterPw1`) as a client
  certificate in your browser, and trust `tls/ca/ca.crt`, to log in — this
  cluster uses pure mutual-TLS auth, no username/password.

## Gotchas hit and fixed here

1. **`sed: cannot rename ... Device or resource busy`** — NiFi's own
   `secure.sh`/`start.sh` do an in-place `sed -i` on `conf/authorizers.xml`
   to fill in `INITIAL_ADMIN_IDENTITY`/`NODE_IDENTITY` placeholders. If you
   bind-mount your own `authorizers.xml` directly over that path, `sed -i`'s
   rename-over-target fails because the target is a mount point. Fix:
   `entrypoint-wrapper.sh` mounts the custom file at a *different* path
   (`/opt/nifi/custom/authorizers.xml`) and `cp`s it into place before
   `exec`ing the real `start.sh`, so `conf/authorizers.xml` stays an
   ordinary, renamable file inside the container. Also worked around the
   image's `secure.sh` only supporting a single `NODE_IDENTITY` env var (a
   3-node cluster needs all 3 node identities in every node's
   `authorizers.xml`) by pre-filling all of them in the mounted file instead.

2. **Identity string must include the space after the comma.** NiFi's
   x509 authentication resolves a client cert's identity as
   `"OU=NIFI, CN=admin"` (comma **+ space**) — not the no-space RFC2253
   canonical form `cert.getSubjectX500Principal().getName()` returns in a
   plain Java program. Seeding `authorizers.xml`'s `Initial Admin Identity` /
   `Initial User Identity N` / `Node Identity N` with the no-space form
   causes every request to fail authorization (`Unable to view the
   controller`) even though the TLS handshake itself succeeds — confirmed by
   reading `nifi-user.log`, which logs the exact identity string NiFi
   resolved: `Identity [OU=NIFI, CN=admin] Groups [] does not have
   permission...`. Fixed by using the space-including form for every
   identity in `authorizers.xml`. (`nifi-tls-gen` itself is unaffected by
   this — it's purely about the string used in NiFi's own config to match
   the identity NiFi extracts from a cert it issued.)

## Verifying independently

```sh
curl --resolve nifi-1:8443:127.0.0.1 --cacert tls/ca/ca.crt \
  --cert-type P12 --cert tls/admin/keystore.p12:nifiClusterPw1 \
  https://nifi-1:8443/nifi-api/controller/cluster
```

Should return all 3 nodes as `CONNECTED`, with one holding `Primary Node` +
`Cluster Coordinator` roles.

## Tear down

```sh
docker compose down
```

No named volumes are used, so this also discards all NiFi state (flow,
users.xml/authorizations.xml bootstrapped from `authorizers.xml`, etc.) —
intentional for a repeatable smoke test.
