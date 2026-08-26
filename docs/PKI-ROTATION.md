# Local PKI expiry and rotation runbook

The lab has three independent trust domains:

1. the mTLS syslog relay CA and per-device client/server leaves;
2. the local ZTNA HTTPS CA and Traefik leaf; and
3. the Wazuh indexer/manager/dashboard PKI generated with the reviewed Wazuh
   certificate tool.

`gen-secrets.sh` renews syslog/ZTNA leaves when fewer than 30 days remain and
fails early when those CAs have fewer than 90 days remaining. The CAs are
**not** silently replaced because doing so would immediately break trusted
peers.

`make wazuh-config` additionally runs `scripts/check_wazuh_pki.py`. It requires
an unexpired Wazuh chain and the canonical service identities, including the
`wazuh-indexer` DNS SAN used by both Compose and Kubernetes. An older PKI that
was issued for `wazuh.indexer` must be deliberately reissued; the checker will
not weaken hostname verification to accommodate stale certificates.

## Routine leaf renewal: syslog and ZTNA

Leaf renewal keeps the existing CA:

```bash
make secrets
```

A ZTNA leaf is also reissued when the desired `ORG_DOMAIN` SAN set changes,
even if the old leaf is not near expiry. Restart the affected workload and run
the corresponding live evidence control.

## Wazuh service-identity reissue

Wazuh certificates are long-lived, so identity drift matters more than a short
renewal window. If `make wazuh-config` reports a missing/wrong SAN or chain:

1. stop the Compose/Kubernetes Wazuh workloads;
2. back up `docker/wazuh/certs/` offline with restrictive permissions;
3. preserve the old directory until the new deployment is proven;
4. remove/recreate the **leaf PKI set using the reviewed `docker/wazuh/certs.yml`**
   and the pinned Wazuh certificate generator;
5. run `make wazuh-config` and require `scripts/check_wazuh_pki.py` to pass;
6. render `k8s/runtime-secrets.yaml` again if Path C is used;
7. start one path and prove manager→indexer and dashboard→indexer TLS with
   hostname verification still set to `full`;
8. run DET/smoke controls before discarding the old backup.

Do not solve a SAN mismatch by changing `FILEBEAT_SSL_VERIFICATION_MODE` or
`opensearch.ssl.verificationMode` to a weaker setting.

## CA rotation: staged overlap

Use a planned overlap before a CA guard becomes blocking.

1. Back up the current PKI directories offline with mode 0600/0700.
2. Generate a **new** CA without overwriting the old one.
3. Distribute a trust bundle containing `old CA + new CA` to receivers first.
4. Issue new leaf certificates from the new CA and restart one canary peer.
5. Prove mutual TLS / trusted HTTPS and the relevant evidence controls.
6. Roll the new leaves to the remaining peers.
7. Keep the dual-CA bundle for a documented overlap period and confirm no
   active peer presents a certificate from the old CA.
8. Remove the old CA from trust stores only after all peers have moved.
9. Destroy/archive the old signing key according to the lab key-retention
   policy and run the complete audit suite.

For Wazuh, treat the official generated root and service certificate set as one
coordinated trust domain. Do not independently rotate only the indexer leaf if
manager/dashboard trust material would then be inconsistent.

## Required evidence

A PKI change is complete only when:

- `openssl verify` succeeds for every active leaf against the intended CA/bundle;
- `scripts/check_wazuh_pki.py` passes for the Wazuh identities;
- Wazuh manager and Dashboard verify `wazuh-indexer` with hostname verification
  enabled (`full`), not CA-only verification;
- DET-02 proves authenticated syslog arrives from every audited Path A identity;
- ZTNA-01 proves the gateway certificate is trusted without `--insecure`;
- the old CA is absent from active trust after the overlap; and
- signing keys are never mounted into the ordinary application/logging plane.

This deliberate ceremony is preferable to automatic CA replacement in a
security lab because CA rotation changes the trust root, not merely certificate
freshness.
