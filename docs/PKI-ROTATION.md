# Local PKI expiry and rotation runbook

The lab uses a private CA for authenticated syslog and a separate local CA for
ZTNA TLS.  `scripts/gen-secrets.sh` renews leaf certificates when fewer than 30
days remain, and fails early when a CA has fewer than 90 days remaining.  The CA
is **not** silently replaced because doing so would instantly break every peer
that trusts the old CA.

## Leaf renewal

Leaf renewal is routine and keeps the existing CA:

```bash
make secrets
```

When a relay/client/ZTNA leaf is inside the 30-day window, the generator creates
an updated certificate/key pair.  Restart the affected workload and run the
corresponding live evidence control.

## CA rotation: staged overlap

Use a planned overlap before the 90-day guard becomes blocking.

1. Back up the current PKI directories offline with mode 0600/0700.
2. Generate a **new** CA without overwriting the old one.
3. Distribute a trust bundle containing `old CA + new CA` to receivers first.
   For syslog this means the relay/clients must trust both during the overlap;
   for ZTNA this means test clients/gateways trust both as applicable.
4. Issue new leaf certificates from the new CA and restart one canary peer.
5. Prove mutual TLS / trusted HTTPS and the relevant evidence controls.
6. Roll the new leaves to the remaining peers.
7. Keep the dual-CA bundle for a documented overlap period and confirm no
   active peer presents a certificate from the old CA.
8. Remove the old CA from trust stores only after all peers have moved.
9. Destroy/archive the old signing key according to the lab's key-retention
   policy and run the complete audit suite.

## Required evidence

A CA rotation is complete only when:

- `openssl verify` succeeds for every active leaf against the new trust bundle;
- DET-02 proves authenticated syslog still arrives from an allowed client;
- ZTNA-01 proves the gateway certificate is trusted without `--insecure`;
- the old CA is absent from active trust after the overlap; and
- the signing key is never mounted into the syslog relay or application plane.

This deliberate manual ceremony is preferable to automatic CA replacement in a
security lab because CA rotation changes the trust root, not just certificate
freshness.
