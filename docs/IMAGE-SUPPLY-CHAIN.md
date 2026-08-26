# Container image supply-chain policy

The project uses `supply-chain/images.lock.yml` to make external container image
selection auditable and reproducible. Compose/Kubernetes/developer images are
portable across Linux/amd64 and Apple-silicon Docker (`linux/arm64`) when the
lock says so. Path A Containerlab has a separate platform contract because the
historical FRR 9.1.0 image is currently `linux/amd64` only.

## Why the project pins an image index

For a multi-architecture image, a registry tag normally resolves to a top-level
OCI image index (Docker manifest list). That index points to separate child
manifests for amd64, arm64 and possibly other platforms.

For a portable multi-architecture component, the repository pins the
**top-level index digest**:

```text
repository@sha256:<image-index-digest>
```

It does **not** pin an amd64/arm64 child manifest and call it portable. A child
digest can be immutable while accidentally making the same Compose/Kubernetes
definition unusable on the other architecture. A genuinely single-platform
component may pin its manifest digest only when `required_platforms` records
that limitation explicitly; FRR 9.1.0 is the current example.

## Lock states

| State | Meaning |
|---|---|
| `verified` | Registry metadata identified an approved immutable digest and the source uses it. |
| `inherited-pinned` | The project already had an immutable reference; the lock adopts and verifies the existing decision. |
| `deferred` | The tag is inventoried but the exact top-level historical index has not yet been independently resolved. No digest is guessed. |

The lock also records a verification level. Digest pinning is a reproducibility
control, not a substitute for CVE scanning or supported-version maintenance.

## Deterministic offline check

Run:

```bash
make image-lock-check
```

This is part of `make lint`, `make dev-check`, and PR CI. It never contacts a
registry. It ensures source references and the committed lock agree.

## Online registry verification

On a networked Docker host with Buildx:

```bash
make verify-image-platforms
```

This command is strict. It:

1. resolves each tag/ref with `docker buildx imagetools inspect`;
2. verifies the top-level digest for committed pins;
3. verifies every platform required by the lock;
4. rejects a portable multi-arch runtime ref that resolves to a single child
   manifest;
5. reads the image config to prove OS/architecture for a single-manifest ref;
6. prints a candidate immutable `pinned_ref` for every deferred entry;
7. exits non-zero until deferred candidates are reviewed and committed.

To inspect one component while updating it:

```bash
python scripts/verify_image_platforms.py --only suricata
```

The non-strict single-entry form is useful while resolving a candidate. The
Make target remains strict to prevent a release engineer from overlooking known
deferred entries.

## Image update workflow

When changing a container image:

1. Change the intended release/tag only as part of a reviewed update/migration.
2. Resolve the tag on a networked Docker host.
3. Confirm the ref is an image index when both amd64 and arm64 are required.
4. Record the intent, immutable index ref, platforms and provenance in
   `supply-chain/images.lock.yml`.
5. Replace runtime/config source with the immutable ref. If the file is
   generated, change the renderer/canonical source and regenerate it.
6. Run:

   ```bash
   make image-lock-check
   make dev-check
   make verify-image-platforms
   make supply-chain-scan
   ```

7. Review `git diff` to ensure no unrelated version upgrade was introduced.

## Platform classes and remaining deferred components

The lock is canonical. After INC-041:

- portable Compose/Kubernetes/developer images require both `linux/amd64` and
  `linux/arm64`;
- CI-only refs require `linux/amd64`;
- Path A Containerlab requires at least `linux/amd64`; FRR 9.1.0 is explicitly
  a pinned single-platform amd64 manifest, while its other helper images may
  still carry additional architectures.

The only unresolved historical portable ref after INC-042 is:

- Suricata 8.0.1.

Authentik is pinned to the first-party GitHub Packages top-level index digest
for the reviewed 2026.8 train; GitHub lists both amd64 and arm64 children for
that index. Existing 2024.8 databases still require the controlled sequential
migration in `docs/AUTHENTIK-UPGRADE.md`.

Do not copy a child digest from an amd64/arm64 row and use it as a universal
pin. Use the online verifier to obtain the top-level index digest, or replace
the historical component through a separately tested lifecycle upgrade.

## Vulnerability and SBOM audit

The image lock answers **what exact artifact is selected**. Trivy/SBOM answers
a different question: **what known vulnerability/configuration risk is reported
for the checked source at audit time**.

Run:

```bash
make supply-chain-scan
```

The scan is explicit rather than a registry/network-dependent PR requirement.
It covers both the checked source/IaC and every immutable `pinned_ref` in the
image lock. Its result can change when vulnerability feeds change even if the
repository commit is unchanged.

## Lifecycle upgrades are separate increments

An immutable digest can preserve an old vulnerable/unsupported release forever.
Therefore release lifecycle work is tracked separately in
`docs/SECURITY-IMPLEMENTATION-LEDGER.md`. In particular, an existing Authentik
2024.8 database still requires its sequential migration even though fresh
deployments now use the reviewed 2026.8 pin; likewise, resolving a Traefik 3.1
digest alone is not a lifecycle upgrade.
