# Security implementation ledger

This ledger records security findings, implementation increments, regressions,
and validation boundaries for the `enterprise-netsec-iac` project. It is meant
to preserve the reasoning behind each hardening change so a future refactor can
distinguish an intentional security invariant from an incidental implementation
detail.

## Validation vocabulary

Every entry uses one or more of the following evidence levels.

| Level | Meaning |
|---|---|
| **Static verified** | Source/render/unit checks prove an invariant without starting the lab. |
| **Registry-metadata verified** | Registry/package metadata identifies the committed top-level OCI/Docker index digest and required architectures. |
| **Runtime verified** | A live deployment/test observed the intended behavior. |
| **Deferred** | The risk or migration is known, but the exact implementation has not been accepted as safe yet. |
| **Historical regression** | An earlier patch caused a failure and was reverted or redesigned. |

A green static gate is never recorded as runtime proof. Likewise, digest pinning
proves reproducibility, not that an old software branch is still supported or
free of vulnerabilities.

## CI-safe patch rules learned by the project

1. Start each increment from a known-green repository snapshot.
2. Do not combine a topology redesign, toolchain upgrade, and assurance-test
   semantic change in one patch.
3. Generated files must only change through their canonical renderer/source.
4. Run `git diff --check` plus every deterministic source/unit gate after each
   increment.
5. A new live assertion needs a fixture or documented precondition that can make
   the assertion true; otherwise it is not ready to become a blocking test.
6. Keep PR CI deterministic. Network-dependent registry verification and
   vulnerability database refreshes belong to explicit release/audit commands,
   not to a gate whose outcome can change because a registry is unavailable.
7. Multi-architecture images are pinned to the top-level image index/manifest
   list digest, never to an amd64 or arm64 child manifest.
8. Security lifecycle upgrades are separate from reproducibility pinning. A
   digest can make an unsupported version immutable; it does not make that
   version supported.

## Patch / increment history

| Patch artifact | Increment(s) | Disposition |
|---|---|---|
| `enterprise-netsec-iac-audit-hardening.patch` | INC-010 | Broad first attempt; partially retained, with regressions documented below. |
| `enterprise-netsec-iac-regression-hotfix.patch` | INC-011 | Restored the known-green baseline after INC-010 regressions. |
| `enterprise-netsec-iac-ci-safe-hardening.patch` | INC-020 | CI-contract/static-security guard increment; retained. |
| `enterprise-netsec-iac-v8-assurance-maturity.patch` | INC-030 | Assurance, evidence, Path C, NetworkPolicy/probe and developer-workflow maturity increment. |
| `enterprise-netsec-iac-v8-supply-chain-ledger.patch` | INC-040 through INC-042 | Current supply-chain lock, platform verification, immutable refs and implementation ledger. |

The patch filename is not the source of truth after merge. The increment and
BUG/REG identifiers below are the stable historical references.

---

## INC-000 — Baseline audit and gap inventory

**Status:** historical baseline / findings inventory.

### Findings

- GitHub CI did not execute `scripts/check_path_b_intent.py` even though the
  local Makefile did, allowing CI/local coverage drift.
- Path A `TIME-01` only proved that `chronyc tracking` executed, not that time
  was synchronized.
- Path A `VPN-01` treated the presence of a WireGuard interface as positive
  evidence without proving a peer handshake.
- Evidence artifacts could be absent when a mapped pytest failed before calling
  the explicit `evidence(...)` helper.
- Kubernetes Kustomize inputs referenced files outside the Kustomize root.
- Kubernetes Suricata EVE logs were isolated in a pod-local `emptyDir` and were
  not consumed by Wazuh.
- Kubernetes had no NetworkPolicy enforcement and no workload health probes.
- Container/tool image tags and several CI dependencies were mutable.
- There was no macOS-oriented deterministic developer check target.

### Security interpretation

The network/IaC foundation was already strong, but several controls had an
**assurance gap**: configuration existence was being proved more strongly than
runtime security state. Path C also lagged Path A/B in security-plane parity.

---

## INC-010 — First broad audit-hardening patch

**Status:** partially retained; contained historical regressions.

### Implementation attempted

- Isolate untrusted endpoints from the shared out-of-band management network.
- Narrow syslog-relay PKI mounts so the relay did not receive the CA private key
  or unrelated client private keys.
- Make Authentik PostgreSQL/Redis wiring explicit.
- Repair Kubernetes generated asset layout and add CI coverage.
- Strengthen TIME/VPN live assertions.

### Regressions discovered

#### REG-010-A — `network-mode: none` broke early Path A provisioning

`pc1`/`dmz-web` were moved to `network-mode: none` before their data-plane
networking existed. Their startup path still needed network/DNS for package
installation, so the security architecture change could break containerlab
bootstrap.

**Root cause:** the patch removed the management/bootstrap network without
redesigning the provisioning channel first.

#### REG-010-B — Terraform changes were not format-safe

The broad patch touched Terraform Path B while the audit sandbox could not run
`terraform fmt`. The repository CI *could* run `terraform fmt -check`, creating
an avoidable CI regression risk.

**Root cause:** a patch included changes whose canonical formatter was not
available in the validation environment.

#### REG-010-C — Live TIME/VPN assertions landed before their fixture contract

Stronger assertions were security-correct, but the first patch did not first
establish/document the clock-sync and recent-WireGuard-handshake preconditions
needed by live validation.

**Lesson:** a stronger assertion is not CI-safe until its positive test state is
reachable and documented.

### Retained low-risk fixes

The PKI-mount narrowing, explicit Authentik service wiring, K8s generated asset
layout, and deterministic CI coverage improvements were retained where they did
not alter the fabric bootstrap contract.

---

## INC-011 — Regression hotfix / green-baseline restoration

**Status:** completed.

### Implementation

- Reverted the premature endpoint OOB redesign.
- Restored Terraform files to the known-green pre-change form.
- Reverted live TIME/VPN assertions until they could be introduced with a clear
  runtime precondition.
- Preserved low-risk source/security improvements from INC-010.

### Result

The repository returned to a known-green static/unit baseline. This increment
established the project rule that security findings and deployable fixes are
not the same thing: architecture changes are only merged after their bootstrap
and validation path is proven.

---

## INC-020 — CI-contract and static-security hardening

**Status:** completed.

### Implementation

- Added `scripts/check_ci_contract.py` to detect drift between expected security
  checks and GitHub Actions.
- Added Python bytecode compilation and Bash syntax validation to deterministic
  checks.
- Added Kubernetes static guards for dangerous privilege expansion, including
  unreviewed `hostPID`, `hostIPC`, `hostPath`, host-network use, capabilities,
  privileged containers, and insecure Traefik dashboard exposure.
- Intentionally did **not** change live topology, Terraform behavior, or live
  control semantics in this increment.

### Negative-regression validation

The checker was tested by deliberately removing a required CI command and by
injecting a prohibited Kubernetes privilege. Each mutation caused the expected
failure.

---

## INC-030 — Assurance and Path C maturity increment

**Status:** implemented in the current baseline before INC-040.

### TIME-01 Path A parity

Path A now requires more than a successful `chronyc` command:

- an active/selected source;
- `Leap status: Normal`;
- valid positive stratum;
- absolute clock offset below the configured 1-second assurance threshold.

This aligns the meaning of TIME-01 more closely with Path B.

### VPN-01 Path A parity

Path A now requires:

- a configured WireGuard peer; and
- a real recent handshake (10-minute assurance window).

A running `wg0` interface without a connected peer no longer satisfies VPN-01.
The README documents the live peer precondition before `make validate`/`audit`.

### Evidence engine fail-closed behavior

Mapped control tests now emit a failure/error artifact even when the test exits
before an explicit `evidence(...)` call. This closes the audit-trail hole where
pytest could be red while the report only saw missing evidence.

Evidence unit coverage expanded from **7 to 20 cases**, including:

- dirty-source rejection;
- source-tree, topology and test-suite hash mismatch;
- duplicate artifacts;
- malformed/reversed timestamps;
- wrong Path A/Path B provenance;
- early assertion and early exception;
- PASS attempts without explicit evidence.

### Path C Suricata → Wazuh

Suricata retains its pod-local EVE log volume, while a Wazuh agent sidecar in
that pod reads `eve.json` and sends events over the Wazuh secure agent channel.
The manager service is aligned to TCP/1514 for that agent transport. This avoids
pretending that a Kubernetes `emptyDir` is shared across pods.

### Kubernetes network policy

Path C gained default-deny ingress/egress policy plus explicit communication
rules for the required application graph (DNS, Traefik/Auth, identity backing
stores, Wazuh components, Suricata agent transport, and reviewed WireGuard
exceptions).

### Kubernetes health semantics

Health/startup/readiness coverage was added for relevant Path C services so a
`Running` pod is not automatically treated as a ready service.

### Supply-chain/developer groundwork

- GitHub Actions changed from mutable major tags to full commit SHAs.
- Terraform CLI version was pinned in CI.
- Batfish CI service was pinned by digest.
- Ansible collection constraints were made exact.
- `make dev-check` was added as a macOS-friendly deterministic validation path.
- `make supply-chain-scan` was added for explicit Trivy/SBOM auditing.

---

## INC-040 — Multi-architecture image lock and immutable runtime references

**Status:** completed baseline increment.

### Problem

The repository still contained mutable image tags across runtime, Kubernetes,
Dockerfile bases, CI helpers and developer tooling. On a project that supports
both Linux/amd64 and Apple-silicon Docker, blindly pinning an architecture child
manifest would make a tag immutable **but break the other architecture**.

### Design

Added `supply-chain/images.lock.yml` as the human-reviewable image inventory.
Each external component records:

- mutable intent/tag;
- approved immutable reference when resolved;
- scope;
- required platforms;
- verification level/source;
- explicit reason when resolution is deferred.

Runtime/developer multi-arch entries require `linux/amd64` and `linux/arm64`.
The approved pin is the **top-level OCI image-index / Docker manifest-list
digest**.

### Images pinned in source

The increment pins the following verified/inherited components without changing
their selected software release:

- Debian 12 slim Dockerfile base;
- Alpine 3.20 containerlab helper;
- Wazuh manager 4.14.6;
- Wazuh indexer 4.14.6;
- Wazuh dashboard 4.14.6;
- Wazuh agent 4.14.6;
- Wazuh cert generator 0.0.4;
- Traefik v3.1;
- PostgreSQL 16 Alpine;
- Redis 7 Alpine;
- nginx-unprivileged stable Alpine as resolved at the audit date;
- existing WireGuard immutable pin;
- existing Batfish immutable CI pin;
- Gitleaks v8.24.3.

The lock intentionally does **not** claim that an immutable legacy tag is a
supported version. Traefik/Auth/Wazuh/Suricata lifecycle upgrades remain
separate migration increments.

### Deferred image resolution at the INC-040 boundary

No digest was guessed when the top-level historical index could not be
independently resolved. The following were explicit `deferred` entries at this
increment boundary:

- `jasonish/suricata:8.0.1`;
- `ghcr.io/goauthentik/server:2024.8`;
- `quay.io/frrouting/frr:9.1.0`;
- `wbitt/network-multitool:sha-2e883bc`;
- `hashicorp/terraform:1.15.9` developer container.

Those tags were therefore recorded as known debt rather than invisible mutable
dependencies. INC-041/INC-042 later close all but Suricata.
`make verify-image-platforms` resolves/verifies deferred entries against a live
registry and fails in strict mode until the resulting index digest is reviewed
and committed.

### Offline enforcement

Added `scripts/check_image_lock.py` and wired it into:

- `make lint`;
- `make dev-check`;
- GitHub Actions static checks;
- `scripts/check_ci_contract.py`.

The checker rejects:

- an external structured image not represented in the lock;
- a verified lock entry whose immutable ref is no longer used;
- reintroduction of a mutable tag for a verified entry;
- a deferred entry that silently disappears without a lock update;
- runtime/developer entries without both required architectures;
- duplicate logical repository entries.

This check is intentionally offline so registry outages/rate limits cannot make
PR CI nondeterministic.

### Online platform/digest verifier

Added `scripts/verify_image_platforms.py`, backed by
`docker buildx imagetools inspect`.

For verified entries it checks that:

1. the mutable intent tag still resolves to the committed top-level digest;
2. all required platforms are present;
3. a multi-platform runtime ref is an image index, not a child manifest.

For deferred entries it prints the exact candidate `pinned_ref`; `--strict`
keeps the command red until those candidates are reviewed/committed.

The verifier is deliberately an explicit release/developer action rather than a
PR gate because it depends on external registries.

### Lifecycle debt deliberately not hidden by this increment

- Authentik `2024.8` requires a supported-version migration; resolving its old
  digest alone is not a security upgrade.
- Traefik `v3.1` is now reproducibly pinned, but version-lifecycle work remains
  a separate upgrade.
- Wazuh 4.14.6 remains version-pinned in this increment; a later patch can move
  the whole Wazuh component set together after integration validation.
- Suricata 8.0.1 digest resolution and release upgrade are distinct actions.

### Validation boundary for INC-040

- Lock/source consistency is **static verified**.
- Recorded approved index digests are **registry-metadata verified** where the
  lock says so.
- Registry verification via `docker buildx` must be run on a networked release
  host; it is not falsely recorded as runtime-verified when the audit sandbox
  cannot reach registries.

---

## INC-041 — Registry resolution expansion and platform-class correction

**Status:** completed increment.

### Bugs / assurance gaps closed

#### BUG-041-A — Known multi-platform tags remained mutable after INC-040

INC-040 intentionally deferred `network-multitool` and the Terraform developer
image because the audit environment could not prove their top-level index
digests. Registry metadata later exposed those exact indexes. Leaving the tags
mutable after that evidence existed would preserve avoidable supply-chain drift.

#### BUG-041-B — Containerlab platform policy overclaimed FRR portability

The first lock policy treated every Containerlab image as if it had to be
portable across both `linux/amd64` and `linux/arm64`. FRR 9.1.0 does not satisfy
that model: the official FRR release link resolves to a historical Quay manifest
and corroborating metadata identifies it as `linux/amd64`. Pretending it was a
multi-platform index would be a false assurance claim.

#### BUG-041-C — Single-manifest online verification could miss architecture

The first online verifier tolerated a missing `Platform:` line for a
single-manifest image. That was appropriate for compatibility with older Buildx
output, but it could not prove that a pinned single manifest was actually the
platform required by the lock.

### Implementation

1. `wbitt/network-multitool:sha-2e883bc` is now pinned to the Docker Hub
   top-level multi-platform index:

   `wbitt/network-multitool@sha256:db2810fe2c8d36db074eab5d98fbf861c8ed55e0786d648d3477b3de9135632e`

2. `hashicorp/terraform:1.15.9` is now pinned to the Docker Hub top-level
   multi-platform index:

   `hashicorp/terraform@sha256:fd5debae63188975d6febc6aa5bd1a982a588f55e4a4ddb7de28be923f250456`

3. `quay.io/frrouting/frr:9.1.0` is pinned to the historical FRR release
   manifest:

   `quay.io/frrouting/frr@sha256:f310c2ebb3827fa03b9674ee05e70a7d5eef2123bcc3b475eb2ef14dafcb52b4`

   This is recorded as a **single-platform `linux/amd64` manifest**, not as a
   multi-platform index. Consequently, live Path A FRR execution is explicitly
   amd64-only at this release. macOS/Apple-silicon remains supported for the
   deterministic `make dev-check` workflow, not for this live FRR container.

4. The image-lock policy now distinguishes:

   - portable runtime/developer images: `linux/amd64` + `linux/arm64`;
   - Path A Containerlab minimum: `linux/amd64`;
   - CI-only images: `linux/amd64`.

5. `scripts/check_image_lock.py` now enforces those platform classes and rejects
   inconsistent metadata such as a `single-platform-manifest` with multiple
   required platforms or a `multi-platform-index` with fewer than two.

6. `scripts/verify_image_platforms.py` now uses Buildx `.Image` configuration
   metadata for a single-manifest ref when the normal output has no platform
   row. Missing architecture is no longer silently accepted.

7. Canonical renderer source was changed before generated Containerlab output,
   preserving `render_fabric.py --check` as the drift guard. The Terraform
   developer image default was updated in `scripts/dev_check.sh`.

### Remaining deferred refs at the end of INC-041

Two historical application refs were still deferred at this increment boundary:

- `jasonish/suricata:8.0.1`;
- `ghcr.io/goauthentik/server:2024.8`.

INC-042 later closes the Authentik reproducibility gap using first-party package
metadata. Suricata remains deferred until its exact historical top-level index
digest is independently resolved; no digest is guessed in source.

### Validation / evidence level

- Lock/source consistency: **static verified**.
- network-multitool index: **registry-metadata verified**.
- Terraform 1.15.9 index: **registry-metadata verified**.
- FRR 9.1.0 digest/platform: **official-release-link + corroborating platform
  metadata**, with live pull/runtime verification still required on Path A.
- Full `docker buildx imagetools inspect` verification: **not executed in this
  sandbox** because Docker/registry access is unavailable; the verifier remains
  the release-host proof.

### Regression policy for this increment

Do not “fix” FRR by copying an arm64 child from an unrelated/newer tag or by
labeling the 9.1.0 manifest multi-architecture. A future arm64-capable Path A
should be a deliberate FRR/containerlab migration with routing regression tests.
Likewise, do not replace deferred tags with unverified digest strings merely
to make the lock count reach zero.

---

## INC-042 — Authentik historical multi-arch pin closure

**Status:** current increment / registry-metadata verified.

### Bugs / assurance gaps closed

#### BUG-042-A — Authentik 2024.8 was still a mutable portable runtime ref

Compose and Kubernetes still selected `ghcr.io/goauthentik/server:2024.8`. A
registry-side retag could therefore change both server and worker artifacts for
the same repository commit. This was a reproducibility gap even though the
separate, larger lifecycle problem is that 2024.8 is no longer a supported
branch.

#### BUG-042-B — Image-lock diagnostics contained a duplicated deferred-ref error

The offline image-lock checker had duplicated the same `deferred intent_ref is
no longer used` diagnostic in one failure branch during earlier iteration. It
did not create a false PASS, but duplicated diagnostics make release/audit
triage noisier and were removed while touching the lock code.

### Registry resolution evidence

GitHub Packages first-party metadata for Authentik server version `2024.8.6`
shows:

- top-level digest:
  `sha256:f2e5c18e922b40bd0cc3b5a2e9ac96ffb9f4109282bbc92f43c9d4e8f232c381`;
- `linux/amd64` child:
  `sha256:dae34433600130715b3d00b80f1f6e32896d2e52182b79a3471e10f15ff0a601`;
- `linux/arm64` child:
  `sha256:61b664f574255a04fac81dc4a88d065979aaabfd4f7e9b660cfaf38b6628698f`;
- both `2024.8.6` and `2024.8` are tags on that same package version.

The committed runtime ref therefore uses the **top-level digest**, not either
architecture child:

`ghcr.io/goauthentik/server@sha256:f2e5c18e922b40bd0cc3b5a2e9ac96ffb9f4109282bbc92f43c9d4e8f232c381`

### Implementation

1. Replaced both Compose Authentik server/worker refs with the immutable index.
2. Replaced both Kubernetes Authentik server/worker refs with the same index.
3. Changed the lock entry from `deferred` to `verified`, declared
   `kind: multi-platform-index`, and retained required `linux/amd64` +
   `linux/arm64` platforms.
4. Preserved `intent_ref: ghcr.io/goauthentik/server:2024.8` in the lock as the
   human-readable release intent while preventing that mutable tag from being
   used by audited runtime source.
5. Kept the branch-lifecycle finding open: immutability does not make 2024.8 a
   supported release.

### Validation / evidence level

- Authentik top-level digest and amd64/arm64 children: **first-party
  registry/package metadata verified**.
- Runtime source/lock consistency: **static verified** by
  `scripts/check_image_lock.py`.
- Live pull/start on both architectures: **not claimed** in this sandbox; use
  `make verify-image-platforms` on a networked Docker/Buildx host.

### Remaining unresolved image

`jasonish/suricata:8.0.1` remains the sole deferred image. Upstream metadata
confirms the normal tag model is multi-platform and historical architecture
variants exist, but this audit has not obtained an independently trustworthy
top-level 8.0.1 index digest. The project deliberately keeps the mutable ref
visible as debt rather than inventing a digest.

### Regression policy for this increment

- Do not replace the Authentik top-level index digest with the amd64 or arm64
  child manifest.
- Do not describe this increment as an Authentik security upgrade.
- Do not suppress the last Suricata deferred state to make the lock report
  `0 deferred`; close it only with registry proof or a separately tested
  Suricata lifecycle migration.

---

## Follow-up backlog

### INC-043 — Close Suricata historical index pin

Resolve the exact `jasonish/suricata:8.0.1` top-level index digest from a
networked Docker/registry host, verify both amd64/arm64 children, then pin the
index consistently in Compose/Kubernetes and update the lock. If a current
Suricata release is adopted instead, treat that as an INC-050 lifecycle change
with IDS/Wazuh integration regression tests rather than a digest-only edit.

### INC-050 — Security lifecycle upgrades

Upgrade unsupported/stale application branches as controlled migrations rather
than mixing them into digest-only hardening. At minimum, Authentik and Traefik
must be treated as lifecycle debt. Wazuh and Suricata should be evaluated as
coordinated component upgrades with integration tests.

### INC-060 — Architecture-level OOB isolation redesign

The earlier shared-management-plane finding remains an architecture concern.
Do not repeat REG-010-A. Introduce a provisioning/console strategy first, then
remove untrusted endpoint adjacency only after Path A/Path B bootstrap and live
negative-connectivity tests pass.
