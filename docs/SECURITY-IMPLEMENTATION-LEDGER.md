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

## Historical follow-up backlog (superseded where closed below)

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

---

## INC-050 — Path A control semantics and declarative ZTNA

**Status:** source/static verified; live Path A revalidation required.

### BUG-050-A — TIME-01 observed a tracking-only container clock

`server1` previously ran `chronyd -x`. Chrony could authenticate and track an
NTS source, but `-x` deliberately does not discipline the system clock. Docker
containers consume the Linux host kernel clock, so the old implementation did
not prove the clock used for security-log timestamps was NTS-disciplined.

**Implementation:** removed container chronyd, added
`host/chrony-cxyz.sources.example` and `scripts/host_time_status.py`, and moved
TIME-01 evidence to the host trust boundary. The verifier requires an active
NTS-authenticated source, `Leap status: Normal`, valid stratum and <1 second
system offset. No `CAP_SYS_TIME` is granted to a container.

### BUG-050-B — VPN-01 proved a handshake but not usable secure administration

A recent WireGuard handshake alone does not prove AllowedIPs, forwarding,
return routing, firewall policy and management reachability.

**Implementation:** `vpn-probe` is a real ignored peer fixture. The WireGuard
server is multi-homed only to edge + DC and mounts
`wireguard-dc-route.sh`, which installs explicit peer-CIDR -> DC-CIDR forwarding
and return-state/NAT rules. The live test requires a recent handshake, a `wg0`
route and TCP/22 success to the approved DC target while the WAN path is denied.

### BUG-050-C — ZTNA had manual identity state and ambiguous DMZ naming

The gateway depended on Authentik provider/application/outpost state that was
not source-controlled, and the Compose demo backend reused the `dmz-web` name
of the canonical routed DMZ asset even though they were separate paths.

**Implementation:** added an Authentik Blueprint for Proxy Provider,
Application and Embedded Outpost mapping; renamed the private backend to
`ztna-demo-app`; generated a lab CA/leaf pair; and changed ZTNA-01 to verify
trusted TLS with `--cacert` instead of bypassing certificate validation. The
architecture now states explicitly that SEG-02 and ZTNA-01 exercise different
assets.

### Validation boundary

All source/render/security/evidence checks can validate the contract, but this
increment is not recorded as runtime PASS until `make audit` succeeds on the
Linux Path A host. TIME-01 specifically requires the host chrony configuration;
VPN-01 specifically requires the generated peer fixture.

---

## INC-051 — Path A endpoint/OOB and hardening-coverage closure

**Status:** source/static verified; live connectivity revalidation required.

### BUG-051-A — untrusted endpoint bootstrap management could bypass routed controls

The first attempted fix (`network-mode:none`) broke package provisioning. The
redesign keeps Docker management only during bootstrap. `pc1` and the canonical
`dmz-web` receive their data-plane address/default route first, then
`scripts/isolate_path_a_management.py` physically disconnects those containers
from `cxyz_mgmt`. An administratively-DOWN interface is not treated as a
security boundary against a compromised root user. `pc4` remains the reviewed
administration endpoint. SEG-01/02 now assert both routed firewall behavior and
physical absence of the alternate management attachment.

### BUG-051-B — HRD wording exceeded node coverage

HRD-02 said Telnet was disabled "everywhere" but the live test omitted endpoint
nodes; HRD-01 also inspected file content rather than effective sshd state.

**Implementation:** introduced one `MANAGED_NODES` set including `pc1`, `pc4`
and `dmz-web`, added the canonical DMZ endpoint to the Ansible inventory, made
hardening tolerate endpoints without sshd, and use `sshd -T` for effective SSH
configuration where applicable.

**Regression rule:** do not remove bootstrap networking before package/data-
plane configuration. Any future OOB redesign must preserve the explicit live
negative connectivity proof.

---

## INC-052 — Path C trust, microsegmentation and live checkpoint

**Status:** source/static verified; runtime UNVERIFIED until `make k8s-smoke`.

### BUG-052-A — Public Traefik previously inherited Kubernetes API/Secret access

Earlier Path C revisions used the Kubernetes CRD provider, which required
Traefik to watch namespace resources and created CNI-dependent API egress
exceptions. That made a public reverse-proxy compromise materially more useful
because the pod could read namespace Secrets.

**Current implementation:** Traefik uses only the file provider,
`automountServiceAccountToken: false`, an ignored runtime ConfigMap for routes,
and a dedicated ZTNA TLS Secret mounted by kubelet. It has no Role/RoleBinding,
no Kubernetes provider, and no Kubernetes API NetworkPolicy exception.

### BUG-052-B — Wazuh service identity differed between Compose and Kubernetes

Using `wazuh.indexer` in Compose and `wazuh-indexer` in Kubernetes made strict
TLS hostname verification impossible with one reviewed PKI. Compose and Path C
now use the same `wazuh-indexer` service/DNS identity. `make wazuh-config` runs a
SAN/chain/expiry checker and refuses stale PKI rather than lowering hostname
verification.

### BUG-052-C — Path C trust/RBAC/hardening was incomplete

Wazuh certificate/API/Filebeat trust is source-wired from the local PKI; agent
enrollment now requires a generated registration password. Public Traefik has
no Kubernetes API token/RBAC. The Dashboard accepts no ordinary pod-network
ingress, and privileged network workloads drop all capabilities before adding
only reviewed capabilities. All containers explicitly disable privilege
escalation and use RuntimeDefault seccomp. Vendor-specific `runAsNonRoot`/
read-only-root changes remain subject to runtime proof instead of blanket
enforcement.

### Runtime checkpoint

`scripts/k8s_smoke.sh` waits for all core deployments/statefulsets/daemonsets,
requires static/runtime NetworkPolicies, and exercises Traefik's file-provider
ZTNA/TLS path through a temporary local port-forward. It iterates every
Suricata DaemonSet pod, verifies the stable node-bound Wazuh agent identity,
and injects a unique EVE marker per sensor that must appear in Wazuh manager
alerts. This checkpoint is deliberately outside PR CI because a real CNI/
cluster is required.

---

## INC-053 — Supply-chain/lifecycle and long-term operational reproducibility

**Status:** static/registry reviewed; selected lifecycle work remains explicit.

### Closed items

- Suricata moved from the sole mutable/deferred 8.0.1 tag to an immutable
  multi-platform 8.0.6 index; image inventory is now 18/18 pinned after the
  removed Authentik Redis dependency.
- Wazuh manager/indexer/dashboard/agent moved together to 4.14.7 immutable
  refs so Path C/Compose versions do not drift.
- Traefik moved from the obsolete 3.1 line to immutable 3.7.11 and the matching
  CRD/RBAC design.
- GitHub runner is `ubuntu-24.04`; direct CI Python dependencies are exact in
  `requirements-ci.txt` / `requirements-batfish.txt`; local Debian images use a
  fixed snapshot and CI builds them.
- Both libvirt Terraform modules use the reviewed `dmacvicar/libvirt` 0.8.3
  provider and commit verified cross-platform lockfiles. `make terraform-lock`
  refreshes signed hashes on a networked Terraform host; the 0.9 provider is a
  schema rewrite and remains a separate migration.
- Leaf certificates renew inside a 30-day window. CA expiry blocks inside 90
  days and `docs/PKI-ROTATION.md` defines a dual-trust staged rotation instead
  of unsafe silent CA replacement.

### BUG-053-A — YAML syntax checking treated Authentik tags as invalid

Authentik Blueprints use application-specific tags such as `!Env` and `!Find`.
Generic `yaml.safe_load` rejects those tags even when the YAML is syntactically
valid. `scripts/check_yaml_syntax.py` uses PyYAML's composition layer to verify
syntax/indentation while preserving unknown tags as nodes; CI and `make lint`
run this gate in addition to yamllint.

### Remaining P1 lifecycle debt — legacy Authentik databases

Fresh deployments use the reviewed Authentik 2026.8 image and a separate
`authentik_db_2026` volume. Existing 2024.8 databases still require sequential
major-release migration. `make security` now fails closed when it detects the
legacy `authentik_db` volume, and points operators to
`docs/AUTHENTIK-UPGRADE.md`; the legacy database must never be direct-jumped.

---

## INC-054 — Model coverage and audit-trail closure

**Status:** deterministic source/unit verified; model scope explicitly bounded.

### BUG-054-A — Batfish was only a three-test smoke gate

The generated snapshot previously proved DNS allow, RADIUS deny and parser
health. The policy matrix now also proves NTP/123 allow and denies user-to-DC
SNMP/161, SSH/22, HTTP/80 and HTTPS/443. This remains a campus-to-DC model test;
it does not claim Internet/DMZ properties that are not represented in the
snapshot.

### BUG-054-B — evidence fallback ignored pytest setup/teardown failures

Mapped controls now use one-artifact semantics across setup/call/teardown.
Early setup errors and teardown failures become explicit ERROR/FAIL evidence
instead of falling through to UNVERIFIED; the evidence unit suite covers those
phases. A successful mapped test without explicit evidence is also not allowed
to become PASS.

### Path B runtime status

Path B source/design readiness remains separate from runtime evidence. The
12-node VyOS first-boot/apply/Day-2/HA audit has not been observed in this
sandbox and must be reported as **UNVERIFIED**, not converted to a numerical
runtime-confidence score. Existing `vm-health`, `vm-idempotency` and `vm-audit`
targets remain the required live checkpoint.


---

## INC-055 — OOB, HA, identity and runtime-config assurance closure

**Status:** source/static/unit verified; Path A/B/C live checkpoints remain required.

### BUG-055-A — HA-01 failed the wrong VLAN

The Path A HA probe originates from PC1/VLAN10, but the failure injection shut
`dist1 eth2` (VLAN40). The test could therefore report sub-five-second recovery
without disrupting PC1's active gateway at all. The injector now shuts the
VLAN10-facing interface, observes DIST2 become MASTER during the failure, and
keeps the failure long enough to exercise VRRP master-down behavior before
restoration.

### BUG-055-B — OOB management was still a routed destination

Removing endpoint management NICs alone does not stop a forwarding router with
a connected `10.1.1.0/24` interface from routing untrusted data-plane traffic
into the OOB LAN. All Path B VyOS devices now drop forwarded traffic whose
destination is the management subnet, and the live audit requires PC1 and the
DMZ endpoint to fail even a probe to the management gateway. Path A untrusted
endpoints are physically detached from the Docker management network after
bootstrap rather than relying on `eth0 DOWN`.

### BUG-055-C — Wazuh identity/enrollment trust was incomplete

Compose and Kubernetes now share one hostname-verified `wazuh-indexer` TLS
identity. `check_wazuh_pki.py` rejects stale SAN/chain/expiry state, Dashboard
verification is `full`, and agent enrollment requires a generated password via
`authd.pass`. This avoids both CA-only server verification and network-location-
only agent enrollment.

### BUG-055-D — Public Traefik could read high-value namespace Secrets

Path C Traefik previously used Kubernetes CRDs and a Role that included Secrets.
The public proxy now uses a file provider, has no service-account token/RBAC,
and receives only a runtime routing ConfigMap plus the dedicated ZTNA TLS
Secret mounted by kubelet. Domain-specific routes are rendered from `.env`, so
custom `ORG_DOMAIN` no longer drifts from checked-in manifests.

### BUG-055-E — configurable WireGuard values were only partially honored

`WG_SERVER_PORT`, endpoint and peer-count values are now consumed by Compose,
the VPN probe and Path C runtime configuration. Static tests prevent a return
to literal port 51820 where the operator contract is configurable.

### BUG-055-F — DET-02 and Path C sensor smoke sampled one identity

Path A DET-02 now emits a unique marker from every audited logging identity and
requires each marker at both relay and Wazuh. Path C uses stable
`suricata-<nodeName>` Wazuh identities and smoke-tests every DaemonSet sensor
with a unique EVE marker.

### BUG-055-G — Path B Linux first boot depended on Internet before routing auth

Path B intentionally starts BGP/OSPF with mismatched fail-closed bootstrap
authentication. Cloud-init therefore no longer performs `apt update/install`
before routing reconciliation. Day-2 installs packages after VyOS secrets are
reconciled. The generated Linux inventory explicitly enables passwordless sudo
through `ansible_become`, matching the cloud-init user contract; otherwise all
root-owned roles/package tasks would fail.

### BUG-055-H — evidence was not bound to behavior-changing deployment knobs

Evidence schema v2 adds a sanitized deployment-configuration digest covering
domain, WireGuard listener/endpoint/peer count, NTP upstreams and Path B public-
key location. Reports reject evidence captured against a different resolved
non-secret deployment configuration while continuing to exclude credentials.

### Remaining validation boundary

The source checks do not convert these controls into runtime PASS. Path A still
requires `make audit`; Path C requires `make k8s-smoke`; and Path B requires the
12-node `vm-configure`/idempotency/`vm-audit` sequence. Wazuh PKI identity
changes require the explicit rotation/reissue runbook instead of a verification
bypass.

---

## INC-070 — SOC/AI closed-loop completion (Paths A, B and C)

**Status:** source/static verified and covered by offline tests; **no runtime evidence.** Every SOC control is
`UNVERIFIED` until `make soc-ai-validate` / `make vm-audit` / `make k8s-smoke` run on lab hosts.

### Assurance gaps closed

- **BUG-070-A — nothing ran the loop.** Added the continuous feature worker, ES-pull enrichment outbox, mTLS inference
  API (Isolation Forest and LSTM), decision runner and orchestrator service with durable journal, recovery, TTL sweep and
  audit export. *Static + offline tested.*
- **BUG-070-B — externally supplied evaluation metrics could justify promotion.** Evaluation is now bound to the exact
  artifact, dataset, labels and vectors (`evaluation-binding-v1`); thresholds are selected on validation only; promotion
  re-derives every claim against a reviewed policy; a five-detector comparison can be carried into the registry.
- **BUG-070-C — shared-key command authentication.** Replaced by Ed25519 (decision runner signs; orchestrator verifies).
- **BUG-070-D — revert could remove a pre-existing block.** The ownership ledger records intent before the side effect and
  removes an entry only for the last owner of an address the response plane added.
- **BUG-070-E — containment had no firewall-side expiry.** nftables elements carry a timeout; VyOS relies on the TTL sweep
  and Day-2 refuses to persist an active containment.
- **BUG-070-F — containment sets and agent surface.** `soc_blocklist` sets with early drops in the nftables and VyOS configs;
  a three-operation mTLS enforcement agent on the management network only; Wazuh isolation verified by a FIM marker.
- **BUG-070-G — Kubernetes had no SOC workloads.** Path C gained Elasticsearch, Kibana, Logstash sidecars and one Deployment
  per service with per-workload Secrets and NetworkPolicies; manifests are validated strictly against the Kubernetes 1.30
  schemas in CI.
- **BUG-070-H — planned controls had no verifier.** Fourteen controls became evidence-backed with a shared live verifier
  library, an in-process lab that proves the verifiers' logic, and profile scoping (`applicable_profiles`).

### Limits recorded, not hidden

- RESP-04 and the network-fidelity gate (OPNsense HA, Core SPAN, VLAN 30/40/50/99) are **not implemented**; the OPNsense
  backend is contract-tested only.
- No model was trained on real telemetry; synthetic metrics are unit-test artifacts.
- Docker image builds, the VyOS/Wazuh API contracts, Logstash on real input and the Kubernetes runtime were not exercised.
- `test_ai_cannot_bypass_decision_orchestrator_boundary` used to fail when a macOS `.DS_Store` existed under `ai/` (it read every
  file as UTF-8 text). It now skips that one OS-metadata name and decodes other files leniently; no other file is exempt, and a
  planted forbidden token is still caught.
- Live scenarios use documentation-range addresses and tagged fixtures; the injected anomaly stands in for model output.

---

## INC-071 — One-command Linux runner, network explorer, strict-TLS PKI fix

**Status:** source/static verified and offline-tested; the Linux, Docker and containerlab stages of the runner are **unverified** until
run on a Linux host.

- **BUG-071-A — the SOC CAs lacked `keyUsage`.** `scripts/gen_soc_certs.sh` produced CAs without `keyUsage keyCertSign`, which strict X.509
  verification rejects (`openssl verify -x509_strict`: "CA cert does not include key usage extension"; the default of Python >= 3.13).
  Found by the first real run of the new runner in a fresh Python 3.13 environment (two mutual-TLS tests failed). The services' Debian image
  ships Python 3.11, so nothing was broken at runtime, but any host-side or newer-Python client would have been. Fixed for the three CAs and
  all leaves (critical `basicConstraints`/`keyUsage`, SKI/AKI); an existing legacy CA is detected and rotated (with every certificate it signed)
  on the next `make secrets`, with an explicit message to restart the SOC services. The test PKI got the same extensions.
- **BUG-071-B — wrong nftables table for fw-dmz in the live verifier.** `DockerLab.blocklists()` queried `inet cxyz` on both firewalls; fw-dmz's
  set lives in `inet dmz`. The live RESP controls would have ended in `ERROR`. Fixed and tied to the shipped configs by a test.
- **BUG-071-C — `.env.example` inline comments.** `env_exec.parse_dotenv` kept `# ...` comments as part of the value
  (`SOC_PATH='path-a   # ...'`, `SOC_MODE='# empty ...'`), unlike Docker Compose. It now strips comments exactly as Compose does, and the
  example keeps comments on their own lines.
- **New:** `scripts/try-on-linux.sh` / `scripts/try_linux.py` (install, build, run, test with stage-level failure analysis),
  `scripts/netviz.py` (read-only GNS3-style explorer derived from the sources of truth), `scripts/demo_registry.py` (DEMO approved model from
  synthetic data), `docs/LINUX-QUICKSTART.md`.

---

## INC-072 — DMZ deception lab (vulnerable web application + honeypot)

**Status:** source/static verified and offline-tested; **never run** (no Docker daemon or Linux host was available).

- Added compose profile `dmzlab`: OWASP Juice Shop (`dmz-vuln`) and Cowrie (`dmz-honeypot`), both pinned by digest in `supply-chain/images.lock.yml`,
  joined to the network namespace of the containerlab `dmz-web` node (no network of their own, no published port, no capabilities, honeypot read-only).
  This keeps the single-source intent and Path B untouched; the DMZ stays one /29 behind fw-dmz.
- `clab/configs/fw-dmz.nft`: two new rules open only tcp/3000 and tcp/2222-2223 to the web host, for NEW connections, counted and logged
  (`CXYZ-DMZLAB-VULN/-HONEYPOT`), placed after the pivot deny and before the egress accept; a test pins that order and that nothing else opens.
- Logstash: pipeline `45-cowrie.conf` reads the honeypot JSON log from a read-only volume; the ECS branch maps it to dataset `cowrie.honeypot`
  and drops attacker-supplied passwords before indexing.
- `make dmzlab-up|down|status|attack`, the runner stages `dmzlab-up`/`dmzlab-verify` (reachable through fw-dmz, counted, logged, unable to pivot) and
  the network explorer (shared-namespace links, ports, IP plan, SOC flow) cover it.
- Open: a honeypot hit is not yet an independent signal for the decision engine; Path B has no equivalent; the shared-namespace design must be restarted
  after `make net`; Cowrie's environment-variable options and read-only root filesystem are unverified against the real image.

---

## INC-073 — Honeypot interaction as a corroborating signal; CI green again

**Status:** offline-tested (decision runner, engine, policy, schemas); live behaviour unverified.

- New independent signal type `honeypot` (policy vocabulary, engine, `correlation-decision-event-v1` kind `honeypot_interaction`,
  `response-request-v1`). The decision runner reads `cowrie.honeypot` events of the anomalous source from `soc-alerts-*` and folds them into
  one signal (worst severity, count). `COR-001` accepts it with `min_severity: 5` in every shipped policy; a static check enforces the floor.
- **BUG-073-A — the routed transit was containable.** `10.255.0.0/16` (router/firewall transit, and the NATed source of all campus traffic
  toward the DMZ) was not a protected network, so a corroborated anomaly on fw-core's outside address could have blocked a whole zone.
  It is now protected in every policy and statically enforced.
- **CI:** `ansible-lint` failed on `no-handler` (`wazuh_agent` refreshed the apt index with `when: changed`; now a handler flushed before the
  install). `gitleaks` reported five findings in history, all reviewed false positives (`curl --user name:${VAR}` variable references, Ed25519 key
  IDs, the `Ed25519PrivateKey` type name); `.gitleaks.toml` allowlists exactly those secret shapes and was checked to still report real-looking
  credentials in the same contexts.

---

## INC-074 — First live run of the SOC and AI planes: blocking bugs, an address collision and a credential leak

**Status:** run for real on Docker Desktop (macOS, arm64) in a throwaway Compose project: SOC plane up, `soc-smoke` PASS, the pinned
Cowrie image driven by real Telnet sessions, its events in `soc-alerts-*`, the decision runner's own signal query run against that
Elasticsearch, then the DEMO model and `make soc-ai-up` (observe mode): features → enrichment → mTLS inference → `soc-ai-*` →
decision records in `soc-response-*`. The containerlab fabric, Wazuh, enforcement on real firewalls and the Linux runner were not part of
this run.

- **BUG-074-A — Logstash never ran the pipeline.** `70-normalize-ecs.conf` set `tag_on_failure` on the `csv` filter, a setting the filter
  does not have; Logstash 9.3.1 refuses the whole `soc-ingestion` pipeline and exits, Docker restarts it (16 restarts observed). Since the
  first SOC commit no event was ever ingested. The filter now maps `_csvparsefailure` to `_firewall_parse_failure`.
- **BUG-074-B — the healthcheck hid it.** It probed `/_node/pipelines`, which answers during every start-up of the crash loop, so
  `docker compose up --wait` reported Logstash healthy. Compose and the Kubernetes readiness probes now require
  `/_node/pipelines/soc-ingestion` (404 until the pipeline is loaded).
- **BUG-074-C — template bootstrap 403.** Each `elasticsearch` output tried to install the default `ecs-logstash` template; the
  least-privilege `cxyz_logstash` role correctly cannot, and the plugin then shuts the pipeline down. Templates and ILM are installed by
  `soc-account-setup`, so every output now sets `manage_template => false`, `ilm_enabled => false`, `data_stream => false` (statically enforced).
- **BUG-074-D — attacker passwords were indexed.** Only the parsed `password` field was dropped; the received line (kept as
  `event.original` in `soc-alerts-*` and as `message`/`event.original` in `soc-raw-*`) still carried it, twice, because Cowrie repeats it in
  `login attempt [user/password] ...`. Both occurrences are now redacted in the line itself before it is preserved or cloned. Verified live with
  passwords containing `/`, `]`, ` failed`, `"` and `\`: 0 occurrences across raw and normalized indices; the event still parses.
- **BUG-074-E — fixture writers.** `soc_smoke.py` and `DockerLab.inject` appended to the root-owned fixture volume as Logstash's uid 1000;
  they now write as root (the file stays readable for the file input).
- **Gate:** `scripts/check_logstash_config.sh` compiles both pipeline trees (Compose and Kubernetes) with the pinned Logstash image; it runs
  in CI, before `make soc-up`, and is part of the CI contract. It fails on the pre-fix tree with the exact plugin and setting.
- Also observed working: the pinned Cowrie image starts with `read_only`, `cap_drop: ALL` and `no-new-privileges` (SSH 2222, Telnet 2223 via
  `COWRIE_TELNET_ENABLED`), the shared volume is initialised with Cowrie's ownership and is readable through Logstash's read-only mount, and the
  decision runner folds the 21 events of one attacker into exactly one `honeypot` signal (severity 9) and none for an unrelated address.
- **BUG-074-F — DC address collision (since the first commit).** `wazuh-indexer`, `wazuh.dashboard` and `soc-response` joined `cxyz_dc`
  without a fixed address. The fabric's `server1` (172.16.50.1) and `fw-core` (.254) are configured inside containerlab nodes, invisible to
  Docker's IPAM, so the first dynamic member is handed .1 (observed: `soc-response` got 172.16.50.1) and collides with `server1` on the same
  bridge. They are now pinned to .13/.14/.15, `ensure_dc_network.sh` reserves .1 and .254 as aux addresses on a new network, and a static
  check requires a unique fixed address outside the fabric's for every member.
- **BUG-074-G — orchestrator never became healthy.** Its healthcheck connected to whatever the container hostname resolves to; with four
  networks that was the management address, while the listener binds only the interface toward Elasticsearch. It now probes that address
  (`address_toward`), and a static check forbids hostname-based probes on multi-homed services.
- **BUG-074-H — the enrichment worker crash-looped.** `serve` held the outbox lock and called `drain()`, which took it again through a second
  open file description; `flock` refuses that even inside one process ("another outbox worker is active", 10 restarts observed). The lock is
  now re-entrant within one `Outbox` and still exclusive against another worker (regression tests fail without the fix).
- After the fixes, live and stable (no restarts): 4 vectors pulled, scored over mTLS and written to `soc-ai-*`; the decision runner produced
  `COR-001` records for 192.168.40.20 (AI anomaly + authentication failures from the smoke fixtures) as **alerts** (observe mode). The scores
  come from the synthetic DEMO model and mean nothing.

---

## INC-075 — Live verifier run without a fabric: credential rotation, a mis-measured queue, a cascading harness failure

**Status:** `make soc-ai-validate` and the new `scripts/honeypot_e2e.py` run for real on Docker Desktop (macOS, arm64) in a
throwaway Compose project, without the containerlab fabric. Controls that need the firewall enforcement agents cannot pass
there; the per-control results are in `docs/TEST-EVERYTHING.md` (after the fixes: LOG-01..03 and AI-01..03 PASS, AI-04 fails
without `--with-lstm` as documented, COR-01/RESP-01/RESP-03/SOC-01..03 fail closed for lack of firewall agents).

- **BUG-075-A — every `docker compose up` rotated all service API keys.** Compose re-runs the one-shot `soc-service-init`
  whenever it starts a service that depends on it (observed: three runs in 40 s during `make soc-ai-up`/`soc-ai-validate-up`).
  Each run invalidated every service's key, but workers that were not recreated kept the old one: the enrichment worker
  answered `HTTP_401` for good (ES: "api key ... has been invalidated"), no anomaly was written and AI-01 timed out; the
  feature worker crashed once on the same error. Now `provision-service-credentials.sh` keeps a key that still authenticates
  as that service with an unchanged role (role hash next to the key); it rotates when the key is missing, rejected, expired,
  the role changed, or on `make soc-ai-rotate-keys`, by creating the new key, renaming it into place atomically and only then
  invalidating the old one by id. Every Elasticsearch client (workers, decision, orchestrator; Path C's `es.cred` too) reads
  its credential through `FileAuthorization`, which re-reads the file when it changes, so a rotation needs no restart.
  Verified live: re-runs log `API keys kept: 4, rotated: 0`; a `make soc-ai-rotate-keys` while every worker was running
  left exactly 4 active keys and 0 requests with an invalidated key, with no restart. AI-01 then PASSED.
- **BUG-075-B — LOG-03 measured the wrong counter.** It required `queue.events_count >= 1` during an Elasticsearch outage.
  On Logstash 9.3 that counts only UNREAD events; a worker had already read the event into a batch the output keeps retrying
  (raw output `in` 38 vs `out` 37, observed), so the event was held but the check reported it lost. The depth is now unread
  plus in-flight at the outputs. LOG-03 then PASSED live: the event was held during the outage and delivered once afterwards.
- **BUG-075-C — one failed scenario became five misleading failures.** The shared response scenario is cached per session,
  but a failure was not: RESP-01, RESP-03 and SOC-01..03 each re-ran it, re-injected the same document ids and failed with
  `HTTP 409 version_conflict` instead of the cause. Failures are now cached and every later check reports the original one.
- **BUG-075-D — `--dry-run` executed Python checks.** Commands were skipped but check stages ran, and `check_docker_access`
  can call `sudo usermod` and re-exec. Dry runs now skip them ("dry run: check not executed").
- **New corner, automated:** runner stage `dmzlab-siem` / `make dmzlab-siem-check` (`scripts/honeypot_e2e.py`) drives a real
  Telnet session from pc1 to the honeypot and proves: events in `soc-alerts-*` with the expected actions and severities, the
  password nowhere in normalized or raw documents (deep scan), one `honeypot` decision signal from the decision runner's own
  query. Run live (PASS) and against a pipeline with the redaction removed (FAIL, naming the three leaking fields).
- **Docs:** `docs/TEST-EVERYTHING.md`, the complete test plan from offline gates to Paths B and C with the corners to check by hand.

---

## INC-076 — First full Path A run on Linux (Kali, kernel 6.16): what passed, what was mis-reported

**Status:** the one-command runner ran the full lab on a real x86-64 Linux host (2026-10-18, from a source download
without `.git`, before the fixes of PR #4 were available there). The fixes made on that host are integrated as
"Fix Linux lab bring-up on Kali / kernel 6.16" (runner on Kali, VRRP bootstrap and ARP/linkdown sysctls, management
egress via table 100 for routers, edge ISP default import, Wazuh rules/decoders, nf_log_all_netns, Kibana 403 retry,
provenance without `.git`, RTR-01/HA-01 parsers). Its run logs were reviewed for secrets (none found) and are not
part of `main`.

- **Real results:** 12/12 nodes, DMZ lab reachable/counted/contained, `soc-smoke` PASS. With the real nftables agents,
  **COR-01, RESP-01, RESP-03, SOC-01, SOC-02, SOC-03 PASS** (containment applied, verified and expired on both
  firewalls), LOG-01..03, AI-02..04 PASS, RTR-01 PASS. AI-01 failed with the same symptom as BUG-075-A (vector built,
  never scored): the service API keys were rotated under the running workers, fixed in PR #4.
- **BUG-076-A — HA-01 passed without traffic.** pc1 got 13 replies, "Destination Net Unreachable" right after dist1 was
  shut, then nothing; the check measured the largest gap between successful replies anywhere in the capture (0.109 s)
  and passed. `scripts/vrrp_failover_check.py` now requires traffic while the master is down: the longest
  interruption from shutdown through the replies to the restore must stay under 5 s, with at least 5 replies. HA-01
  will FAIL honestly until the failover itself works. (Path B already required 35 of 70 replies.)
- **BUG-076-B — controls with evidence reported UNVERIFIED.** Every `make` created its own evidence run; the report
  reads one. The runner now uses one run id (`TS`) for the whole session.
- **BUG-076-C — wrong cause.** `configure` failed because the routers could not install rsyslog (their default route
  had moved into the fabric; fixed on that host by management table 100, mechanism re-checked in a container), but
  the report said TIME-01, matched in a task that had succeeded. Hints now come from the failure region first.
- **BUG-076-D — `make validate` stopped at the VPN probe:** Docker had created `./wireguard` as root. `make security`
  creates the bind-mount sources as the user; the script explains the chown fix.
- **BUG-076-E — shell scripts were never linted in CI.** A malformed shellcheck directive (on `main` since the DC
  network script) disabled analysis of that file, and a new arithmetic test used bare names. Both fixed; every
  shell script is now shellcheck-clean and CI runs `shellcheck -S warning`.
- **Still open from that run:** DET-01 (the scan was enforced, counter +4, but no Wazuh rule 100201 alert; the Wazuh
  rule/decoder and `nf_log_all_netns` fixes target it but have not been re-run), the VRRP failover itself (dist2
  answered "Net Unreachable"), and the network controls SEG/IDM/HRD/DET-02/VPN-01/ZTNA-01, which never ran because
  `configure` and `vpn-probe` failed. TIME-01 needs the host clock on NTS.
