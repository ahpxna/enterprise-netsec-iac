# =====================================================================
#  CompanyXYZ-NG  —  Enterprise Network Security as Code
#  One entrypoint for the whole lifecycle: build -> harden -> validate
# =====================================================================
SHELL       := /bin/bash
.DEFAULT_GOAL := help
TS          := $(shell date -u +%Y%m%dT%H%M%SZ)
EVIDENCE    := evidence/runs/$(TS)
CLAB_TOPO   := clab/companyxyz.clab.yml
ANSIBLE_DIR := ansible

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup
.PHONY: preflight preflight-path-a preflight-audit preflight-path-b preflight-k8s
preflight: preflight-audit ## Check everything needed for the full Path A audit workflow

preflight-path-a: ## Check only tools required to bring up Path A
	@bash scripts/preflight.sh path-a

preflight-audit: ## Check Path A plus lint/audit dependencies
	@bash scripts/preflight.sh audit

preflight-path-b: ## Check Terraform/libvirt/Ansible prerequisites for Path B
	@bash scripts/preflight.sh path-b

preflight-k8s: ## Check kubectl/Python/curl prerequisites for Path C
	@bash scripts/preflight.sh k8s

.PHONY: secrets
secrets: ## Generate .env + RADIUS hashes (idempotent)
	@bash scripts/gen-secrets.sh

# ---------------------------------------------------------------- build
.PHONY: up
up: preflight-path-a secrets images dc-network wazuh-config net security ## FULL STACK: network fabric + security services
	@echo "==> Stack is up.  Dashboards:  make urls"

.PHONY: dc-network
dc-network: ## Create the shared Docker/containerlab DC bridge
	bash scripts/ensure_dc_network.sh

.PHONY: images
images: ## Build deterministic local service images used by Path A
	docker build -t cxyz/server1:local docker/server1
	docker build -t cxyz/syslog-relay:local docker/syslog-relay
	docker build -f docker/soc-python/Dockerfile -t cxyz/soc-python:local .

.PHONY: wazuh-config
wazuh-config: secrets ## Generate Wazuh TLS certificates and password hashes
	@test -f docker/wazuh/certs/root-ca.pem || \
		docker compose -f docker/wazuh/generate-indexer-certs.yml run --rm generator
	python scripts/check_wazuh_pki.py
	bash scripts/render_wazuh_users.sh

.PHONY: render
render: ## Render Path A, Batfish, and Kubernetes-local generated assets
	python scripts/render_fabric.py
	python scripts/render_batfish_snapshot.py
	python scripts/render_k8s_assets.py

.PHONY: runtime-config
runtime-config: secrets ## Render secret-bearing Path A runtime configs outside Git
	python scripts/render_runtime_configs.py

.PHONY: net
net: dc-network runtime-config ## Deploy the routed network fabric (containerlab + FRR/VyOS)
	sudo containerlab deploy -t $(CLAB_TOPO) --reconfigure
	python scripts/isolate_path_a_management.py

.PHONY: authentik-preflight
authentik-preflight: ## Block unsafe reuse of a legacy Authentik database volume
	python scripts/check_authentik_migration.py

.PHONY: security
security: authentik-preflight images dc-network wazuh-config ## Deploy SIEM + IDS + Zero-Trust gateway + DMZ app
	docker compose --profile siem --profile ids --profile ztna --profile dmz up -d

.PHONY: configure
configure: secrets ## Push all device/server configuration with Ansible
	python scripts/env_exec.py --env-file .env -- bash -lc 'cd $(ANSIBLE_DIR) && ansible-playbook site.yml'

.PHONY: harden
harden: ## Apply CIS-aligned hardening only
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/00-baseline.yml --tags baseline,cis

# ------------------------------------------------------------ validate

.PHONY: host-time-check
host-time-check: ## Verify the Linux host kernel clock is NTS-authenticated for Path A
	python scripts/host_time_status.py

.PHONY: dev-check
dev-check: ## macOS-friendly CI parity gate without KVM/libvirt/containerlab/nftables
	bash scripts/dev_check.sh

.PHONY: supply-chain-scan
supply-chain-scan: ## Generate SBOM + scan locked images and IaC for HIGH/CRITICAL findings (requires Trivy)
	bash scripts/supply_chain_scan.sh

.PHONY: image-lock-check
image-lock-check: ## Offline: require every audited external image to match supply-chain/images.lock.yml
	python scripts/check_image_lock.py

.PHONY: verify-image-platforms
verify-image-platforms: ## Online: verify locked OCI index digests and amd64/arm64 coverage with Docker buildx
	python scripts/verify_image_platforms.py --strict

.PHONY: soc-certs soc-contracts soc-up soc-health soc-status soc-smoke soc-down
soc-certs: ## Generate ignored TLS identities for the SOC analytics plane
	bash scripts/gen_soc_certs.sh

soc-contracts: ## Validate SOC architecture and schema invariants
	python scripts/check_soc_static.py
	python -m pytest tests/soc -q

soc-up: secrets dc-network ## Start TLS-protected Elasticsearch, Logstash, and Kibana
	docker compose --profile soc up -d --wait elasticsearch
	docker compose --profile soc run --rm --no-deps soc-account-setup
	docker compose --profile soc up -d --wait --no-deps logstash kibana
	docker compose --profile soc run --rm --no-deps soc-kibana-setup
	docker compose --profile soc run --rm --no-deps soc-kibana-bootstrap-revoke

soc-health: ## Show blocking health for the SOC analytics services
	docker compose --profile soc ps elasticsearch logstash kibana
	docker compose exec -T elasticsearch bash -ec 'curl --silent --fail --cacert config/certs/ca.crt --user "elastic:$${ELASTIC_PASSWORD}" https://localhost:9200/_cluster/health'

soc-status: ## Report raw, normalized, per-dataset, and dead-letter counts
	python scripts/soc_status.py

soc-smoke: soc-up ## Ingest four sources, malformed input, and verify the SOC dashboard
	python scripts/soc_smoke.py

soc-down: ## Stop the SOC plane without deleting persistent data
	docker compose stop soc-kibana-bootstrap-revoke soc-kibana-setup kibana logstash soc-account-setup elasticsearch soc-cert-init
	docker compose rm -f soc-kibana-bootstrap-revoke soc-kibana-setup kibana logstash soc-account-setup elasticsearch soc-cert-init

# ---------------------------------------------------------------- SOC AI / response
# SOC_PATH selects the deployment (path-a: nftables; path-b: VyOS). Path A also joins
# the orchestrator to the containerlab management bridge.
SOC_PATH ?= path-a
SOC_POLICY ?= $(if $(filter path-b,$(SOC_PATH)),lab-path-b,default)
export SOC_PATH SOC_POLICY
SOC_COMPOSE = docker compose $(if $(filter path-a,$(SOC_PATH)),-f docker-compose.yml -f docker-compose.path-a.yml,) --profile soc --profile soc-ai

.PHONY: soc-ai-contracts soc-ai-preflight soc-ai-up soc-ai-down soc-ai-status soc-ai-promote soc-ai-wazuh-user soc-ai-validate-up soc-ai-restore soc-live-deps soc-ai-validate soc-ai-dataset
soc-ai-contracts: ## Offline AI + response contract gates (static checks and the full unit suite)
	python scripts/check_soc_ai_static.py
	python -m pytest tests/soc tests/unit -q

soc-ai-preflight: ## Refuse to start AI/response services without an approved model, PKI and signing key
	python scripts/soc_ai_preflight.py

soc-ai-up: soc-up soc-ai-preflight ## Start features, inference, enrichment, decision and the response orchestrator
	docker build -f docker/soc-python/Dockerfile -t cxyz/soc-python:local .
	$(SOC_COMPOSE) up -d soc-service-init
	$(SOC_COMPOSE) up -d --wait soc-ai-api soc-response
	$(SOC_COMPOSE) up -d soc-feature-worker soc-enrichment-worker soc-decision

soc-ai-down: ## Stop the AI/response services (state and credentials volumes are kept)
	$(SOC_COMPOSE) stop soc-decision soc-enrichment-worker soc-feature-worker soc-response soc-ai-api soc-service-init
	$(SOC_COMPOSE) rm -f soc-decision soc-enrichment-worker soc-feature-worker soc-response soc-ai-api soc-service-init

soc-ai-status: ## Per-stream counts and service state for the AI/response plane
	python scripts/soc_status.py
	$(SOC_COMPOSE) ps soc-ai-api soc-feature-worker soc-enrichment-worker soc-decision soc-response

soc-ai-promote: ## Governed promotion: CANDIDATE=<dir> APPROVER=<name> [POLICY=<file>] -> ai/registry/active
	@test -n "$(CANDIDATE)" -a -n "$(APPROVER)" || { echo "usage: make soc-ai-promote CANDIDATE=<candidate dir> APPROVER=<name>" >&2; exit 2; }
	python -m ai.training.promote promote $(CANDIDATE) --output-dir ai/registry/active --approver "$(APPROVER)" $(if $(POLICY),--policy $(POLICY),)

soc-ai-wazuh-user: ## Provision the least-privilege Wazuh API identity used for endpoint isolation
	python scripts/env_exec.py --env-file .env -- bash -ec 'docker compose exec -T -e RESPONSE_API_PASSWORD="$${WAZUH_RESPONSE_CREDENTIALS#*:}" wazuh.manager /var/ossec/framework/python/bin/python3 - < scripts/provision_wazuh_response_user.py'

# Live validation needs enforcement and the 60 s TTL policy. Both come from the gitignored
# environment, never from edited tracked files, so the evidence stays bound to a clean tree.
# The services are returned to the reviewed observe-mode configuration afterwards.
soc-ai-validate-up: soc-ai-up ## Restart decision + orchestrator in ENFORCE mode with the 60 s validation policy (lab only)
	SOC_MODE=enforce SOC_POLICY=$(if $(filter path-b,$(SOC_PATH)),lab-validation-path-b,lab-validation) \
		$(SOC_COMPOSE) up -d --force-recreate soc-response soc-decision
	@echo "==> enforcement is ON for this lab run; it is switched off again by soc-ai-restore"

soc-ai-restore: ## Return decision + orchestrator to the reviewed configuration (observe mode, standing policy)
	SOC_MODE= $(SOC_COMPOSE) up -d --force-recreate soc-response soc-decision

soc-live-deps:
	@python -c "import jsonschema" 2>/dev/null || { echo "install host deps first: python -m pip install -r requirements-soc-live.txt" >&2; exit 2; }

soc-ai-validate: soc-live-deps soc-ai-validate-up ## LIVE: controls LOG/AI/COR/RESP/SOC (enables lab enforcement, writes evidence, restores observe mode)
	@mkdir -p $(EVIDENCE)
	@rc=0; EVIDENCE_DIR=$(EVIDENCE) python -m pytest tests/validation/test_soc_ai.py -v \
		--junitxml=$(EVIDENCE)/soc-ai-validation.xml || rc=$$?; \
	$(MAKE) soc-ai-restore; exit $$rc

soc-ai-dataset: ## Export a capture and build a leakage-safe dataset: see ai/training/README.md
	@echo "python -m soc.workers.export_events --schema network-window-v1 --start T0 --end T1 --output capture.jsonl"
	@echo "python -m ai.training.build_dataset capture.jsonl --scenarios scenarios.json --schema network-window-v1 ..."

.PHONY: lint
lint: ## Static checks: yamllint, ansible-lint, terraform, gitleaks
	python scripts/render_fabric.py --check
	python scripts/render_batfish_snapshot.py --check
	python scripts/render_vm_inventory.py --check
	python scripts/render_k8s_assets.py --check
	python scripts/check_vyos_boot.py
	python scripts/check_path_b_intent.py
	python scripts/security_static_checks.py
	python scripts/check_image_lock.py
	python scripts/check_soc_static.py
	python scripts/check_soc_ai_static.py
	python scripts/check_ci_contract.py
	python scripts/check_yaml_syntax.py
	python scripts/check_k8s_schema.py
	python -m compileall -q scripts compliance tests ai response soc
	find scripts clab/configs -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
	python compliance/check_wiring.py
	python -m pytest tests/unit tests/soc -q
	docker compose --env-file .env.example --profile siem --profile ids --profile ztna --profile dmz --profile soc --profile soc-ai config --quiet
	yamllint .
	cd $(ANSIBLE_DIR) && ansible-lint
	terraform -chdir=terraform/libvirt init -backend=false -input=false
	terraform -chdir=terraform/libvirt fmt -check -recursive
	terraform -chdir=terraform/libvirt validate
	terraform -chdir=terraform/vyos-fabric init -backend=false -input=false
	terraform -chdir=terraform/vyos-fabric fmt -check -recursive
	terraform -chdir=terraform/vyos-fabric validate
	gitleaks detect --no-banner --redact

.PHONY: batfish
batfish: ## Offline network-config policy tests (pre-merge safety net)
	python -m pytest tests/batfish -v --junitxml=$(EVIDENCE)/batfish.xml

.PHONY: health
health: ## Blocking routing health gate before security validation
	@mkdir -p $(EVIDENCE)
	EVIDENCE_DIR=$(EVIDENCE) python -m pytest tests/validation/test_routing.py -v \
		--junitxml=$(EVIDENCE)/routing-health.xml


.PHONY: vpn-probe
vpn-probe: ## Start a real WireGuard client fixture for VPN-01 end-to-end validation
	python scripts/prepare_vpn_probe.py
	docker compose --profile vpn-test up -d vpn-probe

.PHONY: validate
validate: health vpn-probe ## LIVE controls; skipped entirely if routing health fails
	EVIDENCE_DIR=$(EVIDENCE) python -m pytest \
		tests/validation/test_segmentation.py \
		tests/validation/test_hardening.py -v \
		--junitxml=$(EVIDENCE)/security-validation.xml

.PHONY: attack
attack: ## Replay the CYB-240 attack chain and prove the SIEM sees it
	@mkdir -p $(EVIDENCE)
	EVIDENCE_DIR=$(EVIDENCE) bash scripts/attack_chain.sh

# ---------------------------------------------------------- vm fabric (real NOS)
.PHONY: terraform-lock
terraform-lock: ## Generate verified cross-platform provider locks on a networked Terraform host
	terraform -chdir=terraform/libvirt providers lock -platform=linux_amd64 -platform=darwin_amd64 -platform=darwin_arm64
	terraform -chdir=terraform/vyos-fabric providers lock -platform=linux_amd64 -platform=darwin_amd64 -platform=darwin_arm64

# Alternative to `make net`: real VyOS VMs via Terraform+libvirt instead
# of containerlab/FRR. See terraform/vyos-fabric/README.md before first
# use (image sourcing, Cisco licensing note, sizing).
.PHONY: vm-init
vm-init: ## Init Terraform for the real VyOS VM fabric
	cd terraform/vyos-fabric && terraform init

.PHONY: path-b-vars
path-b-vars: secrets ## Render ignored Terraform Path B public bootstrap input from .env
	python scripts/render_path_b_vars.py

.PHONY: vm-plan
vm-plan: path-b-vars ## Plan the VyOS VM fabric (requires image tfvars, see .example)
	cd terraform/vyos-fabric && terraform plan

.PHONY: vm-up
vm-up: dc-network path-b-vars ## Apply: boot the complete 12-node Path B real-NOS fabric
	cd terraform/vyos-fabric && terraform apply
	@echo "==> Wait ~2 min for cloud-init first-boot config load, then: make vm-configure"

.PHONY: vm-inventory
vm-inventory: ## Render the Path B inventory from intent/fabric.yaml
	python scripts/render_vm_inventory.py

.PHONY: vm-configure
vm-configure: secrets path-b-vars vm-inventory ## Reconcile VyOS and Linux Day-2 configuration for Path B
	@test -s ansible/inventory/known_hosts || (echo "missing verified ansible/inventory/known_hosts; verify VM SSH host keys before configuration" >&2; exit 1)
	python scripts/env_exec.py --env-file .env -- bash -lc 'cd ansible && ansible-playbook -i inventory/vm-fabric.yml playbooks/32-vm-health.yml && ansible-playbook -i inventory/vm-fabric.yml playbooks/31-path-b.yml'

.PHONY: vm-health
vm-health: vm-inventory ## Block if Path B management SSH/network_cli bootstrap is unhealthy
	@test -s ansible/inventory/known_hosts || (echo "missing verified ansible/inventory/known_hosts" >&2; exit 1)
	cd ansible && ansible-playbook -i inventory/vm-fabric.yml playbooks/32-vm-health.yml

.PHONY: vm-idempotency
vm-idempotency: secrets vm-inventory ## Require a zero-change second Path B Day-2 run
	@test -s ansible/inventory/known_hosts || (echo "missing verified ansible/inventory/known_hosts" >&2; exit 1)
	python scripts/env_exec.py --env-file .env -- python scripts/check_path_b_idempotency.py

.PHONY: vm-audit
vm-audit: vm-configure security vpn-probe ## Audit the real Path B VM data plane and fail closed
	@$(MAKE) vm-health
	@$(MAKE) vm-idempotency
	@mkdir -p $(EVIDENCE)-path-b
	@$(MAKE) soc-ai-validate-up SOC_PATH=path-b
	@rc=0; python scripts/env_exec.py --env-file .env -- env \
		LAB_ENVIRONMENT=path-b EVIDENCE_DIR=$(EVIDENCE)-path-b \
		python scripts/path_b_audit.py || rc=$$?; \
	$(MAKE) soc-ai-restore SOC_PATH=path-b; exit $$rc
	LAB_ENVIRONMENT=path-b python -m compliance.generate_report --strict --profile path-b \
		--run $(EVIDENCE)-path-b --out evidence/PATH-B-COMPLIANCE-REPORT.md

.PHONY: vm-down
vm-down: ## Destroy the real VyOS VM fabric
	cd terraform/vyos-fabric && terraform destroy

# ---------------------------------------------------------- kubernetes path
# Alternative to `make security`: same SIEM/IDS/ZTNA stack, on k8s. See
# k8s/README.md for cluster prerequisites and ignored runtime material.
.PHONY: k8s-assets
k8s-assets: ## Refresh Kustomize-local generated config from canonical Docker IDS/SIEM sources
	python scripts/render_k8s_assets.py


.PHONY: k8s-runtime-secrets
k8s-runtime-secrets: secrets wazuh-config k8s-assets ## Render ignored Path C secrets from the same local PKI/.env as Compose
	python scripts/render_k8s_runtime_secrets.py

.PHONY: k8s-runtime-config
k8s-runtime-config: secrets ## Render non-secret Path C domain/WireGuard/Traefik runtime settings
	python scripts/render_k8s_runtime_config.py

K8S_IMAGE_LOADER ?= # kind: `kind load docker-image`; minikube: `minikube image load`; empty: image already on every node
.PHONY: k8s-soc-image
k8s-soc-image: ## Build cxyz/soc-python:local and (optionally) load it into the local cluster: K8S_IMAGE_LOADER="kind load docker-image"
	docker build -f docker/soc-python/Dockerfile -t cxyz/soc-python:local .
	@if [ -n "$(K8S_IMAGE_LOADER)" ]; then $(K8S_IMAGE_LOADER) cxyz/soc-python:local; \
	else echo "==> K8S_IMAGE_LOADER not set: make cxyz/soc-python:local available on every node yourself"; fi

.PHONY: k8s-soc-model
k8s-soc-model: soc-ai-preflight ## Copy the APPROVED registry (ai/registry/active) into the soc-model-registry PVC and re-verify it in-cluster
	@kubectl -n cxyz-security get pvc soc-model-registry >/dev/null 2>&1 || \
		{ echo "soc-model-registry PVC is missing: run make k8s-up first" >&2; exit 1; }
	kubectl -n cxyz-security delete pod soc-model-loader --ignore-not-found --wait=true
	kubectl apply -f k8s/loaders/soc-model-loader.yaml
	kubectl -n cxyz-security wait --for=condition=Ready pod/soc-model-loader --timeout=180s
	kubectl -n cxyz-security exec soc-model-loader -- find /models/active -mindepth 1 -delete
	tar -C ai/registry/active -cf - . | kubectl -n cxyz-security exec -i soc-model-loader -- tar -xf - -C /models/active --no-same-owner
	@digest="$$(python scripts/env_exec.py --env-file .env --print-var SOC_AI_METADATA_SHA256)"; \
	kubectl -n cxyz-security exec soc-model-loader -- env SOC_AI_METADATA_SHA256="$$digest" python -c \
	  'import os, pathlib; from ai.models.isolation_forest import load_approved_model as load; m = load(pathlib.Path("/models/active"), repository_root=pathlib.Path("/app"), trusted_metadata_sha256=os.environ["SOC_AI_METADATA_SHA256"]); print("verified in cluster:", m.model_id)' \
	  || { echo "registry failed provenance verification in the cluster; consumers keep failing closed" >&2; \
	       kubectl -n cxyz-security delete pod soc-model-loader --wait=false; exit 1; }
	kubectl -n cxyz-security delete pod soc-model-loader --wait=true
	@echo "==> registry loaded; restart consumers: kubectl -n cxyz-security rollout restart deployment/soc-ai-api"

.PHONY: k8s-up
k8s-up: preflight-k8s k8s-runtime-secrets k8s-runtime-config ## Deploy the security plane (Wazuh/Suricata/Traefik/Authentik/WG) to k8s
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/runtime-config.yaml
	kubectl apply -f k8s/runtime-secrets.yaml
	kubectl apply -k k8s/
	@echo "==> kubectl -n cxyz-security get pods -w"

.PHONY: k8s-smoke
k8s-smoke: ## Live Path C rollout/trust/policy checkpoint (requires deployed cluster)
	bash scripts/k8s_smoke.sh

.PHONY: k8s-down
k8s-down: ## Tear down the k8s security plane
	@test ! -f k8s/runtime-config.yaml || kubectl delete -f k8s/runtime-config.yaml --ignore-not-found
	kubectl delete -k k8s/ --ignore-not-found
	@test ! -f k8s/runtime-secrets.yaml || kubectl delete -f k8s/runtime-secrets.yaml --ignore-not-found

.PHONY: k8s-status
k8s-status: ## Show pod/service status for the k8s security plane
	kubectl -n cxyz-security get pods,svc

.PHONY: report
report: ## Generate Path A compliance report from controls.yaml + latest evidence
	python -m compliance.generate_report --strict --profile path-a \
		--out evidence/COMPLIANCE-REPORT.md

.PHONY: audit
audit: lint batfish validate attack soc-ai-validate report ## Everything an auditor would ask for
	@echo "==> Evidence bundle: $(EVIDENCE)"

# ---------------------------------------------------------------- misc
.PHONY: urls
urls: ## Print service URLs
	@test -f .env || (echo "missing .env; run make secrets" >&2; exit 1)
	@python scripts/env_exec.py --env-file .env -- bash scripts/urls.sh

.PHONY: logs
logs: ## Tail the SIEM manager
	docker compose logs -f wazuh.manager

.PHONY: down
down: ## Tear Path A services/fabric down and restore host routing state
	docker compose --profile siem --profile ids --profile ztna --profile dmz down -v
	-sudo containerlab destroy -t $(CLAB_TOPO) --cleanup
	-bash scripts/cleanup_dc_network.sh

.PHONY: clean
clean: down ## Tear down + remove generated artifacts
	rm -rf clab-companyxyz evidence/runs/* clab/runtime-configs terraform/vyos-fabric/bootstrap.auto.tfvars.json terraform/vyos-fabric/routing.auto.tfvars.json .cxyz-state
