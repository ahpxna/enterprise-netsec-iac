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
.PHONY: preflight
preflight: ## Check host prerequisites (docker, clab, ansible, terraform)
	@bash scripts/preflight.sh

.PHONY: secrets
secrets: ## Generate .env + RADIUS hashes (idempotent)
	@bash scripts/gen-secrets.sh

# ---------------------------------------------------------------- build
.PHONY: up
up: preflight secrets images dc-network wazuh-config net security ## FULL STACK: network fabric + security services
	@echo "==> Stack is up.  Dashboards:  make urls"

.PHONY: dc-network
dc-network: ## Create the shared Docker/containerlab DC bridge
	bash scripts/ensure_dc_network.sh

.PHONY: images
images: ## Build deterministic local service images used by Path A
	docker build -t cxyz/server1:local docker/server1
	docker build -t cxyz/syslog-relay:local docker/syslog-relay

.PHONY: wazuh-config
wazuh-config: secrets ## Generate Wazuh TLS certificates and password hashes
	@test -f docker/wazuh/certs/root-ca.pem || \
		docker compose -f docker/wazuh/generate-indexer-certs.yml run --rm generator
	bash scripts/render_wazuh_users.sh

.PHONY: render
render: ## Render Path A and Batfish models from canonical fabric intent
	python scripts/render_fabric.py
	python scripts/render_batfish_snapshot.py

.PHONY: net
net: dc-network ## Deploy the routed network fabric (containerlab + FRR/VyOS)
	sudo containerlab deploy -t $(CLAB_TOPO) --reconfigure

.PHONY: security
security: images dc-network wazuh-config ## Deploy SIEM + IDS + Zero-Trust gateway + DMZ app
	docker compose --profile siem --profile ids --profile ztna --profile dmz up -d

.PHONY: configure
configure: ## Push all device/server configuration with Ansible
	cd $(ANSIBLE_DIR) && ansible-playbook site.yml

.PHONY: harden
harden: ## Apply CIS-aligned hardening only
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/20-security.yml

# ------------------------------------------------------------ validate
.PHONY: lint
lint: ## Static checks: yamllint, ansible-lint, terraform, gitleaks
	python scripts/render_fabric.py --check
	python scripts/render_batfish_snapshot.py --check
	python compliance/check_wiring.py
	python -m pytest tests/unit -q
	docker compose --profile siem --profile ids --profile ztna --profile dmz config --quiet
	yamllint .
	cd $(ANSIBLE_DIR) && ansible-lint
	terraform -chdir=terraform/libvirt fmt -check -recursive
	terraform -chdir=terraform/libvirt validate
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

.PHONY: validate
validate: health ## LIVE controls; skipped entirely if routing health fails
	EVIDENCE_DIR=$(EVIDENCE) python -m pytest \
		tests/validation/test_segmentation.py \
		tests/validation/test_hardening.py -v \
		--junitxml=$(EVIDENCE)/security-validation.xml

.PHONY: attack
attack: ## Replay the CYB-240 attack chain and prove the SIEM sees it
	@mkdir -p $(EVIDENCE)
	EVIDENCE_DIR=$(EVIDENCE) bash scripts/attack_chain.sh

# ---------------------------------------------------------- vm fabric (real NOS)
# Alternative to `make net`: real VyOS VMs via Terraform+libvirt instead
# of containerlab/FRR. See terraform/vyos-fabric/README.md before first
# use (image sourcing, Cisco licensing note, sizing).
.PHONY: vm-init
vm-init: ## Init Terraform for the real VyOS VM fabric
	cd terraform/vyos-fabric && terraform init

.PHONY: vm-plan
vm-plan: ## Plan the VyOS VM fabric (requires terraform.tfvars, see .example)
	cd terraform/vyos-fabric && terraform plan

.PHONY: vm-up
vm-up: ## Apply: boot real VyOS VMs (edge, fw-core, fw-dmz, core, dist1, dist2)
	cd terraform/vyos-fabric && terraform apply
	@echo "==> Wait ~2 min for cloud-init first-boot config load, then: make vm-configure"

.PHONY: vm-configure
vm-configure: ## Re-push/reconcile config to the real VyOS VMs via Ansible
	cd ansible && ansible-playbook -i inventory/vm-fabric.yml playbooks/30-vyos-fabric.yml

.PHONY: vm-down
vm-down: ## Destroy the real VyOS VM fabric
	cd terraform/vyos-fabric && terraform destroy

# ---------------------------------------------------------- kubernetes path
# Alternative to `make security`: same SIEM/IDS/ZTNA stack, on k8s. See
# k8s/README.md for cluster prereqs (k3s recommended) and CRD setup.
.PHONY: k8s-up
k8s-up: ## Deploy the security plane (Wazuh/Suricata/Traefik/Authentik/WG) to k8s
	kubectl apply -k k8s/
	@echo "==> kubectl -n cxyz-security get pods -w"

.PHONY: k8s-down
k8s-down: ## Tear down the k8s security plane
	kubectl delete -k k8s/ --ignore-not-found

.PHONY: k8s-status
k8s-status: ## Show pod/service status for the k8s security plane
	kubectl -n cxyz-security get pods,svc

.PHONY: report
report: ## Generate compliance report from controls.yaml + latest evidence
	python compliance/generate_report.py --strict \
		--out evidence/COMPLIANCE-REPORT.md

.PHONY: audit
audit: batfish validate attack report ## Everything an auditor would ask for
	@echo "==> Evidence bundle: $(EVIDENCE)"

# ---------------------------------------------------------------- misc
.PHONY: urls
urls: ## Print service URLs
	@bash scripts/urls.sh

.PHONY: logs
logs: ## Tail the SIEM manager
	docker compose logs -f wazuh.manager

.PHONY: down
down: ## Tear everything down
	docker compose --profile siem --profile ids --profile ztna --profile dmz down -v
	-sudo containerlab destroy -t $(CLAB_TOPO) --cleanup

.PHONY: clean
clean: down ## Tear down + remove generated artifacts
	rm -rf clab-companyxyz evidence/runs/*
