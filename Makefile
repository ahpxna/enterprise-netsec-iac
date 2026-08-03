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
secrets: ## Generate .env + WireGuard keys + RADIUS hashes (idempotent)
	@bash scripts/gen-secrets.sh

# ---------------------------------------------------------------- build
.PHONY: up
up: preflight secrets net security ## FULL STACK: network fabric + security services
	@echo "==> Stack is up.  Dashboards:  make urls"

.PHONY: net
net: ## Deploy the routed network fabric (containerlab + FRR/VyOS)
	sudo containerlab deploy -t $(CLAB_TOPO) --reconfigure

.PHONY: security
security: ## Deploy SIEM + IDS + Zero-Trust gateway + DMZ app
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
	yamllint .
	cd $(ANSIBLE_DIR) && ansible-lint
	terraform -chdir=terraform/libvirt fmt -check -recursive
	terraform -chdir=terraform/libvirt validate
	gitleaks detect --no-banner --redact

.PHONY: batfish
batfish: ## Offline network-config policy tests (pre-merge safety net)
	python -m pytest tests/batfish -v --junitxml=$(EVIDENCE)/batfish.xml

.PHONY: validate
validate: ## LIVE control validation: segmentation + detection + hardening
	@mkdir -p $(EVIDENCE)
	EVIDENCE_DIR=$(EVIDENCE) python -m pytest tests/validation -v \
		--junitxml=$(EVIDENCE)/validation.xml

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
	python compliance/generate_report.py --out docs/COMPLIANCE-REPORT.md

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
