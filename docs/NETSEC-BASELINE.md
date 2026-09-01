# Frozen NetSec baseline

The network-security foundation was frozen before SOC/AI development so that
new analytics code cannot silently redefine the existing assurance claim.

- Tag: `netsec-baseline-2026-08-31`
- Commit: `69fc8f9`
- Primary CI: [successful netdevops-ci run](https://github.com/ahpxna/enterprise-netsec-iac/actions/runs/32982028332)
- Scope: Paths A/B/C, the existing 13 controls, evidence semantics, Suricata,
  Wazuh, RADIUS, VPN, ZTNA, and network-policy source checks.

This tag freezes source and deterministic CI, not live runtime assurance. Each
deployment path retains the validation status recorded in the main README.

The scheduled vulnerability-feed workflow is deliberately separate from the
deterministic source gate. Its latest baseline run reported HIGH/CRITICAL
findings in pinned images. Those findings are lifecycle work to triage and
upgrade; they do not rewrite the historical CI result or justify claiming the
images are vulnerability-free.
