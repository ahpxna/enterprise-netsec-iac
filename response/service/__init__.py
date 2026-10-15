"""Long-running response-plane services: decision runner and orchestrator service.

These wrap the pure decision engine and lifecycle orchestrator with the I/O they
need to run unattended: Elasticsearch evidence reads/audit writes, a signed
command intake, a scheduler for apply/verify/expire/recover, and health metrics.
"""
