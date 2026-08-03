# Contributing

1. `pip install pre-commit && pre-commit install`
2. New control? Add it to `compliance/controls.yaml` **and** write the test it
   names in `verified_by`. CI (`check_wiring.py`) fails otherwise.
3. Firewall/routing change? Add or update a Batfish test in `tests/batfish/`.
4. Never commit `.env`, `*.key`, or `wireguard/keys/` (gitignored + gitleaks).
