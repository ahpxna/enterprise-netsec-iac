# Contributing

1. `pip install pre-commit && pre-commit install`
2. New control? Add it to `compliance/controls.yaml` **and** write the test it
   names in `verified_by`. CI (`check_wiring.py`) fails otherwise.
3. Firewall/routing change? Add or update a Batfish test in `tests/batfish/`.
4. Never commit `.env`, `*.key`, or `wireguard/keys/` (gitignored + gitleaks).
5. Container image change? Update `supply-chain/images.lock.yml`. For portable
   multi-architecture images, pin the top-level image-index digest (never an
   amd64/arm64 child manifest). A genuinely single-platform component may pin
   its manifest digest only when the lock records that platform limitation
   explicitly. Then run `make image-lock-check` and `make verify-image-platforms`
   on a networked Docker host. If the image appears in generated source, update
   the canonical renderer before regenerating output.
6. Record security-relevant implementation/regression decisions in
   `docs/SECURITY-IMPLEMENTATION-LEDGER.md` so later patches preserve the reason
   behind each invariant.
