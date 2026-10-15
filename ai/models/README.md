# Models

- `isolation_forest.py` — `SocIsolationForest`: scaled Isolation Forest calibrated to a 0-1
  score (joblib artifact). Also the provenance-gated `load_approved_model` used for *both*
  families.
- `lstm_autoencoder.py` — `SocLstmAutoencoder`: an LSTM autoencoder over `T = 6` consecutive
  five-minute windows of one entity (counts `log1p`-scaled, ratios as-is; windows with no
  telemetry are all-zero rows). The score is the calibrated reconstruction error. The artifact
  is `safetensors` (tensors plus string metadata only), and `canonical_safetensors` sorts the
  header so identical tensors give identical bytes, which the provenance digest requires.
  Requires `requirements-soc-lstm.txt` (CPU PyTorch).

`load_approved_model` accepts only a registry-local artifact whose name matches its algorithm,
and only when all of these match *before* deserialisation: an `approved` provenance record; the
independently supplied metadata digest; artifact SHA-256 and size; the repository and registry
copies of the feature-schema digest; schema-specific feature order; finite, ordered calibration;
and (LSTM) the declared sequence length. Anonymous binaries, candidates, path traversal,
mismatched contracts and tampered metadata fail closed. `ApprovedModel.infer(features, history)`
requires exactly `sequence_length - 1` history windows for sequence models and none for a point
model; a mismatch is a contract error (HTTP 422), never silently ignored.
