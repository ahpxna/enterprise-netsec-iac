#!/usr/bin/env bash
# Compile every Logstash pipeline (Compose and the Kubernetes copy) with the pinned Logstash image,
# exactly as Logstash does at start-up, plugin settings included. The static checks cannot see an
# unknown plugin setting; a single one makes Logstash refuse the whole pipeline and crash-loop.
# Needs Docker; runs with no network.
set -euo pipefail
cd "$(dirname "$0")/.."

image=$(python3 -c 'import yaml; print(yaml.safe_load(open("docker-compose.yml"))["services"]["logstash"]["image"])')
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The Elasticsearch outputs require their CA file to exist; a throwaway self-signed one is enough.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=cxyz-logstash-config-test" \
  -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
chmod 0644 "$work/ca.crt"

status=0
for tree in soc/logstash k8s/generated/soc/logstash; do
  out=$(docker run --rm --network none -e LOGSTASH_PASSWORD=config-test \
    -v "$PWD/$tree/config:/usr/share/logstash/config:ro" \
    -v "$PWD/$tree/pipelines:/usr/share/logstash/pipeline:ro" \
    -v "$work/ca.crt:/usr/share/logstash/certs/ca.crt:ro" \
    "$image" bin/logstash --config.test_and_exit --path.data /tmp/config-test 2>&1) || true
  if grep -q "Configuration OK" <<<"$out"; then
    echo "OK: $tree/pipelines compile with the pinned Logstash"
  else
    echo "FAIL: $tree/pipelines do not compile:" >&2
    grep -E "ERROR|FATAL" <<<"$out" | cut -c1-400 >&2 || tail -n 20 <<<"$out" >&2
    status=1
  fi
done
exit "$status"
