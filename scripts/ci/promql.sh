#!/usr/bin/env bash
set -euo pipefail
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
python3 scripts/ci/promql_fixture.py "$temporary"
chmod 644 "$temporary"
docker run --rm --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --mount "type=bind,src=$temporary,dst=/tests.json,readonly" \
  --entrypoint /bin/promtool \
  quay.io/prometheus/prometheus@sha256:b2a413d5a03ea6a76782a508d1c7947440bba3b973931a25676e278431891b01 \
  test rules /tests.json
