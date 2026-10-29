#!/usr/bin/env bash
set -euo pipefail
image=$1
platform=$2
temporary=$(mktemp -d)
container=''
# Invoked by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$temporary"
}
trap cleanup EXIT
python3 - "$temporary/config.json" <<'PY'
import json, pathlib, sys
sys.path.insert(0, 'tests')
from test_recovery import config
value = config()
value['enabled'] = False
value['unifi_api_key'] = 'smoke-test-only'
pathlib.Path(sys.argv[1]).write_text(json.dumps(value))
PY
chmod 644 "$temporary/config.json"
test "$(docker image inspect "$image" --format '{{.Config.User}}')" = '10001:10001'
container=$(docker run --detach --rm --platform "$platform" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$temporary/config.json,dst=/etc/pi-recovery/config.json,readonly" "$image")
for ((attempt=0; attempt<30; attempt++)); do
  if docker exec "$container" python3 -c '
from urllib.request import urlopen
assert urlopen("http://127.0.0.1:8080/readyz").read() == b"ok\n"
metrics = urlopen("http://127.0.0.1:8080/metrics").read()
assert b"pi_recovery_automatic_enabled 0" in metrics
' > "$temporary/healthcheck.log" 2>&1; then exit 0; fi
  sleep 1
done
docker logs "$container"
cat "$temporary/healthcheck.log"
exit 1
