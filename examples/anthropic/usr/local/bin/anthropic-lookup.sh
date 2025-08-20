#!/usr/bin/env bash
# Exit 0 (ignore) if $1 is in Anthropic IP ranges; exit 1 otherwise.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

IP="${1:-}"
[[ -z "$IP" ]] && exit 1

# Collect prefixes from bgpq4; fallback to known defaults if none returned.
PREFIXES=$(
  { /usr/bin/bgpq4 -S RADB,RIPE,ARIN,NTTCOM -Ab AS399358 2>/dev/null || true; \
    /usr/bin/bgpq4 -S RADB,RIPE,ARIN,NTTCOM -6b AS399358 2>/dev/null || true; } \
  | /bin/grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+|([0-9A-Fa-f:]+)/[0-9]+' \
  | /usr/bin/sort -u
)

if [[ -z "$PREFIXES" ]]; then
  PREFIXES=$'160.79.104.0/23\n2607:6bc0::/48'
fi

# Check membership using Python's stdlib (no extra packages)
python3 - "$IP" <<'PY' || exit 1
import sys, ipaddress
ip = ipaddress.ip_address(sys.argv[1])
nets = [line.strip() for line in sys.stdin if line.strip()]
for n in nets:
    try:
        if ip in ipaddress.ip_network(n, strict=False):
            sys.exit(0)  # inside Anthropic -> IGNORE
    except ValueError:
        pass
sys.exit(1)          # outside -> DO NOT IGNORE (ban eligible)
PY
