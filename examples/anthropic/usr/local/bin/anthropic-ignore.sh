#!/usr/bin/env bash
# /usr/local/bin/anthropic-ignore.sh
# Prints space-separated CIDRs for Fail2ban ignoreip
# - Pulls Anthropic ranges from bgpq4 (any format) by extracting CIDRs
# - Falls back to /etc/fail2ban/anthropic.json
# - Falls back to safe static defaults
# Usage (verbose): VERBOSE=1 /usr/local/bin/anthropic-ignore.sh

set -euo pipefail

: "${VERBOSE:=0}"                                  # VERBOSE=1 for debug
SOURCES="${BGPQ4_SOURCES:-RADB,RIPE,ARIN,NTTCOM}"  # override with env var
ASN="${ASN:-AS399358}"                             # override with env var

log(){ [[ "$VERBOSE" = "1" ]] && echo "[anthropic-ignore] $*" >&2 || true; }

# Always include localhost
LIST=("127.0.0.1/8" "::1")

# Helper: extract ANY IPv4/IPv6 CIDR from arbitrary text
extract_cidrs() {
  # IPv4 CIDR
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})' || true
  # IPv6 CIDR (loose but effective)
  grep -Eo '([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}/([0-9]{1,3})' || true
}

have=0

if command -v bgpq4 >/dev/null 2>&1; then
  log "Fetching prefixes from bgpq4 (sources: $SOURCES, ASN: $ASN)"
  v4="$(bgpq4 -S "$SOURCES" -Ab -l foo-v4 "$ASN" 2>/dev/null || true)"
  v6="$(bgpq4 -S "$SOURCES" -6b -l foo-v6 "$ASN" 2>/dev/null || true)"
  mapfile -t nets < <( { printf '%s\n' "$v4"; printf '%s\n' "$v6"; } \
                       | extract_cidrs | awk 'NF' | sort -u )
  if ((${#nets[@]})); then
    LIST+=("${nets[@]}")
    have=1
    log "bgpq4 yielded ${#nets[@]} prefixes"
  else
    log "bgpq4 returned output but no CIDRs were parsed"
  fi
else
  log "bgpq4 not found, skipping"
fi

# Fallback to JSON if needed
if (( ! have )) && [[ -f /etc/fail2ban/anthropic.json ]]; then
  log "Using /etc/fail2ban/anthropic.json"
  mapfile -t nets < <(jq -r '.ipv4[]?, .ipv6[]?' /etc/fail2ban/anthropic.json | awk 'NF' | sort -u)
  if ((${#nets[@]})); then
    LIST+=("${nets[@]}")
    have=1
    log "JSON yielded ${#nets[@]} prefixes"
  fi
fi

# Final fallback (static)
if (( ! have )); then
  log "No dynamic ranges—using static defaults"
  LIST+=("160.79.104.0/23" "2607:6bc0::/48")
fi

# Output for Fail2ban (space-separated is fine)
printf '%s ' "${LIST[@]}"
