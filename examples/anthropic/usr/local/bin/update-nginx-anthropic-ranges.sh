#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

OUT="/etc/nginx/anthropic.ranges"
TMP="$(mktemp)"
NEW="$(mktemp)"
trap 'rm -f "$TMP" "$NEW"' EXIT

# 1) Build new content (from your preferred source)
# Example using bgpq4:
{ bgpq4 -S RADB,RIPE,ARIN,NTTCOM -Ab AS399358 2>/dev/null \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' \
    | awk '{print $1" 1;"}';
  bgpq4 -S RADB,RIPE,ARIN,NTTCOM -6b AS399358 2>/dev/null \
    | grep -Eo '([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}/[0-9]+' \
    | awk '{print $1" 1;"}';
} | sort -u > "$NEW"

# Fallback to safe defaults if empty
if ! [ -s "$NEW" ]; then
  printf '%s\n' '160.79.104.0/23 1;' '2607:6bc0::/48  1;' > "$NEW"
fi

# 2) Only proceed if content changed
old_sum="$(sha256sum "$OUT" 2>/dev/null | awk '{print $1}')" || true
new_sum="$(sha256sum "$NEW" | awk '{print $1}')"
if [ "$old_sum" = "$new_sum" ]; then
  exit 0
fi

# 3) Install atomically (preserve perms/owner if file exists)
if [ -f "$OUT" ]; then
  cp --attributes-only --preserve=mode,ownership "$OUT" "$TMP" 2>/dev/null || true
  install -m 0644 "$NEW" "$TMP"
  mv -f "$TMP" "$OUT"
else
  install -m 0644 "$NEW" "$OUT"
fi

# 4) Validate and reload Nginx
nginx -t
systemctl reload nginx
