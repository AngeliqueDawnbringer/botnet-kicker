#!/usr/bin/env bash
# gen-anthropic-logs.sh
# Generate or append Anthropic-like test loglines.

set -euo pipefail
export LC_ALL=C LANG=C LC_TIME=C

LOGFILE="${LOGFILE:-/var/log/apache2/access.log}"
LINES="${LINES:-200}"       # used only in once mode
INTERVAL="${INTERVAL:-2}"   # pause between loop ticks (default 2s)
MODE="once"
[[ "${1:-}" == "--loop" ]] && MODE="loop"

# Pools
METHODS=("GET" "POST" "HEAD")
PATHS=("/" "/status" "/api/v1/completions" "/v1/messages" "/robots.txt" "/healthz" "/docs" "/favicon.ico")
PROTOS=("HTTP/1.1" "HTTP/2.0")
REFS=("-" "https://example.com/" "-" "-")

GOOD_V4=(160.79.104.10 160.79.105.44 160.79.104.66 160.79.105.77 160.79.105.140)
GOOD_V6=("2607:6bc0::123" "2607:6bc0::beef" "2607:6bc0::1:2" "2607:6bc0::5:dead" "2607:6bc0::abcd:1")
DOC_V4_NETS=("192.0.2" "198.51.100" "203.0.113")
DOC_V6_NET="2001:db8"

ua_good(){ echo "Anthropic/$((RANDOM%4+1)).$((RANDOM%10))"; }
ua_spoof(){ echo "Mozilla/5.0 (pretending Anthropic $((RANDOM%3+1)).$((RANDOM%10)))"; }

pick(){ local -n arr="$1"; echo "${arr[$((RANDOM%${#arr[@]}))]}"; }
rand_doc_v4(){ echo "${DOC_V4_NETS[$((RANDOM%${#DOC_V4_NETS[@]}))]}.$((RANDOM%254+1))"; }
rand_doc_v6(){ printf "%s:%x:%x::%x\n" "$DOC_V6_NET" $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536)); }

gen_line(){
  ts=$(date '+%d/%b/%Y:%H:%M:%S %z')
  method=$(pick METHODS)
  path=$(pick PATHS)
  proto=$(pick PROTOS)
  ref=$(pick REFS)

  if (( RANDOM % 2 )); then
    # Good Anthropic IP + UA
    if (( RANDOM%3==0 )); then ip="$(pick GOOD_V6)"; else ip="$(pick GOOD_V4)"; fi
    ua="$(ua_good)"
    status=200
    bytes=$((RANDOM%1200+200))
  else
    # Spoofed IP + UA
    if (( RANDOM%3==0 )); then ip="$(rand_doc_v6)"; else ip="$(rand_doc_v4)"; fi
    ua="$(ua_spoof)"
    status=$(( (RANDOM%2) ? 403 : 429 ))
    bytes=$((RANDOM%2200+50))
  fi

  echo "$ip - - [$ts] \"$method $path $proto\" $status $bytes \"$ref\" \"$ua\"" >> "$LOGFILE"
}

echo ">> Writing to $LOGFILE (mode=$MODE, interval=$INTERVAL)"
touch "$LOGFILE" 2>/dev/null || true

run_tick(){
  local count
  if [[ "$MODE" == "once" ]]; then
    count=$LINES    # exactly 200 or override
  else
    count=10        # always 10 per tick in loop mode
  fi
  for _ in $(seq 1 "$count"); do gen_line; done
  echo ">> Wrote $count lines"
}

if [[ "$MODE" == "once" ]]; then
  run_tick
  echo "Done."
else
  trap 'echo -e "\nStopped."' INT TERM
  while true; do
    run_tick
    sleep "$INTERVAL"
  done
fi
