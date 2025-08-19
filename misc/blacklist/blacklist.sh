#!/usr/bin/env bash
# ===========================================================
# blacklist-v4.sh — Fetch, parse, and (optionally) block from public blocklists
# - Default: dry-run (counts only). Use --apply to enforce via ipset + iptables/ip6tables (or nft with --nft).
# - Caches list files in /var/cache/f2b-blocklists for 6h; use --force to refresh.
# - Robust parsing, CRLF normalisation, progress bars, success/fail counters.
# ===========================================================

set -u
set -o pipefail

# ---------- Colours (TTY-aware) ----------
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  BLUE=$'\033[34m'; MAGENTA=$'\033[35m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; RESET=""
fi

info(){ echo -e "${CYAN}[*]${RESET} $*"; }
ok()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*"; }
die() { echo -e "${RED}[x]${RESET} $*" >&2; exit 1; }

# ---------- Defaults ----------
CACHE_DIR="/var/cache/f2b-blocklists"
MAX_AGE="${MAX_AGE:-21600}"   # 6h
SET_V4="f2b_blocklist_v4"
SET_V6="f2b_blocklist_v6"
DRYRUN=1
APPLY=0
FLUSH=0
FORCE=0
USE_NFT=0
VERBOSE=0

LISTS=(
  https://lists.blocklist.de/lists/all.txt
  https://www.spamhaus.org/drop/drop.txt
  https://www.spamhaus.org/drop/edrop.txt
  https://www.spamhaus.org/drop/dropv6.txt
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  https://rules.emergingthreats.net/blockrules/compromised-ips.txt
  "https://www.dshield.org/ipsascii.html?limit=10000"
  https://cinsscore.com/list/ci-badguys.txt
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
)

CURL_OPTS=(--fail --location --silent --show-error --connect-timeout 10 --max-time 60 -A "f2b-blocklists/1.5")

usage() {
  cat <<EOF
Usage: $0 [--apply] [--force] [--flush] [--nft] [--max-age SECONDS] [--no-color] [--verbose]
  --apply        Apply ipset + firewall rules (default is dry-run)
  --force        Ignore cache age; redownload lists
  --flush        Remove sets/rules and exit
  --nft          Use nftables instead of iptables/ip6tables
  --max-age N    Override cache max age (seconds)
  --no-color     Disable colours
  --verbose      Extra logs
EOF
  exit 0
}

# ---------- Args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)   DRYRUN=0; APPLY=1 ;;
    --force)   FORCE=1 ;;
    --flush)   FLUSH=1 ;;
    --nft)     USE_NFT=1 ;;
    --max-age) shift || true; MAX_AGE="${1:-$MAX_AGE}" ;;
    --no-color) RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; RESET="" ;;
    --verbose) VERBOSE=1 ;;
    -h|--help) usage ;;
    *) die "Unknown arg: $1" ;;
  esac
  shift || true
done

# ---------- Requirements ----------
require_tools() {
  command -v curl  >/dev/null 2>&1 || die "curl not found. Install: sudo apt-get install -y curl"
  command -v ipset >/dev/null 2>&1 || die "ipset not found. Install: sudo apt-get install -y ipset"
  if [[ "$USE_NFT" -eq 0 ]]; then
    command -v iptables  >/dev/null 2>&1 || die "iptables not found. Install: sudo apt-get install -y iptables"
    command -v ip6tables >/dev/null 2>&1 || warn "ip6tables not found (IPv6 drops will be skipped)"
  else
    command -v nft >/dev/null 2>&1 || die "nftables not found. Install: sudo apt-get install -y nftables"
  fi
}

# ---------- Progress ----------
step_print() {
  local idx="$1" total="$2" label="$3"
  echo -e "${MAGENTA}[$idx/$total]${RESET} $label"
}
progress_bar() {
  local current=$1 total=$2 width=40
  [[ "$total" -le 0 ]] && total=1
  local percent=$(( current * 100 / total ))
  local filled=$(( width * percent / 100 ))
  local empty=$(( width - filled ))
  printf "\r[%-${width}s] %3d%% (%d/%d)" \
    "$(printf '%0.s#' $(seq 1 $filled))" \
    "$percent" "$current" "$total"
}

# ---------- Cache path ----------
get_list_file() {
  local url="$1"
  local name
  name="$(basename "$url" | tr -cd '[:alnum:]._-' )"
  echo "$CACHE_DIR/$name"
}

# ---------- Parse one list into tmp files ----------
parse_list_into_tmp() {
  local file="$1" out4="$2" out6="$3"
  local c4=0 c6=0

  while IFS= read -r ip; do
    [[ -z "${ip:-}" ]] && continue
    if [[ "$ip" == *:* ]]; then
      echo "$ip" >> "$out6"; c6=$((c6+1))
    else
      echo "$ip" >> "$out4"; c4=$((c4+1))
    fi
  done < <(
    LC_ALL=C grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9A-Fa-f:]+:+)+[0-9A-Fa-f]+(/[0-9]{1,3})?' "$file" 2>/dev/null | sort -u || true
  )

  [[ "$VERBOSE" -eq 1 ]] && ok "Parsed $(basename "$file"): IPv4=$c4 IPv6=$c6"
  echo "$c4,$c6"
}

# ---------- Download all lists ----------
download_lists() {
  mkdir -p "$CACHE_DIR"
  local total="${#LISTS[@]}" i=0
  info "Fetching blocklists ($total total, cache max-age=${MAX_AGE}s)…"
  for url in "${LISTS[@]}"; do
    i=$((i+1))
    local file; file="$(get_list_file "$url")"
    local label; label="$(basename "$file")"
    step_print "$i" "$total" "$label"

    if [[ -f "$file" && "$FORCE" -eq 0 ]]; then
      local age
      age=$(( $(date +%s) - $(stat -c %Y "$file") ))
      if (( age < MAX_AGE )); then
        [[ "$VERBOSE" -eq 1 ]] && info "Using cache: $label (age ${age}s)"
        continue
      fi
    fi

    if curl "${CURL_OPTS[@]}" -o "$file" "$url"; then
      [[ "$VERBOSE" -eq 1 ]] && ok "Downloaded: $label"
    else
      warn "Failed: $url"
    fi
  done
}

# ---------- Apply iptables/ipset ----------
apply_ipset_iptables() {
  local set4="$1" set6="$2" tmp4="$3" tmp6="$4"

  # Create sets and flush to avoid residue/type issues
  ipset create "$set4" hash:net -exist timeout 86400
  ipset flush "$set4" 2>/dev/null || true
  ipset create "$set6" hash:net family inet6 -exist timeout 86400
  ipset flush "$set6" 2>/dev/null || true

  # Normalize CRLF → LF (critical!)
  sed -i 's/\r$//' "$tmp4" "$tmp6" 2>/dev/null || true

  # IPv4 load with progress + success/fail counters
  if [[ -s "$tmp4" ]]; then
    info "Loading IPv4 entries ($set4)…"
    local total current okc failc n
    total=$(wc -l < "$tmp4" | tr -d ' '); current=0; okc=0; failc=0
    while IFS= read -r n; do
      [[ -n "${n:-}" ]] || continue
      n="${n%%$'\r'}"; n="${n%%[[:space:]]}"; n="${n##[[:space:]]}"
      if ipset add "$set4" "$n" timeout 86400 -exist 2>/dev/null; then
        okc=$((okc+1))
      else
        failc=$((failc+1))
      fi
      current=$((current+1)); progress_bar "$current" "$total"
    done < "$tmp4"
    echo
    [[ "$failc" -gt 0 ]] && warn "IPv4 add failures: $failc" || ok "IPv4 added: $okc"
  else
    warn "No IPv4 entries to load."
  fi

  # IPv6 load
  if [[ -s "$tmp6" ]]; then
    info "Loading IPv6 entries ($set6)…"
    local total6 current6 ok6 fail6 m
    total6=$(wc -l < "$tmp6" | tr -d ' '); current6=0; ok6=0; fail6=0
    while IFS= read -r m; do
      [[ -n "${m:-}" ]] || continue
      m="${m%%$'\r'}"; m="${m%%[[:space:]]}"; m="${m##[[:space:]]}"
      if ipset add "$set6" "$m" timeout 86400 -exist 2>/dev/null; then
        ok6=$((ok6+1))
      else
        fail6=$((fail6+1))
      fi
      current6=$((current6+1)); progress_bar "$current6" "$total6"
    done < "$tmp6"
    echo
    [[ "$fail6" -gt 0 ]] && warn "IPv6 add failures: $fail6" || ok "IPv6 added: $ok6"
  else
    warn "No IPv6 entries to load."
  fi

  # Attach rules (idempotent)
  iptables -C INPUT -m set --match-set "$set4" src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set "$set4" src -j DROP
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -m set --match-set "$set6" src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set "$set6" src -j DROP
  fi

  # Verify
  local count4 count6
  count4="$(ipset list "$set4" 2>/dev/null | sed -n 's/^Number of entries: //p')"
  count6="$(ipset list "$set6" 2>/dev/null | sed -n 's/^Number of entries: //p')"
  ok "Set $set4 entries: ${count4:-0}"
  ok "Set $set6 entries: ${count6:-0}"
  echo
  iptables -S INPUT | grep -- "--match-set $set4" || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -S INPUT | grep -- "--match-set $set6" || true
  fi
  ok "iptables rules installed. Entries auto-expire after 86400s."
}

# ---------- Apply nftables ----------
apply_ipset_nft() {
  local set4="$1" set6="$2" tmp4="$3" tmp6="$4"

  nft list table inet filter >/dev/null 2>&1 || nft add table inet filter
  nft list chain inet filter input >/dev/null 2>&1 || nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'

  nft list set inet filter "$set4" >/dev/null 2>&1 || nft add set inet filter "$set4" '{ type ipv4_addr; flags interval,timeout; }'
  nft list set inet filter "$set6" >/dev/null 2>&1 || nft add set inet filter "$set6" '{ type ipv6_addr; flags interval,timeout; }'

  # Normalize CRLF → LF
  sed -i 's/\r$//' "$tmp4" "$tmp6" 2>/dev/null || true

  # IPv4
  if [[ -s "$tmp4" ]]; then
    info "Loading IPv4 into nft set $set4…"
    local total current okc failc n
    total=$(wc -l < "$tmp4" | tr -d ' '); current=0; okc=0; failc=0
    while IFS= read -r n; do
      [[ -n "${n:-}" ]] || continue
      n="${n%%$'\r'}"; n="${n%%[[:space:]]}"; n="${n##[[:space:]]}"
      if nft add element inet filter "$set4" "{ $n timeout 1d }" 2>/dev/null; then
        okc=$((okc+1))
      else
        failc=$((failc+1))
      fi
      current=$((current+1)); progress_bar "$current" "$total"
    done < "$tmp4"
    echo
    [[ "$failc" -gt 0 ]] && warn "IPv4 add failures: $failc" || ok "IPv4 added: $okc"
  else
    warn "No IPv4 entries to load."
  fi

  # IPv6
  if [[ -s "$tmp6" ]]; then
    info "Loading IPv6 into nft set $set6…"
    local total6 current6 ok6 fail6 m
    total6=$(wc -l < "$tmp6" | tr -d ' '); current6=0; ok6=0; fail6=0
    while IFS= read -r m; do
      [[ -n "${m:-}" ]] || continue
      m="${m%%$'\r'}"; m="${m%%[[:space:]]}"; m="${m##[[:space:]]}"
      if nft add element inet filter "$set6" "{ $m timeout 1d }" 2>/dev/null; then
        ok6=$((ok6+1))
      else
        fail6=$((fail6+1))
      fi
      current6=$((current6+1)); progress_bar "$current6" "$total6"
    done < "$tmp6"
    echo
    [[ "$fail6" -gt 0 ]] && warn "IPv6 add failures: $fail6" || ok "IPv6 added: $ok6"
  else
    warn "No IPv6 entries to load."
  fi

  nft list ruleset | grep -q "ip saddr @$set4 drop"  || nft add rule inet filter input ip saddr \@"$set4" drop
  nft list ruleset | grep -q "ip6 saddr @$set6 drop" || nft add rule inet filter input ip6 saddr \@"$set6" drop
  ok "nftables rules installed. Elements expire after ~1 day."
}

# ---------- Flush ----------
flush_all() {
  info "Flushing sets and rules…"
  ipset destroy "$SET_V4" 2>/dev/null || true
  ipset destroy "$SET_V6" 2>/dev/null || true
  if [[ "$USE_NFT" -eq 0 ]]; then
    iptables  -D INPUT -m set --match-set "$SET_V4" src -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set "$SET_V6" src -j DROP 2>/dev/null || true
  else
    nft delete rule inet filter input ip saddr \@"$SET_V4" drop 2>/dev/null || true
    nft delete rule inet filter input ip6 saddr \@"$SET_V6" drop 2>/dev/null || true
    nft delete set  inet filter "$SET_V4" 2>/dev/null || true
    nft delete set  inet filter "$SET_V6" 2>/dev/null || true
  fi
  ok "Flush complete."
  exit 0
}

# ---------- Main ----------
main() {
  require_tools
  if [[ "$FLUSH" -eq 1 ]]; then flush_all; fi

  TMP_BASE="$(mktemp -t f2bblk.XXXXXX)"
  TMP_V4="$TMP_BASE.v4"; TMP_V6="$TMP_BASE.v6"
  : >"$TMP_V4"; : >"$TMP_V6"
  trap 'rm -f "$TMP_BASE" "$TMP_V4" "$TMP_V6"' EXIT

  download_lists

  total_v4=0; total_v6=0
  for url in "${LISTS[@]}"; do
    file="$(get_list_file "$url")"
    if [[ ! -s "$file" ]]; then
      warn "Missing/empty $(basename "$file") — skipping"
      continue
    fi
    counts="$(parse_list_into_tmp "$file" "$TMP_V4" "$TMP_V6")"
    c4="${counts%%,*}"; c6="${counts##*,}"
    total_v4=$((total_v4 + c4))
    total_v6=$((total_v6 + c6))
  done

  # Dedup for load + normalize CRLF
  sort -u -o "$TMP_V4" "$TMP_V4" || true
  sort -u -o "$TMP_V6" "$TMP_V6" || true
  sed -i 's/\r$//' "$TMP_V4" "$TMP_V6" 2>/dev/null || true

  uniq_v4=$(wc -l < "$TMP_V4" || echo 0)
  uniq_v6=$(wc -l < "$TMP_V6" || echo 0)

  echo
  ok "Totals (raw):    IPv4=$total_v4  IPv6=$total_v6"
  ok "Totals (unique): IPv4=$uniq_v4  IPv6=$uniq_v6"

  if [[ "$APPLY" -ne 1 ]]; then
    warn "Dry-run: no firewall changes applied. Use --apply to enforce."
    exit 0
  fi

  if [[ "$USE_NFT" -eq 1 ]]; then
    apply_ipset_nft "$SET_V4" "$SET_V6" "$TMP_V4" "$TMP_V6"
  else
    apply_ipset_iptables "$SET_V4" "$SET_V6" "$TMP_V4" "$TMP_V6"
  fi

  ok "Done."
}

main
