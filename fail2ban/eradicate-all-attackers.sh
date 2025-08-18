#!/usr/bin/env bash
# eradicate-all-attackers.sh — Run f2b-cymru-ban.sh across all Fail2ban jails (robust jail discovery)
# Requires: fail2ban-client, bash; plus whatever f2b-cymru-ban.sh requires (ipset, iptables, nc/whois)
#
# Usage:
#   ./eradicate-all-attackers.sh [--mode ip|prefix|asn] [--timeout 86400] [--apply]
#                                [--asn-min-ips 10] [--asn-min-prefixes 3] [--asn-exclude-cc SE]
#                                [--run-dir ./f2b_eradic_run] [--parallel N]
#
# Examples:
#   ./eradicate-all-attackers.sh --mode prefix
#   sudo ./eradicate-all-attackers.sh --mode asn --apply --asn-min-ips 10 --asn-min-prefixes 3 --asn-exclude-cc SE

set -euo pipefail
export LC_ALL=C

# ---- defaults ----
MODE="ip"                 # ip | prefix | asn
TIMEOUT=86400
APPLY=0
ASN_MIN_IPS=10
ASN_MIN_PREFIXES=3
ASN_EXCLUDE_CC="SE"
RUN_DIR="./f2b_eradic_run"
PARALLEL=1

# ---- parse args ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)               MODE="${2:-}"; shift 2 ;;
    --timeout)            TIMEOUT="${2:-}"; shift 2 ;;
    --apply)              APPLY=1; shift ;;
    --asn-min-ips)        ASN_MIN_IPS="${2:-}"; shift 2 ;;
    --asn-min-prefixes)   ASN_MIN_PREFIXES="${2:-}"; shift 2 ;;
    --asn-exclude-cc)     ASN_EXCLUDE_CC="${2:-}"; shift 2 ;;
    --run-dir)            RUN_DIR="${2:-}"; shift 2 ;;
    --parallel)           PARALLEL="${2:-}"; shift 2 ;;
    -h|--help)            grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

[[ "$MODE" =~ ^(ip|prefix|asn)$ ]] || { echo "Invalid --mode '$MODE' (ip|prefix|asn)"; exit 1; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "Invalid --timeout '$TIMEOUT'"; exit 1; }
[[ "$ASN_MIN_IPS" =~ ^[0-9]+$ ]] || { echo "Invalid --asn-min-ips '$ASN_MIN_IPS'"; exit 1; }
[[ "$ASN_MIN_PREFIXES" =~ ^[0-9]+$ ]] || { echo "Invalid --asn-min-prefixes '$ASN_MIN_PREFIXES'"; exit 1; }
[[ "$PARALLEL" =~ ^[0-9]+$ && "$PARALLEL" -ge 1 ]] || { echo "Invalid --parallel '$PARALLEL' (>=1)"; exit 1; }

command -v fail2ban-client >/dev/null 2>&1 || { echo "fail2ban-client not found"; exit 2; }

# locate f2b-cymru-ban.sh
if command -v f2b-cymru-ban.sh >/dev/null 2>&1; then
  BAN_SCRIPT="$(command -v f2b-cymru-ban.sh)"
elif [[ -x "$(dirname "$0")/f2b-cymru-ban.sh" ]]; then
  BAN_SCRIPT="$(dirname "$0")/f2b-cymru-ban.sh"
else
  echo "f2b-cymru-ban.sh not found (in PATH or alongside this script)"; exit 2
fi

mkdir -p -- "$RUN_DIR"
RUN_DIR="$(cd "$RUN_DIR" && pwd -P)"

timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# colors (best-effort)
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  GREEN="$(tput bold; tput setaf 2)"; YELLOW="$(tput bold; tput setaf 3)"
  RED="$(tput bold; tput setaf 1)"; CYAN="$(tput bold; tput setaf 6)"; NC="$(tput sgr0)"
else
  GREEN=""; YELLOW=""; RED=""; CYAN=""; NC=""
fi

echo -e "${CYAN}[*] Eradication run starting @ $(timestamp)${NC}"
echo "  mode=$MODE timeout=$TIMEOUT apply=$APPLY run-dir=$RUN_DIR parallel=$PARALLEL"
[[ "$MODE" == "asn" ]] && echo "  asn-min-ips=$ASN_MIN_IPS asn-min-prefixes=$ASN_MIN_PREFIXES asn-exclude-cc=$ASN_EXCLUDE_CC"

# ---- robust jail discovery (handles tree glyphs like '|-' or '`-') ----
STATUS_ALL="$(fail2ban-client status 2>/dev/null || true)"

# Extract the portion after "Jail list:" regardless of prefixing characters
JAILS_LINE="$(printf "%s\n" "$STATUS_ALL" | sed -n 's/.*Jail list:[[:space:]]*//p')"

normalize_list() {
  tr ',|' '\n' | tr ' \t' '\n' | sed '/^$/d' | sort -u
}

declare -a JAILS=()
if [[ -n "${JAILS_LINE// }" ]]; then
  mapfile -t JAILS < <(echo "$JAILS_LINE" | normalize_list)
fi

if [[ "${#JAILS[@]}" -eq 0 ]]; then
  echo -e "${RED}[!] Could not parse jail list from 'fail2ban-client status'.${NC}"
  echo "---- Raw status output (first 30 lines) ----"
  echo "$STATUS_ALL" | sed -n '1,30p'
  echo "-------------------------------------------"
  echo "Hint: run as root (sudo) and ensure Fail2ban is active."
  exit 3
fi

echo -e "${GREEN}[+] Found ${#JAILS[@]} jails:${NC} ${JAILS[*]}"

# ---- worker ----
run_one() {
  local jail="$1"
  local outdir="$RUN_DIR/$jail"
  mkdir -p -- "$outdir"

  echo -e "${CYAN}[*] Processing jail:${NC} $jail  (outdir=$outdir)"

  local args=( --jail "$jail" --mode "$MODE" --timeout "$TIMEOUT" --outdir "$outdir" )
  if [[ "$MODE" == "asn" ]]; then
    args+=( --asn-min-ips "$ASN_MIN_IPS" --asn-min-prefixes "$ASN_MIN_PREFIXES" --asn-exclude-cc "$ASN_EXCLUDE_CC" )
  fi
  [[ "$APPLY" -eq 1 ]] && args+=( --apply )

  if ! "$BAN_SCRIPT" "${args[@]}"; then
    echo -e "${RED}[!] Jail '$jail' run failed.${NC}" >&2
    return 1
  fi

  [[ -f "$outdir/apply_cmds.sh" ]] && echo "  Apply script: $outdir/apply_cmds.sh"
  [[ -f "$outdir/recommendations.txt" ]] && echo "  Recommendations: $outdir/recommendations.txt"
}

export -f run_one
export RUN_DIR MODE TIMEOUT APPLY ASN_MIN_IPS ASN_MIN_PREFIXES ASN_EXCLUDE_CC BAN_SCRIPT
export CYAN GREEN YELLOW RED NC

# ---- execute (serial/parallel) ----
FAILS=0
if [[ "$PARALLEL" -gt 1 && "$(command -v xargs || true)" ]]; then
  printf "%s\n" "${JAILS[@]}" \
    | xargs -I{} -P "$PARALLEL" bash -c 'run_one "$@"' _ {} || FAILS=$?
else
  for j in "${JAILS[@]}"; do
    if ! run_one "$j"; then FAILS=$((FAILS+1)); fi
  done
fi

# ---- summary ----
echo
echo -e "${CYAN}[*] Summary:${NC}"
echo "  Run dir: $RUN_DIR"
echo "  Mode: $MODE, Timeout: $TIMEOUT, Apply: $APPLY, Parallel: $PARALLEL"
[[ "$MODE" == "asn" ]] && echo "  ASN thresholds: ips>=$ASN_MIN_IPS, prefixes>=$ASN_MIN_PREFIXES, exclude-cc=$ASN_EXCLUDE_CC"
echo "  Jails processed: ${#JAILS[@]}  Failures: $FAILS"
echo -e "${GREEN}[✓] Done.${NC}"
