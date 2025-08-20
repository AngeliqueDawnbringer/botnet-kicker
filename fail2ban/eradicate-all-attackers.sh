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
#
# Report includes:
#   - Per-jail discovered counts (IPs / prefixes / ASN-prefixes)
#   - Per-jail planned vs executed bans (IPs / prefixes / ASN)
#   - Per-jail reason/explanation (e.g., no banned IPv4s, thresholds not met)
#   - ASN and prefix→ASN details where available
#   - Totals across all jails

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
DEBUG=0

dbg(){ if [[ "${DEBUG:-0}" -eq 1 ]]; then echo -e "[debug] $*"; fi; }

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
    --debug)              DEBUG=1; shift ;;
    -h|--help)            grep '^# ' "$0" | sed 's/^# //' ; exit 0 ;;
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
echo "  mode=$MODE timeout=$TIMEOUT apply=$APPLY run-dir=$RUN_DIR parallel=$PARALLEL debug=$DEBUG"
[[ "$MODE" == "asn" ]] && echo "  asn-min-ips=$ASN_MIN_IPS asn-min-prefixes=$ASN_MIN_PREFIXES asn-exclude-cc=$ASN_EXCLUDE_CC"

# ---- robust jail discovery ----
STATUS_ALL="$(fail2ban-client status 2>/dev/null || true)"
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

# aggregation files (silent)
: > "$RUN_DIR/jail_stats.txt"
: > "$RUN_DIR/all_prefixes_planned.txt"
: > "$RUN_DIR/all_asns_planned.txt"
: > "$RUN_DIR/failed_jails.txt"

# ---- worker ----
run_one() {
  local jail="$1"
  local outdir="$RUN_DIR/$jail"
  mkdir -p -- "$outdir"

  local DBG_FILE="$outdir/debug_parse.log"
  if [[ "$DEBUG" -eq 1 ]]; then
    {
      echo "=== DEBUG for jail: $jail @ $(timestamp) ==="
      [[ -s "$outdir/list_prefixes.txt" ]] && { echo "--- head list_prefixes.txt ---"; head -n 20 "$outdir/list_prefixes.txt"; }
      [[ -s "$outdir/ips_enriched.csv" ]] && { echo "--- head ips_enriched.csv ---"; head -n 20 "$outdir/ips_enriched.csv"; }
    } >"$DBG_FILE"
  fi

  local args=( --jail "$jail" --mode "$MODE" --timeout "$TIMEOUT" --outdir "$outdir" )
  if [[ "$MODE" == "asn" ]]; then
    args+=( --asn-min-ips "$ASN_MIN_IPS" --asn-min-prefixes "$ASN_MIN_PREFIXES" --asn-exclude-cc "$ASN_EXCLUDE_CC" )
  fi
  [[ "$APPLY" -eq 1 ]] && args+=( --apply )

  # capture output quietly; flag failures
  if ! "$BAN_SCRIPT" "${args[@]}" >"$outdir/run.log" 2>&1; then
    echo -e "Jail $jail → ${RED}FAILED${NC} (script error) — see $outdir/run.log"
    echo "$jail" >> "$RUN_DIR/failed_jails.txt"
    echo "$jail|fail|0|0|0|0|0|0|0|0|0|script error" >> "$RUN_DIR/jail_stats.txt"
    return 0
  fi

  local ips=0 pfx=0 asn=0
  [[ -f "$outdir/list_ips.txt" ]] && ips=$(wc -l < "$outdir/list_ips.txt")
  [[ -f "$outdir/list_prefixes.txt" ]] && pfx=$(wc -l < "$outdir/list_prefixes.txt")
  [[ -f "$outdir/list_asn_prefixes.txt" ]] && asn=$(wc -l < "$outdir/list_asn_prefixes.txt")

  local planned_i=0 planned_p=0 planned_a=0
  if [[ -f "$outdir/apply_cmds.sh" ]]; then
    planned_i=$(grep -cE '^\s*ipset add f2b_ips\b'      "$outdir/apply_cmds.sh" || true)
    planned_p=$(grep -cE '^\s*ipset add f2b_prefixes\b' "$outdir/apply_cmds.sh" || true)
    planned_a=$(grep -cE '^\s*ipset add f2b_asn\b'      "$outdir/apply_cmds.sh" || true)
  fi

  local exec_i=0 exec_p=0 exec_a=0
  if [[ "$APPLY" -eq 1 ]]; then
    exec_i=$planned_i; exec_p=$planned_p; exec_a=$planned_a
  fi

  # concise per-jail output
  if (( ips==0 && pfx==0 && asn==0 )); then
    echo "Jail $jail → empty"
  else
    echo -n "Jail $jail → Discovered: IPs=$ips, Prefixes=$pfx"
    [[ "$MODE" == "asn" ]] && echo -n ", ASN-prefixes=$asn"
    echo
    if [[ "$APPLY" -eq 1 ]]; then
      echo "  Executed bans: IP=$exec_i, Prefix=$exec_p, ASN=$exec_a"
    else
      echo "  Planned bans:  IP=$planned_i, Prefix=$planned_p, ASN=$planned_a (dry-run)"
    fi
  fi

  # ---------- Per-jail details ----------
  # Detect delimiter ('|' vs ',') and use fixed column indexes to avoid CIDR guessing.
  if [[ -s "$outdir/ips_enriched.csv" ]]; then
    local first_data_line delim awk_f pipe_mode asn_col pfx_col name_col
    first_data_line="$(tail -n +2 "$outdir/ips_enriched.csv" | head -n 1 || true)"
    if printf '%s' "$first_data_line" | grep -q '|'; then
      awk_f='[|]'; pipe_mode=1; delim="|"
      # Pipe layout: ASN|IP|BGP_PREFIX|CC|RIR|DATE|AS_NAME
      asn_col=1; pfx_col=3; name_col=7
    else
      awk_f=',';    pipe_mode=0; delim=","
      # CSV layout from header: ip,asn,as_name,bgp_prefix,cc,allocated
      asn_col=2; pfx_col=4; name_col=3
    fi
    if [[ "$DEBUG" -eq 1 ]]; then
      {
        echo "--- delimiter detection ---"
        echo "first_data_line: $first_data_line"
        echo "DELIM chosen: $delim   (pipe_mode=$pipe_mode)"
        echo "Columns: ASN=$asn_col  PFX=$pfx_col  NAME=$name_col"
      } >>"$DBG_FILE"
    fi

    # (A) ASN mode (unchanged)
    if [[ "$MODE" == "asn" && -s "$outdir/asn_qualifying.txt" ]]; then
      awk -F'|' -v jail="$jail" '$1=="ASN"{asn=$2; name=$3;
                                 gsub(/^ip=/,"",$4); gsub(/^pf=/,"",$5);
                                 print jail "|" asn "|" name "|" $4 "|" $5}' \
        "$outdir/asn_qualifying.txt" >> "$RUN_DIR/all_asns_planned.txt"

      awk -F'|' -v jail="$jail" '$1=="PFX"{print jail "|" $2}' \
        "$outdir/asn_qualifying.txt" >> "$RUN_DIR/all_prefixes_planned.txt"
    fi

    # (B) PREFIX mode: owners + ASN impact
    if [[ "$MODE" == "prefix" && -s "$outdir/list_prefixes.txt" ]]; then
      echo "  Prefix owners:"

      # Owners listing (uses fixed columns)
      awk -F"$awk_f" -v jail="$jail" -v A="$asn_col" -v P="$pfx_col" -v N="$name_col" -v dbg="$DEBUG" -v DBGFILE="$DBG_FILE" '
        function trim(s){ gsub(/\r/,"",s); gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
        NR==FNR { key=trim($0); if(key!="") sel[key]=1; next }
        NR==1 { next } # skip header
        {
          for(i=1;i<=NF;i++) $i=trim($i)
          pfx=$P; asn=$A; asname=$N
          if (pfx in sel) { c[pfx]++; owner[pfx]=asn" "asname }
          if (dbg && NR<=30) { printf("ROW NR=%d pfx=%s asn=%s asname=%s\n", NR, pfx, asn, asname) >> DBGFILE }
        }
        END{
          for(p in c) printf "%06d\t%s\t%s\n", c[p], p, owner[p]
        }' "$outdir/list_prefixes.txt" "$outdir/ips_enriched.csv" \
      | sort -r \
      | awk -F'\t' '{printf "    %s (%d IPs, AS%s)\n",$2,$1+0,$3}'

      # ASN impact aggregation (uses fixed columns)
      awk -F"$awk_f" -v jail="$jail" -v A="$asn_col" -v P="$pfx_col" -v N="$name_col" -v dbg="$DEBUG" -v DBGFILE="$DBG_FILE" '
        function trim(s){ gsub(/\r/,"",s); gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
        NR==FNR { key=trim($0); if(key!="") sel[key]=1; next }
        NR==1 { next }
        {
          for(i=1;i<=NF;i++) $i=trim($i)
          pfx=$P; asn=$A; asname=$N
          if (pfx in sel) { ips[asn]++; name[asn]=asname; seen[asn SUBSEP pfx]=1 }
          if (dbg && NR<=30) { printf("AGG NR=%d pfx=%s asn=%s asname=%s\n", NR, pfx, asn, asname) >> DBGFILE }
        }
        END{
          for (a in name){
            pf=0; for (k in seen){ split(k,t,SUBSEP); if(t[1]==a) pf++ }
            printf "%s|%s|%s|%d|%d\n", jail, a, name[a], ips[a]+0, pf+0
          }
        }' "$outdir/list_prefixes.txt" "$outdir/ips_enriched.csv" >> "$RUN_DIR/all_asns_planned.txt"

      # Mismatch analysis with context: show lines containing the missing prefix (literal grep)
      if [[ "$DEBUG" -eq 1 ]]; then
        {
          echo "--- mismatch: prefixes in list_prefixes.txt not found in ips_enriched.csv ---"
          awk -F"$awk_f" '
            function trim(s){ gsub(/\r/,"",s); gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
            NR==FNR { want[trim($0)]=1; next }
            NR==1 { next }
            { for(i=1;i<=NF;i++) $i=trim($i); have[$P]=1 }
            END{ for (p in want) if(!(p in have)) print p }' \
            "$outdir/list_prefixes.txt" "$outdir/ips_enriched.csv" \
          | head -n 20 \
          | while read -r miss; do
              echo "missing: $miss"
              echo "  sample lines containing it:" 
              grep -F "$miss" "$outdir/ips_enriched.csv" | head -n 3 | sed 's/^/    /' || true
            done
        } >> "$DBG_FILE"
      fi
    fi

    # (C) Hotspots (independent of mode; uses fixed columns)
    if [[ $ips -gt 0 ]]; then
      awk -F"$awk_f" -v tot="$ips" -v A="$asn_col" -v P="$pfx_col" -v N="$name_col" -v dbg="$DEBUG" -v DBGFILE="$DBG_FILE" '
        function trim(s){ gsub(/\r/,"",s); gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
        NR==1 { next }
        {
          for(i=1;i<=NF;i++) $i=trim($i)
          pfx=$P; asn=$A; asname=$N
          c[pfx]++; owner[pfx]=asn" "asname
          if (dbg && NR<=30) { printf("HOT NR=%d pfx=%s asn=%s asname=%s\n", NR, pfx, asn, asname) >> DBGFILE }
        }
        END{
          for (p in c) if (c[p] >= 50 || c[p] >= tot*0.2)
            printf "%06d\t%s\t%s\n", c[p], p, owner[p]
        }' "$outdir/ips_enriched.csv" | sort -r | \
      awk -F'\t' '{printf "  Hotspot: %s (%d IPs, AS%s)\n",$2,$1+0,$3}'
    fi
  fi

  # record: jail|status|ips|pfx|asn|planned_i|planned_p|planned_a|exec_i|exec_p|exec_a|reason
  echo "$jail|ok|$ips|$pfx|$asn|$planned_i|$planned_p|$planned_a|$exec_i|$exec_p|$exec_a|ok" >> "$RUN_DIR/jail_stats.txt"
}

export -f run_one
export RUN_DIR MODE TIMEOUT APPLY ASN_MIN_IPS ASN_MIN_PREFIXES ASN_EXCLUDE_CC BAN_SCRIPT DEBUG
export CYAN GREEN YELLOW RED NC

# ---- execute (serial/parallel) ----
if [[ "$PARALLEL" -gt 1 && "$(command -v xargs || true)" ]]; then
  printf "%s\n" "${JAILS[@]}" \
    | xargs -I{} -P "$PARALLEL" bash -c 'run_one "$@"' _ {}
else
  for j in "${JAILS[@]}"; do
    run_one "$j"
  done
fi

# ---- summary ----
echo
echo -e "${CYAN}[*] Totals:${NC}"

total_ips=0; total_pfx=0; total_asn=0
plan_ips=0; plan_pfx=0; plan_asn=0
exec_ips=0; exec_pfx=0; exec_asn=0

if [[ -f "$RUN_DIR/jail_stats.txt" ]]; then
  while IFS='|' read -r _ status ips pfx asn planned_i planned_p planned_a exec_i exec_p exec_a _rest; do
    [[ "$status" != "ok" ]] && continue
    total_ips=$((total_ips + ips))
    total_pfx=$((total_pfx + pfx))
    total_asn=$((total_asn + asn))
    plan_ips=$((plan_ips + planned_i))
    plan_pfx=$((plan_pfx + planned_p))
    plan_asn=$((plan_asn + planned_a))
    exec_ips=$((exec_ips + exec_i))
    exec_pfx=$((exec_pfx + exec_p))
    exec_asn=$((exec_asn + exec_a))
  done < "$RUN_DIR/jail_stats.txt"
fi

echo -e "${GREEN}  Discovered:${NC} IPs=$total_ips  Prefixes=$total_pfx  ASN-prefixes=$total_asn"
if [[ "$APPLY" -eq 1 ]]; then
  echo -e "${GREEN}  Executed:${NC}   IP bans=$exec_ips  Prefix bans=$exec_pfx  ASN bans=$exec_asn"
else
  echo -e "${GREEN}  Planned (dry-run):${NC} IP bans=$plan_ips  Prefix bans=$plan_pfx  ASN bans=$plan_asn"
fi

# Totals: list ASNs impacted/banned (from ASN *and* PREFIX modes)
if [[ -s "$RUN_DIR/all_asns_planned.txt" ]]; then
  echo
  echo -e "${CYAN}ASNs (impact across jails):${NC}"
  awk -F'|' '{asn=$2; name=$3; ip=$4+0; pf=$5+0; ips[asn]+=ip; pfx[asn]+=pf; nm[asn]=name}
             END{for(a in nm) printf "  %s %s  (ips=%d, prefixes=%d)\n", a, nm[a], ips[a], pfx[a]}' \
    "$RUN_DIR/all_asns_planned.txt" | sort -k1,1n
fi

# Failure recap (if any)
if [[ -s "$RUN_DIR/failed_jails.txt" ]]; then
  echo
  echo -e "${RED}Some jails failed:${NC} $(wc -l < "$RUN_DIR/failed_jails.txt")"
  echo "  $(tr '\n' ' ' < "$RUN_DIR/failed_jails.txt" | sed 's/ $//')"
  echo "  See per-jail logs under $RUN_DIR/*/run.log"
fi

echo
case "$MODE" in
  ip)     echo "Why: mirroring Fail2ban jail offenders as IP bans." ;;
  prefix) echo "Why: aggregating multiple offenders within the same BGP subnet (owners shown above)." ;;
  asn)    echo "Why: ASN bans only where thresholds met (>= $ASN_MIN_IPS unique IPs AND >= $ASN_MIN_PREFIXES prefixes) and CC not in exclude list ($ASN_EXCLUDE_CC)." ;;
esac

echo -e "${GREEN}[✓] Done.${NC}"
