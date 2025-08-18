#!/usr/bin/env bash
# f2b-cymru-ban.sh — Read Fail2ban IPs, enrich with Team Cymru, then ban (IP / BGP prefix / ASN)
# Requires: bash, fail2ban-client, ipset, iptables, awk, sed, grep, sort, (nc OR whois)
#
# Usage:
#   ./f2b-cymru-ban.sh --jail <jail-name> [--mode ip|prefix|asn] [--timeout 86400] [--apply]
#                      [--asn-min-ips 10] [--asn-min-prefixes 3] [--asn-exclude-cc SE]
#
# Examples:
#   sudo ./f2b-cymru-ban.sh --jail apache-signup-abuse --apply
#   sudo ./f2b-cymru-ban.sh --jail apache-signup-abuse --mode prefix --apply
#   sudo ./f2b-cymru-ban.sh --jail apache-signup-abuse --mode asn \
#        --asn-min-ips 10 --asn-min-prefixes 3 --asn-exclude-cc SE --apply

set -euo pipefail

# -------- defaults --------
JAIL=""
MODE="ip"                 # ip | prefix | asn
TIMEOUT=86400             # 24h
APPLY=0

ASN_MIN_IPS=10
ASN_MIN_PREFIXES=3
ASN_EXCLUDE_CC="SE"       # comma-separated list; ASN skipped if ANY sample CC matches any of these

OUTDIR="./f2b_cymru_out"

# -------- parse args --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --jail)               JAIL="${2:-}"; shift 2 ;;
    --mode)               MODE="${2:-}"; shift 2 ;;
    --timeout)            TIMEOUT="${2:-}"; shift 2 ;;
    --apply)              APPLY=1; shift ;;
    --asn-min-ips)        ASN_MIN_IPS="${2:-}"; shift 2 ;;
    --asn-min-prefixes)   ASN_MIN_PREFIXES="${2:-}"; shift 2 ;;
    --asn-exclude-cc)     ASN_EXCLUDE_CC="${2:-}"; shift 2 ;;
    --outdir)             OUTDIR="${2:-}"; shift 2 ;;
    -h|--help)            grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# -------- validate --------
[[ -n "$JAIL" ]] || { echo "Usage: $0 --jail <jail-name> [--mode ip|prefix|asn] [--timeout SEC] [--apply]" >&2; exit 1; }
[[ "$MODE" =~ ^(ip|prefix|asn)$ ]] || { echo "Invalid --mode '$MODE' (expected ip|prefix|asn)" >&2; exit 1; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "Invalid --timeout '$TIMEOUT' (seconds)" >&2; exit 1; }
[[ "$ASN_MIN_IPS" =~ ^[0-9]+$ ]] || { echo "Invalid --asn-min-ips '$ASN_MIN_IPS'" >&2; exit 1; }
[[ "$ASN_MIN_PREFIXES" =~ ^[0-9]+$ ]] || { echo "Invalid --asn-min-prefixes '$ASN_MIN_PREFIXES'" >&2; exit 1; }

command -v fail2ban-client >/dev/null 2>&1 || { echo "fail2ban-client not found" >&2; exit 2; }
command -v ipset >/dev/null 2>&1 || { echo "ipset not found" >&2; exit 2; }
command -v iptables >/dev/null 2>&1 || { echo "iptables not found" >&2; exit 2; }
if ! command -v nc >/dev/null 2>&1 && ! command -v whois >/dev/null 2>&1; then
  echo "Need either 'nc' or 'whois' to query Team Cymru." >&2; exit 2
fi

mkdir -p -- "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd -P)"
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# -------- colors (best-effort) --------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  GREEN="$(tput bold; tput setaf 2)"; YELLOW="$(tput bold; tput setaf 3)"
  RED="$(tput bold; tput setaf 1)"; CYAN="$(tput bold; tput setaf 6)"; NC="$(tput sgr0)"
else
  GREEN=""; YELLOW=""; RED=""; CYAN=""; NC=""
fi

echo -e "${CYAN}[*] f2b-cymru-ban starting @ $(timestamp)${NC}"
echo "  jail=$JAIL mode=$MODE timeout=$TIMEOUT apply=$APPLY outdir=$OUTDIR"
[[ "$MODE" == "asn" ]] && echo "  asn-min-ips=$ASN_MIN_IPS asn-min-prefixes=$ASN_MIN_PREFIXES asn-exclude-cc=$ASN_EXCLUDE_CC"

# -------- helpers --------
valid_ip() {
  local ip="$1" a b c d
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip" || return 1
  [[ $a -lt 256 && $b -lt 256 && $c -lt 256 && $d -lt 256 ]] || return 1
  return 0
}

# -------- 1) get banned IPs from Fail2ban (robust) --------
BAN_TMP="$OUTDIR/banned_ips.txt"
: > "$BAN_TMP"

# fast path
banlist="$(fail2ban-client get "$JAIL" banip 2>/dev/null || true)"
banlist="$(echo "$banlist" | tr '\t' ' ' | sed -E 's/[<>]//g; s/  +/ /g')"

if [[ -n "$banlist" && "$banlist" != "no" && "$banlist" != "none" && "$banlist" != "No" && "$banlist" != "<no"*">" ]]; then
  for ip in $banlist; do
    if valid_ip "$ip"; then echo "$ip"; fi
  done | sort -u > "$BAN_TMP"
fi

# fallback: parse pretty status output
if [[ ! -s "$BAN_TMP" ]]; then
  STATUS_TMP="$OUTDIR/status.txt"
  fail2ban-client status "$JAIL" > "$STATUS_TMP" || true
  sed -n '/Banned IP list:/,$p' "$STATUS_TMP" \
    | sed '1 s/.*:[[:space:]]*//' \
    | tr ' \t' '\n' \
    | while IFS= read -r tok; do
        if valid_ip "$tok"; then echo "$tok"; fi
      done \
    | sort -u > "$BAN_TMP"
fi

IPCOUNT=$(wc -l < "$BAN_TMP" || echo 0)
if [[ "$IPCOUNT" -eq 0 ]]; then
  if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] No banned IPv4s found. Try running with sudo.${NC}"
  else
    echo -e "${YELLOW}[!] No banned IPv4s found in jail '$JAIL'.${NC}"
  fi
  exit 0
fi
echo -e "${GREEN}[+] Found $IPCOUNT banned IPv4s.${NC}"

# -------- 2) Team Cymru bulk lookup (verbose) --------
CYMRU_OUT="$OUTDIR/cymru_raw.txt"
: > "$CYMRU_OUT"

echo -e "${CYAN}[*] Querying Team Cymru…${NC}"
if command -v nc >/dev/null 2>&1; then
  { echo "begin"; echo "verbose"; cat "$BAN_TMP"; echo "end"; } \
  | nc whois.cymru.com 43 > "$CYMRU_OUT" || true
else
  while read -r ip; do whois -h whois.cymru.com " -v $ip" >> "$CYMRU_OUT" || true; done < "$BAN_TMP"
fi

# -------- 3) Parse Cymru → CSV --------
ENRICHED="$OUTDIR/ips_enriched.csv"
{
  echo "ip,asn,as_name,bgp_prefix,cc,allocated"
  # Verbose format header: "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
  grep -E '^[[:space:]]*[0-9]+[[:space:]]*\|' "$CYMRU_OUT" || true \
  | awk -F'|' '
      function clean(s){ gsub(/\r|\n/,"",s); gsub(/[ \t]+/," ",s); gsub(/^[ \t]+|[ \t]+$/,"",s); gsub(/,/, " ", s); return s }
      function valid_ip(ip){ if(ip!~/^([0-9]{1,3}\.){3}[0-9]{1,3}$/) return 0; split(ip,o,"."); return (o[1]<256&&o[2]<256&&o[3]<256&&o[4]<256) }
      function valid_cidr(c){ if(c!~/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/) return 0; split(c,a,"/"); split(a[1],o,"."); return (o[1]<256&&o[2]<256&&o[3]<256&&o[4]<256 && a[2]>=0 && a[2]<=32) }
      {
        for(i=1;i<=NF;i++) $i=clean($i)
        asn=$1; ip=$2; pfx=$3; cc=$4; alloc=$6; asname=$7
        if(asn!~/^[0-9]+$/) next
        if(!valid_ip(ip)) next
        if(!valid_cidr(pfx)) next
        printf "%s,%s,%s,%s,%s,%s\n", ip, asn, asname, pfx, cc, alloc
      }'
} > "$ENRICHED"

ENRICH_COUNT=$(awk 'END{print NR-1}' "$ENRICHED")
echo -e "${GREEN}[+] Enriched $ENRICH_COUNT IPs via Cymru.${NC}"

# -------- 4) Materialize clean lists (NO pipelines writing into the apply script) --------
LIST_IPS="$OUTDIR/list_ips.txt"
LIST_PFX="$OUTDIR/list_prefixes.txt"
LIST_ASN_PFX="$OUTDIR/list_asn_prefixes.txt"

# IPs (one per line)
awk -F',' 'NR>1 && $1 ~ /^[0-9.]+$/ {print $1}' "$ENRICHED" | sort -u > "$LIST_IPS"

# Prefixes (one per line)
awk -F',' 'NR>1 && $4 ~ /\/[0-9]+$/ {print $4}' "$ENRICHED" | sort -u > "$LIST_PFX"

# ASN mode: qualify ASNs and collect their prefixes
EX_RE="^($(echo "$ASN_EXCLUDE_CC" | sed 's/,/|/g'))$"
QUAL_TXT="$OUTDIR/asn_qualifying.txt"; : > "$QUAL_TXT"
awk -F',' -v minip="$ASN_MIN_IPS" -v minpf="$ASN_MIN_PREFIXES" -v exre="$EX_RE" '
  NR==1 { next }
  $2 ~ /^[0-9]+$/ && $4 ~ /\/[0-9]+$/ {
    asn=$2; asname=$3; pfx=$4; cc=$5
    gsub(/^[ \t]+|[ \t]+$/, "", asname)
    ipcnt[asn]++
    pref[asn "|" pfx]=1
    if (cc ~ exre) excl[asn]=1
    name[asn]=asname
  }
  END {
    for (a in ipcnt) {
      pf=0
      for (k in pref) { split(k,t,"|"); if (t[1]==a) pf++ }
      if (ipcnt[a] >= minip && pf >= minpf && !(a in excl)) {
        printf "ASN|%s|%s|ip=%d|pf=%d\n", a, name[a], ipcnt[a], pf
        for (k in pref) { split(k,t,"|"); if (t[1]==a) printf "PFX|%s\n", t[2] }
      }
    }
  }' "$ENRICHED" > "$QUAL_TXT"

awk -F'|' '$1=="PFX"{print $2}' "$QUAL_TXT" | sort -u > "$LIST_ASN_PFX"

# -------- 5) Build apply script from the lists only --------
SET_NAME=""
CMDS="$OUTDIR/apply_cmds.sh"
: > "$CMDS"; chmod +x "$CMDS"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
} >> "$CMDS"

case "$MODE" in
  ip)
    SET_NAME="f2b_ips"
    {
      echo "ipset create $SET_NAME hash:ip timeout $TIMEOUT -exist"
      while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        echo "ipset add $SET_NAME $ip timeout $TIMEOUT -exist  # reason=f2b:ip jail=$JAIL"
      done < "$LIST_IPS"
      echo "iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set $SET_NAME src -j DROP"
    } >> "$CMDS"
    ;;
  prefix)
    SET_NAME="f2b_prefixes"
    {
      echo "ipset create $SET_NAME hash:net timeout $TIMEOUT -exist"
      while IFS= read -r pfx; do
        [[ -n "$pfx" ]] || continue
        echo "ipset add $SET_NAME $pfx timeout $TIMEOUT -exist  # reason=f2b:prefix jail=$JAIL"
      done < "$LIST_PFX"
      echo "iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set $SET_NAME src -j DROP"
    } >> "$CMDS"
    ;;
  asn)
    SET_NAME="f2b_asn"
    {
      echo "ipset create $SET_NAME hash:net timeout $TIMEOUT -exist"
      while IFS= read -r pfx; do
        [[ -n "$pfx" ]] || continue
        echo "ipset add $SET_NAME $pfx timeout $TIMEOUT -exist  # reason=f2b:asn jail=$JAIL"
      done < "$LIST_ASN_PFX"
      echo "iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set $SET_NAME src -j DROP"
    } >> "$CMDS"
    ;;
esac

# -------- 6) Recommendations + Proposed Execution --------
echo -e "${CYAN}[*] Building recommendations…${NC}"

now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

UNIQ_PREFIXES=$(awk -F',' 'NR>1 && $4!="" {u[$4]=1} END{print length(u)}' "$ENRICHED")
UNIQ_ASN=$(awk -F',' 'NR>1 && $2 ~ /^[0-9]+$/ {u[$2]=1} END{print length(u)}' "$ENRICHED")

RECO_TXT="$OUTDIR/recommendations.txt"
{
  echo "Recommendations generated: $now_iso (UTC)"
  echo
  echo "Summary"
  echo "-------"
  echo "Fail2ban jail:           $JAIL"
  echo "Mode selected:           $MODE"
  echo "Banned IPs (input):      $IPCOUNT"
  echo "Enriched IPs (Cymru):    $ENRICH_COUNT"
  echo "Unique BGP prefixes:     ${UNIQ_PREFIXES:-0}"
  echo "Unique ASNs observed:    ${UNIQ_ASN:-0}"
  echo "ipset timeout (seconds): $TIMEOUT"
  echo
  echo "Recommended Actions"
  echo "-------------------"
  case "$MODE" in
    ip)
      echo "1) Mirror Fail2ban IPs into ipset for perimeter DROP with auto-expire."
      echo "   - Set name: $SET_NAME"
      echo "   - Sample entries:"
      head -n 10 "$LIST_IPS" | awk '{print "   ipset add '$SET_NAME' "$1" timeout '"$TIMEOUT"' -exist  # reason=f2b:ip jail='$JAIL'"}'
      ;;
    prefix)
      echo "1) Block observed BGP prefixes for banned IPs (auto-expire)."
      echo "   - Set name: $SET_NAME"
      echo "   - Top prefixes (examples):"
      awk -F',' 'NR>1 && $4!="" {c[$4]++} END{for(p in c) printf "%6d %s\n", c[p], p}' "$ENRICHED" \
        | sort -nr | head -n 10 \
        | awk '{print "   ipset add '$SET_NAME' "$2" timeout '"$TIMEOUT"' -exist  # reason=f2b:prefix jail='$JAIL' (hits="$1")"}'
      ;;
    asn)
      echo "1) Ban all observed prefixes for ASNs meeting thresholds and not in excluded CCs."
      echo "   - Set name: $SET_NAME"
      echo "   - Thresholds: unique IPs >= $ASN_MIN_IPS AND unique prefixes >= $ASN_MIN_PREFIXES"
      echo "   - Exclude CCs: $ASN_EXCLUDE_CC"
      echo "   - Candidate ASNs (examples):"
      awk -F'|' '$1=="ASN"{print $2" "$3" "$4" "$5}' "$QUAL_TXT" | head -n 10 | sed 's/^/   /'
      echo "   - Sample adds:"
      head -n 10 "$LIST_ASN_PFX" | awk '{print "   ipset add '$SET_NAME' "$1" timeout '"$TIMEOUT"' -exist  # reason=f2b:asn jail='$JAIL'"}'
      ;;
  esac
  echo
  echo "Proposed Execution"
  echo "------------------"
  echo "A) Dry-run — review generated commands:"
  echo "   bash $OUTDIR/apply_cmds.sh"
  echo
  echo "B) Apply — enforce at the edge via ipset + iptables:"
  echo "   sudo bash $OUTDIR/apply_cmds.sh"
  echo
  echo "C) Verify — check counters and membership:"
  echo "   sudo ipset list"
  echo "   sudo iptables -S | grep match-set"
  echo
  echo "D) Rollback — remove set or wait for timeouts:"
  echo "   sudo iptables -D INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || true"
  echo "   sudo ipset destroy $SET_NAME 2>/dev/null || true"
} > "$RECO_TXT"

echo -e "${GREEN}[✓] Recommendations written to:${NC} $RECO_TXT"
echo -e "${GREEN}[✓] Apply script:${NC} $CMDS"

# -------- 7) Apply or dry-run --------
if [[ "$APPLY" -eq 1 ]]; then
  echo -e "${GREEN}[+] Applying bans to ipset (set=$SET_NAME, timeout=${TIMEOUT}s)…${NC}"
  bash "$CMDS"
  echo -e "${GREEN}[✓] Done. Entries auto-expire after ${TIMEOUT}s.${NC}"
else
  echo -e "${YELLOW}[DRY-RUN] Not applying changes. To enforce, run:${NC}"
  echo "  sudo bash $CMDS"
fi

echo -e "${CYAN}Outputs in ${OUTDIR}:${NC}"
printf "  %s\n" \
  "$BAN_TMP" \
  "$CYMRU_OUT" \
  "$ENRICHED" \
  "$LIST_IPS" \
  "$LIST_PFX" \
  "$LIST_ASN_PFX" \
  "$RECO_TXT" \
  "$CMDS"
[[ "$MODE" == "asn" ]] && printf "  %s\n" "$QUAL_TXT"
echo -e "${GREEN}[✓] f2b-cymru-ban complete.${NC}"
