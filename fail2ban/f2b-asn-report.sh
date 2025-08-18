#!/usr/bin/env bash
# f2b-asn-report.sh — Build ASN and “big route” lists from a Fail2ban jail (robust + colored + 24h recommendations)
# Usage:  ./f2b-asn-report.sh <jail-name> [outdir] [min_prefix_count] [min_asn_count]
# Defaults: outdir=./f2b_asn_out  min_prefix_count=5  min_asn_count=5
#
# Outputs:
#   status.txt
#   banned_ips.txt
#   cymru_raw.txt
#   ips_enriched.csv
#   asn_summary.csv
#   prefixes.txt
#   prefixes_annotated.txt
#   asn_blocklist.txt
#   asn_blocklist_only.txt
#   recommendations.txt

set -euo pipefail

# ---------- Colours (portable via tput) ----------

if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
  RED=$(tput setaf 1; tput bold)
  GREEN=$(tput setaf 2; tput bold)
  YELLOW=$(tput setaf 3; tput bold)
  BLUE=$(tput setaf 4; tput bold)
  MAG=$(tput setaf 5; tput bold)
  CYAN=$(tput setaf 6; tput bold)
  NC=$(tput sgr0)
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAG=""; CYAN=""; NC=""
fi

JAIL="${1:-}"
OUTDIR="${2:-./f2b_recommendations}"
MIN_PREFIX_COUNT="${3:-5}"
MIN_ASN_COUNT="${4:-5}"

if [[ -z "$JAIL" ]]; then
  echo -e "${RED}Usage:${NC} $0 <jail-name> [outdir] [min_prefix_count] [min_asn_count]" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

# 1) Capture jail status and extract banned IPs
echo -e "${CYAN}[*] Capturing jail status for ${YELLOW}$JAIL${NC}"
fail2ban-client status "$JAIL" > "$OUTDIR/status.txt"

# Extract banned IPs
sed -n '/Banned IP list:/,$p' "$OUTDIR/status.txt" \
  | sed '1 s/.*:\t//' \
  | tr ' ' '\n' \
  | sed 's/^[[:space:]]\+//; s/[[:space:]]\+$//' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | awk -F. '$1<=255 && $2<=255 && $3<=255 && $4<=255' \
  | sort -u > "$OUTDIR/banned_ips.txt"

IPCOUNT=$(wc -l < "$OUTDIR/banned_ips.txt" || echo 0)
if [[ "$IPCOUNT" -eq 0 ]]; then
  echo -e "${YELLOW}[!] No banned IPv4s found in jail '${JAIL}'.${NC}"
  echo "Wrote $OUTDIR/status.txt"
  exit 0
fi

echo -e "${GREEN}[+] Found $IPCOUNT banned IPv4s.${NC}"
echo -e "${CYAN}[*] Looking up ASN/prefix with Team Cymru…${NC}"

# 2) Team Cymru lookup
CYMRU_OUT="$OUTDIR/cymru_raw.txt"
: > "$CYMRU_OUT"

if command -v nc >/dev/null 2>&1; then
  {
    echo "begin"
    echo "verbose"
    cat "$OUTDIR/banned_ips.txt"
    echo "end"
  } | nc whois.cymru.com 43 > "$CYMRU_OUT"
elif command -v whois >/dev/null 2>&1; then
  while read -r ip; do
    whois -h whois.cymru.com " -v $ip" >> "$CYMRU_OUT"
  done < "$OUTDIR/banned_ips.txt"
else
  echo -e "${RED}[!] Need either 'nc' or 'whois' installed to query Team Cymru.${NC}" >&2
  exit 2
fi

# 3) Parse Cymru output → CSV
echo -e "${CYAN}[*] Parsing Team Cymru results…${NC}"
{
  echo "ip,asn,as_name,bgp_prefix,cc,allocated"
  grep -E '^[0-9]+' "$CYMRU_OUT" \
  | awk -F'\|' '{
      for (i=1;i<=NF;i++){ gsub(/^ +| +$/,"",$i) }
      asn=$1; ip=$2; prefix=$3; cc=$4; alloc=$6; asname=$7;
      gsub(/,/, " ", asname);
      printf "%s,%s,%s,%s,%s,%s\n", ip, asn, asname, prefix, cc, alloc
    }'
} > "$OUTDIR/ips_enriched.csv"

# 4) ASN summary
echo -e "${CYAN}[*] Building ASN summary…${NC}"
awk -F',' 'NR>1 { key=$2 "|" $3; cnt[key]++ } END {
  printf "asn,as_name,count\n";
  for (k in cnt){
    split(k,a,"|");
    printf "%s,%s,%d\n", a[1], a[2], cnt[k];
  }
}' "$OUTDIR/ips_enriched.csv" \
| sort -t, -k3,3nr > "$OUTDIR/asn_summary.csv"

# 5) Prefixes
awk -F',' 'NR>1 && $4!="" { print $4 }' "$OUTDIR/ips_enriched.csv" \
| sort -u > "$OUTDIR/prefixes.txt"

# 6) Annotated prefixes
awk -F',' -v minc="$MIN_PREFIX_COUNT" '
NR>1 && $4!="" {
  prefix=$4; asn=$2; asname=$3;
  key=prefix"|"asn"|"asname;
  cnt[key]++
}
END {
  for (k in cnt) {
    if (cnt[k] >= minc) {
      split(k,a,"|");
      prefix=a[1]; asn=a[2]; asname=a[3];
      printf "%d\t%s\tAS%s\t%s\n", cnt[k], prefix, asn, asname;
    }
  }
}' "$OUTDIR/ips_enriched.csv" \
| sort -k1,1nr \
| awk 'BEGIN{OFS=""} {print $2," # ",$3," ",$4," (count=",$1,")"}' \
> "$OUTDIR/prefixes_annotated.txt"

# 7) ASN blocklist
awk -F',' -v minc="$MIN_ASN_COUNT" '
NR>1 { key=$2 "|" $3; cnt[key]++ }
END {
  for (k in cnt) {
    if (cnt[k] >= minc) {
      split(k,a,"|");
      asn=a[1]; asname=a[2];
      printf "%d\tAS%s\t%s\n", cnt[k], asn, asname;
    }
  }
}' "$OUTDIR/ips_enriched.csv" \
| sort -k1,1nr \
| awk 'BEGIN{OFS=""} {print $2," # ",$3," (count=",$1,")"}' \
> "$OUTDIR/asn_blocklist.txt"

awk -F'[ #()]' '{print $1}' "$OUTDIR/asn_blocklist.txt" > "$OUTDIR/asn_blocklist_only.txt"

# 8) Recommendations

echo -e "${CYAN}[*] Generating recommendations…${NC}"
now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

TOTAL_IPS=$(wc -l < "$OUTDIR/banned_ips.txt" 2>/dev/null || echo 0)
TOTAL_ASN=$(awk -F',' 'NR>1{print $2}' "$OUTDIR/ips_enriched.csv" 2>/dev/null | sort -u | wc -l || echo 0)
TOTAL_PREFIX=$(wc -l < "$OUTDIR/prefixes.txt" 2>/dev/null || echo 0)

RECO=$(
cat <<EOF
Recommendations generated: $now_iso (UTC)

Summary
-------
Banned IPs observed:         $TOTAL_IPS
Unique ASNs (observed):      $TOTAL_ASN
Unique prefixes (observed):  $TOTAL_PREFIX

Recommended Actions
-------------------
1) Block high-volume ASNs at your edge/WAF
   - Import $OUTDIR/asn_blocklist_only.txt into your WAF/CDN ASN rules.
   - Threshold used: ASNs with >= $MIN_ASN_COUNT offending IPs.

   Top ASNs:
$( if [[ -s "$OUTDIR/asn_blocklist.txt" ]]; then head -n 15 "$OUTDIR/asn_blocklist.txt" | sed 's/^/   /'; else echo "   (none exceeded threshold)"; fi )

2) Block attack networks by prefix on perimeter firewalls
   - Use ipset/nftables to add prefixes. Threshold: >= $MIN_PREFIX_COUNT offending IPs.

   Example (ipset + iptables):
   ipset create f2b_big_routes hash:net -exist
$( if [[ -s "$OUTDIR/prefixes_annotated.txt" ]]; then awk -F' #' '{print "   ipset add f2b_big_routes " $1 " -exist"}' "$OUTDIR/prefixes_annotated.txt" | head -n 30; elif [[ -s "$OUTDIR/prefixes.txt" ]]; then awk '{print "   ipset add f2b_big_routes " $0 " -exist"}' "$OUTDIR/prefixes.txt" | head -n 30; else echo "   (no prefixes available)"; fi )
   iptables -I INPUT -m set --match-set f2b_big_routes src -j DROP

3) Keep Fail2ban IP bans; optionally extend with temporary perimeter drops
   - For heaviest single sources you may add temporary blocks (e.g., 24h):
$( if [[ -s "$OUTDIR/banned_ips.txt" ]]; then head -n 25 "$OUTDIR/banned_ips.txt" | awk '{print "   iptables -I INPUT -s "$1" -j DROP  # temp"}'; else echo "   (no banned IPs found)"; fi )

4) Safety & Review
   - Review ASNs for false positives (hosting/CDN that may serve legit users).
   - Prefer ASN/WAF or prefix/ipset at the edge; avoid app-layer denials where possible.
   - Time-limit aggressive measures (e.g., auto-expire ipset members after 24–48h).

Reference Files
---------------
ASNs (filtered):               $OUTDIR/asn_blocklist.txt
ASNs (numbers only):           $OUTDIR/asn_blocklist_only.txt
Big prefixes (filtered):       $OUTDIR/prefixes_annotated.txt
All prefixes (raw):            $OUTDIR/prefixes.txt
Per-IP list (current ban set): $OUTDIR/banned_ips.txt
EOF
)

# Save plain text (no ANSI) for automation
echo "$RECO" > "$OUTDIR/recommendations.txt"

# Print with colors (no sed; match headings once)
echo -e "${GREEN}[✓] Recommendations:${NC}"
while IFS= read -r line; do
  case "$line" in
    "Recommendations generated:"*) printf "%s%s%s\n" "$YELLOW" "$line" "$NC" ;;
    "Summary")                     printf "%s%s%s\n" "$CYAN"   "$line" "$NC" ;;
    "Recommended Actions")         printf "%s%s%s\n" "$CYAN"   "$line" "$NC" ;;
    "Reference Files")             printf "%s%s%s\n" "$CYAN"   "$line" "$NC" ;;
    1\)\ *|2\)\ *|3\)\ *|4\)\ *)  printf "%s%s%s\n" "$MAG"    "$line" "$NC" ;;
    *)                             printf "%s\n" "$line" ;;
  esac
done <<< "$RECO"

# Final output
echo -e "${GREEN}[✓] Done.${NC}"
echo -e "${BLUE}Outputs in $OUTDIR:${NC}"
printf "  ${MAG}%-32s${NC}\n" \
  "status.txt" \
  "banned_ips.txt" \
  "cymru_raw.txt" \
  "ips_enriched.csv" \
  "asn_summary.csv" \
  "prefixes.txt" \
  "prefixes_annotated.txt (min_prefix_count=$MIN_PREFIX_COUNT)" \
  "asn_blocklist.txt (min_asn_count=$MIN_ASN_COUNT)" \
  "asn_blocklist_only.txt" \
  "recommendations.txt"
