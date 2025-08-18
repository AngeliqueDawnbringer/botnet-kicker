#!/usr/bin/env bash
# ===========================================================
# f2b-ban-explain.sh
# -----------------------------------------------------------
# Purpose:
#   Summarize current bans per Fail2ban jail and provide a
#   short, human-friendly reason for each jail's bans.
#
# Output:
#   - Colourized console table
#   - Optional CSV and Markdown exports
#
# Usage:
#   sudo /usr/local/bin/f2b-ban-explain.sh
#   sudo /usr/local/bin/f2b-ban-explain.sh --csv bans.csv --md bans.md
#
# Notes:
#   - Requires root to read the Fail2ban socket.
#   - Explanations are heuristics based on common filter names
#     (sshd, apache-*, nginx-*, recidive, postfix, dovecot, etc.).
# ===========================================================

set -euo pipefail

CSV_OUT=""
MD_OUT=""

# Parse CLI
while [[ $# -gt 0 ]]; do
  case "$1" in
    --csv) CSV_OUT="${2:-}"; shift 2;;
    --md|--markdown) MD_OUT="${2:-}"; shift 2;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "[!] Unknown arg: $1" >&2; exit 1;;
  esac
done

# Root check (Fail2ban socket)
if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "\033[1;31m[!] Must run as root (Fail2ban socket requires root).\033[0m"
  exit 1
fi

# Colors if TTY
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  BOLD="$(tput bold)"; RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"; CYAN="$(tput setaf 6)"; NC="$(tput sgr0)"
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
fi

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Get list of jails (robust against formatting)
STATUS_ALL="$(fail2ban-client status 2>&1 || true)"
if echo "$STATUS_ALL" | grep -qi 'permission denied'; then
  echo -e "${RED}[!] Permission denied to Fail2ban socket. Run as root.${NC}"
  exit 2
fi

# Try to parse “Jail list: …”
JAILS_LINE="$(printf '%s\n' "$STATUS_ALL" | awk -F: '/Jail list:/ {print $2; exit}')"
declare -a JAILS=()
if [[ -n "$JAILS_LINE" ]]; then
  # Comma or space separated
  read -r -a JAILS <<<"$(echo "$JAILS_LINE" | tr ',' ' ' | xargs)"
else
  # Fallback: scan lines after "Jail list:" block (for older outputs)
  JAILS_BLOCK="$(printf '%s\n' "$STATUS_ALL" | awk '
    /^Jail list:/ { inb=1; next }
    inb {
      if ($0 ~ /^[[:space:]]*$/) exit
      print
    }')"
  if [[ -n "$JAILS_BLOCK" ]]; then
    read -r -a JAILS <<<"$(echo "$JAILS_BLOCK" | tr ',' ' ' | xargs)"
  fi
fi

if [[ ${#JAILS[@]} -eq 0 ]]; then
  echo -e "${YELLOW}[i] No jails found or Fail2ban is not running.${NC}"
  exit 0
fi

# Heuristic explanations by filter/jail name
explain_filter() {
  local name="$1"
  name="$(echo "$name" | tr '[:upper:]' '[:lower:]')"

  case "$name" in
    sshd|ssh|sshd-auth) echo "Repeated SSH authentication failures (password/bruteforce)."; return;;
    recidive|recidiv*) echo "Repeat offenders across multiple jails within a timeframe."; return;;
    apache-auth|apache-auth*|http-auth|nginx-http-auth)
      echo "Repeated HTTP auth failures (basic/digest/login endpoint)."; return;;
    apache-badbots*|badbots*|nginx-badbots*)
      echo "Known bad/crawler user-agents or disallowed bots."; return;;
    apache-botsearch*|botsearch*)
      echo "Aggressive scanning/crawling of web paths/endpoints."; return;;
    apache-noscript*|noscript*)
      echo "Requests for scripts/executables where not allowed."; return;;
    apache-overflows*|overflow*)
      echo "Suspicious long/overflowing HTTP requests."; return;;
    apache-nohome*|nohome*)
      echo "Requests to non-existent users' home pages."; return;;
    apache-nohttps*|nohttps*)
      echo "HTTP access where HTTPS is required."; return;;
    nginx-botsearch*|nginx-noscript*|nginx-proxy*)
      echo "Web scanning or disallowed script/proxy access on Nginx."; return;;
    postfix*|sasl|dovecot*|exim*)
      echo "Mail service auth failures or abuse (SMTP/IMAP/POP3)."; return;;
    pureftpd*|vsftpd*|proftpd*) echo "FTP login failures or abuse."; return;;
    pam-generic|pam*)
      echo "Generic PAM authentication failures across services."; return;;
    mysql*|mariadb*) echo "Database login failures or abuse."; return;;
    named*|bind*) echo "DNS server abuse or query anomalies."; return;;
    docker-*) echo "Service in Docker jail (name-prefixed)."; return;;
    *anthropic*) echo "Anthropic User-Agent causing errors / violating rules."; return;;
    *signup*|*register*|*signup-abuse*)
      echo "Abusive signup/registration attempts or form submission floods."; return;;
    *wordpress*|*wp-*)
      echo "WordPress-specific abuse (wp-login, xmlrpc, scanning)."; return;;
    *)
      echo "Matches filter ‘$1’ (see filter.d); typical cause: repeated errors or abuse patterns."; return;;
  esac
}

# Try to resolve each jail's filter name (optional; if not available, use jail name)
resolve_filter() {
  local jail="$1"
  # Use fail2ban-client to dump jail info and grep "Filter file" or infer
  local dump; dump="$(fail2ban-client get "$jail" logpath 2>/dev/null || true)"
  # Many installs don't expose filter name directly via client; fallback to jail name
  # If filter is accessible:
  # fail2ban-client get "$jail" addignoreip  (not helpful), so we parse status line “|- Filter”
  local st; st="$(fail2ban-client status "$jail" 2>/dev/null || true)"
  local maybe
  maybe="$(printf '%s\n' "$st" | awk -F'Filter:' '/Filter:/ {print $2; exit}')"
  if [[ -n "$maybe" ]]; then
    echo "$jail"  # status does not reveal name; stick to jail id
  else
    echo "$jail"
  fi
}

# Collect rows: Jail, CurrentlyBanned, TotalBanned, Reason
rows=()
total_banned_now=0

for jail in "${JAILS[@]}"; do
  STATUS="$(fail2ban-client status "$jail" 2>/dev/null || true)"
  if [[ -z "$STATUS" ]]; then
    rows+=("$jail|ERR|ERR|Could not read jail status.")
    continue
  fi

  cur="$(printf '%s\n' "$STATUS" | awk -F'\t' '/Currently banned:/ {print $2; exit}' | xargs || true)"
  [[ -z "$cur" ]] && cur=0
  tot="$(printf '%s\n' "$STATUS" | awk -F'\t' '/Total banned:/ {print $2; exit}' | xargs || true)"
  [[ -z "$tot" ]] && tot=0

  # Use jail name as filter hint; explanations are heuristic
  reason="$(explain_filter "$jail")"

  rows+=("$jail|$cur|$tot|$reason")
  if [[ "$cur" =~ ^[0-9]+$ ]]; then
    total_banned_now=$(( total_banned_now + cur ))
  fi
done

# Optional CSV/MD headers
if [[ -n "$CSV_OUT" ]]; then
  echo "jail,currently_banned,total_banned,reason" > "$CSV_OUT"
fi
if [[ -n "$MD_OUT" ]]; then
  {
    echo "# Fail2ban Ban Summary"
    echo ""
    echo "- Generated: $(timestamp) UTC"
    echo "- Jails scanned: ${#JAILS[@]}"
    echo "- Currently banned (total across jails): $total_banned_now"
    echo ""
    echo "| Jail | Currently Banned | Total Banned | Reason |"
    echo "|------|-------------------|--------------|--------|"
  } > "$MD_OUT"
fi

# Console header
echo -e "${BOLD}${CYAN}Fail2ban Ban Summary — $(timestamp) UTC${NC}"
echo -e "${BOLD}Jails:${NC} ${#JAILS[@]}    ${BOLD}Currently banned (sum):${NC} $total_banned_now"
printf "%-28s %12s %14s  %s\n" "Jail" "Current" "Total" "Reason"
printf "%-28s %12s %14s  %s\n" "----------------------------" "--------" "------------" "-------------------------------"

# Emit rows
for r in "${rows[@]}"; do
  IFS='|' read -r jail cur tot reason <<<"$r"
  # Console
  printf "%-28s %12s %14s  %s\n" "$jail" "$cur" "$tot" "$reason"

  # CSV
  if [[ -n "$CSV_OUT" ]]; then
    # Escape quotes in reason
    safe_reason="${reason//\"/\"\"}"
    echo "\"$jail\",$cur,$tot,\"$safe_reason\"" >> "$CSV_OUT"
  fi
  # MD
  if [[ -n "$MD_OUT" ]]; then
    echo "| \`$jail\` | $cur | $tot | $reason |" >> "$MD_OUT"
  fi
done

# Footers
if [[ -n "$CSV_OUT" ]]; then
  echo -e "${GREEN}[✓] CSV written:${NC} $CSV_OUT"
fi
if [[ -n "$MD_OUT" ]]; then
  echo -e "${GREEN}[✓] Markdown written:${NC} $MD_OUT"
fi
