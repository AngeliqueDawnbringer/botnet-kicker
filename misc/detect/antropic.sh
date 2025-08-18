#!/usr/bin/env bash
# ===========================================================
# check-anthropic-logs.sh
# -----------------------------------------------------------
# Purpose:
#   Scan Apache, Nginx, and Caddy access logs for requests
#   containing "Anthropic" in the User-Agent.
#
# Features:
#   - Works on live and rotated logs (*.log, *.log.gz)
#   - Apache/Nginx combined log formats supported
#   - Caddy JSON logs supported (best with jq)
#   - Report sections (colorized if TTY):
#       * Sample hits
#       * Count per log file
#       * Unique IPs
#       * Top paths
#       * Status code distribution
#
# Usage:
#   sudo /usr/local/bin/check-anthropic-logs.sh
#
# Notes:
#   - Caddy JSON logs usually live in /var/log/caddy/*.log
#     and contain fields like: status, request>uri, request>remote_ip,
#     request>headers>User-Agent.
#   - If jq is installed, JSON parsing is accurate; otherwise we grep.
# ===========================================================

set -euo pipefail

# Use nullglob so unmatched globs expand to nothing (not literals)
shopt -s nullglob

APACHE_FILES=(/var/log/apache2/*access*.log*)
NGINX_FILES=(/var/log/nginx/*access*.log*)
CADDY_FILES=(/var/log/caddy/*.log*)

# Colors only if interactive
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  BOLD="$(tput bold)"; RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"; CYAN="$(tput setaf 6)"; NC="$(tput sgr0)"
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
fi

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

divider() { echo -e "${BOLD}${CYAN}===========================================================${NC}"; }
section()  { echo -e "${BOLD}${YELLOW}=== $* ===${NC}"; }

# --- helpers for text logs (Apache/Nginx) ---
grep_text_any()   { zgrep -iE "anthropic" "$@" 2>/dev/null || true; }
grep_text_count() { zgrep -iEc "anthropic" "$@" 2>/dev/null || true; }

# --- helpers for Caddy JSON logs ---
caddy_json_any() {
  if [[ $have_jq -eq 1 ]]; then
    jq -r '
      select(.request.headers["User-Agent"][]? | test("Anthropic"; "i")) |
      [
        (.request.remote_ip // .request.remote_addr // "-"),
        (.status // "-"),
        (.request.method // "-"),
        (.request.uri // "-"),
        ("UA=" + ((.request.headers["User-Agent"][0]) // "-"))
      ] | @tsv
    ' "$@" 2>/dev/null || true
  else
    zgrep -i "Anthropic" "$@" 2>/dev/null || true
  fi
}
caddy_json_ips() {
  if [[ $have_jq -eq 1 ]]; then
    jq -r '
      select(.request.headers["User-Agent"][]? | test("Anthropic"; "i")) |
      (.request.remote_ip // .request.remote_addr // empty)
    ' "$@" 2>/dev/null || true
  else
    zgrep -i "Anthropic" "$@" 2>/dev/null | awk -F'"remote_ip":' '{print $2}' \
      | awk -F'"' '{print $2}' | sed '/^$/d' || true
  fi
}
caddy_json_paths() {
  if [[ $have_jq -eq 1 ]]; then
    jq -r '
      select(.request.headers["User-Agent"][]? | test("Anthropic"; "i")) |
      (.request.uri // empty)
    ' "$@" 2>/dev/null || true
  else
    zgrep -i "Anthropic" "$@" 2>/dev/null | awk -F'"uri":' '{print $2}' \
      | awk -F'"' '{print $2}' | sed '/^$/d' || true
  fi
}
caddy_json_status() {
  if [[ $have_jq -eq 1 ]]; then
    jq -r '
      select(.request.headers["User-Agent"][]? | test("Anthropic"; "i")) |
      (.status // empty)
    ' "$@" 2>/dev/null || true
  else
    zgrep -i "Anthropic" "$@" 2>/dev/null | awk -F'"status":' '{print $2}' \
      | awk -F'[ ,}]' '{print $1}' | grep -E '^[0-9]{3}$' || true
  fi
}

divider
echo -e "${BOLD}${CYAN}Anthropic User-Agent Log Report${NC}"
divider
echo

# Count total discovered files robustly (no bash arithmetic with ==)
APACHE_COUNT=${#APACHE_FILES[@]}
NGINX_COUNT=${#NGINX_FILES[@]}
CADDY_COUNT=${#CADDY_FILES[@]}
TOTAL_FILES=$((APACHE_COUNT + NGINX_COUNT + CADDY_COUNT))

if [ "$TOTAL_FILES" -eq 0 ]; then
  echo -e "${RED}No log files found under:${NC}"
  echo "  /var/log/apache2/*access*.log*"
  echo "  /var/log/nginx/*access*.log*"
  echo "  /var/log/caddy/*.log*"
  exit 0
fi

section "Samples (first 5 lines per family)"
if [ "$APACHE_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Apache:${NC}"
  grep_text_any "${APACHE_FILES[@]}" | head -n 5 || echo "No matches."
  echo
fi
if [ "$NGINX_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Nginx:${NC}"
  grep_text_any "${NGINX_FILES[@]}" | head -n 5 || echo "No matches."
  echo
fi
if [ "$CADDY_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Caddy:${NC}"
  caddy_json_any "${CADDY_FILES[@]}" | head -n 5 || echo "No matches."
  echo
fi

section "Count per log file"
if [ "$APACHE_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Apache:${NC}"
  grep_text_count "${APACHE_FILES[@]}"
fi
if [ "$NGINX_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Nginx:${NC}"
  grep_text_count "${NGINX_FILES[@]}"
fi
if [ "$CADDY_COUNT" -gt 0 ]; then
  echo -e "${BOLD}Caddy:${NC}"
  if [ "$have_jq" -eq 1 ]; then
    for f in "${CADDY_FILES[@]}"; do
      c=$(jq -r 'select(.request.headers["User-Agent"][]? | test("Anthropic"; "i")) | 1' "$f" 2>/dev/null | wc -l || echo 0)
      printf "%8d %s\n" "$c" "$f"
    done
  else
    zgrep -iEc "Anthropic" "${CADDY_FILES[@]}" 2>/dev/null || true
  fi
fi
echo

section "Unique IPs (top 20)"
{
  if [ "$APACHE_COUNT" -gt 0 ]; then grep_text_any "${APACHE_FILES[@]}"; fi
  if [ "$NGINX_COUNT" -gt 0 ]; then grep_text_any "${NGINX_FILES[@]}"; fi
} | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 20 || true
if [ "$CADDY_COUNT" -gt 0 ]; then
  caddy_json_ips "${CADDY_FILES[@]}" | sort | uniq -c | sort -nr | head -n 20 || true
fi
echo

section "Top paths (top 20)"
{
  if [ "$APACHE_COUNT" -gt 0 ]; then grep_text_any "${APACHE_FILES[@]}"; fi
  if [ "$NGINX_COUNT" -gt 0 ]; then grep_text_any "${NGINX_FILES[@]}"; fi
} | awk -F\" '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 20 || true
if [ "$CADDY_COUNT" -gt 0 ]; then
  caddy_json_paths "${CADDY_FILES[@]}" | sort | uniq -c | sort -nr | head -n 20 || true
fi
echo

section "Status codes"
{
  if [ "$APACHE_COUNT" -gt 0 ]; then grep_text_any "${APACHE_FILES[@]}"; fi
  if [ "$NGINX_COUNT" -gt 0 ]; then grep_text_any "${NGINX_FILES[@]}"; fi
} | awk '{print $9}' | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -nr || true
if [ "$CADDY_COUNT" -gt 0 ]; then
  caddy_json_status "${CADDY_FILES[@]}" | sort | uniq -c | sort -nr || true
fi
echo

divider
echo -e "${BOLD}${GREEN}Report complete.${NC}"
divider
