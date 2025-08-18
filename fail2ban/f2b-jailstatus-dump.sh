#!/usr/bin/env bash
# ===========================================================
# f2b-jailstatus-dump.sh
# -----------------------------------------------------------
# Purpose:
#   Dump status information for each active Fail2ban jail
#   into separate log files under /var/www/html/log.
#
# Features:
#   - One log file per jail: /var/www/html/log/<jail>.log
#   - Ensures /var/www/html/log exists (created if missing).
#   - Runs only as root (fail2ban socket requires root).
#   - Console output in colour (for interactive readability).
#   - Log files kept in plain text (safe for web serving).
#
# Example crontab:
#   */5 * * * * root /usr/local/bin/f2b-jailstatus-dump.sh >/dev/null 2>&1
#
# Example log (apache-signup-abuse.log):
#   Status for the jail: apache-signup-abuse
#   # Updated: 2025-08-18T21:45:01Z
#   |- Filter
#   |  |- Currently failed:  1
#   |  |- Total failed:      586
#   |  `- File list:         /var/log/apache2/access.log
#   `- Actions
#      |- Currently banned:  1
#      |- Total banned:      221
#      `- Banned IP list:    154.192.138.12
#
# ===========================================================

set -euo pipefail

OUTDIR="/var/www/html/log"

# Ensure we run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "\033[1;31m[!] Must be run as root (fail2ban socket requires root).\033[0m"
    exit 1
fi

# Create directory if missing (fix rights only on first creation)
if [[ ! -d "$OUTDIR" ]]; then
    mkdir -p "$OUTDIR"
    chown www-data:www-data "$OUTDIR"
    chmod 755 "$OUTDIR"
fi

# Colours (only if stdout is a terminal)
if [[ -t 1 ]]; then
    GREEN=$(tput bold; tput setaf 2)
    YELLOW=$(tput bold; tput setaf 3)
    CYAN=$(tput bold; tput setaf 6)
    RED=$(tput bold; tput setaf 1)
    NC=$(tput sgr0)
else
    GREEN=""; YELLOW=""; CYAN=""; RED=""; NC=""
fi

# Get list of jails
if ! JAILS=$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list:/ {print $2}' | tr ',' ' ' | xargs); then
    echo -e "${RED}[!] Could not connect to fail2ban. Are you root?${NC}"
    exit 1
fi

if [[ -z "$JAILS" ]]; then
    echo -e "${YELLOW}[!] No jails found in fail2ban.${NC}"
    exit 0
fi

for jail in $JAILS; do
    logfile="$OUTDIR/${jail}.log"
    {
        echo "Status for the jail: $jail"
        echo "# Updated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        fail2ban-client status "$jail" || echo "Error: could not fetch status for jail $jail"
    } > "$logfile"

    # Ensure correct permissions (if not already)
    chown www-data:www-data "$logfile"
    chmod 644 "$logfile"

    echo -e "${CYAN}[*] Jail:${NC} $jail → ${GREEN}updated${NC} (${logfile})"
done

echo -e "${GREEN}[✓] All jail statuses updated.${NC}"
