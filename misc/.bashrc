findip() {
  local ip="$1"
  local found=0

  if [[ -z "$ip" ]]; then
    echo "Usage: findip <ip-or-ipv6>"
    return 2
  fi

  echo "== Checking ipset membership =="
  for set in $(sudo ipset list -name 2>/dev/null); do
    if sudo ipset test "$set" "$ip" &>/dev/null; then
      echo "✓ $ip is in ipset: $set"
      found=1
    fi
  done

  echo
  echo "== Checking Fail2ban jails =="
  local jails_raw
  jails_raw=$(sudo fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p')
  local jails
  jails=$(printf '%s\n' "$jails_raw" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')

  for jail in $jails; do
    if sudo fail2ban-client get "$jail" banip 2>/dev/null | tr ' ' '\n' | grep -Fxq "$ip"; then
      echo "✓ $ip is banned in jail: $jail"
      found=1
    fi
  done

  if [[ $found -eq 0 ]]; then
    echo "✗ $ip not found in any ipset or jail."
  fi
}
