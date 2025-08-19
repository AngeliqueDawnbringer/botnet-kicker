findip() {
  local query="$1"
  local found=0

  if [[ -z "$query" ]]; then
    echo "Usage: findip <ip-or-pattern>"
    echo "Examples:"
    echo "  findip 203.0.113.42     # exact"
    echo "  findip 203.0.113.       # partial"
    echo "  findip '2001:db8::'    # IPv6 prefix"
    echo "  findip '203\\.0\\.113\\.[0-9]*'  # regex"
    return 2
  fi

  echo "== Checking ipset membership =="
  for set in $(sudo ipset list -name 2>/dev/null); do
    matches=$(sudo ipset list "$set" | awk '/Members:/,/^$/' | tail -n +2 | grep -E "$query" | sort -V || true)
    if [[ -n "$matches" ]]; then
      echo "✓ Found in $set:"
      echo "$matches" | sed 's/^/   /'
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
    matches=$(sudo fail2ban-client get "$jail" banip 2>/dev/null | tr ' ' '\n' | grep -E "$query" | sort -V || true)
    if [[ -n "$matches" ]]; then
      echo "✓ Found in jail $jail:"
      echo "$matches" | sed 's/^/   /'
      found=1
    fi
  done

  if [[ $found -eq 0 ]]; then
    echo "✗ No match for pattern: $query"
  fi
}
