findipset() {
  ip="$1"
  for set in $(sudo ipset list -name); do
    if sudo ipset test "$set" "$ip" 2>/dev/null | grep -q "is in set"; then
      echo "$ip is in $set"
    fi
  done
}
