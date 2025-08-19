#!/bin/bash
# generator.sh - append dummy JSON loglines every 5s
# mixes IPv4 and IPv6 addresses

LOGFILE="/var/log/web_suspects.jsonl"

while true; do
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # 20% chance to generate IPv6
  if (( RANDOM % 5 == 0 )); then
    # IPv6 example 2001:db8::/32 reserved for documentation
    ip="2001:db8:$(printf '%x' $((RANDOM%65536))):$(printf '%x' $((RANDOM%65536)))::$(printf '%x' $((RANDOM%65536)))"
  else
    # IPv4 example 203.0.113.0/24 reserved for docs
    ip="203.0.113.$((RANDOM % 200 + 10))"
  fi

  # coin flip: good vs bad
  if (( RANDOM % 2 )); then
    risk=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.1f", 8+rand()*2)}')
    mode="unsupervised"
    count=$((RANDOM % 200 + 100))
    ratio4xx=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.2f", 0.4+rand()*0.3)}')
    ua_entropy=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.2f", 5.0+rand()*1.5)}')
  else
    risk=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.1f", 1+rand()*2)}')
    mode="supervised"
    count=$((RANDOM % 30 + 10))
    ratio4xx=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.2f", rand()*0.05)}')
    ua_entropy=$(awk -v r=$RANDOM 'BEGIN{srand(r); printf("%.2f", 4.0+rand()*0.5)}')
  fi

  echo "{\"ts\":\"$ts\",\"ip\":\"$ip\",\"risk\":$risk,\"mode\":\"$mode\",\"features\":{\"count\":$count,\"ratio4xx\":$ratio4xx},\"sample\":{\"ua_entropy\":$ua_entropy}}" >> "$LOGFILE"

  sleep 5
done
