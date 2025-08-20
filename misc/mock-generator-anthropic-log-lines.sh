#!/usr/bin/env bash
# gen-anthropic-logs.sh
# Generate 200 test loglines (100 good, 100 bad) in Nginx combined format.

OUT="anthropic-test.log"
: > "$OUT"

GOOD_V4=(160.79.104.10 160.79.105.44)
GOOD_V6=("2607:6bc0::123" "2607:6bc0::dead:beef")
BAD_V4=(198.51.100.23 203.0.113.42 192.0.2.77)
BAD_V6=("2001:db8::1234" "2001:db8:abcd::1")

for i in $(seq 1 100); do
  # good IPv4
  ip=${GOOD_V4[$RANDOM % ${#GOOD_V4[@]}]}
  ts=$(date -d "now - $((RANDOM%3600)) sec" '+%d/%b/%Y:%H:%M:%S %z')
  echo "$ip - - [$ts] \"GET /anthropic$i HTTP/1.1\" 200 123 \"-\" \"Anthropic/1.0\"" >>"$OUT"

  # good IPv6
  ip=${GOOD_V6[$RANDOM % ${#GOOD_V6[@]}]}
  ts=$(date -d "now - $((RANDOM%3600)) sec" '+%d/%b/%Y:%H:%M:%S %z')
  echo "$ip - - [$ts] \"POST /anthropic$i HTTP/1.1\" 200 234 \"-\" \"Anthropic/1.0\"" >>"$OUT"

  # bad IPv4 spoof
  ip=${BAD_V4[$RANDOM % ${#BAD_V4[@]}]}
  ts=$(date -d "now - $((RANDOM%3600)) sec" '+%d/%b/%Y:%H:%M:%S %z')
  echo "$ip - - [$ts] \"GET /anthropic$i HTTP/1.1\" 200 321 \"-\" \"Mozilla/5.0 (pretending to be Anthropic)\"" >>"$OUT"

  # bad IPv6 spoof
  ip=${BAD_V6[$RANDOM % ${#BAD_V6[@]}]}
  ts=$(date -d "now - $((RANDOM%3600)) sec" '+%d/%b/%Y:%H:%M:%S %z')
  echo "$ip - - [$ts] \"POST /anthropic$i HTTP/1.1\" 403 456 \"-\" \"Mozilla/5.0 (Anthropic Spoof)\"" >>"$OUT"
done

echo "Generated $(wc -l < "$OUT") lines in $OUT"
