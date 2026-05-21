#!/bin/bash
# Kill all harness-launched servers (both v1 and v2).
HARNESS="$HOME/work/ap2_whispers/harness"
for pf in "$HARNESS/.v2_pids" "$HARNESS/.v1_pids"; do
  [ -f "$pf" ] && while read -r pid; do kill -9 "$pid" 2>/dev/null || true; done < "$pf"
  [ -f "$pf" ] && : > "$pf"
done
for p in 8080 8081 8082 8083 8001 8002 8003 8000; do
  pid=$(lsof -ti tcp:$p 2>/dev/null || true); [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
done
pkill -9 -f "run_server.py" 2>/dev/null || true
pkill -9 -f "roles.merchant_agent" 2>/dev/null || true
pkill -9 -f "roles.credentials_provider_agent" 2>/dev/null || true
pkill -9 -f "roles.merchant_payment_processor_agent" 2>/dev/null || true
pkill -9 -f "adk api_server" 2>/dev/null || true
pkill -9 -f "trigger_server.py" 2>/dev/null || true
echo "stopped"
