#!/bin/bash
# Headless launcher: AP2 v2 / human-not-present / cards. Reuses
# scenarios/.../cards/run.sh server-start logic, DROPS the web-client/npm
# block. Services are setsid-detached so they persist after the launcher
# (nohup'd) exits. Driven by driver_v2.py.
set -eu

AP2_PY="$HOME/work/ap2_whispers/AP2/code/samples/python"
SCEN_DIR="$AP2_PY/scenarios/a2a/human-not-present/cards"
HARNESS="$HOME/work/ap2_whispers/harness"
export PATH="$HOME/.local/bin:$PATH"

readonly AGENT_PORT=8080
readonly MERCHANT_TRIGGER_PORT=8081
readonly CREDENTIALS_PROVIDER_PORT=8082
readonly PAYMENT_PROCESSOR_PORT=8083

set -a
source "$HOME/work/ap2_whispers/AP2/.env"
set +a

export TEMP_DB_DIR="$SCEN_DIR/.temp-db"
export LOGS_DIR="$SCEN_DIR/.logs"
rm -rf "$TEMP_DB_DIR" "$LOGS_DIR"
mkdir -p "$TEMP_DB_DIR" "$LOGS_DIR"

export MERCHANT_TRIGGER_STATE_PATH="$TEMP_DB_DIR/merchant_trigger_state.json"
export AP2_TOKEN_STORE_PATH="$TEMP_DB_DIR/ap2_token_store.json"
export MERCHANT_INVENTORY_PATH="$TEMP_DB_DIR/merchant_inventory.json"
export AGENT_PUBLIC_KEY_PATH="$TEMP_DB_DIR/agent_signing_key.pub"
export MERCHANT_SIGNING_KEY_PATH="$TEMP_DB_DIR/merchant_signing_key.pem"
export FLOW=card

PIDFILE="$HARNESS/.v2_pids"
: > "$PIDFILE"

kill_port() { local pid; pid=$(lsof -ti tcp:"$1" 2>/dev/null || true); [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true; }

start_service() {
  local name="$1" dir="$2" cmd="$3"
  echo "Starting ${name}..."
  ( cd "$dir" && setsid bash -c "$cmd" >"$LOGS_DIR/${name}.log" 2>&1 & echo $! >> "$PIDFILE" )
}

cd "$AP2_PY"
uv sync --quiet 2>/dev/null || true

kill_port $MERCHANT_TRIGGER_PORT
start_service "merchant-trigger" "$AP2_PY/src/roles/merchant_agent_mcp" "uv run python trigger_server.py"
sleep 1
kill_port $CREDENTIALS_PROVIDER_PORT
start_service "credentials-provider" "$AP2_PY/src/roles/credentials_provider_mcp" "uv run python trigger_server.py"
sleep 1
kill_port $PAYMENT_PROCESSOR_PORT
start_service "merchant-payment-processor" "$AP2_PY/src/roles/merchant_payment_processor_mcp" "uv run python trigger_server.py"
sleep 1
kill_port $AGENT_PORT
start_service "agent" "$AP2_PY/src/roles/shopping_agent_v2" "uv run python run_server.py"

echo "Waiting for agent card..."
for i in $(seq 1 120); do
  if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$AGENT_PORT/a2a/shopping_agent/.well-known/agent-card.json" 2>/dev/null | grep -q 200; then
    echo "v2 stack UP (agent card live)"; exit 0
  fi
  sleep 1
done
echo "ERROR: v2 agent card never came up" >&2
tail -20 "$LOGS_DIR/agent.log" >&2 || true
exit 1
