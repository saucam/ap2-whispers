#!/bin/bash
# Phase 3c: apply the production-shaped middleware (ZeroID resource server
# OR naive-cookie-shape baseline) to the AP2 v1 credentials provider.
# Idempotent + reversible. Reverse with revert_defense.sh (restores the
# pristine reference executor `agent_executor.py.orig`).
#
# The Phase 3c executor (`agent_executor.py.phase3c`) reads
# `AP2_DEFENSE_MODE` from its environment:
#   AP2_DEFENSE_MODE=zeroid_3c -> real OSS-ZeroID resource-server middleware
#                                  (validate-at-entry via JWKS, aud/exp/scope,
#                                   substitute principal in account tools,
#                                   scope-confine the write/issue tool).
#   AP2_DEFENSE_MODE=naive_3c  -> production-shaped naive comparison
#                                  middleware (same shape, NO oauth2
#                                   properties).
#   AP2_DEFENSE_MODE=none      -> transparent pass-through == unmodified
#                                  AP2 reference (Phase 1 behavior).
#
# Pre-requisites for zeroid_3c:
#   * standalone public `highflame-ai/zeroid` running at :8899
#     (see NOTES_ZEROID_OSS.md for clone + bring-up + bootstrap).
#   * `./zeroid_oss_client.env` exists (written by
#     `zeroid_oss_bootstrap.py`).
#
# Usage:  bash apply_defense_3c.sh <mode>
#   <mode> = zeroid_3c | naive_3c
set -eu
MODE="${1:-}"
if [ "$MODE" != "zeroid_3c" ] && [ "$MODE" != "naive_3c" ]; then
  echo "Usage: $0 <zeroid_3c | naive_3c>" >&2
  exit 2
fi

AP2_CP="$HOME/work/ap2_whispers/AP2/code/samples/python/src/roles/credentials_provider_agent"
DEF="$HOME/work/ap2_whispers/harness/defense"
OSS_ENV="$HOME/work/ap2_whispers/zeroid_oss_client.env"

# Copy in the Phase 3c executor + both middlewares + scope payload + scorer
# (the runner imports payloads/scorer from the harness directly, but the
# AP2 server side needs the middlewares + executor in the agent package).
cp "$DEF/zeroid_middleware_oss.py" "$AP2_CP/zeroid_middleware_oss.py"
cp "$DEF/naive_middleware.py"      "$AP2_CP/naive_middleware.py"
cp "$DEF/agent_executor.py.phase3c" "$AP2_CP/agent_executor.py"
echo "[apply_defense_3c] copied Phase 3c executor + middlewares into AP2 creds-provider package"

# Stop any running stack from a prior phase / variant.
bash "$HOME/work/ap2_whispers/harness/stop.sh" || true

# Phase 3c env flags. Clear older flags from prior phases so they don't
# accidentally double-fire on the new executor.
export AP2_DEFENSE_MODE="$MODE"
unset AP2_SCOPED_CRED_ENFORCE 2>/dev/null || true
unset AP2_ZEROID_ENFORCE       2>/dev/null || true
unset AP2_NAIVEAUTHZ_ENFORCE   2>/dev/null || true
unset AP2_ZEROID_OSS_ENFORCE   2>/dev/null || true

# zeroid_3c also turns ON the new 3c flag the new middleware checks.
if [ "$MODE" = "zeroid_3c" ]; then
  if [ ! -f "$OSS_ENV" ]; then
    echo "ERROR: $OSS_ENV not found." >&2
    echo "Run zeroid_oss_bootstrap.py once first; see NOTES_ZEROID_OSS.md." >&2
    exit 3
  fi
  set -a; source "$OSS_ENV"; set +a
  export AP2_ZEROID_3C_ENFORCE=1
  export AP2_NAIVE_3C_ENFORCE=0
  echo "[apply_defense_3c] mode=zeroid_3c with:"
  echo "  AP2_ZEROID_OSS_BASE=$AP2_ZEROID_OSS_BASE"
  echo "  AP2_ZEROID_OSS_CLIENT_ID=$AP2_ZEROID_OSS_CLIENT_ID"
  echo "  AP2_ZEROID_OSS_ACCOUNT=$AP2_ZEROID_OSS_ACCOUNT"
  echo "  AP2_ZEROID_OSS_PROJECT=$AP2_ZEROID_OSS_PROJECT"
  echo "  AP2_ZEROID_3C_SCOPE=${AP2_ZEROID_3C_SCOPE:-account:read}"
else
  export AP2_NAIVE_3C_ENFORCE=1
  export AP2_ZEROID_3C_ENFORCE=0
  echo "[apply_defense_3c] mode=naive_3c (no OAuth2: no token, no JWKS, no scope)"
  echo "  AP2_NAIVE_3C_SUBJECT=${AP2_NAIVE_3C_SUBJECT:-bugsbunny@gmail.com}"
fi

echo "[apply_defense_3c] launching v1 stack (model=$(grep -E '^AGENT_MODEL' \
    $HOME/work/ap2_whispers/AP2/.env | cut -d= -f2))"

setsid bash "$HOME/work/ap2_whispers/harness/launch_v1.sh"
echo "[apply_defense_3c] v1 stack relaunched (mode=$MODE)"
