#!/bin/bash
# Phase 3b-oss: apply the OSS-ZeroID credentials-provider executor (talks to
# the PUBLIC, standalone highflame-ai/zeroid service via its own docker-
# compose) into the AP2 v1 tree, then relaunch the v1 stack with the OSS
# enforce flag ON. Idempotent. Reverse with revert_defense.sh (restores the
# pristine reference executor; variant-agnostic).
#
# Pre-requisite: the public `highflame-ai/zeroid` service must be up
# (default :8899) AND `./zeroid_oss_client.env` must exist
# (written by zeroid_oss_bootstrap.py, sourced below to inject
# AP2_ZEROID_OSS_CLIENT_ID/_SECRET/_ACCOUNT/_PROJECT into the v1 launch
# environment). The bootstrap is a one-shot; subsequent runs reuse the
# registered identity + OAuth client.
#
# Usage:  bash apply_defense_oss.sh
set -eu
AP2_CP="$HOME/work/ap2_whispers/AP2/code/samples/python/src/roles/credentials_provider_agent"
DEF="$HOME/work/ap2_whispers/harness/defense"
OSS_ENV="$HOME/work/ap2_whispers/zeroid_oss_client.env"

if [ ! -f "$OSS_ENV" ]; then
  echo "ERROR: $OSS_ENV not found." >&2
  echo "Run zeroid_oss_bootstrap.py once first; see NOTES_ZEROID_OSS.md." >&2
  exit 2
fi

cp "$DEF/zeroid_oss_credential.py" "$AP2_CP/zeroid_oss_credential.py"
cp "$DEF/agent_executor.py.phase3b_oss" "$AP2_CP/agent_executor.py"
echo "phase3b-oss executor + OSS guard copied into AP2 creds-provider package"

bash "$HOME/work/ap2_whispers/harness/stop.sh" || true

export AP2_ZEROID_OSS_ENFORCE=1
unset AP2_ZEROID_ENFORCE   2>/dev/null || true
unset AP2_NAIVEAUTHZ_ENFORCE 2>/dev/null || true
# Source the bootstrap-produced client creds so launch_v1.sh's
# `--preserve-env` propagates them into the v1 role servers.
set -a; source "$OSS_ENV"; set +a
echo "launching v1 with REAL standalone OSS-ZeroID enforcement"
echo "  AP2_ZEROID_OSS_BASE=$AP2_ZEROID_OSS_BASE"
echo "  AP2_ZEROID_OSS_CLIENT_ID=$AP2_ZEROID_OSS_CLIENT_ID"
echo "  AP2_ZEROID_OSS_ACCOUNT=$AP2_ZEROID_OSS_ACCOUNT"
echo "  AP2_ZEROID_OSS_PROJECT=$AP2_ZEROID_OSS_PROJECT"

# launch_v1.sh sources AP2/.env (which pins AGENT_MODEL=gemini-2.5-flash for
# Gap A consistency) and propagates AP2_* enforce flags from this env.
AP2_ZEROID_OSS_PRINCIPAL="${AP2_ZEROID_OSS_PRINCIPAL:-bugsbunny@gmail.com}" \
setsid bash "$HOME/work/ap2_whispers/harness/launch_v1.sh"
echo "v1 stack relaunched (variant=zeroid_oss, model=gemini-2.5-flash)"
