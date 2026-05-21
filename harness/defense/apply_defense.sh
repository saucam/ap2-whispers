#!/bin/bash
# Phase 3: apply the ZeroID-style scoped-credential defense to the AP2 v1
# credentials provider, then (re)launch the v1 stack with enforcement ON.
# Idempotent. Reverse with revert_defense.sh.
set -eu
AP2_CP="$HOME/work/ap2_whispers/AP2/code/samples/python/src/roles/credentials_provider_agent"
DEF="$HOME/work/ap2_whispers/harness/defense"
cp "$DEF/scoped_credential.py" "$AP2_CP/scoped_credential.py"
cp "$DEF/agent_executor.py.patched" "$AP2_CP/agent_executor.py"
echo "defense applied (scoped_credential.py + patched agent_executor.py)"
bash "$HOME/work/ap2_whispers/harness/stop.sh"
AP2_SCOPED_CRED_ENFORCE=1 setsid bash "$HOME/work/ap2_whispers/harness/launch_v1.sh"
echo "v1 stack relaunched with AP2_SCOPED_CRED_ENFORCE=1"
