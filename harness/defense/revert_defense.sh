#!/bin/bash
# Phase 3: revert to the pristine AP2 reference credentials provider.
set -eu
AP2_CP="$HOME/work/ap2_whispers/AP2/code/samples/python/src/roles/credentials_provider_agent"
DEF="$HOME/work/ap2_whispers/harness/defense"
cp "$DEF/agent_executor.py.orig" "$AP2_CP/agent_executor.py"
echo "reverted to pristine reference agent_executor.py (scoped_credential.py left in place, inert)"
