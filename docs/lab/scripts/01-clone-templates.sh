#!/usr/bin/env bash
# Lab phase 1 — clones 2 additional DCs from the Windows Server 2022 template.
# Existing VMID 100 is left untouched here — its repurposing is lab specific
# (see ../setup-procedure.md, phase B).
#
# Prerequisites:
#   - Template VM exists (in our lab: VMID 9000).
#   - VMIDs 101 and 102 are free.
set -eu

TEMPLATE_VMID="${TEMPLATE_VMID:-9000}"
TIER1_VMID="${TIER1_VMID:-101}"
TIER2_VMID="${TIER2_VMID:-102}"

echo "=== clone $TEMPLATE_VMID -> tier1 ($TIER1_VMID) ==="
qm clone "$TEMPLATE_VMID" "$TIER1_VMID" --name tier1
qm set "$TIER1_VMID" --memory 16384

echo "=== clone $TEMPLATE_VMID -> tier2 ($TIER2_VMID) ==="
qm clone "$TEMPLATE_VMID" "$TIER2_VMID" --name tier2
qm set "$TIER2_VMID" --memory 16384

echo "=== start ==="
qm start "$TIER1_VMID"
qm start "$TIER2_VMID"

echo "=== status ==="
qm list | awk 'NR==1 || $1 ~ /^('"$TEMPLATE_VMID"'|'"$TIER1_VMID"'|'"$TIER2_VMID"')$/ { print }'
