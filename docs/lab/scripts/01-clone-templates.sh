#!/usr/bin/env bash
# Lab Phase 1 — Klont 2 weitere DCs aus dem Windows-Server-2022-Template.
# Existierende VMID 100 wird hier nicht angetastet — die Umwidmung ist Lab-spezifisch
# (siehe ../setup-procedure.md, Phase B).
#
# Voraussetzungen:
#   - Template-VM existiert (in unserem Lab: VMID 9000).
#   - VMIDs 101 und 102 sind frei.
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
