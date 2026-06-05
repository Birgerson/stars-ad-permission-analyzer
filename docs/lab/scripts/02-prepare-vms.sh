#!/usr/bin/env bash
# Lab Phase 2 — Hostname, statische IP, DNS=self, Local-Admin-Passwort, AD-DS-Feature.
# Voraussetzungen:
#   - VMs sind oben (qemu-guest-agent erreichbar).
#   - $LAB_ADMIN_PASSWORD ist gesetzt.
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

TIER0_VMID="${TIER0_VMID:-100}"
TIER1_VMID="${TIER1_VMID:-101}"
TIER2_VMID="${TIER2_VMID:-102}"

TIER0_IP="${TIER0_IP:-192.168.11.100}"
TIER1_IP="${TIER1_IP:-192.168.11.101}"
TIER2_IP="${TIER2_IP:-192.168.11.102}"
GATEWAY="${GATEWAY:-192.168.11.1}"

run_ps() {
    local vmid="$1"
    local ps_file="$2"
    local label="$3"
    echo "=== $label (VMID $vmid) ==="
    local ENC
    ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout 600 -- powershell -NoProfile -EncodedCommand "$ENC"
}

write_prep_ps() {
    local target_hostname="$1"
    local target_ip="$2"
    local out_file="$3"
    cat > "$out_file" <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference = "SilentlyContinue"

# Local Administrator password (template may have none)
& net user Administrator "${LAB_ADMIN_PASSWORD}" | Out-Null

\$adapter = Get-NetAdapter | Where-Object { \$_.Status -eq "Up" } | Select-Object -First 1
\$ifa = \$adapter.InterfaceAlias

Get-NetIPAddress -InterfaceAlias \$ifa -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:\$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceAlias \$ifa -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:\$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceAlias \$ifa -IPAddress "${target_ip}" -PrefixLength 24 -DefaultGateway "${GATEWAY}" | Out-Null
Set-DnsClientServerAddress -InterfaceAlias \$ifa -ServerAddresses 127.0.0.1

Rename-Computer -NewName "${target_hostname}" -Force
\$f = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
"prep-ok: \$(\$f.Success) restart-needed=\$(\$f.RestartNeeded)"
PSEOF
}

write_prep_ps "tier1" "$TIER1_IP" /tmp/prep-tier1.ps1
write_prep_ps "tier2" "$TIER2_IP" /tmp/prep-tier2.ps1
run_ps "$TIER1_VMID" /tmp/prep-tier1.ps1 "prepare tier1"
run_ps "$TIER2_VMID" /tmp/prep-tier2.ps1 "prepare tier2"

# Reboot to apply hostname-rename
for V in "$TIER1_VMID" "$TIER2_VMID"; do
    echo "=== reboot VMID $V ==="
    qm shutdown "$V" --timeout 180
    qm start "$V"
done
