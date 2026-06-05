#!/usr/bin/env bash
# Lab Phase 5 — Conditional DNS Forwarders zwischen allen drei Forests.
set -eu

write_cf_ps() {
    local out_file="$1"
    shift
    {
        echo '$ErrorActionPreference = "Continue"'
        echo '$ProgressPreference = "SilentlyContinue"'
        while (( $# >= 2 )); do
            local zone="$1"
            local ip="$2"
            shift 2
            cat <<PSEOF
if (-not (Get-DnsServerZone -Name "$zone" -ErrorAction SilentlyContinue)) {
    try {
        Add-DnsServerConditionalForwarderZone -Name "$zone" -MasterServers "$ip" -ReplicationScope Forest -ErrorAction Stop
        "added cf: $zone -> $ip"
    } catch { "failed cf $zone: \$(\$_.Exception.Message)" }
} else { "cf exists: $zone" }
PSEOF
        done
        echo '"cf-done"'
    } > "$out_file"
}

write_cf_ps /tmp/cf-tier0.ps1 "tier1.lab" "192.168.11.101" "tier2.lab" "192.168.11.102"
write_cf_ps /tmp/cf-tier1.ps1 "tier0.lab" "192.168.11.100" "tier2.lab" "192.168.11.102"
write_cf_ps /tmp/cf-tier2.ps1 "tier0.lab" "192.168.11.100" "tier1.lab" "192.168.11.101"

for vmid_file in "100:/tmp/cf-tier0.ps1" "101:/tmp/cf-tier1.ps1" "102:/tmp/cf-tier2.ps1"; do
    vmid="${vmid_file%%:*}"
    file="${vmid_file##*:}"
    echo "=== CFs on VMID $vmid ==="
    ENC=$(iconv -t UTF-16LE "$file" | base64 -w0)
    qm guest exec "$vmid" --timeout 60 -- powershell -NoProfile -EncodedCommand "$ENC"
done
