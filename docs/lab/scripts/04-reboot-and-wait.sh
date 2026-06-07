#!/usr/bin/env bash
# Lab phase 4 — reboot all three VMs (promote activation) and wait until AD responds.
set -eu

wait_for_agent() {
    local vmid="$1"
    for i in $(seq 1 120); do
        if qm guest cmd "$vmid" ping >/dev/null 2>&1; then
            echo "  agent up on VMID $vmid after ${i}x5s"
            return 0
        fi
        sleep 5
    done
    echo "  TIMEOUT VMID $vmid"
    return 1
}

cat > /tmp/wait-ad.ps1 <<'PSEOF'
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
for ($i = 0; $i -lt 60; $i++) {
    try {
        $d = Get-ADDomain -ErrorAction Stop
        "ad-up: $($d.DNSRoot)"
        exit 0
    } catch { Start-Sleep -Seconds 5 }
}
"ad-timeout"
exit 1
PSEOF
ENC=$(iconv -t UTF-16LE /tmp/wait-ad.ps1 | base64 -w0)

for V in 100 101 102; do
    echo "=== reboot VMID $V ==="
    qm shutdown "$V" --timeout 300
    qm start "$V"
done

sleep 30
for V in 100 101 102; do
    wait_for_agent "$V"
done

sleep 30
for V in 100 101 102; do
    echo "=== wait-AD on VMID $V ==="
    qm guest exec "$V" --timeout 360 -- powershell -NoProfile -EncodedCommand "$ENC"
done
