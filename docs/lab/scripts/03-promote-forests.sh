#!/usr/bin/env bash
# Lab phase 3 — Install-ADDSForest on tier0/tier1/tier2 in parallel.
# Prerequisites:
#   - VMs are up, hostnames are tier0/tier1/tier2.
#   - Local admin password is set (phase 2).
#   - $LAB_ADMIN_PASSWORD is set.
set -eu
: "${LAB_ADMIN_PASSWORD:?Please export LAB_ADMIN_PASSWORD}"

write_promote_ps() {
    local domain="$1"
    local netbios="$2"
    local out_file="$3"
    cat > "$out_file" <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference = "SilentlyContinue"
try {
    \$pw = ConvertTo-SecureString "${LAB_ADMIN_PASSWORD}" -AsPlainText -Force
    Import-Module ADDSDeployment
    Install-ADDSForest \`
        -DomainName "${domain}" \`
        -DomainNetbiosName "${netbios}" \`
        -SafeModeAdministratorPassword \$pw \`
        -InstallDns \`
        -CreateDnsDelegation:\$false \`
        -Force \`
        -Confirm:\$false \`
        -NoRebootOnCompletion
    "promote-ok: ${domain}"
} catch {
    "promote-failed-${domain}: \$(\$_.Exception.Message)"
    exit 1
}
PSEOF
}

# NetBIOS-Namen unterscheiden sich bewusst vom Hostnamen, sonst lehnt der
# Promote check rejected: "The NetBIOS name TIER0 is already in use."
write_promote_ps "tier0.lab" "T0LAB" /tmp/promote-100.ps1
write_promote_ps "tier1.lab" "T1LAB" /tmp/promote-101.ps1
write_promote_ps "tier2.lab" "T2LAB" /tmp/promote-102.ps1

ENC0=$(iconv -t UTF-16LE /tmp/promote-100.ps1 | base64 -w0)
ENC1=$(iconv -t UTF-16LE /tmp/promote-101.ps1 | base64 -w0)
ENC2=$(iconv -t UTF-16LE /tmp/promote-102.ps1 | base64 -w0)

echo "=== launching parallel promotes ==="
qm guest exec 100 --timeout 1800 -- powershell -NoProfile -EncodedCommand "$ENC0" > /tmp/promote-100.log 2>&1 &
PID0=$!
qm guest exec 101 --timeout 1800 -- powershell -NoProfile -EncodedCommand "$ENC1" > /tmp/promote-101.log 2>&1 &
PID1=$!
qm guest exec 102 --timeout 1800 -- powershell -NoProfile -EncodedCommand "$ENC2" > /tmp/promote-102.log 2>&1 &
PID2=$!

wait $PID0 || true; RC0=$?
wait $PID1 || true; RC1=$?
wait $PID2 || true; RC2=$?

echo "tier0 rc=$RC0 -> see /tmp/promote-100.log"
echo "tier1 rc=$RC1 -> see /tmp/promote-101.log"
echo "tier2 rc=$RC2 -> see /tmp/promote-102.log"
