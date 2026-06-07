#!/usr/bin/env bash
# Lab phase 6 — bidirectional forest trusts via Forest.CreateTrustRelationship.
# Prerequisites: conditional forwarders (phase 5) are set, cross-forest DNS resolution works.
set -eu
: "${LAB_ADMIN_PASSWORD:?Please export LAB_ADMIN_PASSWORD}"

make_trust_ps() {
    local local_fqdn="$1"
    local remote_fqdn="$2"
    local remote_netbios="$3"
    local out_file="$4"
    cat > "$out_file" <<PSEOF
\$ErrorActionPreference = "Continue"
\$ProgressPreference = "SilentlyContinue"
try {
    \$localCtx  = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "${local_fqdn}")
    \$local     = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(\$localCtx)
    \$remoteCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "${remote_fqdn}", "${remote_netbios}\\Administrator", "${LAB_ADMIN_PASSWORD}")
    \$remote    = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(\$remoteCtx)
    \$existing = \$local.GetAllTrustRelationships() | Where-Object { \$_.TargetName -eq "${remote_fqdn}" }
    if (\$existing) {
        "trust exists: ${local_fqdn} <-> ${remote_fqdn}"
    } else {
        \$local.CreateTrustRelationship(\$remote, [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional)
        "trust created: ${local_fqdn} <-> ${remote_fqdn}"
    }
} catch {
    "trust-failed ${local_fqdn} <-> ${remote_fqdn}: \$(\$_.Exception.Message)"
    exit 1
}
PSEOF
}

run_ps() {
    local vmid="$1"
    local ps_file="$2"
    local label="$3"
    echo "=== $label (VMID $vmid) ==="
    local ENC
    ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout 300 -- powershell -NoProfile -EncodedCommand "$ENC"
}

make_trust_ps "tier0.lab" "tier1.lab" "T1LAB" /tmp/trust-01.ps1
make_trust_ps "tier1.lab" "tier2.lab" "T2LAB" /tmp/trust-12.ps1
make_trust_ps "tier0.lab" "tier2.lab" "T2LAB" /tmp/trust-02.ps1

run_ps 100 /tmp/trust-01.ps1 "trust tier0 <-> tier1"
run_ps 101 /tmp/trust-12.ps1 "trust tier1 <-> tier2"
run_ps 100 /tmp/trust-02.ps1 "trust tier0 <-> tier2"
