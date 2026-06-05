#!/usr/bin/env bash
# Lab Phase 8 — Stars-CLI Smoke-Tests gegen das Lab.
# Voraussetzung: adpa.exe liegt auf VMID 100 unter C:\Stars\adpa.exe.
# Upload Beispiel (vom Steuer-Rechner mit Local-Admin von tier0):
#   net use \\192.168.11.100\c$ /user:T0LAB\Administrator <lab-pw>
#   mkdir \\192.168.11.100\c$\Stars
#   copy target\release\adpa.exe \\192.168.11.100\c$\Stars\adpa.exe
#   net use \\192.168.11.100\c$ /delete
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

run_test() {
    local label="$1"
    local user="$2"
    local server="$3"
    local base_dn="$4"
    local bind_dn="$5"
    local out_file="$6"
    cat > "$out_file" <<PSEOF
\$ProgressPreference = "SilentlyContinue"
\$ErrorActionPreference = "Continue"
\$env:ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"
& 'C:\Stars\adpa.exe' analyze \`
    --path 'C:\TestShare' \`
    --user '${user}' \`
    --server '${server}' \`
    --base-dn '${base_dn}' \`
    --bind-dn '${bind_dn}' \`
    --insecure-ldap 2>&1
"adpa-exit=\$LASTEXITCODE"
PSEOF
    echo "############################################################"
    echo "# $label"
    echo "############################################################"
    local ENC
    ENC=$(iconv -t UTF-16LE "$out_file" | base64 -w0)
    qm guest exec 100 --timeout 120 -- powershell -NoProfile -EncodedCommand "$ENC"
    echo
}

run_test "T1: alice@tier0.lab (nested groups)" \
    "T0LAB\\alice" "tier0.tier0.lab" "DC=tier0,DC=lab" \
    "CN=Administrator,CN=Users,DC=tier0,DC=lab" /tmp/stars-t1.ps1

run_test "T2: T1LAB\\bob (Cross-Forest FSP)" \
    "T1LAB\\bob" "tier1.tier1.lab" "DC=tier1,DC=lab" \
    "CN=Administrator,CN=Users,DC=tier1,DC=lab" /tmp/stars-t2.ps1

run_test "T3: T2LAB\\carol (Cross-Forest, no ACE)" \
    "T2LAB\\carol" "tier2.tier2.lab" "DC=tier2,DC=lab" \
    "CN=Administrator,CN=Users,DC=tier2,DC=lab" /tmp/stars-t3.ps1
