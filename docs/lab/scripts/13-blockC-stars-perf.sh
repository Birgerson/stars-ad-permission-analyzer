#!/usr/bin/env bash
# Lab Block C.4 — Stars Performance-Benchmark gegen 5105 Ordner / 500 Users
# auf tier0 mit Live-LDAP-Resolve und CSV-Output.
set -eu
: "${LAB_ADMIN_PASSWORD:?Please export LAB_ADMIN_PASSWORD}"

run_ps() {
    local vmid="$1"; local ps_file="$2"; local label="$3"; local timeout="${4:-1800}"
    echo "=== $label (VMID $vmid) ==="
    local ENC; ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout "$timeout" -- powershell -NoProfile -EncodedCommand "$ENC"
}

# Full scan: mm0001 (Sales-Alpha) on C:\Data
cat > /tmp/scan.ps1 <<PSEOF
\$env:ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"
\$out = 'C:\\Stars\\scan-output.csv'
if (Test-Path \$out) { Remove-Item \$out }

\$sw = [System.Diagnostics.Stopwatch]::StartNew()
& 'C:\\Stars\\adpa.exe' scan \`
    --path 'C:\\Data' \`
    --user 'T0LAB\\mm0001' \`
    --server 'tier0.tier0.lab' \`
    --base-dn 'DC=tier0,DC=lab' \`
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \`
    --insecure-ldap \`
    --output \$out --force 2>&1 | Select-Object -Last 30
\$rc = \$LASTEXITCODE
\$sw.Stop()

"elapsed_seconds : \$([math]::Round(\$sw.Elapsed.TotalSeconds, 2))"
"adpa rc         : \$rc"
if (Test-Path \$out) {
    "csv_lines       : \$((Get-Content \$out | Measure-Object -Line).Lines)"
    "csv_size_kb     : \$([math]::Round((Get-Item \$out).Length / 1KB, 1))"
}
PSEOF
run_ps 100 /tmp/scan.ps1 "scan C:\\Data (5105 dirs, mm0001/Sales-Alpha)" 1800

# Single deep analyze
cat > /tmp/analyze.ps1 <<PSEOF
\$env:ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"
\$sw = [System.Diagnostics.Stopwatch]::StartNew()
& 'C:\\Stars\\adpa.exe' analyze \`
    --path 'C:\\Data\\Sales\\Project05\\Folder25' \`
    --user 'T0LAB\\mm0001' \`
    --server 'tier0.tier0.lab' \`
    --base-dn 'DC=tier0,DC=lab' \`
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \`
    --insecure-ldap 2>&1 | Select-Object -Last 25
"elapsed_seconds : \$([math]::Round(\$sw.Elapsed.TotalSeconds, 2))"
PSEOF
run_ps 100 /tmp/analyze.ps1 "deep analyze (mm0001 on Sales/Project05/Folder25)" 120
