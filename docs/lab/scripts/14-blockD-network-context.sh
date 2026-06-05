#!/usr/bin/env bash
# Lab Block D (v1.5.9) — Verifikation Round-7 Finding 1:
# lokaler NTFS-Pfad + expliziter SMB-Kontext muss `NETWORK` in den Token
# packen, damit Share-DACL-ACEs gegen NETWORK korrekt aggregiert werden.
#
# Setup auf tier0:
#   - C:\TestShare\NetworkBlock (Subordner, NTFS Modify via GroupB inherited)
#   - SMB-Share TestShareNetBlock -> C:\TestShare\NetworkBlock
#     mit Share-Permission "Everyone = Full" + "NETWORK = Full Deny"
#
# Stars-Tests:
#   E4a: local path, no SMB hint        -> NETWORK Deny ignored (NTFS dominates)
#   E4b: local path + --smb-server +    -> NETWORK Deny dominates (the round-7 fix)
#        --share-name
#   E4c: UNC path + SMB hints           -> Share blocks NETWORK end-to-end
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

run_ps() {
    local vmid="$1"; local ps_file="$2"; local label="$3"; local timeout="${4:-180}"
    echo "=== $label (VMID $vmid) ==="
    local ENC; ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout "$timeout" -- powershell -NoProfile -EncodedCommand "$ENC"
}

cat > /tmp/blockD-setup.ps1 <<'PSEOF'
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$base = 'C:\TestShare'
$dir  = Join-Path $base 'NetworkBlock'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$shareName = 'TestShareNetBlock'
if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
    Remove-SmbShare -Name $shareName -Force
}
New-SmbShare -Name $shareName -Path $dir -FullAccess 'Everyone' | Out-Null
Grant-SmbShareAccess -Name $shareName -AccountName 'NT AUTHORITY\NETWORK' -AccessRight Read -Force | Out-Null
Block-SmbShareAccess -Name $shareName -AccountName 'NT AUTHORITY\NETWORK' -Force | Out-Null
"--- $shareName share access ---"
Get-SmbShareAccess -Name $shareName | ForEach-Object { "  $($_.AccountName) $($_.AccessRight) $($_.AccessControlType)" }
PSEOF
run_ps 100 /tmp/blockD-setup.ps1 "Block D — NetworkBlock subdir + restrictive SMB share" 120

write_test() {
    local label="$1"
    local extra="$2"
    local path_arg="$3"
    local out_file="$4"
    cat > "$out_file" <<PSEOF
\$env:ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"
& 'C:\\Stars\\adpa.exe' analyze \`
    --path '${path_arg}' \`
    --user 'T0LAB\\alice' \`
    --server 'tier0.tier0.lab' \`
    --base-dn 'DC=tier0,DC=lab' \`
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \`
    --insecure-ldap ${extra} 2>&1 | Select-String -Pattern 'Result|NTFS|Share|NETWORK' -Context 0,1 | ForEach-Object { \$_.ToString() }
PSEOF
}

write_test "E4a" ""                                              'C:\TestShare\NetworkBlock'   /tmp/stars-e4a.ps1
write_test "E4b" "--smb-server tier0 --share-name TestShareNetBlock" 'C:\TestShare\NetworkBlock' /tmp/stars-e4b.ps1
write_test "E4c" "--smb-server tier0 --share-name TestShareNetBlock" '\\tier0\TestShareNetBlock' /tmp/stars-e4c.ps1

run_ps 100 /tmp/stars-e4a.ps1 "E4a: local path, NO SMB hint  -> NTFS Modify, NETWORK Deny ignored" 120
run_ps 100 /tmp/stars-e4b.ps1 "E4b: local path + SMB hints  -> NETWORK Deny dominates (round-7 fix)" 120
run_ps 100 /tmp/stars-e4c.ps1 "E4c: UNC path                -> Share blocks NETWORK end-to-end (Access denied)" 120
