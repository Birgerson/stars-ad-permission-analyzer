#!/usr/bin/env bash
# Lab Block A — NTFS-Edge-Cases (Deny + Protect + Share) + Stars-CLI-Smoke.
# Voraussetzungen:
#   - Phases 01..08 sind durchgelaufen.
#   - C:\Stars\adpa.exe ist auf VMID 100 vorhanden.
#   - $LAB_ADMIN_PASSWORD ist gesetzt.
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

run_ps() {
    local vmid="$1"
    local ps_file="$2"
    local label="$3"
    local timeout="${4:-180}"
    echo "############################################################"
    echo "# $label (VMID $vmid)"
    echo "############################################################"
    local ENC
    ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout "$timeout" -- powershell -NoProfile -EncodedCommand "$ENC"
    echo
}

# -------- Setup auf tier0 --------
cat > /tmp/blockA-setup.ps1 <<'PSEOF'
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$base = 'C:\TestShare'
$dz   = Join-Path $base 'DenyZone'
$pz   = Join-Path $base 'Protected'

# E1 — DenyZone: Allow Modify via GroupB (inherited) + explicit Deny Modify for alice
if (-not (Test-Path $dz)) { New-Item -ItemType Directory -Path $dz | Out-Null }
$acl = Get-Acl $dz
$acl.Access | Where-Object { $_.IdentityReference.Value -like '*alice*' } |
    ForEach-Object { $acl.RemoveAccessRuleSpecific($_) | Out-Null }
$aliceSid = (Get-ADUser -Identity alice).SID
$deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $aliceSid, "Modify",
    "ContainerInherit,ObjectInherit", "None",
    "Deny")
$acl.AddAccessRule($deny)
Set-Acl -Path $dz -AclObject $acl
"E1 DenyZone ACL set"

# E2 — Protected: inheritance off, only Administrators+SYSTEM allowed
if (-not (Test-Path $pz)) { New-Item -ItemType Directory -Path $pz | Out-Null }
$acl = Get-Acl $pz
$acl.SetAccessRuleProtection($true, $false)
foreach ($a in @($acl.Access)) { $acl.RemoveAccessRule($a) | Out-Null }
$admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$system = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $admins, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $system, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
Set-Acl -Path $pz -AclObject $acl
"E2 Protected ACL set (inheritance off, only Admins+SYSTEM)"

# E3 — SMB share with Read for Everyone, FullControl for Domain Admins
$shareName = 'TestShareSMB'
if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
    Remove-SmbShare -Name $shareName -Force
}
New-SmbShare -Name $shareName -Path $base `
    -ReadAccess 'Everyone' -FullAccess 'T0LAB\Domain Admins' | Out-Null
"E3 SMB share created: $shareName -> $base"
PSEOF
run_ps 100 /tmp/blockA-setup.ps1 "Block A — setup edge-case fixtures on tier0" 120

# -------- Stars-CLI Smoke gegen alle drei Konstellationen --------
write_stars_test() {
    local user="$1"
    local path="$2"
    local extra="${3:-}"
    local out_file="$4"
    cat > "$out_file" <<PSEOF
\$ProgressPreference    = "SilentlyContinue"
\$ErrorActionPreference = "Continue"
\$env:ADPA_BIND_PASSWORD = "${LAB_ADMIN_PASSWORD}"
& 'C:\Stars\adpa.exe' analyze \`
    --path '${path}' \`
    --user '${user}' \`
    --server 'tier0.tier0.lab' \`
    --base-dn 'DC=tier0,DC=lab' \`
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \`
    --insecure-ldap ${extra} 2>&1
"adpa-exit=\$LASTEXITCODE"
PSEOF
}

write_stars_test "T0LAB\\alice" "C:\\TestShare\\DenyZone" \
    "" /tmp/stars-e1.ps1
write_stars_test "T0LAB\\alice" "C:\\TestShare\\Protected" \
    "" /tmp/stars-e2.ps1
write_stars_test "T0LAB\\alice" "\\\\tier0\\TestShareSMB" \
    "--smb-server tier0 --share-name TestShareSMB" /tmp/stars-e3.ps1

run_ps 100 /tmp/stars-e1.ps1 "E1: alice on DenyZone (Deny dominates)" 180
run_ps 100 /tmp/stars-e2.ps1 "E2: alice on Protected (inheritance off)" 180
run_ps 100 /tmp/stars-e3.ps1 "E3: alice on UNC (Share=Read dominates NTFS=Modify)" 180
