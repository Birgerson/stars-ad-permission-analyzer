#!/usr/bin/env bash
# Lab Phase 7 — Test-OUs, Test-User, verschachtelte Gruppen, Test-Pfad mit ACL inkl. Cross-Forest-FSP.
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

run_ps() {
    local vmid="$1"
    local ps_file="$2"
    local label="$3"
    echo "=== $label (VMID $vmid) ==="
    local ENC
    ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout 180 -- powershell -NoProfile -EncodedCommand "$ENC"
}

# tier0.lab: TestOU, GroupA -> GroupB, alice, C:\TestShare mit ACE für GroupB
cat > /tmp/td-tier0.ps1 <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference = "SilentlyContinue"
\$pw = ConvertTo-SecureString "${LAB_ADMIN_PASSWORD}" -AsPlainText -Force
\$dn = (Get-ADDomain).DistinguishedName
if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "TestOU"' -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "TestOU" -Path \$dn -ProtectedFromAccidentalDeletion:\$false
}
\$ouDN = "OU=TestOU,\$dn"
foreach (\$g in @('GroupA','GroupB')) {
    if (-not (Get-ADGroup -Filter ('Name -eq "{0}"' -f \$g) -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name \$g -GroupScope Global -GroupCategory Security -Path \$ouDN
    }
}
\$gbMembers = Get-ADGroupMember -Identity GroupB | Select-Object -ExpandProperty SamAccountName
if (\$gbMembers -notcontains 'GroupA') {
    Add-ADGroupMember -Identity GroupB -Members (Get-ADGroup -Identity GroupA)
}
if (-not (Get-ADUser -Filter 'SamAccountName -eq "alice"' -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "alice" -SamAccountName "alice" -Path \$ouDN \`
        -AccountPassword \$pw -Enabled \$true \`
        -ChangePasswordAtLogon \$false -PasswordNeverExpires \$true
    Add-ADGroupMember -Identity GroupA -Members (Get-ADUser -Identity alice)
}
\$path = 'C:\TestShare'
if (-not (Test-Path \$path)) { New-Item -ItemType Directory -Path \$path | Out-Null }
\$acl = Get-Acl \$path
\$gbSid = (Get-ADGroup -Identity GroupB).SID
\$existing = \$acl.Access | Where-Object {
    \$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq \$gbSid.Value
}
if (-not \$existing) {
    \$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(\$gbSid, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    \$acl.AddAccessRule(\$rule)
    Set-Acl -Path \$path -AclObject \$acl
}
"td-tier0-ok"
PSEOF

cat > /tmp/td-tier1.ps1 <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference = "SilentlyContinue"
\$pw = ConvertTo-SecureString "${LAB_ADMIN_PASSWORD}" -AsPlainText -Force
\$dn = (Get-ADDomain).DistinguishedName
if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "TestOU"' -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "TestOU" -Path \$dn -ProtectedFromAccidentalDeletion:\$false
}
\$ouDN = "OU=TestOU,\$dn"
if (-not (Get-ADUser -Filter 'SamAccountName -eq "bob"' -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "bob" -SamAccountName "bob" -Path \$ouDN \`
        -AccountPassword \$pw -Enabled \$true \`
        -ChangePasswordAtLogon \$false -PasswordNeverExpires \$true
}
"td-tier1-ok"
PSEOF

cat > /tmp/td-tier2.ps1 <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference = "SilentlyContinue"
\$pw = ConvertTo-SecureString "${LAB_ADMIN_PASSWORD}" -AsPlainText -Force
\$dn = (Get-ADDomain).DistinguishedName
if (-not (Get-ADOrganizationalUnit -Filter 'Name -eq "TestOU"' -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "TestOU" -Path \$dn -ProtectedFromAccidentalDeletion:\$false
}
\$ouDN = "OU=TestOU,\$dn"
if (-not (Get-ADUser -Filter 'SamAccountName -eq "carol"' -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "carol" -SamAccountName "carol" -Path \$ouDN \`
        -AccountPassword \$pw -Enabled \$true \`
        -ChangePasswordAtLogon \$false -PasswordNeverExpires \$true
}
"td-tier2-ok"
PSEOF

run_ps 100 /tmp/td-tier0.ps1 "test-data tier0.lab"
run_ps 101 /tmp/td-tier1.ps1 "test-data tier1.lab"
run_ps 102 /tmp/td-tier2.ps1 "test-data tier2.lab"

# Cross-Forest FSP ACE: T1LAB\bob auf tier0 C:\TestShare
cat > /tmp/fsp-tier0.ps1 <<'PSEOF'
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$path = 'C:\TestShare'
$acct = New-Object System.Security.Principal.NTAccount("T1LAB","bob")
$sid = $acct.Translate([System.Security.Principal.SecurityIdentifier])
$acl = Get-Acl $path
$already = $acl.Access | Where-Object {
    $_.IdentityReference -is [System.Security.Principal.SecurityIdentifier] -and
    $_.IdentityReference.Value -eq $sid.Value
}
if (-not $already) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $path -AclObject $acl
    "fsp-ace-added: T1LAB\bob ReadAndExecute"
} else { "fsp-ace-exists" }
PSEOF
run_ps 100 /tmp/fsp-tier0.ps1 "Cross-Forest FSP ACE for T1LAB\\bob on tier0"
