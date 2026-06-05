#!/usr/bin/env bash
# Lab Block C.1 — AD-Bulk-Setup:
#   - OUs Company/Departments/Users/Groups
#   - 5 Departments × 3 Sub-Teams = 20 Sicherheitsgruppen
#   - Nesting: User -> Sub-Team-Group -> Department-Group
#   - 1000 User max.mustermann0001..1000 verteilt:
#       tier0.lab: 0001..0500 (500)
#       tier1.lab: 0501..0800 (300)
#       tier2.lab: 0801..1000 (200)
#
# Cross-Forest-FSPs (50 Stueck) sind in diesem Skript bewusst auskommentiert —
# der ForeignSecurityPrincipal-Container in tier0.lab muss fuer die Variante
# mit Add-ADGroupMember + Cross-Forest-SID erst per dsadd oder New-ADObject
# foreignSecurityPrincipal vorbereitet werden. Das ist ein Lab-Setup-Quirk,
# kein Stars-Bug — Stars liest existierende FSPs korrekt (siehe Test T2 in
# verification.md). Wer das Lab-Setup vervollstaendigen will, ergaenzt den
# FSP-Step manuell auf tier0.
set -eu
: "${LAB_ADMIN_PASSWORD:?Bitte LAB_ADMIN_PASSWORD exportieren}"

run_ps() {
    local vmid="$1"
    local ps_file="$2"
    local label="$3"
    local timeout="${4:-1800}"
    echo "=== $label (VMID $vmid) ==="
    local ENC
    ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout "$timeout" -- powershell -NoProfile -EncodedCommand "$ENC"
}

write_forest_setup() {
    local START="$1"
    local END="$2"
    local NETBIOS="$3"
    local OUT="$4"
    cat > "$OUT" <<PSEOF
\$ErrorActionPreference = "Stop"
\$ProgressPreference    = "SilentlyContinue"
\$sw = [System.Diagnostics.Stopwatch]::StartNew()
\$dom = (Get-ADDomain)
\$dn  = \$dom.DistinguishedName
\$pw  = ConvertTo-SecureString "${LAB_ADMIN_PASSWORD}" -AsPlainText -Force

function Ensure-OU(\$name, \$path) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '\$name'" -SearchBase \$path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name \$name -Path \$path -ProtectedFromAccidentalDeletion:\$false
    }
}
Ensure-OU "Company" \$dn
\$companyDN  = "OU=Company,\$dn"
Ensure-OU "Departments" \$companyDN
Ensure-OU "Users"       \$companyDN
Ensure-OU "Groups"      \$companyDN
\$deptsBase  = "OU=Departments,\$companyDN"
\$usersBase  = "OU=Users,\$companyDN"
\$groupsBase = "OU=Groups,\$companyDN"

\$departments = @('Sales','Engineering','HR','Finance','IT')
\$subteams    = @('Alpha','Beta','Gamma')
foreach (\$d in \$departments) { Ensure-OU \$d \$deptsBase }

foreach (\$d in \$departments) {
    \$gn = "Dept-\$d"
    if (-not (Get-ADGroup -Filter "Name -eq '\$gn'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name \$gn -GroupScope Global -GroupCategory Security -Path \$groupsBase
    }
    foreach (\$s in \$subteams) {
        \$sgn = "\$d-\$s"
        if (-not (Get-ADGroup -Filter "Name -eq '\$sgn'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name \$sgn -GroupScope Global -GroupCategory Security -Path \$groupsBase
        }
        \$members = Get-ADGroupMember -Identity \$gn -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        if (\$members -notcontains \$sgn) { Add-ADGroupMember -Identity \$gn -Members (Get-ADGroup -Identity \$sgn) }
    }
}

\$start = ${START}
\$end   = ${END}
"creating users mm{0:D4}..mm{1:D4} on \$(\$dom.DNSRoot)..." -f \$start, \$end
\$count = 0
for (\$i = \$start; \$i -le \$end; \$i++) {
    \$sam = "mm{0:D4}" -f \$i
    \$idx = (\$i - \$start)
    \$dept = \$departments[\$idx % \$departments.Count]
    \$subIdx = [int][math]::Floor(\$idx / \$departments.Count) % \$subteams.Count
    \$sub  = \$subteams[\$subIdx]
    \$subTeamGroup = "\$dept-\$sub"
    if (-not (Get-ADUser -Filter "SamAccountName -eq '\$sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "Max Mustermann \$i" -SamAccountName \$sam -GivenName "Max" -Surname "Mustermann \$i" \`
            -Path \$usersBase \`
            -AccountPassword \$pw -Enabled \$true \`
            -ChangePasswordAtLogon \$false -PasswordNeverExpires \$true \`
            -Department \$dept -Title \$subTeamGroup
        Add-ADGroupMember -Identity \$subTeamGroup -Members \$sam
        \$count++
        if (\$count % 50 -eq 0) {
            "  ...\$count users, t=\$([math]::Round(\$sw.Elapsed.TotalSeconds,1))s"
        }
    }
}
"users created: \$count   total t=\$([math]::Round(\$sw.Elapsed.TotalSeconds,1))s"
PSEOF
}

write_forest_setup 1   500  "T0LAB" /tmp/ad-tier0.ps1
write_forest_setup 501 800  "T1LAB" /tmp/ad-tier1.ps1
write_forest_setup 801 1000 "T2LAB" /tmp/ad-tier2.ps1

run_ps 100 /tmp/ad-tier0.ps1 "tier0.lab — 500 users + groups + nesting" 1800
run_ps 101 /tmp/ad-tier1.ps1 "tier1.lab — 300 users + groups + nesting" 1800
run_ps 102 /tmp/ad-tier2.ps1 "tier2.lab — 200 users + groups + nesting" 1800
