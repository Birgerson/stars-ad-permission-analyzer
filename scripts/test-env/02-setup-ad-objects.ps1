#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates the AD test departments, users, and groups in the DevMS test tenant.

.DESCRIPTION
    Run on the domain controller (testdomain.local) after the reboot.
    Idempotent - objects that already exist are skipped.

    Structure:

        OU=DevMS-Test,DC=testdomain,DC=local
            (legacy test users for Rust integration tests)
            max.mustermann   (resolver and group-recursion test)
            anna.schmidt     (identity caching test)

            OU=Management
                Birger Labinsch
            OU=HR
                Susanne Mueller
            OU=Analysis
                Thomas Hibel
                Markus Neuer
            OU=Production
                Reiner Wanscher
                Frank Hilbert
            OU=Finance
                Heidi Weger
            OU=Warehouse
                Oscar Wolle
            OU=Science
                Julia Kurz
                Jasmin Koppen

    Groups:
        Legacy (for crates/ad_resolver/src/resolver.rs):
            GRP_IT_Admins      <- max.mustermann (direct)
            GRP_Development    <- max.mustermann (direct)
            GRP_FullAccess_FS  <- GRP_IT_Admins  (nested)
            GRP_ShareAccess_SMB<- GRP_Development (nested)

        Per department:
            GRP_Management_Members
            GRP_HR_Members
            GRP_Analysis_Members
            GRP_Production_Members
            GRP_Finance_Members
            GRP_Warehouse_Members
            GRP_Science_Members

    IMPORTANT: the legacy users and groups MUST be preserved, otherwise the
    `resolve_group_memberships_max_mustermann` integration test goes red.

.PARAMETER BaseDn
    Domain DN where the OUs are created. Default: DC=testdomain,DC=local

.PARAMETER OuName
    Root OU name for all test objects. Default: DevMS-Test

.PARAMETER UserPassword
    Secure-string default password for all created users. Prompted securely
    when not provided.

.EXAMPLE
    .\02-setup-ad-objects.ps1
    # Prompts for the password interactively.

.EXAMPLE
    $pw = ConvertTo-SecureString '<your-test-password>' -AsPlainText -Force
    .\02-setup-ad-objects.ps1 -UserPassword $pw
    # Scriptable; use only in the test environment, never with a production password.
#>
[CmdletBinding()]
param(
    [string]$BaseDn = "DC=testdomain,DC=local",
    [string]$OuName = "DevMS-Test",
    [System.Security.SecureString]$UserPassword
)

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$rootOuDn = "OU=$OuName,$BaseDn"

# Prompt for password securely if not passed in.
if (-not $UserPassword) {
    Write-Host "Set the password for all test users (must satisfy the complexity rules)." -ForegroundColor Cyan
    $UserPassword = Read-Host -AsSecureString -Prompt "Test user password"
}

# Helpers.

function New-TestOu {
    param([string]$Name, [string]$ParentDn)
    if (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $ParentDn -SearchScope OneLevel -ErrorAction SilentlyContinue) {
        Write-Host "  OU exists: OU=$Name,$ParentDn" -ForegroundColor DarkGray
        return
    }
    New-ADOrganizationalUnit -Name $Name -Path $ParentDn -ProtectedFromAccidentalDeletion $false
    Write-Host "  OU created: OU=$Name,$ParentDn" -ForegroundColor Green
}

function New-TestUser {
    param(
        [string]$Sam,
        [string]$Display,
        [string]$Department,
        [string]$OuDn
    )
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "  user exists: $Sam" -ForegroundColor DarkGray
        return
    }
    $params = @{
        Name                 = $Display
        SamAccountName       = $Sam
        UserPrincipalName    = "$Sam@testdomain.local"
        DisplayName          = $Display
        Path                 = $OuDn
        AccountPassword      = $UserPassword
        Enabled              = $true
        ChangePasswordAtLogon = $false
    }
    if ($Department) {
        $params['Department'] = $Department
    }
    New-ADUser @params
    Write-Host "  created user: $Sam ($Display)" -ForegroundColor Green
}

function New-TestGroup {
    param([string]$Name, [string]$OuDn)
    if (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Host "  group exists: $Name" -ForegroundColor DarkGray
        return
    }
    New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $OuDn
    Write-Host "  created group: $Name" -ForegroundColor Green
}

function Add-TestMember {
    param([string]$Group, [string]$Member)
    $existing = Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue |
        Where-Object { $_.SamAccountName -eq $Member -or $_.Name -eq $Member }
    if ($existing) {
        Write-Host "  membership exists: $Member -> $Group" -ForegroundColor DarkGray
        return
    }
    Add-ADGroupMember -Identity $Group -Members $Member
    Write-Host "  added member: $Member -> $Group" -ForegroundColor Green
}

# ===========================================================================
# 1) Root OU
# ===========================================================================
Write-Host ""
Write-Host "1) Root OU" -ForegroundColor Cyan
New-TestOu -Name $OuName -ParentDn $BaseDn

# ===========================================================================
# 2) Departments as sub-OUs (ASCII names for DN safety).
#    Display name kept identical to the OU name.
# ===========================================================================
Write-Host ""
Write-Host "2) Departments" -ForegroundColor Cyan

$departments = @(
    @{ Ou = "Management";  Display = "Management" },
    @{ Ou = "HR";          Display = "HR" },
    @{ Ou = "Analysis";    Display = "Analysis" },
    @{ Ou = "Production";  Display = "Production" },
    @{ Ou = "Finance";     Display = "Finance" },
    @{ Ou = "Warehouse";   Display = "Warehouse" },
    @{ Ou = "Science";     Display = "Science" }
)

foreach ($dept in $departments) {
    New-TestOu -Name $dept.Ou -ParentDn $rootOuDn
}

# ===========================================================================
# 3) Legacy test users for integration tests (MUST be preserved).
# ===========================================================================
Write-Host ""
Write-Host "3) Legacy test users" -ForegroundColor Cyan
New-TestUser -Sam "max.mustermann" -Display "Max Mustermann"  -OuDn $rootOuDn
New-TestUser -Sam "anna.schmidt"   -Display "Anna Schmidt"    -OuDn $rootOuDn

# ===========================================================================
# 4) Ten test users from PASSWORD.md, distributed across the departments.
#    The distribution is exemplary (PASSWORD.md does not specify it).
#    Adjust if a different layout is desired.
# ===========================================================================
Write-Host ""
Write-Host "4) Test users per department" -ForegroundColor Cyan

$testUsers = @(
    @{ Sam = "birger.labinsch";  Display = "Birger Labinsch";  Dept = "Management" },
    @{ Sam = "susanne.mueller";  Display = "Susanne Mueller";  Dept = "HR" },
    @{ Sam = "thomas.hibel";     Display = "Thomas Hibel";     Dept = "Analysis" },
    @{ Sam = "markus.neuer";     Display = "Markus Neuer";     Dept = "Analysis" },
    @{ Sam = "reiner.wanscher";  Display = "Reiner Wanscher";  Dept = "Production" },
    @{ Sam = "frank.hilbert";    Display = "Frank Hilbert";    Dept = "Production" },
    @{ Sam = "heidi.weger";      Display = "Heidi Weger";      Dept = "Finance" },
    @{ Sam = "oscar.wolle";      Display = "Oscar Wolle";      Dept = "Warehouse" },
    @{ Sam = "julia.kurz";       Display = "Julia Kurz";       Dept = "Science" },
    @{ Sam = "jasmin.koppen";    Display = "Jasmin Koppen";    Dept = "Science" }
)

foreach ($u in $testUsers) {
    $ouDn = "OU=$($u.Dept),$rootOuDn"
    New-TestUser -Sam $u.Sam -Display $u.Display -Department $u.Dept -OuDn $ouDn
}

# ===========================================================================
# 5) Legacy groups + nesting (relevant for the integration test).
# ===========================================================================
Write-Host ""
Write-Host "5) Legacy groups" -ForegroundColor Cyan
New-TestGroup "GRP_IT_Admins"       -OuDn $rootOuDn
New-TestGroup "GRP_Development"     -OuDn $rootOuDn
New-TestGroup "GRP_FullAccess_FS"   -OuDn $rootOuDn
New-TestGroup "GRP_ShareAccess_SMB" -OuDn $rootOuDn

Add-TestMember -Group "GRP_IT_Admins"       -Member "max.mustermann"
Add-TestMember -Group "GRP_Development"     -Member "max.mustermann"
Add-TestMember -Group "GRP_FullAccess_FS"   -Member "GRP_IT_Admins"
Add-TestMember -Group "GRP_ShareAccess_SMB" -Member "GRP_Development"

# ===========================================================================
# 6) One members group per department + add all department users.
# ===========================================================================
Write-Host ""
Write-Host "6) Per-department groups" -ForegroundColor Cyan

foreach ($dept in $departments) {
    $grpName = "GRP_$($dept.Ou)_Members"
    $ouDn    = "OU=$($dept.Ou),$rootOuDn"
    New-TestGroup -Name $grpName -OuDn $ouDn

    foreach ($u in $testUsers | Where-Object { $_.Dept -eq $dept.Ou }) {
        Add-TestMember -Group $grpName -Member $u.Sam
    }
}

# ===========================================================================
# Done.
# ===========================================================================
Write-Host ""
Write-Host "AD test objects fully created." -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  - $($departments.Count) departments (sub-OUs)" -ForegroundColor White
Write-Host "  - $($testUsers.Count + 2) users ($($testUsers.Count) from PASSWORD.md + 2 legacy)" -ForegroundColor White
Write-Host "  - $(4 + $departments.Count) groups (4 legacy + 1 per department)" -ForegroundColor White
Write-Host ""
Write-Host "Next step: 03-setup-fileserver.ps1 (file-server ACLs)" -ForegroundColor Cyan
Write-Host "  Script 03 creates the legacy structure (Public, IT, Development, Shared, Secrets)" -ForegroundColor Gray
Write-Host "  AND all 7 department folders under C:\DevMS-TestData\Departments." -ForegroundColor Gray
