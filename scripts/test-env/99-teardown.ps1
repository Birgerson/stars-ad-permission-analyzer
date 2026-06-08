#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the test file server data and the AD test objects.

.DESCRIPTION
    Run on the test VM. Restoring a VM snapshot is the preferred alternative.

    This script does NOT demote the domain controller. Demotion
    (Uninstall-ADDSDomainController) must be performed deliberately by hand.
#>
[CmdletBinding()]
param(
    [string]$Root = "C:\DevMS-TestData",
    [string]$BaseDn = "DC=testdomain,DC=local",
    [string]$OuName = "DevMS-Test"
)

$ErrorActionPreference = "Stop"

$confirm = Read-Host "Remove test file server and AD test objects? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Aborted." -ForegroundColor Yellow
    return
}

# Remove SMB shares.
foreach ($share in @("Public$", "IT", "Shared")) {
    if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $share -Force
        Write-Host "removed share: $share" -ForegroundColor Green
    }
}

# Remove the test folders.
if (Test-Path $Root) {
    Remove-Item -Path $Root -Recurse -Force
    Write-Host "removed folder: $Root" -ForegroundColor Green
}

# Remove the AD test OU.
if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $BaseDn -ErrorAction SilentlyContinue
    if ($ou) {
        # Remove the accidental-deletion protection, then delete recursively.
        Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
        Write-Host "removed AD test OU: $($ou.DistinguishedName)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Teardown complete." -ForegroundColor Green
Write-Host "The domain controller was NOT demoted." -ForegroundColor Yellow
