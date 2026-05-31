#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Entfernt die Test-Fileserver-Daten und die AD-Testobjekte.
    Removes the test file server data and the AD test objects.

.DESCRIPTION
    Auf der Test-VM ausfuehren. Bevorzugt wird stattdessen ein VM-Snapshot
    zurueckgespielt.

    Run on the test VM. Restoring a VM snapshot is the preferred alternative.

    Dieses Skript stuft den Domaenencontroller NICHT herab. Die Herabstufung
    (Uninstall-ADDSDomainController) muss bewusst manuell erfolgen.
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

$confirm = Read-Host "Test-Fileserver und AD-Testobjekte entfernen? (ja/nein)"
if ($confirm -ne "ja") {
    Write-Host "Abgebrochen." -ForegroundColor Yellow
    return
}

# --- SMB-Freigaben entfernen / remove SMB shares ---
foreach ($share in @("Public$", "IT", "Shared")) {
    if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $share -Force
        Write-Host "Freigabe entfernt / removed share: $share" -ForegroundColor Green
    }
}

# --- Test-Ordner entfernen / remove the test folders ---
if (Test-Path $Root) {
    Remove-Item -Path $Root -Recurse -Force
    Write-Host "Ordner entfernt / removed folder: $Root" -ForegroundColor Green
}

# --- AD-Test-OU entfernen / remove the AD test OU ---
if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $BaseDn -ErrorAction SilentlyContinue
    if ($ou) {
        # Loeschschutz aufheben, dann rekursiv entfernen.
        # Remove the accidental-deletion protection, then delete recursively.
        Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
        Write-Host "AD-Test-OU entfernt / removed AD test OU: $($ou.DistinguishedName)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Aufraeumen abgeschlossen / teardown complete." -ForegroundColor Green
Write-Host "Der Domaenencontroller wurde NICHT herabgestuft." -ForegroundColor Yellow
