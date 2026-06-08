#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promotes this Windows Server VM to a domain controller for testdomain.local.

.DESCRIPTION
    Installs the AD DS role and creates a new forest. THE VM REBOOTS at the end.

    Run ONLY on a dedicated, disposable test VM - never on a workstation.
    Take a VM snapshot beforehand.

.PARAMETER DomainName
    FQDN of the forest to create. Default: testdomain.local

.PARAMETER NetbiosName
    NetBIOS name of the domain. Default: TESTDOMAIN
#>
[CmdletBinding()]
param(
    [string]$DomainName = "testdomain.local",
    [string]$NetbiosName = "TESTDOMAIN"
)

$ErrorActionPreference = "Stop"

# Guard: Windows Server only.
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) {
    throw "This is a workstation OS (Windows 10/11) - a domain controller " +
          "requires Windows Server. Aborting."
}
if ($os.ProductType -eq 2) {
    Write-Host "This machine is already a domain controller. Aborting." -ForegroundColor Yellow
    return
}

Write-Host "Domain : $DomainName ($NetbiosName)" -ForegroundColor Cyan
Write-Host "OS     : $($os.Caption)" -ForegroundColor Cyan
Write-Host ""
$confirm = Read-Host "This VM will be promoted to a DC and REBOOTED. Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Aborted." -ForegroundColor Yellow
    return
}

# Prompt for the DSRM password securely.
$dsrmPassword = Read-Host -AsSecureString -Prompt "Set the DSRM recovery password"

# Install the AD DS role.
Write-Host "Installing AD DS role ..." -ForegroundColor Cyan
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

# Create the forest.
Write-Host "Creating forest ... (the VM will reboot afterwards)" -ForegroundColor Cyan
Import-Module ADDSDeployment

Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword $dsrmPassword `
    -InstallDns `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -NoRebootOnCompletion:$false `
    -Force

# Note: the VM reboots automatically as part of Install-ADDSForest.
