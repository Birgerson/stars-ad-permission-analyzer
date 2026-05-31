#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stuft diese Windows-Server-VM zum Domaenencontroller fuer testdomain.local hoch.
    Promotes this Windows Server VM to a domain controller for testdomain.local.

.DESCRIPTION
    Installiert die Rolle AD DS und erstellt eine neue Gesamtstruktur.
    DIE VM STARTET AM ENDE NEU.

    Installs the AD DS role and creates a new forest. THE VM REBOOTS at the end.

    Nur auf einer dedizierten, wegwerfbaren Test-VM ausfuehren - niemals auf einer
    Arbeitsstation. Vorher einen VM-Snapshot anlegen.
    Run ONLY on a dedicated, disposable test VM - never on a workstation.
    Take a VM snapshot beforehand.

.PARAMETER DomainName
    FQDN der zu erstellenden Domaene. Standard: testdomain.local

.PARAMETER NetbiosName
    NetBIOS-Name der Domaene. Standard: TESTDOMAIN
#>
[CmdletBinding()]
param(
    [string]$DomainName = "testdomain.local",
    [string]$NetbiosName = "TESTDOMAIN"
)

$ErrorActionPreference = "Stop"

# --- Schutz: nur auf Windows Server ausfuehren / guard: Windows Server only ---
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) {
    throw "Dieser Rechner ist eine Workstation (Windows 10/11). Ein Domaenencontroller " +
          "erfordert Windows Server. Abbruch. / This is a workstation OS - a domain " +
          "controller requires Windows Server. Aborting."
}
if ($os.ProductType -eq 2) {
    Write-Host "Dieser Rechner ist bereits ein Domaenencontroller. Abbruch." -ForegroundColor Yellow
    return
}

Write-Host "Domaene / domain : $DomainName ($NetbiosName)" -ForegroundColor Cyan
Write-Host "OS               : $($os.Caption)" -ForegroundColor Cyan
Write-Host ""
$confirm = Read-Host "Diese VM wird zum DC hochgestuft und NEU GESTARTET. Fortfahren? (ja/nein)"
if ($confirm -ne "ja") {
    Write-Host "Abgebrochen." -ForegroundColor Yellow
    return
}

# --- DSRM-Passwort sicher abfragen / prompt for the DSRM password securely ---
$dsrmPassword = Read-Host -AsSecureString -Prompt "DSRM-Wiederherstellungspasswort festlegen"

# --- Rolle AD DS installieren / install the AD DS role ---
Write-Host "Installiere Rolle AD DS / installing AD DS role ..." -ForegroundColor Cyan
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

# --- Gesamtstruktur erstellen / create the forest ---
Write-Host "Erstelle Gesamtstruktur / creating forest ... (die VM startet danach neu)" -ForegroundColor Cyan
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

# Hinweis: Die VM startet durch Install-ADDSForest automatisch neu.
# Note: the VM reboots automatically as part of Install-ADDSForest.
