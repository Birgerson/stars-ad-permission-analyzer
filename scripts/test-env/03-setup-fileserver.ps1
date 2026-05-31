#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Erstellt die Test-Ordnerstruktur mit NTFS-ACLs und SMB-Freigaben.
    Creates the test folder structure with NTFS ACLs and SMB shares.

.DESCRIPTION
    Auf der Test-VM nach 02-setup-ad-objects.ps1 ausfuehren. Idempotent.
    Run on the test VM after 02-setup-ad-objects.ps1. Idempotent.

    Diese Struktur deckt die fachlichen Analysefaelle des DevMS-Analyzers ab:
    Gruppenrechte, verschachtelte Gruppen, Vererbungsunterbrechung, Deny-ACE,
    NTFS-/Share-Kombination, direkter Benutzer-ACE und sensible Pfadnamen.

    Hinweis: Dies ist Testumgebungs-Provisionierung. Der DevMS-Analyzer selbst
    veraendert niemals Berechtigungen - er liest sie nur.
    Note: this is test environment provisioning. The analyzer itself never
    modifies permissions - it only reads them.
#>
[CmdletBinding()]
param(
    [string]$Root = "C:\DevMS-TestData",
    [string]$Domain = "TESTDOMAIN"
)

$ErrorActionPreference = "Stop"

function New-TestDir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        Write-Host "Ordner angelegt / created folder: $Path" -ForegroundColor Green
    } else {
        Write-Host "Ordner vorhanden / folder exists: $Path" -ForegroundColor DarkGray
    }
}

function Grant-Ntfs {
    # icacls-Maske: (OI)(CI) = Vererbung auf Dateien und Unterordner
    # icacls mask: (OI)(CI) = inherit to files and subfolders
    param([string]$Path, [string]$Principal, [string]$Rights)
    & icacls $Path /grant "${Principal}:(OI)(CI)$Rights" | Out-Null
    Write-Host "  NTFS grant: $Principal -> $Rights auf $Path" -ForegroundColor Gray
}

function Deny-Ntfs {
    param([string]$Path, [string]$Principal, [string]$Rights)
    & icacls $Path /deny "${Principal}:(OI)(CI)$Rights" | Out-Null
    Write-Host "  NTFS deny : $Principal -> $Rights auf $Path" -ForegroundColor Gray
}

function New-TestShare {
    param([string]$Name, [string]$Path, [hashtable]$Access)
    if (Get-SmbShare -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host "Freigabe vorhanden / share exists: $Name" -ForegroundColor DarkGray
        return
    }
    $params = @{ Name = $Name; Path = $Path }
    if ($Access.ContainsKey("Full"))   { $params["FullAccess"]   = $Access["Full"] }
    if ($Access.ContainsKey("Change")) { $params["ChangeAccess"] = $Access["Change"] }
    if ($Access.ContainsKey("Read"))   { $params["ReadAccess"]   = $Access["Read"] }
    New-SmbShare @params | Out-Null
    Write-Host "Freigabe angelegt / created share: $Name -> $Path" -ForegroundColor Green
}

# --- 1) Legacy-Ordnerstruktur (deckt die fachlichen Test-Faelle ab) ---
# --- 1) Legacy folder structure (covers the analysis test cases) ---
Write-Host ""
Write-Host "1) Legacy-Ordnerstruktur / legacy folder structure" -ForegroundColor Cyan
New-TestDir $Root
New-TestDir "$Root\Public"
New-TestDir "$Root\IT"
New-TestDir "$Root\IT\maxdata"
New-TestDir "$Root\Development"
New-TestDir "$Root\Development\Restricted"
New-TestDir "$Root\Shared"
New-TestDir "$Root\Secrets"
New-TestDir "$Root\Secrets\passwords"

# --- Legacy-NTFS-Berechtigungen / legacy NTFS permissions ---
# Public: Everyone Read -> Broad-Group-/Everyone-Regel
Grant-Ntfs "$Root\Public" "Everyone" "R"

# IT: GRP_IT_Admins Modify (wird auf maxdata vererbt)
Grant-Ntfs "$Root\IT" "$Domain\GRP_IT_Admins" "M"

# IT\maxdata: zusaetzlich direkter expliziter Benutzer-ACE -> DIRECT_USER_ACE
Grant-Ntfs "$Root\IT\maxdata" "$Domain\max.mustermann" "M"

# Development: GRP_Development Modify
Grant-Ntfs "$Root\Development" "$Domain\GRP_Development" "M"

# Development\Restricted: Vererbung trennen, dann explizites Deny
# Break inheritance (keep copied entries), then add an explicit Deny.
& icacls "$Root\Development\Restricted" /inheritance:d | Out-Null
Deny-Ntfs "$Root\Development\Restricted" "$Domain\GRP_Development" "M"

# Shared: GRP_FullAccess_FS Full Control (Share-Recht ist nur Read -> NTFS-Share-Kombination)
Grant-Ntfs "$Root\Shared" "$Domain\GRP_FullAccess_FS" "F"

# Secrets\passwords: sensibler Pfadname -> SENSITIVE_PATH-Regel
Grant-Ntfs "$Root\Secrets\passwords" "$Domain\GRP_IT_Admins" "R"

# --- Legacy-SMB-Freigaben / legacy SMB shares ---
New-TestShare -Name "Public$" -Path "$Root\Public" -Access @{ Full = "Everyone" }
New-TestShare -Name "IT"      -Path "$Root\IT"     -Access @{ Change = "$Domain\GRP_IT_Admins" }
# Shared: Share-Recht Read trifft auf NTFS Full Control -> effektiv Read.
New-TestShare -Name "Shared"  -Path "$Root\Shared" -Access @{ Read = "Everyone" }

# ===========================================================================
# 2) Abteilungs-Ordner und -Freigaben (analog zu den Sub-OUs in 02)
#    Department folders and shares (mirroring the sub-OUs in 02)
#
#    Pattern pro Abteilung:
#      Ordner:   $Root\Abteilungen\<Dept>
#      NTFS:     GRP_<Dept>_Members  -> Modify (OI)(CI)
#      Share:    <Dept>              -> Change (GRP_<Dept>_Members)
#    Damit haben CLI- und GUI-Tests pro Abteilungs-User einen eigenen
#    Berechtigungs-Scope inkl. SMB-Pfad.
# ===========================================================================
Write-Host ""
Write-Host "2) Abteilungs-Ordner und -Freigaben / department folders + shares" -ForegroundColor Cyan

New-TestDir "$Root\Abteilungen"

$departments = @(
    "Geschaeftsleitung",
    "Personal",
    "Analyse",
    "Produktion",
    "Finanzen",
    "Lager",
    "Wissenschaft"
)

foreach ($dept in $departments) {
    $deptPath = "$Root\Abteilungen\$dept"
    $deptGrp  = "$Domain\GRP_${dept}_Members"

    New-TestDir $deptPath
    Grant-Ntfs $deptPath $deptGrp "M"

    # Share-Name = Abteilungsname (kein $ -> sichtbar in der Netzwerk-Liste,
    # damit Auditoren sie ohne Vorwissen finden).
    # Administrators bekommen zusaetzlich Full-Access auf die Share, sonst
    # koennen Auditoren-/Read-only-Accounts die DACL gar nicht auslesen
    # (Share-Permissions schiessen NTFS-Rechte ab). Dies ist Audit-Tooling-
    # Pflicht und entspricht der Default-Praxis fuer administrative Shares.
    # Share name = department name (no $ -> visible in network browsing so
    # auditors can find it without prior knowledge).
    # Administrators additionally get Full Access at the share level —
    # otherwise auditor / read-only accounts cannot even read the DACL
    # (share permissions cap NTFS rights). This is mandatory for audit
    # tooling and matches the default practice for administrative shares.
    New-TestShare -Name $dept -Path $deptPath -Access @{
        Full   = "BUILTIN\Administrators"
        Change = $deptGrp
    }
}

Write-Host ""
Write-Host "Test-Fileserver vollstaendig eingerichtet / test file server complete." -ForegroundColor Green
Write-Host "  - $($departments.Count) Abteilungs-Ordner + Shares" -ForegroundColor White
Write-Host "  - 5 Legacy-Ordner (Public, IT, Development, Shared, Secrets)" -ForegroundColor White
Write-Host "Naechster Schritt / next step: 04-run-integration-tests.ps1 (auf dem Entwicklungsrechner)" -ForegroundColor Cyan
