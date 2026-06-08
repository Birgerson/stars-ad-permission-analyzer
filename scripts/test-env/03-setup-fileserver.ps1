#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates the test folder structure with NTFS ACLs and SMB shares.

.DESCRIPTION
    Run on the test VM after 02-setup-ad-objects.ps1. Idempotent.

    The structure covers the analyzer's main analysis cases: group rights,
    nested groups, inheritance break, Deny ACE, NTFS / share combination,
    direct user ACE, and sensitive path names.

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
        Write-Host "created folder: $Path" -ForegroundColor Green
    } else {
        Write-Host "folder exists: $Path" -ForegroundColor DarkGray
    }
}

function Grant-Ntfs {
    # icacls mask: (OI)(CI) = inherit to files and subfolders.
    param([string]$Path, [string]$Principal, [string]$Rights)
    & icacls $Path /grant "${Principal}:(OI)(CI)$Rights" | Out-Null
    Write-Host "  NTFS grant: $Principal -> $Rights on $Path" -ForegroundColor Gray
}

function Deny-Ntfs {
    param([string]$Path, [string]$Principal, [string]$Rights)
    & icacls $Path /deny "${Principal}:(OI)(CI)$Rights" | Out-Null
    Write-Host "  NTFS deny : $Principal -> $Rights on $Path" -ForegroundColor Gray
}

function New-TestShare {
    param([string]$Name, [string]$Path, [hashtable]$Access)
    if (Get-SmbShare -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host "share exists: $Name" -ForegroundColor DarkGray
        return
    }
    $params = @{ Name = $Name; Path = $Path }
    if ($Access.ContainsKey("Full"))   { $params["FullAccess"]   = $Access["Full"] }
    if ($Access.ContainsKey("Change")) { $params["ChangeAccess"] = $Access["Change"] }
    if ($Access.ContainsKey("Read"))   { $params["ReadAccess"]   = $Access["Read"] }
    New-SmbShare @params | Out-Null
    Write-Host "created share: $Name -> $Path" -ForegroundColor Green
}

# --- 1) Legacy folder structure (covers the analysis test cases) ---
Write-Host ""
Write-Host "1) Legacy folder structure" -ForegroundColor Cyan
New-TestDir $Root
New-TestDir "$Root\Public"
New-TestDir "$Root\IT"
New-TestDir "$Root\IT\maxdata"
New-TestDir "$Root\Development"
New-TestDir "$Root\Development\Restricted"
New-TestDir "$Root\Shared"
New-TestDir "$Root\Secrets"
New-TestDir "$Root\Secrets\passwords"

# Legacy NTFS permissions.
# Public: Everyone Read -> broad-group / Everyone rule.
Grant-Ntfs "$Root\Public" "Everyone" "R"

# IT: GRP_IT_Admins Modify (inherited to maxdata).
Grant-Ntfs "$Root\IT" "$Domain\GRP_IT_Admins" "M"

# IT\maxdata: additional explicit user ACE -> DIRECT_USER_ACE rule.
Grant-Ntfs "$Root\IT\maxdata" "$Domain\max.mustermann" "M"

# Development: GRP_Development Modify.
Grant-Ntfs "$Root\Development" "$Domain\GRP_Development" "M"

# Development\Restricted: break inheritance (keep copied entries),
# then add an explicit Deny.
& icacls "$Root\Development\Restricted" /inheritance:d | Out-Null
Deny-Ntfs "$Root\Development\Restricted" "$Domain\GRP_Development" "M"

# Shared: GRP_FullAccess_FS Full Control (share permission is only Read -> NTFS / share combination).
Grant-Ntfs "$Root\Shared" "$Domain\GRP_FullAccess_FS" "F"

# Secrets\passwords: sensitive path name -> SENSITIVE_PATH rule.
Grant-Ntfs "$Root\Secrets\passwords" "$Domain\GRP_IT_Admins" "R"

# Legacy SMB shares.
New-TestShare -Name "Public$" -Path "$Root\Public" -Access @{ Full = "Everyone" }
New-TestShare -Name "IT"      -Path "$Root\IT"     -Access @{ Change = "$Domain\GRP_IT_Admins" }
# Shared: share permission Read meets NTFS Full Control -> effective Read.
New-TestShare -Name "Shared"  -Path "$Root\Shared" -Access @{ Read = "Everyone" }

# ===========================================================================
# 2) Department folders and shares (mirroring the sub-OUs in 02).
#
#    Pattern per department:
#      Folder:   $Root\Departments\<Dept>
#      NTFS:     GRP_<Dept>_Members  -> Modify (OI)(CI)
#      Share:    <Dept>              -> Change (GRP_<Dept>_Members)
#    This gives CLI and GUI tests a dedicated permission scope per
#    department user, including an SMB path.
# ===========================================================================
Write-Host ""
Write-Host "2) Department folders + shares" -ForegroundColor Cyan

New-TestDir "$Root\Departments"

$departments = @(
    "Management",
    "HR",
    "Analysis",
    "Production",
    "Finance",
    "Warehouse",
    "Science"
)

foreach ($dept in $departments) {
    $deptPath = "$Root\Departments\$dept"
    $deptGrp  = "$Domain\GRP_${dept}_Members"

    New-TestDir $deptPath
    Grant-Ntfs $deptPath $deptGrp "M"

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
Write-Host "Test file server complete." -ForegroundColor Green
Write-Host "  - $($departments.Count) department folders + shares" -ForegroundColor White
Write-Host "  - 5 legacy folders (Public, IT, Development, Shared, Secrets)" -ForegroundColor White
Write-Host "Next step: 04-run-integration-tests.ps1 (on the developer machine)" -ForegroundColor Cyan
