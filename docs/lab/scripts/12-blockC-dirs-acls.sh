#!/usr/bin/env bash
# Lab Block C.2 + C.3 — directory structure + ACLs on tier0.
# Structure (5 depts × 20 projects × 50 folders = 5000 folder dirs):
#   C:\Data\<Department>\<Project01..20>\<Folder01..50>
# ACL-Variation:
#   Dept root   : Dept-<Department>      = Modify (inherited)
#   Project01..15: <Department>-<Sub-Team> = Modify (explicit)
#   Project16..18: PROTECT inheritance + only Admins+SYSTEM
#   Project19..20: Deny Read for <Department>-Gamma
set -eu

run_ps() {
    local vmid="$1"; local ps_file="$2"; local label="$3"; local timeout="${4:-1800}"
    echo "=== $label (VMID $vmid) ==="
    local ENC; ENC=$(iconv -t UTF-16LE "$ps_file" | base64 -w0)
    qm guest exec "$vmid" --timeout "$timeout" -- powershell -NoProfile -EncodedCommand "$ENC"
}

cat > /tmp/dirs-acls.ps1 <<'PSEOF'
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$root = 'C:\Data'
$departments = @('Sales','Engineering','HR','Finance','IT')
$subteams    = @('Alpha','Beta','Gamma')
if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root | Out-Null }

"creating directory tree..."
$count = 0
foreach ($d in $departments) {
    $deptPath = Join-Path $root $d
    if (-not (Test-Path $deptPath)) { New-Item -ItemType Directory -Path $deptPath | Out-Null }
    for ($p = 1; $p -le 20; $p++) {
        $projPath = Join-Path $deptPath ("Project{0:D2}" -f $p)
        if (-not (Test-Path $projPath)) { New-Item -ItemType Directory -Path $projPath | Out-Null }
        for ($f = 1; $f -le 50; $f++) {
            $folderPath = Join-Path $projPath ("Folder{0:D2}" -f $f)
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath | Out-Null
                $count++
            }
        }
    }
}
"folders created: $count   t=$([math]::Round($sw.Elapsed.TotalSeconds, 1))s"

"setting dept-root ACLs..."
foreach ($d in $departments) {
    $deptPath = Join-Path $root $d
    $deptSid = (Get-ADGroup -Identity "Dept-$d").SID
    $acl = Get-Acl $deptPath
    $acl.Access | Where-Object {
        $_.IdentityReference -is [System.Security.Principal.SecurityIdentifier] -and
        $_.IdentityReference.Value -eq $deptSid.Value
    } | ForEach-Object { $acl.RemoveAccessRuleSpecific($_) | Out-Null }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $deptSid, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl -Path $deptPath -AclObject $acl
}

"setting project ACLs..."
$projectsTouched = 0
foreach ($d in $departments) {
    for ($p = 1; $p -le 20; $p++) {
        $projPath = Join-Path (Join-Path $root $d) ("Project{0:D2}" -f $p)
        $subIdx = (($p - 1) % $subteams.Count)
        $sgSid = (Get-ADGroup -Identity "$d-$($subteams[$subIdx])").SID
        $acl = Get-Acl $projPath
        if ($p -le 15) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sgSid, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
        }
        elseif ($p -le 18) {
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($a in @($acl.Access)) { $acl.RemoveAccessRule($a) | Out-Null }
            $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $system = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $admins, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $system, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        }
        else {
            $gammaSid = (Get-ADGroup -Identity "$d-Gamma").SID
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $gammaSid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Deny")))
        }
        Set-Acl -Path $projPath -AclObject $acl
        $projectsTouched++
    }
}
"project ACLs set: $projectsTouched   t=$([math]::Round($sw.Elapsed.TotalSeconds, 1))s"
"total dirs under $root : $((Get-ChildItem -Path $root -Recurse -Directory | Measure-Object).Count)"
PSEOF

run_ps 100 /tmp/dirs-acls.ps1 "Block C.2+C.3 — 5000 folders + 100 project ACLs on tier0" 1800
