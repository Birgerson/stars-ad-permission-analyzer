# verify-grp-geschaeftsleitung.ps1
#
# Auf dem DC als Administrator ausfuehren.
# Prueft auf vier unabhaengigen Wegen, ob die Gruppe
# GRP_Geschaeftsleitung_Members tatsaechlich existiert
# und wer drin ist.

$ErrorActionPreference = "Continue"

function Section($name) {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host " $name" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
}

# ----------------------------------------------------------------------
# 1. Get-ADGroup ueber das AD-PowerShell-Modul
# ----------------------------------------------------------------------
Section "1. Get-ADGroup (AD-PowerShell-Modul)"
try {
    $g = Get-ADGroup -Filter "Name -eq 'GRP_Geschaeftsleitung_Members'" -Properties Description, whenCreated, Members
    if ($g) {
        "GEFUNDEN:"
        "  DN:          $($g.DistinguishedName)"
        "  Name:        $($g.Name)"
        "  SamName:     $($g.SamAccountName)"
        "  SID:         $($g.SID)"
        "  GroupCat:    $($g.GroupCategory)"
        "  GroupScope:  $($g.GroupScope)"
        "  whenCreated: $($g.whenCreated)"
        "  Description: $($g.Description)"
    } else {
        "NICHT GEFUNDEN per Get-ADGroup."
    }
} catch {
    "FEHLER: $_"
}

# ----------------------------------------------------------------------
# 2. ADSI-Searcher (unabhaengig vom AD-Modul)
# ----------------------------------------------------------------------
Section "2. ADSI-Searcher (objectClass=group, cn=GRP_Geschaeftsleitung_Members)"
try {
    $searcher = [adsisearcher]"(&(objectClass=group)(cn=GRP_Geschaeftsleitung_Members))"
    $result = $searcher.FindOne()
    if ($result) {
        "GEFUNDEN:"
        "  DN:        $($result.Properties['distinguishedname'][0])"
        "  Name:      $($result.Properties['name'][0])"
        $sid = New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectsid"][0], 0)
        "  SID:       $($sid.Value)"
        "  Created:   $($result.Properties['whencreated'][0])"
    } else {
        "NICHT GEFUNDEN per ADSI-Searcher."
    }
} catch {
    "FEHLER: $_"
}

# ----------------------------------------------------------------------
# 3. Direkte SID-Aufloesung (Windows-LSA)
# ----------------------------------------------------------------------
Section "3. LookupAccountSidW per .NET (gleicher Weg wie Stars)"
try {
    $sidStr = "S-1-5-21-1233146484-3946085625-3355911197-1119"
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
    $nt = $sid.Translate([System.Security.Principal.NTAccount])
    "GEFUNDEN per LSA:"
    "  SID:    $sidStr"
    "  NTName: $($nt.Value)"
} catch {
    "FEHLER bei LSA-Aufloesung der SID -1119: $_"
}

# ----------------------------------------------------------------------
# 4. Mitglieder der Gruppe
# ----------------------------------------------------------------------
Section "4. Mitglieder der Gruppe"
try {
    $members = Get-ADGroupMember -Identity "GRP_Geschaeftsleitung_Members" -ErrorAction Stop
    if ($members) {
        "Mitglieder:"
        $members | ForEach-Object { "  - $($_.SamAccountName)  ($($_.DistinguishedName))" }
    } else {
        "Gruppe ist leer."
    }
} catch {
    "FEHLER: $_"
}

# ----------------------------------------------------------------------
# 5. Suche im DevMS-Test-OU
# ----------------------------------------------------------------------
Section "5. Alle Gruppen unter OU=DevMS-Test"
try {
    Get-ADGroup -SearchBase "OU=DevMS-Test,DC=testdomain,DC=local" -Filter * |
        Select-Object Name, DistinguishedName | Format-Table -AutoSize
} catch {
    "FEHLER: $_"
}

# ----------------------------------------------------------------------
# 6. Was sagt birger.labinsch tatsaechlich
# ----------------------------------------------------------------------
Section "6. Mitgliedschaften von birger.labinsch"
try {
    $u = Get-ADUser birger.labinsch -Properties MemberOf
    "PrimaryGroupID (in der DC SAM-DB): $($u.PrimaryGroupID)"
    "memberOf-Eintraege:"
    $u.MemberOf | ForEach-Object { "  - $_" }
} catch {
    "FEHLER: $_"
}

Write-Host ""
Write-Host "Fertig. Bitte den gesamten Output zurueck an Claude." -ForegroundColor Green
