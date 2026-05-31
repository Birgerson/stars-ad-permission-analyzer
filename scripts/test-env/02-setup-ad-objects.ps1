#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Legt die AD-Testabteilungen, -Benutzer und -Gruppen im DevMS-Testtenant an.
    Creates the AD test departments, users and groups in the DevMS test tenant.

.DESCRIPTION
    Auf dem Domaenencontroller (testdomain.local) nach dem Neustart ausfuehren.
    Idempotent - bereits vorhandene Objekte werden uebersprungen.

    Run on the domain controller (testdomain.local) after the reboot.
    Idempotent - objects that already exist are skipped.

    Struktur / structure:

        OU=DevMS-Test,DC=testdomain,DC=local
            (Legacy-Testbenutzer fuer rust-Integrationstests)
            max.mustermann   (Resolver- und Gruppenrekursions-Test)
            anna.schmidt     (Identity-Caching-Test)

            OU=Geschaeftsleitung
                Birger Labinsch
            OU=Personal
                Susanne Mueller
            OU=Analyse
                Thomas Hibel
                Markus Neuer
            OU=Produktion
                Reiner Wanscher
                Frank Hilbert
            OU=Finanzen
                Heidi Weger
            OU=Lager
                Oscar Wolle
            OU=Wissenschaft
                Julia Kurz
                Jasmin Koppen

    Gruppen / groups:
        Legacy (fuer crates/ad_resolver/src/resolver.rs):
            GRP_IT_Admins      <- max.mustermann (direkt)
            GRP_Development    <- max.mustermann (direkt)
            GRP_FullAccess_FS  <- GRP_IT_Admins  (nested)
            GRP_ShareAccess_SMB<- GRP_Development (nested)

        Pro Abteilung / per department:
            GRP_Geschaeftsleitung_Members
            GRP_Personal_Members
            GRP_Analyse_Members
            GRP_Produktion_Members
            GRP_Finanzen_Members
            GRP_Lager_Members
            GRP_Wissenschaft_Members

    WICHTIG: Die Legacy-Benutzer und -Gruppen MUESSEN erhalten bleiben, sonst
    wird der Integrationstest `resolve_group_memberships_max_mustermann` rot.
    IMPORTANT: the legacy users and groups MUST be preserved, otherwise the
    `resolve_group_memberships_max_mustermann` integration test goes red.

.PARAMETER BaseDn
    Domain-DN, in dem die OUs angelegt werden. Standard: DC=testdomain,DC=local

.PARAMETER OuName
    Name der Wurzel-OU fuer alle Testobjekte. Standard: DevMS-Test

.PARAMETER UserPassword
    SecureString des Standard-Passworts fuer alle angelegten Benutzer.
    Wird ohne diesen Parameter sicher abgefragt.
    Secure-string default password for all created users. Prompted securely
    when not provided.

.EXAMPLE
    .\02-setup-ad-objects.ps1
    # Fragt das Passwort interaktiv ab.

.EXAMPLE
    $pw = ConvertTo-SecureString '<dein-Testpasswort>' -AsPlainText -Force
    .\02-setup-ad-objects.ps1 -UserPassword $pw
    # Skriptbar; nur in der Testumgebung verwenden, nie ein Produktivpasswort einsetzen.
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

# --- Passwort sicher abfragen, wenn nicht uebergeben ---
# --- Prompt for password securely if not passed in ---
if (-not $UserPassword) {
    Write-Host "Passwort fuer alle Testbenutzer festlegen (muss die Komplexitaetsregeln erfuellen)." -ForegroundColor Cyan
    $UserPassword = Read-Host -AsSecureString -Prompt "Test-Benutzerpasswort"
}

# --- Hilfsfunktionen / helpers ---

function New-TestOu {
    param([string]$Name, [string]$ParentDn)
    if (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $ParentDn -SearchScope OneLevel -ErrorAction SilentlyContinue) {
        Write-Host "  OU vorhanden / exists: OU=$Name,$ParentDn" -ForegroundColor DarkGray
        return
    }
    New-ADOrganizationalUnit -Name $Name -Path $ParentDn -ProtectedFromAccidentalDeletion $false
    Write-Host "  OU angelegt / created : OU=$Name,$ParentDn" -ForegroundColor Green
}

function New-TestUser {
    param(
        [string]$Sam,
        [string]$Display,
        [string]$Department,
        [string]$OuDn
    )
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "  Benutzer vorhanden / user exists: $Sam" -ForegroundColor DarkGray
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
    Write-Host "  Benutzer angelegt / created user: $Sam ($Display)" -ForegroundColor Green
}

function New-TestGroup {
    param([string]$Name, [string]$OuDn)
    if (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Host "  Gruppe vorhanden / group exists: $Name" -ForegroundColor DarkGray
        return
    }
    New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $OuDn
    Write-Host "  Gruppe angelegt / created group: $Name" -ForegroundColor Green
}

function Add-TestMember {
    param([string]$Group, [string]$Member)
    $existing = Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue |
        Where-Object { $_.SamAccountName -eq $Member -or $_.Name -eq $Member }
    if ($existing) {
        Write-Host "  Mitgliedschaft vorhanden / membership exists: $Member -> $Group" -ForegroundColor DarkGray
        return
    }
    Add-ADGroupMember -Identity $Group -Members $Member
    Write-Host "  Mitglied hinzugefuegt / added member: $Member -> $Group" -ForegroundColor Green
}

# ===========================================================================
# 1) Wurzel-OU
# ===========================================================================
Write-Host ""
Write-Host "1) Wurzel-OU / root OU" -ForegroundColor Cyan
New-TestOu -Name $OuName -ParentDn $BaseDn

# ===========================================================================
# 2) Abteilungen als Sub-OUs (mit ASCII-Namen fuer DN-Sicherheit)
#    Departments as sub-OUs (ASCII names for DN safety)
#    Display-Name in Kommentar fuer Klarheit. Anzeige in AD UI = OU-Name.
# ===========================================================================
Write-Host ""
Write-Host "2) Abteilungen / departments" -ForegroundColor Cyan

$departments = @(
    @{ Ou = "Geschaeftsleitung"; Display = "Geschaeftsleitung" },
    @{ Ou = "Personal";           Display = "Personal" },
    @{ Ou = "Analyse";            Display = "Analyse" },
    @{ Ou = "Produktion";         Display = "Produktion" },
    @{ Ou = "Finanzen";           Display = "Finanzen" },
    @{ Ou = "Lager";              Display = "Lager" },
    @{ Ou = "Wissenschaft";       Display = "Wissenschaft" }
)

foreach ($dept in $departments) {
    New-TestOu -Name $dept.Ou -ParentDn $rootOuDn
}

# ===========================================================================
# 3) Legacy-Testbenutzer fuer Integrationstests (MUSS erhalten bleiben)
#    Legacy test users for integration tests (MUST be preserved)
# ===========================================================================
Write-Host ""
Write-Host "3) Legacy-Testbenutzer / legacy test users" -ForegroundColor Cyan
New-TestUser -Sam "max.mustermann" -Display "Max Mustermann"  -OuDn $rootOuDn
New-TestUser -Sam "anna.schmidt"   -Display "Anna Schmidt"    -OuDn $rootOuDn

# ===========================================================================
# 4) Zehn Testbenutzer aus PASSWORD.md, sinnvoll auf Abteilungen verteilt
#    Ten test users from PASSWORD.md, distributed across the departments
#
#    Die Verteilung ist exemplarisch (PASSWORD.md spezifiziert sie nicht).
#    Anpassen, falls eine andere Aufteilung gewuenscht ist.
#    Distribution is exemplary (PASSWORD.md does not specify it).
#    Adjust if a different layout is desired.
# ===========================================================================
Write-Host ""
Write-Host "4) Test-Benutzer pro Abteilung / test users per department" -ForegroundColor Cyan

$testUsers = @(
    @{ Sam = "birger.labinsch";  Display = "Birger Labinsch";  Dept = "Geschaeftsleitung" },
    @{ Sam = "susanne.mueller";  Display = "Susanne Mueller";  Dept = "Personal" },
    @{ Sam = "thomas.hibel";     Display = "Thomas Hibel";     Dept = "Analyse" },
    @{ Sam = "markus.neuer";     Display = "Markus Neuer";     Dept = "Analyse" },
    @{ Sam = "reiner.wanscher";  Display = "Reiner Wanscher";  Dept = "Produktion" },
    @{ Sam = "frank.hilbert";    Display = "Frank Hilbert";    Dept = "Produktion" },
    @{ Sam = "heidi.weger";      Display = "Heidi Weger";      Dept = "Finanzen" },
    @{ Sam = "oscar.wolle";      Display = "Oscar Wolle";      Dept = "Lager" },
    @{ Sam = "julia.kurz";       Display = "Julia Kurz";       Dept = "Wissenschaft" },
    @{ Sam = "jasmin.koppen";    Display = "Jasmin Koppen";    Dept = "Wissenschaft" }
)

foreach ($u in $testUsers) {
    $ouDn = "OU=$($u.Dept),$rootOuDn"
    New-TestUser -Sam $u.Sam -Display $u.Display -Department $u.Dept -OuDn $ouDn
}

# ===========================================================================
# 5) Legacy-Gruppen + Verschachtelung (Integrationstest-relevant)
#    Legacy groups + nesting (relevant for integration test)
# ===========================================================================
Write-Host ""
Write-Host "5) Legacy-Gruppen / legacy groups" -ForegroundColor Cyan
New-TestGroup "GRP_IT_Admins"       -OuDn $rootOuDn
New-TestGroup "GRP_Development"     -OuDn $rootOuDn
New-TestGroup "GRP_FullAccess_FS"   -OuDn $rootOuDn
New-TestGroup "GRP_ShareAccess_SMB" -OuDn $rootOuDn

Add-TestMember -Group "GRP_IT_Admins"       -Member "max.mustermann"
Add-TestMember -Group "GRP_Development"     -Member "max.mustermann"
Add-TestMember -Group "GRP_FullAccess_FS"   -Member "GRP_IT_Admins"
Add-TestMember -Group "GRP_ShareAccess_SMB" -Member "GRP_Development"

# ===========================================================================
# 6) Pro Abteilung eine Members-Gruppe + alle Abteilungs-Benutzer eintragen
#    One members group per department + add all department users
# ===========================================================================
Write-Host ""
Write-Host "6) Pro-Abteilung-Gruppen / per-department groups" -ForegroundColor Cyan

foreach ($dept in $departments) {
    $grpName = "GRP_$($dept.Ou)_Members"
    $ouDn    = "OU=$($dept.Ou),$rootOuDn"
    New-TestGroup -Name $grpName -OuDn $ouDn

    foreach ($u in $testUsers | Where-Object { $_.Dept -eq $dept.Ou }) {
        Add-TestMember -Group $grpName -Member $u.Sam
    }
}

# ===========================================================================
# Fertig
# ===========================================================================
Write-Host ""
Write-Host "AD-Testobjekte vollstaendig angelegt." -ForegroundColor Green
Write-Host "Zusammenfassung:" -ForegroundColor Cyan
Write-Host "  - $($departments.Count) Abteilungen (Sub-OUs)" -ForegroundColor White
Write-Host "  - $($testUsers.Count + 2) Benutzer ($($testUsers.Count) aus PASSWORD.md + 2 Legacy)" -ForegroundColor White
Write-Host "  - $(4 + $departments.Count) Gruppen (4 Legacy + 1 pro Abteilung)" -ForegroundColor White
Write-Host ""
Write-Host "Naechster Schritt / next step: 03-setup-fileserver.ps1 (Fileserver-ACLs)" -ForegroundColor Cyan
Write-Host "  Skript 03 legt Legacy-Struktur (Public, IT, Development, Shared, Secrets)" -ForegroundColor Gray
Write-Host "  UND alle 7 Abteilungs-Ordner unter C:\DevMS-TestData\Abteilungen an." -ForegroundColor Gray
