<#
.SYNOPSIS
    Fuehrt die AD-Integrationstests gegen die Test-Domaene aus.
    Runs the AD integration tests against the test domain.

.DESCRIPTION
    Auf dem ENTWICKLUNGSRECHNER ausfuehren (nicht auf der Test-VM).
    Setzt die DEVMS_TEST_LDAP_*-Variablen prozesslokal und ruft
    `cargo test --workspace -- --ignored` auf.

    Run on the DEVELOPMENT MACHINE (not the test VM). Sets the DEVMS_TEST_LDAP_*
    variables process-locally and invokes `cargo test --workspace -- --ignored`.

    Das Bind-Passwort wird sicher abgefragt und nur prozesslokal gesetzt - es
    landet nicht in der Shell-History.
    The bind password is prompted securely and set process-locally only - it does
    not end up in the shell history.

.PARAMETER Server
    FQDN oder IP des Domaenencontrollers, z.B. dc01.testdomain.local

.PARAMETER BaseDn
    Base-DN der Test-Domaene. Standard: DC=testdomain,DC=local

.PARAMETER BindDn
    Bind-DN fuer die LDAP-Anmeldung.
    Standard: CN=Administrator,CN=Users,DC=testdomain,DC=local

.PARAMETER Insecure
    Unverschluesseltes LDAP (Port 389) verwenden. Nur fuer isolierte Testnetze
    ohne LDAPS-Zertifikat.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,
    [string]$BaseDn = "DC=testdomain,DC=local",
    [string]$BindDn = "CN=Administrator,CN=Users,DC=testdomain,DC=local",
    [switch]$Insecure
)

$ErrorActionPreference = "Stop"

# --- Bind-Passwort sicher abfragen / prompt for the bind password securely ---
$secure = Read-Host -AsSecureString -Prompt "LDAP-Bind-Passwort"
$plain  = [System.Net.NetworkCredential]::new("", $secure).Password

# --- Umgebungsvariablen prozesslokal setzen / set env vars process-locally ---
$env:DEVMS_TEST_LDAP_SERVER   = $Server
$env:DEVMS_TEST_LDAP_BASE_DN  = $BaseDn
$env:DEVMS_TEST_LDAP_BIND_DN  = $BindDn
$env:DEVMS_TEST_LDAP_PASSWORD = $plain
if ($Insecure) {
    $env:DEVMS_TEST_LDAP_INSECURE = "1"
    Write-Host "WARNUNG: unverschluesseltes LDAP aktiv - nur fuer isolierte Testnetze." -ForegroundColor Yellow
} else {
    Remove-Item Env:\DEVMS_TEST_LDAP_INSECURE -ErrorAction SilentlyContinue
}

Write-Host "LDAP-Server / server : $Server" -ForegroundColor Cyan
Write-Host "Base-DN              : $BaseDn" -ForegroundColor Cyan
Write-Host "Fuehre Integrationstests aus / running integration tests ..." -ForegroundColor Cyan
Write-Host ""

try {
    # --ignored fuehrt die sonst uebersprungenen Integrationstests aus.
    # --ignored runs the otherwise-skipped integration tests.
    cargo test --workspace -- --ignored
    $exitCode = $LASTEXITCODE
}
finally {
    # --- Passwort aus dem Prozess-Environment entfernen / scrub the password ---
    $plain = $null
    Remove-Item Env:\DEVMS_TEST_LDAP_PASSWORD -ErrorAction SilentlyContinue
}

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "Integrationstests erfolgreich / integration tests passed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Integrationstests fehlgeschlagen (Exit $exitCode)." -ForegroundColor Red
}
exit $exitCode
