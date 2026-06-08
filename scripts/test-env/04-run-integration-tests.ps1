<#
.SYNOPSIS
    Runs the AD integration tests against the test domain.

.DESCRIPTION
    Run on the DEVELOPMENT MACHINE (not the test VM). Sets the DEVMS_TEST_LDAP_*
    variables process-locally and invokes `cargo test --workspace -- --ignored`.

    The bind password is prompted securely and set process-locally only - it does
    not end up in the shell history.

.PARAMETER Server
    FQDN or IP of the domain controller, e.g. dc01.testdomain.local

.PARAMETER BaseDn
    Base DN of the test domain. Default: DC=testdomain,DC=local

.PARAMETER BindDn
    Bind DN for the LDAP login.
    Default: CN=Administrator,CN=Users,DC=testdomain,DC=local

.PARAMETER Insecure
    Use plain LDAP (port 389). Only for isolated test networks without an
    LDAPS certificate.
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

# Prompt for the bind password securely.
$secure = Read-Host -AsSecureString -Prompt "LDAP bind password"
$plain  = [System.Net.NetworkCredential]::new("", $secure).Password

# Set env vars process-locally.
$env:DEVMS_TEST_LDAP_SERVER   = $Server
$env:DEVMS_TEST_LDAP_BASE_DN  = $BaseDn
$env:DEVMS_TEST_LDAP_BIND_DN  = $BindDn
$env:DEVMS_TEST_LDAP_PASSWORD = $plain
if ($Insecure) {
    $env:DEVMS_TEST_LDAP_INSECURE = "1"
    Write-Host "WARNING: plain LDAP active - only for isolated test networks." -ForegroundColor Yellow
} else {
    Remove-Item Env:\DEVMS_TEST_LDAP_INSECURE -ErrorAction SilentlyContinue
}

Write-Host "LDAP server : $Server" -ForegroundColor Cyan
Write-Host "Base DN     : $BaseDn" -ForegroundColor Cyan
Write-Host "Running integration tests ..." -ForegroundColor Cyan
Write-Host ""

try {
    # --ignored runs the otherwise-skipped integration tests.
    cargo test --workspace -- --ignored
    $exitCode = $LASTEXITCODE
}
finally {
    # Scrub the password from the process environment.
    $plain = $null
    Remove-Item Env:\DEVMS_TEST_LDAP_PASSWORD -ErrorAction SilentlyContinue
}

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "Integration tests passed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Integration tests failed (exit $exitCode)." -ForegroundColor Red
}
exit $exitCode
