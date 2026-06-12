#!/usr/bin/env bash
# Lab Block B — GUI boot smoke on tier0.
# Prerequisites:
#
# What this does: start the process, wait 15s, check that it still exists,
# then shut it down cleanly. Full UI validation remains a manual step (qm guest
set -eu

cat > /tmp/gui-smoke.ps1 <<'PSEOF'
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

$exe = 'C:\Stars\adpa-gui.exe'
if (-not (Test-Path $exe)) { "GUI binary missing: $exe"; exit 2 }
"gui-binary: $exe"
"gui-size  : $((Get-Item $exe).Length) bytes"

Get-Process -Name 'adpa-gui' -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force
    "killed stale pid=$($_.Id)"
}

$env:SLINT_STYLE         = 'fluent'
$env:SLINT_BACKEND       = 'winit-software'
$env:SLINT_COLOR_SCHEME  = 'light'
$out = Join-Path $env:TEMP 'adpa-gui-stdout.log'
$err = Join-Path $env:TEMP 'adpa-gui-stderr.log'
$p = Start-Process -FilePath $exe `
    -WindowStyle Hidden `
    -RedirectStandardOutput $out `
    -RedirectStandardError  $err `
    -PassThru
"launched pid=$($p.Id)"

Start-Sleep -Seconds 15
$alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($alive) {
    "still-alive-after-15s pid=$($p.Id) handle-count=$($alive.HandleCount) ws=$($alive.WS / 1MB)MB"
    Stop-Process -Id $p.Id -Force
    Start-Sleep -Seconds 2
    "process-terminated cleanly"
} else {
    "process-died-early"
    $p | Format-List Id,HasExited,ExitCode | Out-String
}

"--- stdout (first 60 lines) ---"
if (Test-Path $out) { Get-Content $out -TotalCount 60 }
"--- stderr (first 60 lines) ---"
if (Test-Path $err) { Get-Content $err -TotalCount 60 }
"GUI-SMOKE-DONE"
PSEOF

ENC=$(iconv -t UTF-16LE /tmp/gui-smoke.ps1 | base64 -w0)
echo "=== GUI boot-smoke on tier0 (VMID 100) ==="
qm guest exec 100 --timeout 60 -- powershell -NoProfile -EncodedCommand "$ENC"
