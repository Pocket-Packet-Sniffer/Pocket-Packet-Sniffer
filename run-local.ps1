$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$storage = Join-Path $root "captures"
$demoStorage = Join-Path $root "demo-captures"

# Reuse an existing database so the API does not point at a new empty folder.
if (-not (Test-Path (Join-Path $storage "metadata.sqlite3")) -and
    (Test-Path (Join-Path $demoStorage "metadata.sqlite3"))) {
    $storage = $demoStorage
}

if (-not (Test-Path (Join-Path $root "web\package.json"))) {
    throw "Frontend folder not found: $root\web"
}

$backendCommand = "`$ErrorActionPreference = 'Stop'; Set-Location '$root'; `$env:PPS_STORAGE_DIR = '$storage'; python -m uvicorn pocket_packet_sniffer.api:app --host 127.0.0.1 --port 8000"
$frontendCommand = "`$ErrorActionPreference = 'Stop'; Set-Location '$root\web'; npm run dev"

Write-Host "Pocket Packet Sniffer"
Write-Host "Backend storage: $storage"
Write-Host "Backend URL: http://127.0.0.1:8000"
Write-Host "Frontend URL: http://127.0.0.1:5173"
Write-Host ""
Write-Host "If live capture fails on Windows, close these windows and relaunch PowerShell as Administrator."
Write-Host "Keep both terminal windows open while using the dashboard."

Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $backendCommand)
Start-Sleep -Seconds 2
Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $frontendCommand)
