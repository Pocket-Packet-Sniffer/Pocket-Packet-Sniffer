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

# A stale preview server on port 5173 can keep showing synthetic data even after
# the integrated frontend has been pulled. Ask before stopping an existing listener.
foreach ($port in @(8000, 5173)) {
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique)
    foreach ($processId in $listeners) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
        $processName = if ($process) { $process.Name } else { "unknown process" }
        Write-Host "Port $port is already used by PID $processId ($processName)."
        $answer = Read-Host "Stop this process so Pocket Packet Sniffer can use port $port? (y/N)"
        if ($answer -match "^(y|yes)$") {
            Stop-Process -Id $processId -Force
            Start-Sleep -Milliseconds 500
        } else {
            throw "Port $port is occupied. Stop its listener, then run .\run-local.ps1 again."
        }
    }
}

Push-Location $root
try {
    python -c "import fastapi, scapy, uvicorn" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Python dependencies are missing. Run: python -m pip install -e ."
    }
} finally {
    Pop-Location
}

if (-not (Test-Path (Join-Path $root "web\node_modules"))) {
    Write-Host "Frontend dependencies are missing; installing them with npm install..."
    Push-Location (Join-Path $root "web")
    try {
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed." }
    } finally {
        Pop-Location
    }
}

$backendCommand = "\`$ErrorActionPreference = 'Stop'; Set-Location '$root'; \`$env:PYTHONPATH = '$root\src'; \`$env:PPS_STORAGE_DIR = '$storage'; python -m uvicorn pocket_packet_sniffer.api:app --host 127.0.0.1 --port 8000"
$frontendCommand = "\`$ErrorActionPreference = 'Stop'; Set-Location '$root\web'; npm run dev"

Write-Host ""
Write-Host "Pocket Packet Sniffer - LIVE API MODE"
Write-Host "Backend storage: $storage"
Write-Host "Backend URL: http://127.0.0.1:8000"
Write-Host "Frontend URL: http://127.0.0.1:5173"
Write-Host "No execution-policy bypass is used."
Write-Host "Keep both terminal windows open. The dashboard must show BACKEND ONLINE before capture can start."
Write-Host "If live capture reports a permissions/Npcap error, run PowerShell as Administrator and retry."

Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-Command", $backendCommand)
Start-Sleep -Seconds 2
Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-Command", $frontendCommand)
