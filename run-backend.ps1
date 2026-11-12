$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$env:PYTHONPATH = Join-Path $root "src"
$env:PPS_STORAGE_DIR = Join-Path $root "captures"

Write-Host "Pocket Packet Sniffer - backend startup"
Write-Host "Project: $root"
Write-Host "Python:  $((Get-Command python -ErrorAction Stop).Source)"
Write-Host "Storage: $env:PPS_STORAGE_DIR"

# Install this project into the active Python environment if imports are missing.
python -c "import fastapi, scapy, uvicorn"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Required Python packages are missing. Installing project dependencies..."
    python -m pip install -e .
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed. Check the pip error above."
    }
}

# Verify imports before starting Uvicorn so failures are visible here.
python -c "from pocket_packet_sniffer.api import app; print('API import: OK')"
if ($LASTEXITCODE -ne 0) {
    throw "The API could not be imported. Fix the Python traceback above before starting the frontend."
}

New-Item -ItemType Directory -Force -Path $env:PPS_STORAGE_DIR | Out-Null

$listeners = @(Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique)
if ($listeners.Count -gt 0) {
    $listeners | ForEach-Object {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $_" -ErrorAction SilentlyContinue
        Write-Host "Port 8000 is already used by PID $_ : $($process.Name) $($process.CommandLine)"
    }
    throw "Port 8000 is already occupied. Identify the process above; do not start a second backend on another port."
}

Write-Host ""
Write-Host "Starting API at http://127.0.0.1:8000"
Write-Host "Health check: http://127.0.0.1:8000/api/health"
Write-Host "Interface list: http://127.0.0.1:8000/api/interfaces"
python -m uvicorn pocket_packet_sniffer.api:app --host 127.0.0.1 --port 8000
if ($LASTEXITCODE -ne 0) {
    throw "Backend exited with code $LASTEXITCODE. See the traceback above."
}
