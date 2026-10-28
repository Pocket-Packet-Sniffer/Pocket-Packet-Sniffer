$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$env:PYTHONPATH = Join-Path $root "src"
$env:PPS_STORAGE_DIR = Join-Path $root "captures"

python -c "import fastapi, scapy, uvicorn" 
if ($LASTEXITCODE -ne 0) {
    throw "Backend dependencies missing. Run: python -m pip install -e ."
}

Write-Host "Pocket Packet Sniffer API"
Write-Host "Storage: $env:PPS_STORAGE_DIR"
Write-Host "Health:  http://127.0.0.1:8000/api/health"
Write-Host "Interfaces: http://127.0.0.1:8000/api/interfaces"
Write-Host "Starting backend on http://127.0.0.1:8000 ..."
python -m uvicorn pocket_packet_sniffer.api:app --host 127.0.0.1 --port 8000
if ($LASTEXITCODE -ne 0) {
    throw "Backend exited with code $LASTEXITCODE. Check whether port 8000 is already occupied."
}
