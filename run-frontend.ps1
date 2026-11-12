$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$web = Join-Path $root "web"
Set-Location $web

if (-not (Test-Path (Join-Path $web "package.json"))) {
    throw "Frontend package.json not found: $web"
}

if (-not (Test-Path (Join-Path $web "node_modules"))) {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
}

Write-Host "Pocket Packet Sniffer frontend"
Write-Host "API: http://127.0.0.1:8000"
Write-Host "Dashboard: http://127.0.0.1:5173"
Write-Host "Starting the Next.js dashboard on port 5173..."
npm run dev
if ($LASTEXITCODE -ne 0) {
    throw "Frontend exited with code $LASTEXITCODE. Check whether port 5173 is already occupied."
}
