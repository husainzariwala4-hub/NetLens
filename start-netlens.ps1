Set-Location -LiteralPath $PSScriptRoot
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    Write-Host 'Python environment not found. Follow the setup instructions in README.md.'
    exit 1
}
$driver = & $python -m netlens.setup driver
if ($driver -notcontains 'ready') {
    Write-Host 'Npcap was not detected. Install Npcap from https://npcap.com/ and restart PowerShell.' -ForegroundColor Yellow
    exit 1
}
$interfaceJson = & $python -m netlens.setup interfaces
if ($LASTEXITCODE -ne 0) { Write-Host 'Could not list network interfaces.'; exit 1 }
$interfaces = ConvertFrom-Json -InputObject ($interfaceJson -join '')
$interfaces = @($interfaces)
if ($interfaces.Count -eq 0) { Write-Host 'No interfaces were found.'; exit 1 }
Write-Host 'Select an interface you are authorized to capture on:'
for ($i = 0; $i -lt $interfaces.Count; $i++) { Write-Host ("{0}. {1} - {2}" -f ($i + 1), $interfaces[$i].name, $interfaces[$i].description) }
$selection = Read-Host 'Enter interface number'
$number = 0
if (-not [int]::TryParse($selection, [ref]$number) -or $number -lt 1 -or $number -gt $interfaces.Count) { Write-Host 'Invalid selection.'; exit 1 }
$env:NETLENS_ALLOWED_INTERFACES = $interfaces[$number - 1].id
if ([string]::IsNullOrWhiteSpace($env:NETLENS_ALLOWED_INTERFACES)) { Write-Host 'The selected interface has no capture identifier. Try another interface.'; exit 1 }
Write-Host 'Starting NetLens. Open http://127.0.0.1:8000/ and select the authorized interface. Press Ctrl+C to stop.'
& $python -m uvicorn netlens.main:app --host 127.0.0.1 --port 8000
