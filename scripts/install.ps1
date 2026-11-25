<#
  EmberScan installer (PowerShell wrapper).
  install.py creates/repairs .\venv itself, so it is always started with the
  system Python, never with the (possibly broken) venv.
  Usage:  .\scripts\install.ps1 [--check] [--dev] [--recreate-venv]
#>
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $here "install.py"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $script @args
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $script @args
} else {
    Write-Host "Python 3.9+ is required: https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "INSTALLATION FAILED -- EmberScan is NOT installed." -ForegroundColor Red
    exit 1
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "INSTALLATION FAILED -- see the messages above." -ForegroundColor Red
}
exit $LASTEXITCODE
