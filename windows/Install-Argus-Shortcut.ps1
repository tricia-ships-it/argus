# Creates an Argus icon on your Desktop and in your Start menu.
# After it runs, you can pin Argus to the taskbar (see the note it prints).

$here     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$launcher = Join-Path $here 'Argus.cmd'
$icon     = Join-Path $here 'argus.ico'

if (-not (Test-Path $launcher)) {
  Write-Host "Could not find Argus.cmd next to this script. Keep the 'windows' folder together." -ForegroundColor Red
  exit 1
}

$shell = New-Object -ComObject WScript.Shell

function New-ArgusShortcut($path) {
  $s = $shell.CreateShortcut($path)
  $s.TargetPath       = "$env:ComSpec"            # cmd.exe
  $s.Arguments        = "/c `"$launcher`""
  $s.WorkingDirectory = $here
  $s.IconLocation     = "$icon,0"
  $s.Description       = 'Argus security platform'
  $s.WindowStyle      = 1
  $s.Save()
}

# Desktop icon
$desktop = [Environment]::GetFolderPath('Desktop')
New-ArgusShortcut (Join-Path $desktop 'Argus.lnk')

# Start menu icon (this is the one Windows lets you pin to the taskbar)
$startMenu = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs'
if (-not (Test-Path $startMenu)) { New-Item -ItemType Directory -Path $startMenu | Out-Null }
New-ArgusShortcut (Join-Path $startMenu 'Argus.lnk')

Write-Host ""
Write-Host "Done. You now have an Argus icon on your Desktop and in your Start menu." -ForegroundColor Green
Write-Host ""
Write-Host "To add it to the taskbar:" -ForegroundColor Cyan
Write-Host "  1. Open the Start menu and type:  Argus"
Write-Host "  2. Right-click the Argus result."
Write-Host "  3. Choose 'Pin to taskbar'. On Windows 11 click 'More' first."
Write-Host ""
Write-Host "Double-click the Desktop icon any time to start Argus." -ForegroundColor Cyan
Write-Host ""
