@echo off
rem Double-click this to put an Argus icon on your Desktop and Start menu.
rem It runs the PowerShell helper for you, so you do not have to change any
rem PowerShell settings yourself.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Argus-Shortcut.ps1"
echo.
pause
