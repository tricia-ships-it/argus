@echo off
rem ============================================================
rem  Argus launcher for Windows
rem  Starts Argus on your own machine and opens it in your browser.
rem  Closing this window stops Argus.
rem ============================================================
title Argus
setlocal

rem Go to the app folder (this file lives in the "windows" folder next to "app")
cd /d "%~dp0\..\app"

rem Pick a Python launcher: prefer the "py" launcher, fall back to "python"
set PYEXE=py -3
where py >nul 2>&1 || set PYEXE=python

rem First run only: build a private environment and install the parts Argus needs
if not exist "venv\Scripts\python.exe" (
  echo.
  echo First run setup. This downloads what Argus needs and takes a minute or two.
  echo Please wait...
  echo.
  %PYEXE% -m venv venv
  call "venv\Scripts\activate.bat"
  python -m pip install --upgrade pip
  pip install -r requirements.txt
) else (
  call "venv\Scripts\activate.bat"
)

rem Open the browser a few seconds after the server starts
start "" /b cmd /c "timeout /t 4 >nul & start http://127.0.0.1:8080"

echo.
echo ============================================================
echo  Argus is running at  http://127.0.0.1:8080
echo  Your browser will open on its own in a moment.
echo  Keep this window open while you use Argus.
echo  Close this window when you are done to stop Argus.
echo ============================================================
echo.

rem Run the server (stays in the foreground so this window = Argus running)
python app.py --host 127.0.0.1 --port 8080

endlocal
