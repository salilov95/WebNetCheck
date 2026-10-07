@echo off
rem WebNetCheck: first run creates .venv and installs dependencies, then starts the GUI.
cd /d "%~dp0"
if exist ".venv\Scripts\pythonw.exe" goto run

where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 (
  echo Python 3.11+ not found. Install it from https://www.python.org/downloads/windows/
  echo and enable "Add python.exe to PATH" in the installer.
  pause
  exit /b 1
)
echo Creating virtual environment...
%PY% -m venv .venv || (echo venv creation failed & pause & exit /b 1)
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt || (echo pip install failed - check proxy settings, see README & pause & exit /b 1)

:run
start "" ".venv\Scripts\pythonw.exe" app.py
