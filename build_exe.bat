@echo off
rem Builds dist\WebNetCheck\WebNetCheck.exe (GUI) and dist\webnetcheck-cli\webnetcheck-cli.exe (console).
rem Pass "nopause" as the first argument to run unattended.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run run.bat once first - it creates .venv with dependencies.
  goto fail
)
tasklist /fi "imagename eq WebNetCheck.exe" 2>nul | find /i "WebNetCheck.exe" >nul
if not errorlevel 1 (
  echo WebNetCheck.exe is running. Close all its windows and start the build again.
  goto fail
)
".venv\Scripts\python.exe" -m pip install "pyinstaller>=6.3"
if errorlevel 1 goto fail

".venv\Scripts\pyinstaller.exe" --noconfirm --clean --windowed --name WebNetCheck ^
  --icon assets\webnetcheck.ico --collect-submodules dns ^
  --add-data "profiles;profiles" app.py
if errorlevel 1 goto fail

".venv\Scripts\pyinstaller.exe" --noconfirm --clean --console --name webnetcheck-cli ^
  --icon assets\webnetcheck.ico --collect-submodules dns --exclude-module PySide6 ^
  --add-data "profiles;profiles" cli.py
if errorlevel 1 goto fail

rem Editable copy of profiles next to the exe (it takes priority over the bundled one)
xcopy /E /I /Y profiles dist\WebNetCheck\profiles >nul
xcopy /E /I /Y profiles dist\webnetcheck-cli\profiles >nul
echo.
echo BUILD OK: dist\WebNetCheck\WebNetCheck.exe and dist\webnetcheck-cli\webnetcheck-cli.exe
if not "%1"=="nopause" pause
exit /b 0

:fail
echo.
echo BUILD FAILED
if not "%1"=="nopause" pause
exit /b 1
