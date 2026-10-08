@echo off
rem Builds dist\WebNetCheck\WebNetCheck.exe (GUI folder), dist\portable\WebNetCheck.exe (GUI single file),
rem dist\webnetcheck-cli\webnetcheck-cli.exe (console) and, if Inno Setup 6 is installed,
rem dist\WebNetCheck-<version>-setup.exe (installer).
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

".venv\Scripts\pyinstaller.exe" --noconfirm --clean --windowed --onefile --name WebNetCheck ^
  --distpath dist\portable --workpath build\portable ^
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

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" goto no_inno
rem Outside of a ( ) block on purpose: %APPVER% would expand before it is set
for /f %%v in ('".venv\Scripts\python.exe" -c "import netcheck; print(netcheck.__version__)"') do set "APPVER=%%v"
"%ISCC%" /Q "/DAppVersion=%APPVER%" installer\webnetcheck.iss
if errorlevel 1 goto fail
echo Installer: dist\WebNetCheck-%APPVER%-setup.exe
goto built
:no_inno
echo Inno Setup 6 not found - installer skipped. Get it at https://jrsoftware.org/isinfo.php
:built
echo.
echo BUILD OK: dist\WebNetCheck\WebNetCheck.exe, dist\portable\WebNetCheck.exe, dist\webnetcheck-cli\webnetcheck-cli.exe
if not "%1"=="nopause" pause
exit /b 0

:fail
echo.
echo BUILD FAILED
if not "%1"=="nopause" pause
exit /b 1
