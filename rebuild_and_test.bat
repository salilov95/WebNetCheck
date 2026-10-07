@echo off
rem Rebuilds both exe files and self-tests them. Output goes to _verify\
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
if not exist _verify mkdir _verify
set LOG=_verify\rebuild.txt
echo ==== start %date% %time% > %LOG%
del _verify\exe_*.png _verify\exe_*.txt _verify\trace_exe*.txt 2>nul
del "%LOCALAPPDATA%\WebNetCheck\crash.log" 2>nul
".venv\Scripts\python.exe" -m unittest discover -s tests >> %LOG% 2>&1
echo unittest exit=%errorlevel% >> %LOG%
call build_exe.bat nopause > _verify\build.txt 2>&1
if errorlevel 1 (
  echo build FAILED - see _verify\build.txt >> %LOG%
  echo ==== done %date% %time% >> %LOG%
  exit /b 1
)
echo build exit=0 >> %LOG%

"dist\webnetcheck-cli\webnetcheck-cli.exe" github --html _verify\exe_cli_github.html > _verify\exe_cli_github.txt 2>&1
echo exe cli github exit=%errorlevel% >> %LOG%
"dist\webnetcheck-cli\webnetcheck-cli.exe" https://expired.badssl.com/ --only dns,tcp,tls,http > _verify\exe_cli_badssl.txt 2>&1
echo exe cli badssl exit=%errorlevel% >> %LOG%
"dist\webnetcheck-cli\webnetcheck-cli.exe" https://10.255.255.1/ --only dns,icmp,trace,tcp,http --timeout 3 > _verify\exe_cli_blackhole.txt 2>&1
echo exe cli blackhole exit=%errorlevel% >> %LOG%

set WEBNETCHECK_TRACE=_verify\trace_exe_github.txt
start "" /wait "dist\WebNetCheck\WebNetCheck.exe" --selftest https://github.com/ --screenshot _verify\exe_gui_github.png
echo exe gui github exit=%errorlevel% >> %LOG%
set WEBNETCHECK_TRACE=_verify\trace_exe_badssl.txt
start "" /wait "dist\WebNetCheck\WebNetCheck.exe" --selftest https://expired.badssl.com/ --screenshot _verify\exe_gui_badssl.png
echo exe gui badssl exit=%errorlevel% >> %LOG%
set WEBNETCHECK_TRACE=
if exist "%LOCALAPPDATA%\WebNetCheck\crash.log" copy /y "%LOCALAPPDATA%\WebNetCheck\crash.log" _verify\crash.log >nul
dir dist\WebNetCheck\WebNetCheck.exe dist\webnetcheck-cli\webnetcheck-cli.exe >> %LOG% 2>&1
echo ==== done %date% %time% >> %LOG%
