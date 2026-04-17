@echo off
echo ===================================================
echo   Malviz Simulation: LSASS Masquerading in ProgramData
echo ===================================================
echo.
echo This script tests dual-heuristics:
echo 1. Suspicious Execution Path (ProgramData)
echo 2. Masquerading System Process (lsass.exe)
echo.

set TEMP_DIR=C:\ProgramData\MalwareSim
mkdir "%TEMP_DIR%" 2>nul

echo [*] Staging fake lsass.exe...
copy /Y "C:\Windows\System32\ping.exe" "%TEMP_DIR%\lsass.exe" >nul

echo [*] Launching fake lsass.exe...
start "" "%TEMP_DIR%\lsass.exe" localhost -n 15 >nul

echo [*] Payload launched!
echo [*] Check Malviz Dashboard now! It should flag this as a Critical threat.
echo.
echo [*] Waiting 16 seconds for simulation to finish...
timeout /t 16 /nobreak >nul

echo [*] Cleaning up...
del /F /Q "%TEMP_DIR%\lsass.exe" 2>nul
rmdir "%TEMP_DIR%" 2>nul
echo [*] Done!
pause
