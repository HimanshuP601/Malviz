@echo off
echo ===================================================
echo   Malviz Threat Simulation Script
echo ===================================================
echo.
echo This script will safely trigger two of Malviz's detection heuristics:
echo 1. Suspicious Execution Path (Running from Temp)
echo 2. Masquerading (Using a System process name in the wrong folder)
echo.

set TEMP_DIR=%LOCALAPPDATA%\Temp\MalvizTest

:: Create a temporary test directory
mkdir "%TEMP_DIR%" 2>nul

:: Copy a harmless built-in Windows binary (ping.exe) and rename it to svchost.exe
echo [*] Copying ping.exe to %TEMP_DIR%\svchost.exe...
copy /Y "C:\Windows\System32\ping.exe" "%TEMP_DIR%\svchost.exe" >nul

:: Execute the masqueraded file. We use ping localhost to keep it alive for 10 seconds.
echo [*] Executing %TEMP_DIR%\svchost.exe (pinging localhost for 10 seconds)...
echo [*] Check your Malviz Dashboard now! It should flag this as a CRITICAL threat.
echo.

"%TEMP_DIR%\svchost.exe" localhost -n 10 >nul

echo [*] Simulation complete. Cleaning up...
del /F /Q "%TEMP_DIR%\svchost.exe"
rmdir "%TEMP_DIR%"
echo [*] Done!
pause
