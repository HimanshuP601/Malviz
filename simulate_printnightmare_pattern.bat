@echo off
echo ===================================================
echo   Malviz Simulation: PrintNightmare Ancestry
echo ===================================================
echo.
echo This script tests the "Dangerous Ancestry (PrintNightmare Pattern)" rule.
echo It creates a fake spoolsv.exe process which then spawns powershell.exe.
echo.

set TEMP_DIR=%LOCALAPPDATA%\Temp\MalvizTestPN
mkdir "%TEMP_DIR%" 2>nul
if not exist "%TEMP_DIR%" (
    echo [!] Failed to create temp directory.
    exit /b
)

echo [*] Staging fake spoolsv.exe (using cmd.exe)...
copy /Y "C:\Windows\System32\cmd.exe" "%TEMP_DIR%\spoolsv.exe" >nul

echo [*] Launching fake spoolsv.exe and forcing it to spawn powershell...
:: Start the fake spoolsv.exe in the background. It will execute a command to start powershell.
start "" "%TEMP_DIR%\spoolsv.exe" /c "powershell.exe -WindowStyle Hidden -Command ""Start-Sleep -Seconds 15"""

echo [*] Payloads launched!
echo [*] Check Malviz Dashboard now! It should flag spoolsv.exe spawning powershell.exe as a CRITICAL threat.
echo.
echo [*] Waiting 16 seconds for simulation to finish...
timeout /t 16 /nobreak >nul

echo [*] Cleaning up...
del /F /Q "%TEMP_DIR%\spoolsv.exe" 2>nul
rmdir "%TEMP_DIR%" 2>nul
echo [*] Done!
pause
