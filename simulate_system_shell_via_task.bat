@echo off
echo ===================================================
echo   Malviz Simulation: System Shell Spawned
echo ===================================================
echo.
echo This script requires Administrator privileges.
echo It schedules a temporary task to run cmd.exe as NT AUTHORITY\SYSTEM.
echo This will trigger the "System Shell Spawned" rule in Malviz.
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This specific test must be run as Administrator!
    echo Please close this window, right-click the script and select "Run as Administrator".
    pause
    exit /b
)

echo [*] Creating scheduled task to run cmd.exe as SYSTEM...
schtasks /create /tn "MalvizSysShellTest" /tr "cmd.exe /c timeout /t 15 /nobreak" /sc once /st 00:00 /ru "NT AUTHORITY\SYSTEM" /f >nul

echo [*] Executing task manually now...
schtasks /run /tn "MalvizSysShellTest" >nul

echo [*] Payload launched! Malviz should detect cmd.exe running as SYSTEM
echo [*] spawned by svchost.exe (Task Scheduler), which is not an expected parent.
echo.
echo [*] Waiting 16 seconds for simulation to finish...
timeout /t 16 /nobreak >nul

echo [*] Cleaning up...
schtasks /delete /tn "MalvizSysShellTest" /f >nul
echo [*] Done!
pause
