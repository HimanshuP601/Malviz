@echo off
echo [*] Simulating Known Impersonation Tool Execution Pattern
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Spoofing ping.exe as PrintSpoofer.exe...
copy /Y C:\Windows\System32\ping.exe "%TEST_DIR%\PrintSpoofer.exe" >nul

echo [*] Starting fake PrintSpoofer.exe...
start "" "%TEST_DIR%\PrintSpoofer.exe" localhost -n 25 >nul

echo [*] Payload deployed. It will run for ~25 seconds.
echo [*] See Malviz dashboard for alerts...
timeout /t 22 >nul
del /f /q "%TEST_DIR%\PrintSpoofer.exe" 2>nul
