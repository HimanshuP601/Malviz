@echo off
echo [*] Simulating Known Impersonation Tool Execution Pattern
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Spoofing ping.exe as PrintSpoofer.exe...
copy /Y C:\Windows\System32\ping.exe "%TEST_DIR%\PrintSpoofer.exe" >nul

echo [*] Starting fake PrintSpoofer.exe...
start "" "%TEST_DIR%\PrintSpoofer.exe" localhost -t >nul

echo [*] Payload deployed. It will run indefinitely until killed via UI.
echo [*] See Malviz dashboard for alerts...
