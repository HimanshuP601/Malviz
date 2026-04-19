@echo off
echo [*] Simulating Privileged Scheduled Task Creation
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Spoofing cmd.exe as schtasks.exe...
copy /Y C:\Windows\System32\cmd.exe "%TEST_DIR%\schtasks.exe" >nul

echo [*] Launching fake schtasks with mocked malicious arguments inside...
start "" "%TEST_DIR%\schtasks.exe" /c "ping localhost -t >nul & REM /create /ru system"

echo [*] Payload deployed. It will run indefinitely until killed via UI.
echo [*] See Malviz dashboard for Scheduled Task alert...
