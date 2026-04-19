@echo off
echo [*] Simulating Masquerading Payload (svchost.exe outside System32)
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Copying ping.exe to spoof svchost.exe...
copy /Y C:\Windows\System32\ping.exe "%TEST_DIR%\svchost.exe" >nul

echo [*] Launching spoofed svchost.exe from %TEST_DIR% ...
start "" "%TEST_DIR%\svchost.exe" localhost -t >nul

echo [*] Payload deployed. It will run indefinitely until killed via UI.
echo [*] See Malviz dashboard for alerts...
