@echo off
echo [*] Simulating Masquerading Payload (svchost.exe outside System32)
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Copying ping.exe to spoof svchost.exe...
copy /Y C:\Windows\System32\ping.exe "%TEST_DIR%\svchost.exe" >nul

echo [*] Launching spoofed svchost.exe from %TEST_DIR% ...
start "" "%TEST_DIR%\svchost.exe" localhost -n 25 >nul

echo [*] Payload deployed. It will run for ~25 seconds.
echo [*] See Malviz dashboard for alerts...
timeout /t 22 >nul
del /f /q "%TEST_DIR%\svchost.exe" 2>nul
