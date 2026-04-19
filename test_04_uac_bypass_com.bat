@echo off
echo [*] Simulating UAC Bypass Execution (fodhelper.exe -^> cmd.exe)
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

:: We use cmd.exe exactly renamed as fodhelper.exe so we can easily spawn a child cmd.exe
echo [*] Staging cmd.exe as fodhelper.exe...
copy /Y C:\Windows\System32\cmd.exe "%TEST_DIR%\fodhelper.exe" >nul

echo [*] Launching fake fodhelper.exe which will spawn a child cmd.exe...
start "" "%TEST_DIR%\fodhelper.exe" /c "cmd.exe /c ""ping localhost -n 25 >nul"""

echo [*] Payload deployed. Process will stay alive for ~25 seconds.
echo [*] Check Malviz dashboard!
timeout /t 22 >nul
del /f /q "%TEST_DIR%\fodhelper.exe" 2>nul
