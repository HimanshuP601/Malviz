@echo off
echo ===================================================
echo   Malviz Threat Simulation Script - UAC Bypass
echo ===================================================
echo.
echo This script will safely simulate a UAC Bypass technique
echo relying on COM Object hijacking via fodhelper.exe.
echo.

set TEMP_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEMP_DIR%" 2>nul
echo [*] Copying cmd.exe to simulate elevated payload...
copy /Y "C:\Windows\System32\cmd.exe" "%TEMP_DIR%\cmd.exe" >nul
echo [*] Copying fodhelper.exe to test directory for simulated execution...
copy /Y "C:\Windows\System32\fodhelper.exe" "%TEMP_DIR%\fodhelper.exe" >nul

echo [*] Launching payload from fodhelper.exe helper.
echo [*] (In reality, we would hijack HKCU\Software\Classes\ms-settings\Shell\Open\command)
echo [*] Check your Malviz Dashboard! It should detect process ancestry fodhelper.exe -^> cmd.exe
echo.

:: We execute the fake UAC bypass parent which will then spawn our shell
start "" "%TEMP_DIR%\fodhelper.exe" /c "%TEMP_DIR%\cmd.exe /c ping localhost -n 10 >nul"

:: Keep script open so the test processes can be seen by the monitor
echo [*] Ping is running invisibly to maintain process alive.
timeout /t 10

echo [*] Simulation complete. Cleaning up...
del /F /Q "%TEMP_DIR%\cmd.exe"
del /F /Q "%TEMP_DIR%\fodhelper.exe"
rmdir "%TEMP_DIR%"
echo [*] Done!
pause
