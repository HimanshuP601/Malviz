@echo off
echo [*] Simulating PrintNightmare Ancestry (spoolsv.exe -^> powershell.exe)
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul

echo [*] Staging cmd.exe as spoolsv.exe...
copy /Y C:\Windows\System32\cmd.exe "%TEST_DIR%\spoolsv.exe" >nul

echo [*] Launching fake spoolsv.exe and forcing it to spawn powershell...
start "" "%TEST_DIR%\spoolsv.exe" /c "powershell.exe -WindowStyle Hidden -Command ""while($true){Start-Sleep -Seconds 1}"""

echo [*] Payloads launched! They will run indefinitely until killed via UI.
echo [*] See Malviz dashboard for Critical PrintNightmare alert...
