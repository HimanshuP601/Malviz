@echo off
echo [*] Simulating Obfuscated Command Line Execution
echo [*] Launching powershell.exe with -ExecutionPolicy Bypass and -EncodedCommand

:: This will spawn a powershell process that sleeps for 25 seconds
start "" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMgA1AA=="

echo [*] Payload deployed. It will run for ~25 seconds.
echo [*] Check Malviz dashboard!
timeout /t 20 >nul
