@echo off
echo [*] Simulating Obfuscated Command Line Execution
echo [*] Launching powershell.exe with -ExecutionPolicy Bypass and -EncodedCommand

:: This will spawn a powershell process that loops infinitely
start "" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "while(1) { Start-Sleep -Seconds 1 }"

echo [*] Payload deployed. It will run indefinitely until killed via UI.
echo [*] Check Malviz dashboard!
