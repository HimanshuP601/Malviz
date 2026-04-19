@echo off
echo [*] Simulating Suspicious DLL Loading
set TEST_DIR=%LOCALAPPDATA%\Temp\MalvizTest
mkdir "%TEST_DIR%" 2>nul
echo DUMMY_DATA > "%TEST_DIR%\malicious_payload_test.dll"

echo [*] Launching rundll32.exe pointed at dummy DLL in user Temp folder...
echo [*] Note: An error dialog might pop up because the DLL is bogus. 
echo [*] DO NOT close the error dialog yet! Malviz needs time to see the open process.

start "" rundll32.exe "%TEST_DIR%\malicious_payload_test.dll",EntryPoint

echo [*] Payload deployed. 
echo [*] Check Malviz dashboard! Close the rundll dialog later.
timeout /t 20 >nul
