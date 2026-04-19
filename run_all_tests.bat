@echo off
echo ===========================================
echo Malviz Detection Logic Test Suite
echo ===========================================
echo Launching all simulations in parallel...
echo.

start cmd.exe /c test_01_masquerading.bat
start cmd.exe /c test_02_printnightmare.bat
start cmd.exe /c test_03_obfuscated_cmdline.bat
start cmd.exe /c test_04_uac_bypass_com.bat
start cmd.exe /c test_05_dll_hijack.bat
start cmd.exe /c test_06_impersonation_tool.bat
start cmd.exe /c test_07_scheduled_task.bat

echo All tests have been launched!
echo Open Malviz Dashboard, wait a few seconds, and watch the detections roll in.
echo Note: Test 5 may open an error dialog about a missing DLL, please leave it open 
echo until you see the detection in the dashboard.
echo.
pause
