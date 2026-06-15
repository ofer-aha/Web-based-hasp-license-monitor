@echo off
setlocal
set "TASK_NAME=AladdinLicenseMonitor"

echo ================================================
echo   Aladdin License Monitor - Uninstaller
echo ================================================
echo.

net session >nul 2>&1
if errorlevel 1 ( echo ERROR: Run as Administrator. & pause & exit /b 1 )

echo Stopping task...
schtasks /end /tn "%TASK_NAME%" >nul 2>&1

echo Removing task...
schtasks /delete /tn "%TASK_NAME%" /f

echo.
echo Task "%TASK_NAME%" removed.
echo Log files remain in: %~dp0logs\
pause
