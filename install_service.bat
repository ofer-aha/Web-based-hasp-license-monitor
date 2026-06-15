@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "APP_DIR=%~dp0"
set "TASK_NAME=AladdinLicenseMonitor"

echo ================================================
echo   Aladdin License Monitor - Service Installer
echo ================================================
echo.

:: --- Admin check ---------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: Run this script as Administrator.
    echo Right-click ^> "Run as administrator"
    pause & exit /b 1
)

:: --- Locate Python -------------------------------------------------------
for /f "usebackq delims=" %%i in (`where python 2^>nul`) do (
    set "PYTHON=%%i" & goto :python_ok
)
echo ERROR: Python not found in PATH.
pause & exit /b 1
:python_ok
echo Python : %PYTHON%

:: --- Install Python packages ---------------------------------------------
echo.
echo Installing / verifying Python packages...
"%PYTHON%" -m pip install -r "%APP_DIR%requirements.txt" --quiet
if errorlevel 1 ( echo ERROR: pip install failed. & pause & exit /b 1 )
echo Packages OK.

:: --- Service account -----------------------------------------------------
echo.
echo The task needs a domain admin account so WMI and AD queries work.
echo Press ENTER to use the current account: %USERDOMAIN%\%USERNAME%
echo Or type  DOMAIN\username  to use a different account.
echo.
set /p "SVC_USER=Account [%USERDOMAIN%\%USERNAME%]: "
if "!SVC_USER!"=="" set "SVC_USER=%USERDOMAIN%\%USERNAME%"
echo.
set /p "SVC_PASS=Password for !SVC_USER!: "
echo.

:: --- Remove existing task ------------------------------------------------
echo Removing existing task (if any)...
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: --- Create logs directory -----------------------------------------------
if not exist "%APP_DIR%logs" mkdir "%APP_DIR%logs"

:: --- Create scheduled task -----------------------------------------------
echo Creating scheduled task "%TASK_NAME%"...
schtasks /create ^
  /tn "%TASK_NAME%" ^
  /tr "\"%PYTHON%\" \"%APP_DIR%start_server.py\"" ^
  /sc onstart ^
  /ru "!SVC_USER!" ^
  /rp "!SVC_PASS!" ^
  /rl HIGHEST ^
  /f

if errorlevel 1 (
    echo ERROR: Failed to create scheduled task.
    pause & exit /b 1
)

:: --- Start task now ------------------------------------------------------
echo.
echo Starting task now...
schtasks /run /tn "%TASK_NAME%"
if errorlevel 1 (
    echo WARNING: Task created but could not start immediately.
    echo It will run automatically on next reboot.
) else (
    timeout /t 4 /nobreak >nul
    echo Server should now be running at http://localhost:5000
)

echo.
echo ================================================
echo   Installation complete
echo   Task    : %TASK_NAME%
echo   Account : !SVC_USER!
echo   URL     : http://localhost:5000
echo   Logs    : %APP_DIR%logs\service.log
echo.
echo   Manage:
echo     schtasks /run   /tn %TASK_NAME%
echo     schtasks /end   /tn %TASK_NAME%
echo     schtasks /query /tn %TASK_NAME%
echo   Or run uninstall_service.bat to remove.
echo ================================================
pause
