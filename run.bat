@echo off
cd /d "%~dp0"

echo Installing / verifying dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo ERROR: pip install failed. Make sure Python and pip are working.
    pause
    exit /b 1
)

echo.
echo Starting Aladdin License Monitor...
echo Open http://localhost:5000 in your browser
echo Press Ctrl+C to stop.
echo.
python server.py
pause
