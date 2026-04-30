@echo off
cd /d "%~dp0"

echo Starting SynJuris...
echo.

:: Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python from python.org
    pause
    exit /b 1
)

:: Check for API key
if "%ANTHROPIC_API_KEY%"=="" (
    echo WARNING: ANTHROPIC_API_KEY not set. AI features will be disabled.
    echo Set it by running: set ANTHROPIC_API_KEY=your-key-here
    echo.
)

:: Install dependencies
echo Installing dependencies...
pip install reportlab >nul 2>&1

:: Launch
echo Launching SynJuris at http://localhost:5000
echo Press Ctrl+C to stop.
echo.
python synjuris.py

:: If we get here something went wrong
echo.
echo SynJuris stopped. See error above.
pause
