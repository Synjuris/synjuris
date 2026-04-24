@echo off
REM ═══════════════════════════════════════════════════════════════
REM  SynJuris — Windows Launcher
REM  Double-click this file to start SynJuris.
REM ═══════════════════════════════════════════════════════════════

cd /d "%~dp0"

cls
echo.
echo   ╔══════════════════════════════════════════════════╗
echo   ║           SynJuris Legal Assistant               ║
echo   ║     Local-First · AI-Assisted · Your Data        ║
echo   ╚══════════════════════════════════════════════════╝
echo.

REM ── 1. Check Python 3 ────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo   ✗  Python 3 is required but not found.
        echo.
        echo   Install it from: https://www.python.org/downloads/
        echo   Make sure to check "Add Python to PATH" during install.
        echo.
        pause
        exit /b 1
    ) else (
        set PYTHON=py
    )
) else (
    set PYTHON=python
)

for /f "tokens=2" %%i in ('%PYTHON% --version 2^>^&1') do set PYVER=%%i
echo   ✓  Python %PYVER%

REM ── 2. Check synjuris-10.py ──────────────────────────────────
if not exist "synjuris-10.py" (
    echo   ✗  synjuris-10.py not found in this folder.
    echo      Make sure launch_synjuris_windows.bat is in the
    echo      same folder as synjuris-10.py
    echo.
    pause
    exit /b 1
)

echo   ✓  synjuris-10.py found

REM ── 3. API key (optional) ─────────────────────────────────────
if "%ANTHROPIC_API_KEY%"=="" (
    echo.
    echo   ─────────────────────────────────────────────────────
    echo   AI features require an Anthropic API key.
    echo   Get a free key at: https://console.anthropic.com
    echo.
    echo   Paste your key below and press Enter,
    echo   or just press Enter to skip ^(AI will be disabled^).
    echo   ─────────────────────────────────────────────────────
    set /p USER_KEY="  API key: "
    if not "%USER_KEY%"=="" (
        set ANTHROPIC_API_KEY=%USER_KEY%
        echo.
        echo   ✓  API key set for this session.
        echo.
        echo   To make this permanent, run in PowerShell:
        echo   [System.Environment]::SetEnvironmentVariable^('ANTHROPIC_API_KEY','%USER_KEY%','User'^)
    ) else (
        echo.
        echo   Continuing without API key - AI features disabled.
    )
) else (
    echo   ✓  API key: set ^(from environment^)
)

REM ── 4. Launch ─────────────────────────────────────────────────
echo.
echo   Starting SynJuris on http://localhost:5000 ...
echo   Press Ctrl+C to stop. Close this window to quit.
echo.

%PYTHON% synjuris-10.py

echo.
echo   SynJuris stopped.
pause
