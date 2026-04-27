@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM  SynJuris v2 — Windows Launcher
REM ═══════════════════════════════════════════════════════════════════════════

cd /d "%~dp0"
cls
echo.
echo   ╔════════════════════════════════════════════════════════╗
echo   ║         SynJuris v2 — Advanced Architecture           ║
echo   ║    Merkle DAG · Semantic AI · Streaming · Local       ║
echo   ╚════════════════════════════════════════════════════════╝
echo.

REM ── Check Python ────────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo   ✗  Python not found. Install from python.org
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

REM ── Check script ─────────────────────────────────────────────────────────────
if exist "synjuris-20.py" (
    set SCRIPT=synjuris-20.py
    echo   ✓  synjuris-20.py found
) else if exist "synjuris-10.py" (
    set SCRIPT=synjuris-10.py
    echo   ⚠  synjuris-20.py not found, using synjuris-10.py
) else (
    echo   ✗  No SynJuris script found.
    pause
    exit /b 1
)

REM ── API key ──────────────────────────────────────────────────────────────────
if "%ANTHROPIC_API_KEY%"=="" (
    echo.
    echo   ─────────────────────────────────────────────────────────
    echo   AI features require an Anthropic API key.
    echo   Get one at: https://console.anthropic.com
    echo   ─────────────────────────────────────────────────────────
    set /p USER_KEY="  API key (or Enter to skip): "
    if not "%USER_KEY%"=="" (
        set ANTHROPIC_API_KEY=%USER_KEY%
        echo   ✓  API key set.
    ) else (
        echo   Continuing without API key.
    )
) else (
    echo   ✓  API key: set
)

REM ── Optional enhancements ─────────────────────────────────────────────────
echo.
echo   ─────────────────────────────────────────────────────────
echo   Install optional v2 enhancements? (streaming, semantic AI)
echo   This will run: pip install anthropic sentence-transformers
echo   ─────────────────────────────────────────────────────────
set /p INSTALL_CHOICE="  Install? [y/N]: "

if /i "%INSTALL_CHOICE%"=="y" (
    echo   Installing Anthropic SDK...
    %PYTHON% -m pip install anthropic --quiet
    echo   Installing sentence-transformers...
    %PYTHON% -m pip install sentence-transformers --quiet
    echo   ✓  Done. Failures above are non-critical.
)

REM ── Launch ────────────────────────────────────────────────────────────────
echo.
echo   ════════════════════════════════════════════════════════
echo   Starting SynJuris on http://localhost:5000 ...
echo   Press Ctrl+C to stop.
echo   ════════════════════════════════════════════════════════
echo.

%PYTHON% %SCRIPT%

echo.
echo   SynJuris stopped.
pause
