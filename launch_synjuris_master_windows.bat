@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM  SynJuris v2 — Windows Launcher
REM  Double-click to start. Click "More info" then "Run anyway" if Defender prompts.
REM ═══════════════════════════════════════════════════════════════════════════

cd /d "%~dp0"
cls
echo.
echo   ╔════════════════════════════════════════════════════════╗
echo   ║         SynJuris v2 — Legal Intelligence               ║
echo   ║   Local-First · AI-Assisted · Your Data Stays Yours    ║
echo   ╚════════════════════════════════════════════════════════╝
echo.

REM ── Check Python ────────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo   ✗  Python not found.
        echo      Download from: https://www.python.org/downloads/
        echo      Make sure to check "Add Python to PATH" during install.
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

REM ── Check synjuris.py ────────────────────────────────────────────────────────
if not exist "synjuris.py" (
    echo   ✗  synjuris.py not found in this folder.
    echo      Make sure this launcher is in the same folder as synjuris.py
    echo.
    pause
    exit /b 1
)
echo   ✓  synjuris.py found

REM ── API key ──────────────────────────────────────────────────────────────────
if "%ANTHROPIC_API_KEY%"=="" (
    echo.
    echo   ─────────────────────────────────────────────────────────
    echo   AI features require an API key.
    echo.
    echo   Anthropic (default): https://console.anthropic.com
    echo   OpenAI:              https://platform.openai.com/api-keys
    echo   Ollama (local/free): https://ollama.com — no key needed
    echo.
    echo   Paste your Anthropic or OpenAI key, or press Enter to skip.
    echo   ─────────────────────────────────────────────────────────
    set /p USER_KEY="  API key (or Enter to skip): "
    if not "%USER_KEY%"=="" (
        set ANTHROPIC_API_KEY=%USER_KEY%
        echo   ✓  API key set for this session.
    ) else (
        echo   Continuing without API key — AI features disabled until configured.
    )
) else (
    echo   ✓  API key: set
)

REM ── Optional enhancements ─────────────────────────────────────────────────
echo.
echo   ─────────────────────────────────────────────────────────
echo   Optional enhancements (non-critical — app works without them):
echo.
echo     True streaming AI responses  -^> pip install anthropic
echo     Semantic pattern detection   -^> pip install sentence-transformers
echo.
set /p INSTALL_CHOICE="  Install optional enhancements? [y/N]: "

if /i "%INSTALL_CHOICE%"=="y" (
    echo.
    echo   Installing...
    %PYTHON% -m pip install anthropic --quiet
    echo   ✓  anthropic SDK
    %PYTHON% -m pip install sentence-transformers --quiet
    echo   ✓  sentence-transformers
    echo.
    echo   ✓  Done. Any failures above are non-critical.
) else (
    echo   Skipping — SynJuris works fully without these.
)

REM ── Launch ────────────────────────────────────────────────────────────────
echo.
echo   ════════════════════════════════════════════════════════
echo   Starting SynJuris on http://localhost:5000 ...
echo   Press Ctrl+C to stop. Close this window to quit.
echo   ════════════════════════════════════════════════════════
echo.

%PYTHON% synjuris.py

echo.
echo   SynJuris stopped.
pause
