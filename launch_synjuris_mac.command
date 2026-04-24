#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  SynJuris — Mac/Linux Launcher
#  Double-click this file to start SynJuris.
#  On first run: right-click → Open (to bypass Gatekeeper).
# ═══════════════════════════════════════════════════════════════

# Move to the folder containing this script (where synjuris-10.py lives)
cd "$(dirname "$0")"

clear
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║           SynJuris Legal Assistant               ║"
echo "  ║     Local-First · AI-Assisted · Your Data        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# ── 1. Check Python 3 ────────────────────────────────────────
PYTHON=""
for cmd in python3 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 9 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  ✗  Python 3.9 or later is required but not found."
    echo ""
    echo "  Install it from: https://www.python.org/downloads/"
    echo "  Or with Homebrew: brew install python3"
    echo ""
    echo "  Press Enter to exit."
    read -r
    exit 1
fi

echo "  ✓  Python: $($PYTHON --version)"

# ── 2. Check synjuris-10.py exists ───────────────────────────
if [ ! -f "synjuris-10.py" ]; then
    echo "  ✗  synjuris-10.py not found in this folder."
    echo "     Make sure launch_synjuris_mac.command is in the"
    echo "     same folder as synjuris-10.py"
    echo ""
    echo "  Press Enter to exit."
    read -r
    exit 1
fi

echo "  ✓  synjuris-10.py found"

# ── 3. API key (optional — AI features only) ─────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "  ─────────────────────────────────────────────────────"
    echo "  AI features (document drafting, case analysis, chat)"
    echo "  require an Anthropic API key."
    echo ""
    echo "  Get a free key at: https://console.anthropic.com"
    echo ""
    echo "  You can paste your key here (or press Enter to skip):"
    echo "  Everything else works without a key."
    echo "  ─────────────────────────────────────────────────────"
    printf "  API key: "
    read -r USER_KEY
    if [ -n "$USER_KEY" ]; then
        export ANTHROPIC_API_KEY="$USER_KEY"
        echo ""
        echo "  ✓  API key set for this session."
        echo ""
        echo "  To make this permanent, add to your shell profile:"
        echo "  export ANTHROPIC_API_KEY=\"$USER_KEY\""
        echo "  (~/.zshrc on macOS 10.15+, ~/.bash_profile on older)"
    else
        echo ""
        echo "  Continuing without API key — AI features will be disabled."
    fi
else
    echo "  ✓  API key: set (from environment)"
fi

# ── 4. Launch ─────────────────────────────────────────────────
echo ""
echo "  Starting SynJuris on http://localhost:5000 ..."
echo "  Press Ctrl+C to stop."
echo ""

$PYTHON synjuris-10.py

# ── 5. Exit message ───────────────────────────────────────────
echo ""
echo "  SynJuris stopped. Press Enter to close this window."
read -r
