#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SynJuris v2 — Mac/Linux Launcher
#  Double-click to start. Right-click → Open on first run if macOS blocks it.
# ═══════════════════════════════════════════════════════════════════════════════

cd "$(dirname "$0")"

clear
echo ""
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║           SynJuris v2 — Legal Intelligence             ║"
echo "  ║     Local-First · AI-Assisted · Your Data Stays Yours  ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Check Python 3.9+ ─────────────────────────────────────────────────────
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
    echo "  ✗  Python 3.9 or later required."
    echo "     Download from: https://www.python.org/downloads/"
    echo ""
    read -r; exit 1
fi
echo "  ✓  Python: $($PYTHON --version)"

# ── 2. Check synjuris.py ─────────────────────────────────────────────────────
if [ ! -f "synjuris.py" ]; then
    echo "  ✗  synjuris.py not found in this folder."
    echo "     Make sure this launcher is in the same folder as synjuris.py"
    echo ""
    read -r; exit 1
fi
echo "  ✓  synjuris.py found"

# ── 3. API key ────────────────────────────────────────────────────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "  ─────────────────────────────────────────────────────────"
    echo "  AI features require an API key."
    echo ""
    echo "  Anthropic (default): https://console.anthropic.com"
    echo "  OpenAI:              https://platform.openai.com/api-keys"
    echo "  Ollama (local/free): https://ollama.com — no key needed"
    echo ""
    echo "  Paste your Anthropic or OpenAI key here, or press Enter to skip."
    echo "  (To use Ollama, just press Enter — configure it inside the app)"
    echo "  ─────────────────────────────────────────────────────────"
    printf "  API key: "
    read -r USER_KEY
    if [ -n "$USER_KEY" ]; then
        export ANTHROPIC_API_KEY="$USER_KEY"
        echo "  ✓  API key set for this session."
    else
        echo "  Continuing without API key — AI features disabled until configured."
    fi
else
    echo "  ✓  API key: set (from environment)"
fi

# ── 4. Optional enhancements ──────────────────────────────────────────────────
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo "  Optional enhancements (all non-critical — app works without them):"
echo ""
echo "  • True streaming AI responses  → pip install anthropic"
echo "  • Semantic pattern detection   → pip install sentence-transformers"
echo "  • Advanced negation detection  → pip install spacy"
echo ""
printf "  Install optional enhancements now? [y/N]: "
read -r INSTALL_CHOICE

if [[ "$INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
    echo ""
    echo "  Installing..."

    if $PYTHON -m pip install anthropic --quiet --break-system-packages 2>/dev/null || \
       $PYTHON -m pip install anthropic --quiet 2>/dev/null; then
        echo "  ✓  anthropic SDK"
    else
        echo "  ⚠  anthropic install failed (optional — app still works)"
    fi

    if $PYTHON -m pip install sentence-transformers --quiet --break-system-packages 2>/dev/null || \
       $PYTHON -m pip install sentence-transformers --quiet 2>/dev/null; then
        echo "  ✓  sentence-transformers"
    else
        echo "  ⚠  sentence-transformers install failed (optional)"
    fi

    if { $PYTHON -m pip install spacy --quiet --break-system-packages 2>/dev/null || \
         $PYTHON -m pip install spacy --quiet 2>/dev/null; } && \
       $PYTHON -m spacy download en_core_web_sm --quiet 2>/dev/null; then
        echo "  ✓  spacy"
    else
        echo "  ⚠  spacy install failed (optional)"
    fi

    echo ""
    echo "  ✓  Done. Any failures above are non-critical."
else
    echo ""
    echo "  Skipping — SynJuris works fully without these."
fi

# ── 5. Launch ─────────────────────────────────────────────────────────────────
echo ""
echo "  ═══════════════════════════════════════════════════════"
echo "  Starting SynJuris on http://localhost:5000 ..."
echo "  Press Ctrl+C to stop."
echo "  ═══════════════════════════════════════════════════════"
echo ""

$PYTHON synjuris.py

echo ""
echo "  SynJuris stopped. Press Enter to close."
read -r
