#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SynJuris v2 — Mac/Linux Launcher
#  Checks for optional v2 dependencies and installs them if you want them.
# ═══════════════════════════════════════════════════════════════════════════════

cd "$(dirname "$0")"

clear
echo ""
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║           SynJuris v2 — Advanced Architecture         ║"
echo "  ║     Merkle DAG · Semantic AI · Streaming · Local      ║"
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
    echo "  ✗  Python 3.9 or later required. Install from python.org"
    read -r; exit 1
fi
echo "  ✓  Python: $($PYTHON --version)"

# ── 2. Check synjuris-20.py ──────────────────────────────────────────────────
if [ ! -f "synjuris-20.py" ]; then
    # Try falling back to synjuris-10.py
    if [ -f "synjuris-10.py" ]; then
        echo "  ⚠  synjuris-20.py not found — launching synjuris-10.py (v1)"
        SCRIPT="synjuris-10.py"
    else
        echo "  ✗  No SynJuris script found in this folder."
        read -r; exit 1
    fi
else
    SCRIPT="synjuris-20.py"
    echo "  ✓  $SCRIPT found"
fi

# ── 3. API key ────────────────────────────────────────────────────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "  ─────────────────────────────────────────────────────────"
    echo "  AI features require an Anthropic API key."
    echo "  Get a free key at: https://console.anthropic.com"
    echo ""
    echo "  Paste your key here (or Enter to skip):"
    echo "  ─────────────────────────────────────────────────────────"
    printf "  API key: "
    read -r USER_KEY
    if [ -n "$USER_KEY" ]; then
        export ANTHROPIC_API_KEY="$USER_KEY"
        echo "  ✓  API key set for this session."
    else
        echo "  Continuing without API key — AI features disabled."
    fi
else
    echo "  ✓  API key: set (from environment)"
fi

# ── 4. Optional v2 enhancements ──────────────────────────────────────────────
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo "  SynJuris v2 has optional enhancements:"
echo ""
echo "  • Streaming generation (real-time text as it's written)"
echo "    → pip install anthropic"
echo ""
echo "  • Semantic pattern detection (catches paraphrased violations)"
echo "    → pip install sentence-transformers"
echo ""
echo "  • Advanced negation detection"
echo "    → pip install spacy && python -m spacy download en_core_web_sm"
echo ""
echo "  Install optional enhancements now? (y/N)"
echo "  ─────────────────────────────────────────────────────────"
printf "  Install? [y/N]: "
read -r INSTALL_CHOICE

if [[ "$INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
    echo ""
    echo "  Installing Anthropic SDK (streaming)..."
    if $PYTHON -m pip install anthropic --quiet --break-system-packages 2>/dev/null || \
       $PYTHON -m pip install anthropic --quiet 2>/dev/null; then
        echo "  ✓  anthropic"
    else
        echo "  ⚠  anthropic install failed (optional)"
    fi

    echo "  Installing sentence-transformers (semantic patterns)..."
    if $PYTHON -m pip install sentence-transformers --quiet --break-system-packages 2>/dev/null || \
       $PYTHON -m pip install sentence-transformers --quiet 2>/dev/null; then
        echo "  ✓  sentence-transformers"
    else
        echo "  ⚠  sentence-transformers install failed (optional)"
    fi

    echo "  Installing spaCy (negation detection)..."
    if { $PYTHON -m pip install spacy --quiet --break-system-packages 2>/dev/null || \
         $PYTHON -m pip install spacy --quiet 2>/dev/null; } && \
       $PYTHON -m spacy download en_core_web_sm --quiet 2>/dev/null; then
        echo "  ✓  spacy en_core_web_sm"
    else
        echo "  ⚠  spacy install failed (optional)"
    fi

    echo ""
    echo "  ✓  Enhancement installation complete (failures above are non-critical)"
else
    echo ""
    echo "  Skipping — SynJuris runs fully without these (falls back to v1 behavior)"
fi

# ── 5. Launch ─────────────────────────────────────────────────────────────────
echo ""
echo "  ═══════════════════════════════════════════════════════"
echo "  Starting SynJuris on http://localhost:5000 ..."
echo "  Press Ctrl+C to stop."
echo "  ═══════════════════════════════════════════════════════"
echo ""

$PYTHON "$SCRIPT"

echo ""
echo "  SynJuris stopped. Press Enter to close."
read -r
