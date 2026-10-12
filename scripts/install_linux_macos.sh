#!/usr/bin/env bash
# ==============================================================================
# BHARYDANGEROUS-Investigator — Linux & macOS Installer Script
# Created by Ashim for the Cybersecurity Community
# ==============================================================================
set -euo pipefail

echo "========================================================================"
echo "Installing BHARYDANGEROUS-Investigator"
echo "A modular, production-grade digital forensics & incident response CLI."
echo "========================================================================"

# Step 1: Check Python Version (3.11+)
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed or not in PATH."
    echo "    Please install Python 3.11 or newer (e.g. 'sudo apt install python3 python3-venv' or 'brew install python@3.11')."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    echo "[-] Error: Detected Python $PY_VERSION. BHARYDANGEROUS-Investigator requires Python 3.11+."
    exit 1
fi
echo "[+] Detected Python $PY_VERSION (Compatible)."

# Step 2: Create isolated virtual environment
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating isolated virtual environment in '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
else
    echo "[+] Virtual environment '$VENV_DIR' already exists."
fi

# Step 3: Upgrade pip and install package
echo "[*] Installing dependencies into virtual environment (non-root)..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install -e ".[all]"

# Step 4: Verify installation
echo "[*] Running environment diagnostics..."
"$VENV_DIR/bin/python" scripts/verify_environment.py

echo "========================================================================"
echo "[+] BHARYDANGEROUS-Investigator installation complete!"
echo ""
echo "To activate the environment in your shell:"
echo "    source .venv/bin/activate"
echo ""
echo "Then launch the tool:"
echo "    bdinvestigator --help"
echo "    bdinvestigator doctor"
echo "========================================================================"
