#!/usr/bin/env bash
# Setup script for MITM TV Sync
# Run this on your MacBook to install dependencies and configure the environment.

set -e

echo "=== MITM TV Sync Setup ==="
echo

# Check for Python 3.10+
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3 is required. Install it with: brew install python3"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "ERROR: Python 3.10+ required (found $PY_VERSION)"
    echo "Install with: brew install python@3.12"
    exit 1
fi
echo "Python $PY_VERSION found"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -e .

echo
echo "=== Setup Complete ==="
echo
echo "Usage:"
echo "  source venv/bin/activate"
echo "  sudo mitm-tv --help"
echo
echo "Quick start:"
echo "  1. sudo mitm-tv info                                    # Check network"
echo "  2. sudo mitm-tv sniff -t <TV1_IP>                       # Discover traffic"
echo "  3. sudo mitm-tv learn -t <TV1_IP> -n 'Samsung TV'       # Capture fingerprint"
echo "  4. sudo mitm-tv clone -t <TV2_IP> -s 'Samsung TV'       # Clone identity"
echo
echo "NOTE: Most commands require sudo for network access."
