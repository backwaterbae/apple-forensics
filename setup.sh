#!/bin/bash
# Setup script for X DM Deleter Tool - Selenium Version

set -e

echo "======================================================================"
echo "Twitter/X DM Conversation Deletion Tool - Selenium Version - Setup"
echo "======================================================================"
echo ""

# Check Python version
echo "[1/5] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✓ Python 3 found: $PYTHON_VERSION"
else
    echo "✗ Python 3 not found. Please install Python 3.7 or higher."
    exit 1
fi

# Check pip
echo ""
echo "[2/5] Checking pip..."
if command -v pip3 &> /dev/null; then
    echo "✓ pip3 found"
else
    echo "✗ pip3 not found. Please install pip3."
    exit 1
fi

# Install dependencies
echo ""
echo "[3/5] Installing Python dependencies..."
pip3 install -r requirements.txt
echo "✓ Dependencies installed"

# Check for Chrome/Chromium
echo ""
echo "[4/5] Checking for Chrome/Chromium..."
if command -v google-chrome &> /dev/null || command -v chromium &> /dev/null || command -v chromium-browser &> /dev/null; then
    echo "✓ Chrome/Chromium found"
else
    echo "⚠️  Chrome/Chromium not found"
    echo ""
    echo "Please install Chrome or Chromium:"
    echo "  macOS:       brew install --cask google-chrome"
    echo "  Kali Linux:  sudo apt-get install chromium chromium-driver"
    echo "  Ubuntu:      sudo apt install chromium-browser chromium-chromedriver"
    echo "  Or download: https://www.google.com/chrome/"
    echo ""
fi

# Check for chromedriver
echo ""
echo "Checking for chromedriver..."
if command -v chromedriver &> /dev/null; then
    echo "✓ chromedriver found"
else
    echo "⚠️  chromedriver not found"
    echo ""
    echo "Please install chromedriver:"
    echo "  macOS:       brew install chromedriver"
    echo "  Kali Linux:  sudo apt-get install chromium-driver"
    echo "  Ubuntu:      sudo apt install chromium-chromedriver"
    echo ""
fi

# Setup config
echo ""
echo "[5/5] Setting up configuration..."
if [ ! -f config_dm.json ]; then
    cp config_dm.example.json config_dm.json
    echo "✓ Created config_dm.json from template"
    echo ""
    echo "⚠  IMPORTANT: Edit config_dm.json with your X/Twitter credentials"
    echo ""
    echo "⚠️  SECURITY WARNING:"
    echo "   • Never share config_dm.json (contains your password!)"
    echo "   • This file is in .gitignore for your protection"
    echo "   • Use a strong, unique password"
else
    echo "⚠  config_dm.json already exists, skipping..."
fi

# Create logs directory
mkdir -p logs
echo "✓ Created logs directory"

# Make script executable
chmod +x dm_deleter_selenium.py
echo "✓ Made dm_deleter_selenium.py executable"

echo ""
echo "======================================================================"
echo "Setup Complete!"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "1. Edit config_dm.json with your X username & password"
echo "2. Run: python3 dm_deleter_selenium.py          (dry run)"
echo "3. Watch the browser automate (keep visible first time!)"
echo "4. Run: python3 dm_deleter_selenium.py --execute (actual deletion)"
echo ""
echo "⚠️  IMPORTANT NOTE:"
echo "  • X deletes ENTIRE CONVERSATIONS, not individual messages"
echo "  • This cannot be undone"
echo ""
echo "For detailed usage, see QUICKSTART.md and README.md"
echo ""
