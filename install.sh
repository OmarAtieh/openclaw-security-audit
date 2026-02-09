#!/bin/bash
# OpenClaw Security Audit Tool - Quick Install Script

set -e

echo "🛡️  OpenClaw Security Audit Tool - Installation"
echo "================================================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

if (( $(echo "$PYTHON_VERSION < $REQUIRED_VERSION" | bc -l) )); then
    echo "❌ Error: Python 3.8+ required, found $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"
echo ""

# Determine install location
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    DATA_DIR="/usr/local/share/openclaw-audit"
    echo "📦 Installing system-wide to $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/.local/bin"
    DATA_DIR="$HOME/.local/share/openclaw-audit"
    echo "📦 Installing for current user to $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
fi

echo ""

# Create data directory
echo "📁 Creating data directory: $DATA_DIR"
mkdir -p "$DATA_DIR"

# Copy files
echo "📋 Copying audit script..."
cp audit.py "$INSTALL_DIR/openclaw-audit"
chmod +x "$INSTALL_DIR/openclaw-audit"

echo "📋 Copying malicious skill database..."
cp known_malicious.json "$DATA_DIR/"

# Update the script to use the data directory
sed -i "s|Path(__file__).parent / \"known_malicious.json\"|Path(\"$DATA_DIR/known_malicious.json\")|g" "$INSTALL_DIR/openclaw-audit"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Usage:"
echo "  openclaw-audit                           # Run basic scan"
echo "  openclaw-audit --output-json report.json # Generate JSON report"
echo "  openclaw-audit --output-md report.md     # Generate Markdown report"
echo "  openclaw-audit --help                    # Show all options"
echo ""

# Check if install dir is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠️  Warning: $INSTALL_DIR is not in your PATH"
    echo ""
    echo "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
fi

echo "📚 Documentation: https://github.com/your-org/openclaw-security-audit"
echo ""
echo "🚀 Ready to scan! Run: openclaw-audit"
