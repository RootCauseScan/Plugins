#!/bin/bash
# Installation script for infralyzer plugin.
# Creates venv, installs dependencies from requirements.txt, and plugin_wrapper.sh.

set -e

echo "Installing infralyzer plugin dependencies..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

VENV_PIP="./venv/bin/pip"
VENV_PYTHON="./venv/bin/python"

echo "Upgrading pip..."
$VENV_PIP install --upgrade pip

echo "Installing dependencies from requirements.txt..."
$VENV_PIP install -r requirements.txt

echo "Creating plugin wrapper..."
cat > plugin_wrapper.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
exec ./venv/bin/python plugin.py "$@"
EOF

chmod +x plugin_wrapper.sh

echo "Installation completed successfully!"
echo "Plugin can be run using: ./plugin_wrapper.sh"
