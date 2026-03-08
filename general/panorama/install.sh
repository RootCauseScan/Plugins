#!/bin/bash
# Installation script for panorama plugin.
# Creates venv, installs Python deps, Syft + Grype (bin/), and plugin_wrapper.sh.

set -e

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PLUGIN_DIR"

echo "Installing panorama plugin dependencies..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

VENV_PIP="./venv/bin/pip"
echo "Upgrading pip..."
$VENV_PIP install --upgrade pip

echo "Installing Python dependencies from requirements.txt..."
$VENV_PIP install -r requirements.txt

# --- Syft + Grype + Trivy: download to bin/ only if not already in PATH or ./bin ---
mkdir -p bin

_need_syft() {
    command -v syft >/dev/null 2>&1 || [ -x "$PLUGIN_DIR/bin/syft" ]
}
_need_grype() {
    command -v grype >/dev/null 2>&1 || [ -x "$PLUGIN_DIR/bin/grype" ]
}
_need_trivy() {
    command -v trivy >/dev/null 2>&1 || [ -x "$PLUGIN_DIR/bin/trivy" ]
}

if _need_syft; then
    echo "Syft already available (PATH or ./bin), skipping install."
else
    echo "Installing Syft to ./bin/..."
    if curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$PLUGIN_DIR/bin" 2>/dev/null; then
        chmod +x bin/syft 2>/dev/null || true
        [ -x "./bin/syft" ] && echo "  Syft installed at ./bin/syft"
    else
        echo "  Warning: Syft install failed. Download from https://github.com/anchore/syft/releases and put syft in ./bin/"
    fi
fi

if _need_grype; then
    echo "Grype already available (PATH or ./bin), skipping install."
else
    echo "Installing Grype to ./bin/..."
    if curl -sSfL https://get.anchore.io/grype | sh -s -- -b "$PLUGIN_DIR/bin" 2>/dev/null; then
        chmod +x bin/grype 2>/dev/null || true
        [ -x "./bin/grype" ] && echo "  Grype installed at ./bin/grype"
    else
        echo "  Warning: Grype install failed. Download from https://github.com/anchore/grype/releases and put grype in ./bin/"
    fi
fi

if _need_trivy; then
    echo "Trivy already available (PATH or ./bin), skipping install."
else
    echo "Installing Trivy to ./bin/..."
    if curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$PLUGIN_DIR/bin" 2>/dev/null; then
        chmod +x bin/trivy 2>/dev/null || true
        [ -x "./bin/trivy" ] && echo "  Trivy installed at ./bin/trivy"
    else
        echo "  Warning: Trivy install failed. Download from https://github.com/aquasecurity/trivy/releases and put trivy in ./bin/"
    fi
fi

# Create plugin wrapper
echo "Creating plugin wrapper..."
cat > plugin_wrapper.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
exec ./venv/bin/python plugin.py "$@"
EOF
chmod +x plugin_wrapper.sh

echo "Installation completed."
echo "Plugin: ./plugin_wrapper.sh"
echo "Deps: Syft + Grype. Infra: Trivy (all in ./bin/). Run ./install.sh if any is missing."
