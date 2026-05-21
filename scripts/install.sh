#!/usr/bin/env bash
# Intruder Detector installation script (Arch Linux / generic systemd)
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
USER_UNIT_DIR="${HOME}/.config/systemd/user"

echo "==> Installing Intruder Detector"
echo "    Project: $PROJECT_ROOT"
echo "    Prefix:  $PREFIX"

# Dependencies check
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v pip3 >/dev/null || command -v pip >/dev/null || { echo "pip required"; exit 1; }

PIP=$(command -v pip3 || command -v pip)
python3 -m venv "$PROJECT_ROOT/.venv" 2>/dev/null || true
if [[ -d "$PROJECT_ROOT/.venv" ]]; then
  source "$PROJECT_ROOT/.venv/bin/activate"
  PIP=pip
fi

echo "==> Installing Python dependencies (this may download InsightFace models)..."
$PIP install -r "$PROJECT_ROOT/requirements.txt"
$PIP install -e "$PROJECT_ROOT"

# Config
mkdir -p "${HOME}/.config/intruder-detector"
if [[ ! -f "${HOME}/.config/intruder-detector/config.yaml" ]]; then
  cp "$PROJECT_ROOT/configs/default.yaml" "${HOME}/.config/intruder-detector/config.yaml"
  echo "    Created ~/.config/intruder-detector/config.yaml"
fi

# Data dir
mkdir -p "${HOME}/.local/share/intruder-detector"
chmod 700 "${HOME}/.local/share/intruder-detector"

# systemd user service
mkdir -p "$USER_UNIT_DIR"
sed "s|/usr/bin/intruder-detector|$PROJECT_ROOT/.venv/bin/intruder-detector|g" \
  "$PROJECT_ROOT/systemd/intruder-detector.service" > "$USER_UNIT_DIR/intruder-detector.service"

# Fallback if no venv
if [[ ! -x "$PROJECT_ROOT/.venv/bin/intruder-detector" ]]; then
  sed "s|$PROJECT_ROOT/.venv/bin/intruder-detector|$(which intruder-detector 2>/dev/null || echo python3 -m main)|g" \
    -i "$USER_UNIT_DIR/intruder-detector.service"
fi

echo ""
echo "==> Installation complete"
echo ""
echo "Next steps:"
echo "  1. Add user to 'video' group:  sudo usermod -aG video \$USER"
echo "  2. Run setup:                 intruder-setup  (or: python $PROJECT_ROOT/intruder_detector/cli/setup.py)"
echo "  3. Unlock vault:              intruder-detector unlock"
echo "  4. Enable daemon:             systemctl --user enable --now intruder-detector"
echo "  5. View history:              intruder-history list"
echo "  6. Dashboard (optional):      python -m dashboard.app"
echo ""
