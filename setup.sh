#!/usr/bin/env bash
set -e
# A-ZGuard Installer
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 -m venv "$PROJECT_DIR/venv"
source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$PROJECT_DIR/requirements.txt"
dos2unix "$PROJECT_DIR"/*.py
dos2unix "$PROJECT_DIR"/templates/*.html
# Install systemd units
sudo cp "$PROJECT_DIR"/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "Installation complete. Enable services with:"
echo "  sudo systemctl enable a-zguard-web.service a-zguard-scanner.service"
echo "  sudo systemctl start a-zguard-web.service a-zguard-scanner.service"
