#!/usr/bin/env bash
set -euo pipefail

USERNAME="zainab1022"
APP_ROOT="/home/${USERNAME}/mysite"
APP_DIR="${APP_ROOT}/fixed_asset_register"
VENV_NAME="mysite"

echo "[1/5] Preparing app directory"
mkdir -p "${APP_ROOT}"
cd "${APP_ROOT}"

echo "[2/5] Unzipping project bundle"
if [[ -f "/home/${USERNAME}/assettrack-pro.zip" ]]; then
  unzip -o "/home/${USERNAME}/assettrack-pro.zip"
elif [[ -f "${APP_ROOT}/assettrack-pro.zip" ]]; then
  unzip -o "${APP_ROOT}/assettrack-pro.zip"
else
  echo "ERROR: assettrack-pro.zip not found in /home/${USERNAME} or ${APP_ROOT}"
  exit 1
fi

echo "[3/5] Creating/using virtualenv"
if [[ ! -d "/home/${USERNAME}/.virtualenvs/${VENV_NAME}" ]]; then
  mkvirtualenv --python=/usr/bin/python3.9 "${VENV_NAME}"
else
  workon "${VENV_NAME}"
fi

echo "[4/5] Installing dependencies"
pip install -r "${APP_DIR}/requirements.txt"

echo "[5/5] Setting permissions"
mkdir -p "${APP_DIR}/instance"
chmod 755 "${APP_DIR}"
chmod 755 "${APP_DIR}/instance"
if [[ -f "${APP_DIR}/instance/assets.db" ]]; then
  chmod 664 "${APP_DIR}/instance/assets.db"
fi

echo "Done. Next in PythonAnywhere Web tab:"
echo "- Virtualenv: /home/${USERNAME}/.virtualenvs/${VENV_NAME}"
echo "- Static map: /static/ -> ${APP_DIR}/static"
echo "- WSGI file: use pythonanywhere_wsgi_zainab1022.py content"
echo "- Reload web app"
