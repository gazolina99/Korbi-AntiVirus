#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install pyinstaller

pyinstaller \
  --noconfirm \
  --windowed \
  --name "KorbiAntiVirus" \
  --add-data "data:data" \
  app/main.py

mkdir -p dist/macos
cp -R dist/KorbiAntiVirus.app dist/macos/KorbiAntiVirus.app

echo "Build complete: dist/macos/KorbiAntiVirus.app"
