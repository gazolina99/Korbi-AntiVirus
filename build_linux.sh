#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install pyinstaller

pyinstaller \
  --noconfirm \
  --windowed \
  --onefile \
  --name "KorbiAntiVirus" \
  --add-data "data:data" \
  app/main.py

mkdir -p dist/linux
cp -f dist/KorbiAntiVirus dist/linux/KorbiAntiVirus

echo "Build complete: dist/linux/KorbiAntiVirus"
