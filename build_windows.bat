@echo off
setlocal

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller

pyinstaller ^
  --noconfirm ^
  --windowed ^
  --onefile ^
  --name "KorbiAntiVirus" ^
  --add-data "data;data" ^
  app\main.py

if not exist dist\windows mkdir dist\windows
copy /Y dist\KorbiAntiVirus.exe dist\windows\KorbiAntiVirus.exe

echo Build complete: dist\windows\KorbiAntiVirus.exe
