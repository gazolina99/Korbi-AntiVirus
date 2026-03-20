# Korbi AntiVirus

Korbi AntiVirus is a local-only, offline-first desktop security app with a modern GUI.
It monitors suspicious activity, scans files using offline heuristics and signatures,
and notifies the user in real time.

## Core principles

- Local only: no cloud backend, no external server required.
- Offline by default: all checks run on-device.
- Transparent alerts: each suspicious event includes reason and severity.
- Cross-platform: targets Windows, Linux, and macOS.

## Features

- Real-time filesystem monitoring on user-selected folders.
- Quick process risk checks (temp execution, obfuscated names, unusual behavior patterns).
- Startup location and persistence risk indicators.
- File hash signature matching against local rules.
- Heuristic scoring engine for unknown suspicious files.
- In-app alert center and risk dashboard.
- File intelligence explorer with extension explanations (hover details).
- Danger meter based on extension, source location, and origin heuristics.
- Email legitimacy checker for pasted email headers/content (SPF/DKIM/DMARC parsing).
- CPU checker, network throughput checker, and live clock panel.

## Project structure

- `app/main.py` - entry point
- `app/gui/main_window.py` - modern Tkinter GUI
- `app/core/scanner.py` - scan engine and heuristics
- `app/core/monitor.py` - real-time monitor and scheduler
- `app/core/signatures.py` - local signature loading and matching
- `app/core/notifier.py` - local notification adapter
- `data/signatures.json` - offline signature database
- `index.html`, `style.css`, `assets/` - marketing + download site (repo root for GitHub Pages)

## GitHub Pages

Enable **Settings → Pages** and set the source to your default branch with folder **/** (root).
The site loads from `index.html` at the repository root. Download links point to `dist/` after you build and commit binaries (or host releases elsewhere and update those links).

## Installation

1. Install Python 3.11+.
2. Create virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run:

```bash
python app/main.py
```

## Build desktop app

Install PyInstaller:

```bash
pip install pyinstaller
```

Then use platform script:

- Windows: `build_windows.bat`
- Linux: `./build_linux.sh`
- macOS: `./build_macos.sh`

## Security notes

- This is an advanced local scanner and monitor, but no software can guarantee 100% detection.
- Keep your operating system updated.
- Never run unknown executables from untrusted sources.
- Always keep offline backups of critical files.
