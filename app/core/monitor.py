import os
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .scanner import OfflineScanner


class SuspiciousEventHandler(FileSystemEventHandler):
    def __init__(self, scanner: OfflineScanner, output_queue: queue.Queue):
        super().__init__()
        self.scanner = scanner
        self.output_queue = output_queue

    def on_created(self, event):
        if event.is_directory:
            return
        self._analyze(Path(event.src_path), "New file created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._analyze(Path(event.src_path), "File modified")

    def _analyze(self, path: Path, trigger: str):
        detection = self.scanner.scan_file(path)
        if detection:
            payload = {
                "type": "file",
                "trigger": trigger,
                "path": detection.path,
                "severity": detection.severity,
                "score": detection.score,
                "reasons": detection.reasons,
            }
            self.output_queue.put(payload)


class LocalActivityMonitor:
    def __init__(self, scanner: OfflineScanner, on_event: Callable[[Dict], None]):
        self.scanner = scanner
        self.on_event = on_event
        self._queue: queue.Queue = queue.Queue()
        self._observer: Optional[Observer] = None
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._process_thread: Optional[threading.Thread] = None

    def start(self, watch_paths: List[Path]):
        if self._running:
            return
        self._running = True

        handler = SuspiciousEventHandler(self.scanner, self._queue)
        self._observer = Observer()
        for path in watch_paths:
            if path.exists() and path.is_dir():
                self._observer.schedule(handler, str(path), recursive=True)
        self._observer.start()

        self._monitor_thread = threading.Thread(target=self._drain_events, daemon=True)
        self._monitor_thread.start()

        self._process_thread = threading.Thread(target=self._process_watchdog, daemon=True)
        self._process_thread.start()

    def stop(self):
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None

    def _drain_events(self):
        while self._running:
            try:
                event = self._queue.get(timeout=1)
                self.on_event(event)
            except queue.Empty:
                continue

    def _process_watchdog(self):
        while self._running:
            self._scan_processes()
            time.sleep(10)

    def _scan_processes(self):
        suspicious = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent"]):
            try:
                info = proc.info
                exe = (info.get("exe") or "").lower()
                name = (info.get("name") or "").lower()
                cmdline = " ".join(info.get("cmdline") or []).lower()
                reasons = []
                score = 0

                if any(token in exe for token in ["/tmp/", "\\temp\\", "\\appdata\\local\\temp\\"]):
                    reasons.append("Process launched from temporary path.")
                    score += 30
                if "powershell -enc" in cmdline or "frombase64string" in cmdline:
                    reasons.append("Potentially obfuscated command execution.")
                    score += 35
                if name in {"svchost32.exe", "winupdter.exe", "chrome_update_service.exe"}:
                    reasons.append("Suspicious process name masquerading as system software.")
                    score += 35
                if (info.get("cpu_percent") or 0) > 85:
                    reasons.append("Unusually high CPU usage pattern.")
                    score += 10

                if score >= 35:
                    suspicious.append(
                        {
                            "type": "process",
                            "pid": info.get("pid"),
                            "name": info.get("name"),
                            "path": info.get("exe"),
                            "severity": "high" if score >= 70 else "medium",
                            "score": score,
                            "reasons": reasons,
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for event in suspicious:
            self.on_event(event)

    @staticmethod
    def default_watch_paths() -> List[Path]:
        home = Path.home()
        paths = [home / "Downloads", home / "Desktop", home / "Documents"]

        if os.name == "nt":
            appdata = Path(os.environ.get("APPDATA", ""))
            if appdata.exists():
                paths.append(appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")

        return [p for p in paths if p.exists()]
