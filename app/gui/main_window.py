import os
import queue
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

import psutil

from core.email_checker import check_email_legitimacy
from core.file_intel import calculate_file_risk, explain_file_type
from core.monitor import LocalActivityMonitor
from core.notifier import notify_local
from core.scanner import OfflineScanner


class KorbiMainWindow:
    def __init__(self, scanner: OfflineScanner):
        self.scanner = scanner
        self.root = tk.Tk()
        self.root.title("Korbi AntiVirus")
        self.root.geometry("1360x860")
        self.root.configure(bg="#0b1020")
        self.root.minsize(1180, 760)

        self.event_queue: queue.Queue = queue.Queue()
        self.monitor = LocalActivityMonitor(scanner=self.scanner, on_event=self._queue_event)
        self.monitor_started = False
        self._last_net = psutil.net_io_counters()
        self._last_row = None

        self._build_ui()
        self._poll_events()
        self._update_system_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def run(self):
        self.root.mainloop()

    def _build_ui(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Card.TFrame", background="#111a2f")
        style.configure("Title.TLabel", background="#0b1020", foreground="#e8eeff", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#0b1020", foreground="#8ca0d6", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background="#111a2f", foreground="#c7d3ff", font=("Segoe UI", 12, "bold"))
        style.configure("Body.TLabel", background="#111a2f", foreground="#d9e2ff", font=("Segoe UI", 10))
        style.configure("Treeview", background="#0f1730", fieldbackground="#0f1730", foreground="#d8e2ff")
        style.configure("Treeview.Heading", background="#1d2a4d", foreground="#f2f6ff", font=("Segoe UI", 10, "bold"))

        header = ttk.Frame(self.root, style="Card.TFrame")
        header.pack(fill="x", padx=20, pady=(18, 8))
        ttk.Label(header, text="Korbi AntiVirus - Advanced Analyst Mode", style="Title.TLabel").pack(anchor="w", padx=16, pady=(14, 0))
        ttk.Label(
            header,
            text="Offline and serverless: local-only monitoring, file intelligence, and suspicious activity alerts.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", padx=16, pady=(5, 12))

        health = ttk.Frame(self.root, style="Card.TFrame")
        health.pack(fill="x", padx=20, pady=(0, 8))
        ttk.Label(health, text="System Health", style="CardTitle.TLabel").pack(side="left", padx=(12, 8), pady=10)
        self.cpu_label = ttk.Label(health, text="CPU: --%", style="Body.TLabel")
        self.cpu_label.pack(side="left", padx=8)
        self.net_label = ttk.Label(health, text="Network: -- KB/s", style="Body.TLabel")
        self.net_label.pack(side="left", padx=8)
        self.clock_label = ttk.Label(health, text="Clock: --:--:--", style="Body.TLabel")
        self.clock_label.pack(side="right", padx=12)

        top_row = ttk.Frame(self.root, style="Card.TFrame")
        top_row.pack(fill="x", padx=20, pady=8)
        controls = ttk.Frame(top_row, style="Card.TFrame")
        controls.pack(side="left", fill="both", expand=True, padx=(0, 8))
        ttk.Label(controls, text="Actions", style="CardTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        btn_row = ttk.Frame(controls, style="Card.TFrame")
        btn_row.pack(fill="x", padx=12, pady=(0, 10))

        tk.Button(btn_row, text="Start Real-Time Monitor", command=self._start_monitor, bg="#1dd75f", fg="#08111d", relief="flat").pack(side="left", padx=(0, 6))
        tk.Button(btn_row, text="Quick Scan", command=self._quick_scan, bg="#41b8ff", fg="#08111d", relief="flat").pack(side="left", padx=6)
        tk.Button(btn_row, text="Custom Scan", command=self._custom_scan, bg="#ffd34a", fg="#111", relief="flat").pack(side="left", padx=6)
        tk.Button(btn_row, text="Research System Files", command=self._research_files, bg="#a78bfa", fg="#111", relief="flat").pack(side="left", padx=6)
        tk.Button(btn_row, text="Check Email", command=self._open_email_checker, bg="#7ef7c7", fg="#08111d", relief="flat").pack(side="left", padx=6)
        tk.Button(btn_row, text="Stop Monitor", command=self._stop_monitor, bg="#ff6363", fg="#111", relief="flat").pack(side="left", padx=6)

        meter_card = ttk.Frame(top_row, style="Card.TFrame")
        meter_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(meter_card, text="Danger Meter", style="CardTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        self.risk_value = tk.IntVar(value=0)
        self.risk_meter = ttk.Progressbar(meter_card, orient="horizontal", mode="determinate", maximum=100, variable=self.risk_value)
        self.risk_meter.pack(fill="x", padx=12, pady=(0, 6))
        self.risk_label = ttk.Label(meter_card, text="Risk: Low (0/100)", style="Body.TLabel")
        self.risk_label.pack(anchor="w", padx=12, pady=(0, 10))
        self.hover_tip = ttk.Label(meter_card, text="Hover over a file row to see file type meaning.", style="Body.TLabel")
        self.hover_tip.pack(anchor="w", padx=12, pady=(0, 12))

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=(8, 20))

        alerts_tab = ttk.Frame(notebook, style="Card.TFrame")
        intel_tab = ttk.Frame(notebook, style="Card.TFrame")
        notebook.add(alerts_tab, text="Threat Feed")
        notebook.add(intel_tab, text="File Intelligence")

        ttk.Label(alerts_tab, text="Suspicious Activity Feed", style="CardTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        columns = ("time", "type", "severity", "score", "target", "reason")
        self.tree = ttk.Treeview(alerts_tab, columns=columns, show="headings", height=18)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for col, width in [("time", 145), ("type", 95), ("severity", 80), ("score", 70), ("target", 360), ("reason", 440)]:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor="w")

        ttk.Label(intel_tab, text="System File Explorer & Risk", style="CardTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        columns2 = ("name", "type_info", "location", "origin", "risk")
        self.file_tree = ttk.Treeview(intel_tab, columns=columns2, show="headings", height=18)
        self.file_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for col, width in [("name", 290), ("type_info", 330), ("location", 360), ("origin", 170), ("risk", 130)]:
            self.file_tree.heading(col, text=col.upper())
            self.file_tree.column(col, width=width, anchor="w")
        self.file_tree.tag_configure("risk_high", foreground="#ff6e6e")
        self.file_tree.tag_configure("risk_medium", foreground="#ffd36f")
        self.file_tree.tag_configure("risk_low", foreground="#8cf0ac")
        self.file_tree.bind("<Motion>", self._on_file_hover)

    def _start_monitor(self):
        if self.monitor_started:
            return
        paths = LocalActivityMonitor.default_watch_paths()
        self.monitor.start(paths)
        self.monitor_started = True
        self._push_info("monitor", "info", 0, ", ".join([str(p) for p in paths]), "Real-time local monitoring enabled.")

    def _stop_monitor(self):
        if not self.monitor_started:
            return
        self.monitor.stop()
        self.monitor_started = False
        self._push_info("monitor", "info", 0, "Korbi", "Monitoring stopped.")

    def _quick_scan(self):
        target = Path.home() / "Downloads"
        self._scan_background(target)

    def _custom_scan(self):
        selected = filedialog.askdirectory()
        if selected:
            self._scan_background(Path(selected))

    def _scan_background(self, target: Path):
        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()

    def _run_scan(self, target: Path):
        self._push_info("scan", "info", 0, str(target), "Scan started.")
        detections = self.scanner.scan_path(target)
        if not detections:
            self._push_info("scan", "info", 0, str(target), "No suspicious files found.")
            return
        for d in detections:
            self._queue_event({"type": "file", "path": d.path, "severity": d.severity, "score": d.score, "reasons": d.reasons})

    def _research_files(self):
        selected = filedialog.askdirectory(title="Choose directory to research")
        if not selected:
            return
        self._push_info("intel", "info", 0, selected, "File intelligence research started.")
        threading.Thread(target=self._run_file_intel, args=(Path(selected),), daemon=True).start()

    def _run_file_intel(self, root: Path):
        rows = []
        max_files = 1500
        scanned = 0
        for cur_root, _, files in os.walk(root):
            for file_name in files:
                if scanned >= max_files:
                    break
                path = Path(cur_root) / file_name
                type_info = explain_file_type(path)
                risk_score, level, factors = calculate_file_risk(path)
                rows.append(
                    (
                        path.name,
                        type_info,
                        str(path.parent),
                        f"ext={factors.get('extension', 0)},loc={factors.get('location', 0)},orig={factors.get('origin', 0)}",
                        f"{level.upper()} ({risk_score}/100)",
                        level,
                    )
                )
                scanned += 1
            if scanned >= max_files:
                break
        self.root.after(0, lambda: self._render_intel_rows(rows, str(root), scanned))

    def _render_intel_rows(self, rows, root_str: str, scanned: int):
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        for name, type_info, location, origin, risk_text, level in rows:
            tag = "risk_high" if level == "high" else "risk_medium" if level == "medium" else "risk_low"
            self.file_tree.insert("", "end", values=(name, type_info, location, origin, risk_text), tags=(tag,))
        self._push_info("intel", "info", 0, root_str, f"File intelligence completed ({scanned} files).")

    def _on_file_hover(self, event):
        row = self.file_tree.identify_row(event.y)
        if not row or row == self._last_row:
            return
        self._last_row = row
        values = self.file_tree.item(row, "values")
        if not values or len(values) < 5:
            return
        file_name, type_info, location, origin, risk_text = values
        risk_value = 0
        if "(" in risk_text and "/100" in risk_text:
            try:
                risk_value = int(risk_text.split("(")[1].split("/")[0])
            except (ValueError, IndexError):
                risk_value = 0
        self._set_risk_meter(risk_value)
        self.hover_tip.config(text=f"{file_name}: {type_info} | {location} | {origin}")

    def _set_risk_meter(self, risk: int):
        self.risk_value.set(risk)
        level = "High" if risk >= 70 else "Medium" if risk >= 40 else "Low"
        self.risk_label.config(text=f"Risk: {level} ({risk}/100)")

    def _open_email_checker(self):
        win = tk.Toplevel(self.root)
        win.title("Check Email")
        win.geometry("760x440")
        win.configure(bg="#0f1730")
        ttk.Label(win, text="Paste email headers/content to validate legitimacy", style="CardTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        text = tk.Text(win, height=14, bg="#0b1020", fg="#d9e2ff", insertbackground="#d9e2ff", relief="flat")
        text.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        result = ttk.Label(win, text="Result: waiting", style="Body.TLabel")
        result.pack(anchor="w", padx=12, pady=(0, 12))

        def run_check():
            data = text.get("1.0", "end").strip()
            checked = check_email_legitimacy(data)
            result.config(text=f"Result: {checked.verdict.upper()} | Score {checked.score}/100 | {checked.details}")
            self._set_risk_meter(100 - checked.score)
            self._push_info("email", "info", 100 - checked.score, "Email Check", checked.details)

        tk.Button(win, text="Analyze Email", command=run_check, bg="#7ef7c7", fg="#0a1324", relief="flat").pack(anchor="e", padx=12, pady=(0, 12))

    def _update_system_widgets(self):
        cpu = psutil.cpu_percent(interval=None)
        net_now = psutil.net_io_counters()
        down_kbps = max(0, (net_now.bytes_recv - self._last_net.bytes_recv) // 1024)
        up_kbps = max(0, (net_now.bytes_sent - self._last_net.bytes_sent) // 1024)
        self._last_net = net_now

        self.cpu_label.config(text=f"CPU: {cpu:.1f}%")
        self.net_label.config(text=f"Network: Down {down_kbps} KB/s | Up {up_kbps} KB/s")
        self.clock_label.config(text=f"Clock: {datetime.now().strftime('%H:%M:%S')}")
        self.root.after(1000, self._update_system_widgets)

    def _queue_event(self, event):
        self.event_queue.put(event)

    def _poll_events(self):
        while True:
            try:
                event = self.event_queue.get_nowait()
                reason = "; ".join(event.get("reasons", [])) if event.get("reasons") else event.get("trigger", "alert")
                target = event.get("path") or event.get("name") or "unknown"
                score = event.get("score", 0)
                self._insert_feed(event.get("type", "event"), event.get("severity", "medium"), score, target, reason)
                self._set_risk_meter(min(max(int(score), 0), 100))
                if event.get("severity") in {"high", "medium"}:
                    notify_local("Korbi AntiVirus Alert", f"{event.get('severity', 'medium').upper()} risk detected:\n{target}\n{reason}")
            except queue.Empty:
                break
        self.root.after(900, self._poll_events)

    def _push_info(self, ev_type: str, severity: str, score: int, target: str, reason: str):
        self._insert_feed(ev_type, severity, score, target, reason)

    def _insert_feed(self, ev_type: str, severity: str, score: int, target: str, reason: str):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", 0, values=(now, ev_type, severity, score, target, reason))

    def _on_close(self):
        self.monitor.stop()
        self.root.destroy()
