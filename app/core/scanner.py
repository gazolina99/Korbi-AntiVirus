import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


MAX_FILE_BYTES = 8 * 1024 * 1024
TEXT_SCAN_BYTES = 16 * 1024


@dataclass
class Detection:
    path: str
    severity: str
    score: int
    reasons: List[str]


class OfflineScanner:
    def __init__(self, signatures: Dict):
        self.signatures = signatures

    def scan_path(self, target_path: Path) -> List[Detection]:
        detections: List[Detection] = []
        if target_path.is_file():
            result = self.scan_file(target_path)
            if result:
                detections.append(result)
            return detections

        for root, _, files in os.walk(target_path):
            for name in files:
                file_path = Path(root) / name
                result = self.scan_file(file_path)
                if result:
                    detections.append(result)
        return detections

    def scan_file(self, file_path: Path):
        if not file_path.exists() or not file_path.is_file():
            return None

        reasons: List[str] = []
        score = 0
        lower_name = file_path.name.lower()
        ext = file_path.suffix.lower()

        if lower_name in [n.lower() for n in self.signatures.get("suspicious_names", [])]:
            reasons.append("Known suspicious filename pattern.")
            score += 40

        if ext in [e.lower() for e in self.signatures.get("suspicious_extensions", [])]:
            reasons.append(f"High-risk file extension: {ext}")
            score += 20

        if self._is_hidden_executable(file_path):
            reasons.append("Double-extension or hidden executable behavior.")
            score += 20

        if file_path.stat().st_size <= MAX_FILE_BYTES:
            file_hash = self._sha256(file_path)
            if file_hash and file_hash.lower() in [h.lower() for h in self.signatures.get("sha256", [])]:
                reasons.append("Hash match with local malware signature database.")
                score += 100

        content_hits = self._scan_text_content(file_path)
        if content_hits:
            reasons.append(f"Contains suspicious commands: {', '.join(content_hits[:3])}")
            score += min(40, 10 * len(content_hits))

        if score < 30:
            return None

        severity = "high" if score >= 80 else "medium" if score >= 50 else "low"
        return Detection(path=str(file_path), severity=severity, score=score, reasons=reasons)

    @staticmethod
    def _is_hidden_executable(path: Path) -> bool:
        name = path.name.lower()
        executable_exts = [".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".app", ".sh"]
        if any(name.endswith(ext) for ext in executable_exts) and "." in name[:-4]:
            chunks = name.split(".")
            if len(chunks) >= 3:
                return True
        return False

    def _scan_text_content(self, path: Path) -> List[str]:
        hits = []
        try:
            with path.open("rb") as f:
                content = f.read(TEXT_SCAN_BYTES)
            text = content.decode("utf-8", errors="ignore").lower()
            for keyword in self.signatures.get("dangerous_keywords", []):
                if keyword.lower() in text:
                    hits.append(keyword)
        except OSError:
            return hits
        return hits

    @staticmethod
    def _sha256(path: Path):
        try:
            digest = hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None
