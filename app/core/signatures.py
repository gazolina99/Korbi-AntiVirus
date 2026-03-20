import json
from pathlib import Path
from typing import Any, Dict


DEFAULT_SIGNATURES = {
    "sha256": [],
    "suspicious_names": [],
    "suspicious_extensions": [],
    "dangerous_keywords": [],
}


def load_signatures(signature_path: Path) -> Dict[str, Any]:
    if not signature_path.exists():
        return DEFAULT_SIGNATURES.copy()

    try:
        with signature_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        merged = DEFAULT_SIGNATURES.copy()
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return DEFAULT_SIGNATURES.copy()
