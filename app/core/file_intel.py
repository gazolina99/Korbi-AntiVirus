from pathlib import Path
from typing import Dict, Tuple


FILE_TYPE_MEANINGS = {
    ".log": "Log file. Stores events or app/system messages.",
    ".txt": "Plain text document.",
    ".json": "Structured data/configuration file.",
    ".xml": "Markup data file often used by configs/apps.",
    ".ini": "Initialization/configuration file.",
    ".yaml": "Configuration file used in many tools.",
    ".yml": "Configuration file used in many tools.",
    ".exe": "Windows executable program.",
    ".dll": "Dynamic library used by programs.",
    ".sys": "System-level driver or OS component.",
    ".ps1": "PowerShell script file.",
    ".bat": "Batch command script.",
    ".cmd": "Windows command script.",
    ".vbs": "VBScript automation script.",
    ".js": "JavaScript file (can be script or web asset).",
    ".zip": "Compressed archive.",
    ".rar": "Compressed archive.",
    ".7z": "Compressed archive.",
    ".msi": "Windows installer package.",
    ".pdf": "Portable document format.",
    ".docx": "Microsoft Word document.",
    ".xlsx": "Microsoft Excel spreadsheet.",
    ".pptx": "Microsoft PowerPoint presentation.",
}


def explain_file_type(path: Path) -> str:
    ext = path.suffix.lower()
    if not ext:
        return "Unknown extension. Could be data, executable, or custom format."
    return FILE_TYPE_MEANINGS.get(ext, f"{ext} file type. Behavior depends on the application using it.")


def calculate_file_risk(path: Path) -> Tuple[int, str, Dict[str, int]]:
    score = 0
    factors: Dict[str, int] = {}
    ext = path.suffix.lower()
    lower_path = str(path).lower()

    high_risk_ext = {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".pif", ".hta"}
    medium_risk_ext = {".zip", ".rar", ".7z", ".docm", ".xlsm"}

    if ext in high_risk_ext:
        factors["extension"] = 35
        score += 35
    elif ext in medium_risk_ext:
        factors["extension"] = 15
        score += 15
    else:
        factors["extension"] = 4
        score += 4

    location_score = 0
    if any(token in lower_path for token in ["\\downloads\\", "/downloads/"]):
        location_score += 20
    if any(token in lower_path for token in ["\\temp\\", "/tmp/", "\\appdata\\local\\temp\\"]):
        location_score += 25
    if any(token in lower_path for token in ["\\startup\\", "/autostart/"]):
        location_score += 20
    if any(token in lower_path for token in ["\\windows\\system32\\", "/system/"]):
        location_score += 12

    factors["location"] = location_score
    score += location_score

    origin_score = 0
    if "download" in path.parent.name.lower():
        origin_score += 12
    if path.name.count(".") >= 2:
        origin_score += 18
    factors["origin"] = origin_score
    score += origin_score

    score = min(score, 100)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return score, level, factors
