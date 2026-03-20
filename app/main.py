from pathlib import Path

from core.scanner import OfflineScanner
from core.signatures import load_signatures
from gui.main_window import KorbiMainWindow


def main():
    project_root = Path(__file__).resolve().parent.parent
    signature_path = project_root / "data" / "signatures.json"
    signatures = load_signatures(signature_path)

    scanner = OfflineScanner(signatures)
    app = KorbiMainWindow(scanner)
    app.run()


if __name__ == "__main__":
    main()
