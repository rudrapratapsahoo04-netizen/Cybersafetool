import hashlib
import json
from pathlib import Path

BASELINE = Path("logs/integrity_baseline.json")

def _hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def integrity_menu():
    path = Path(input("File to monitor: ").strip())
    if not path.is_file():
        print("File not found.")
        return
    action = input("[1] Create baseline  [2] Check baseline: ").strip()

    BASELINE.parent.mkdir(exist_ok=True)
    current = _hash(path)

    if action == "1":
        BASELINE.write_text(json.dumps({"file": str(path.resolve()), "sha256": current}, indent=2))
        print("Baseline saved.")
    elif action == "2":
        if not BASELINE.exists():
            print("No baseline exists.")
            return
        old = json.loads(BASELINE.read_text())
        if old.get("file") != str(path.resolve()):
            print("Baseline belongs to another file.")
        elif old.get("sha256") == current:
            print("[OK] File unchanged.")
        else:
            print("[ALERT] File hash changed.")
    else:
        print("Invalid option.")
