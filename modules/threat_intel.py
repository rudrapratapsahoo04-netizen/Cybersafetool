import hashlib
from pathlib import Path

def threat_lookup():
    print("Local threat-intelligence helper")
    print("Enter a file to calculate a SHA-256 hash.")
    path = Path(input("File path: ").strip())
    if not path.is_file():
        print("File not found.")
        return
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    print("SHA-256:", h)
    print("Use this hash with a trusted threat-intelligence service manually.")
    print("This V1 does not upload your files.")
