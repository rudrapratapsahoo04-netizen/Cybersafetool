import hashlib
from pathlib import Path

def generate_hash():
    path = input("File path: ").strip()
    p = Path(path)
    if not p.is_file():
        print("File not found.")
        return
    data = p.read_bytes()
    print("SHA-256:", hashlib.sha256(data).hexdigest())
    print("SHA-512:", hashlib.sha512(data).hexdigest())
