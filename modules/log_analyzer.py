from collections import Counter
from pathlib import Path
import re

def analyze_log():
    path = Path(input("Log file path: ").strip())
    if not path.is_file():
        print("Log file not found.")
        return
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    failed = sum(bool(re.search(r"failed|failure|invalid|denied", x, re.I)) for x in lines)
    ips = Counter(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    print("Total lines:", len(lines))
    print("Failure-like lines:", failed)
    print("Top IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {ip}: {count}")
