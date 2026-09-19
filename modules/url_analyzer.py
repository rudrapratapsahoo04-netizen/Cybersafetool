from urllib.parse import urlparse
import re

def analyze_url():
    url = input("URL: ").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    print("\nURL Analysis")
    print("-" * 40)
    print("Scheme :", p.scheme)
    print("Host   :", p.hostname)
    print("Port   :", p.port or ("443" if p.scheme == "https" else "80"))
    print("Path   :", p.path or "/")
    print("Length :", len(url))
    print("HTTPS  :", "Yes" if p.scheme == "https" else "No")
    print("Has @  :", "Yes" if "@" in url else "No")
    print("Has IP :", bool(p.hostname and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", p.hostname)))
