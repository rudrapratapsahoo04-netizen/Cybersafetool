import ipaddress
import socket
from config import ALLOWED_PRIVATE_PREFIXES

def _allowed(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return ip.is_loopback or ip.is_private
        except OSError:
            return False

def network_scan():
    target = input("Enter authorized private/localhost target: ").strip()
    if not _allowed(target):
        print("Blocked: active scans are limited to localhost/private IPv4 targets.")
        return
    print(f"Checking reachability of {target}...")
    try:
        ip = socket.gethostbyname(target)
        with socket.create_connection((ip, 80), timeout=1):
            print(f"{target} responds on TCP/80.")
    except OSError:
        try:
            socket.gethostbyname(target)
            print(f"{target} resolved successfully, but TCP/80 did not respond.")
        except OSError:
            print("Host could not be resolved.")
