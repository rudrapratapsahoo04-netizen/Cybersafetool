import ipaddress
import socket

def _allowed(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            return ip.is_loopback or ip.is_private
        except OSError:
            return False

def port_scan():
    host = input("Authorized localhost/private target: ").strip()
    if not _allowed(host):
        print("Blocked: only localhost/private targets are allowed.")
        return

    try:
        start = int(input("Start port (1-1024): "))
        end = int(input("End port (1-1024): "))
    except ValueError:
        print("Ports must be numbers.")
        return

    if not (1 <= start <= end <= 1024):
        print("Use a range from 1 to 1024.")
        return

    ip = socket.gethostbyname(host)
    print(f"Scanning {ip}...")
    found = []
    for port in range(start, end + 1):
        sock = socket.socket()
        sock.settimeout(0.15)
        try:
            if sock.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                found.append((port, service))
                print(f"[OPEN] {port} - {service}")
        finally:
            sock.close()
    print(f"Done. Open ports found: {len(found)}")
