import socket

def dns_check():
    host = input("Domain/hostname: ").strip()
    try:
        print("IPv4:", socket.gethostbyname_ex(host)[2])
        try:
            print("Canonical:", socket.getfqdn(host))
        except Exception:
            pass
    except OSError as exc:
        print("DNS lookup failed:", exc)
