import socket
import ssl
from datetime import datetime

def ssl_check():
    host = input("Authorized hostname: ").strip()
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                print("TLS version:", sock.version())
                print("Cipher:", sock.cipher())
                print("Subject:", cert.get("subject"))
                print("Issuer:", cert.get("issuer"))
                print("Valid from:", cert.get("notBefore"))
                print("Valid until:", cert.get("notAfter"))
    except Exception as exc:
        print("TLS check failed:", exc)
