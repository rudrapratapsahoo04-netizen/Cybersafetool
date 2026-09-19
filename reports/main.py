"""
CYBERSECURITY TOOLKIT v1.0
Single-file educational defensive security toolkit.

Features:
01 Network Scanner
02 Port Scanner
03 URL Analyzer
04 Phishing URL Detector
05 Hash Generator
06 File Integrity Monitor
07 Log Analyzer
08 DNS Security Checker
09 SSL/TLS Checker
10 PCAP Analyzer
11 Threat Intelligence
12 Phishing Awareness Simulator
13 Security Report Generator
00 Exit

This version is intentionally self-contained and uses Python's standard library.
No external package is required.
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# COLORS
# ============================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def enable_windows_ansi():
    """Enable ANSI colors on modern Windows terminals when possible."""
    if os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass


enable_windows_ansi()


# ============================================================
# COMMON HELPERS
# ============================================================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input(f"\n{C.CYAN}Press ENTER to return to the main menu...{C.RESET}")


def header(title):
    print()
    print(C.CYAN + "═" * 58 + C.RESET)
    print(C.BOLD + C.YELLOW + f"  {title}" + C.RESET)
    print(C.CYAN + "═" * 58 + C.RESET)
    print()


def safe_input(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""
    except KeyboardInterrupt:
        print()
        return ""


def print_error(message):
    print(f"{C.RED}[ERROR]{C.RESET} {message}")


def print_ok(message):
    print(f"{C.GREEN}[+]{C.RESET} {message}")


def print_warn(message):
    print(f"{C.YELLOW}[!]{C.RESET} {message}")


def print_info(message):
    print(f"{C.CYAN}[*]{C.RESET} {message}")


# ============================================================
# BANNER / MENU
# ============================================================

def show_banner():
    print()
    print(C.CYAN + "╔" + "═" * 58 + "╗")
    print(C.CYAN + "║" + C.YELLOW +
          "              CYBERSECURITY TOOLKIT              " +
          C.CYAN + "║")
    print(C.CYAN + "║" + C.GREEN +
          "                       v1.0                       " +
          C.CYAN + "║")
    print(C.CYAN + "║" + " " * 58 + "║")
    print(C.CYAN + "║" + C.MAGENTA +
          "           Tool Developed by Rudrapratap Sahoo            " +
          C.CYAN + "║")
    print(C.CYAN + "╚" + "═" * 58 + "╝")
    print()


def show_menu():
    items = [
        ("01", "Network Scanner", C.GREEN),
        ("02", "Port Scanner", C.GREEN),
        ("03", "URL Analyzer", C.GREEN),
        ("04", "Phishing URL Detector", C.YELLOW),
        ("05", "Hash Generator", C.GREEN),
        ("06", "File Integrity Monitor", C.GREEN),
        ("07", "Log Analyzer", C.GREEN),
        ("08", "DNS Security Checker", C.GREEN),
        ("09", "SSL/TLS Checker", C.GREEN),
        ("10", "PCAP Analyzer", C.GREEN),
        ("11", "Threat Intelligence", C.GREEN),
        ("12", "Phishing Awareness Simulator", C.MAGENTA),
        ("13", "Security Report Generator", C.CYAN),
    ]

    width = 58
    print(C.BLUE + "┌" + "─" * width + "┐")
    title = "SECURITY TOOLS"
    print(C.BLUE + "│" + C.YELLOW + title.center(width) + C.BLUE + "│")
    print(C.BLUE + "├" + "─" * width + "┤")

    for number, name, color in items:
        text = f"  [{number}] {name}"
        print(C.BLUE + "│" + color + text.ljust(width) + C.BLUE + "│")

    print(C.BLUE + "├" + "─" * width + "┤")
    text = "  [00] Exit"
    print(C.BLUE + "│" + C.RED + text.ljust(width) + C.BLUE + "│")
    print(C.BLUE + "└" + "─" * width + "┘")
    print()


# ============================================================
# 01 NETWORK SCANNER
# ============================================================

def network_scan():
    header("NETWORK SCANNER")

    target = safe_input("Enter hostname or IP: ")
    if not target:
        print_warn("No target entered.")
        return

    try:
        hostname = socket.gethostbyname_ex(target)
        print(f"{C.CYAN}Hostname :{C.RESET} {hostname[0]}")
        print(f"{C.CYAN}Aliases  :{C.RESET} {', '.join(hostname[1]) or 'None'}")
        print(f"{C.CYAN}Addresses:{C.RESET}")

        for addr in sorted(set(hostname[2])):
            try:
                reverse = socket.gethostbyaddr(addr)[0]
            except Exception:
                reverse = "Reverse lookup unavailable"
            print(f"  {C.GREEN}{addr}{C.RESET} -> {reverse}")

    except socket.gaierror:
        print_error("Could not resolve the hostname/IP.")
    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 02 PORT SCANNER
# ============================================================

def port_scan():
    header("PORT SCANNER")

    target = safe_input("Enter hostname/IP (use only systems you own or are authorized to test): ")
    if not target:
        print_warn("No target entered.")
        return

    start_text = safe_input("Start port [1]: ")
    end_text = safe_input("End port [1024]: ")

    try:
        start = int(start_text or "1")
        end = int(end_text or "1024")
    except ValueError:
        print_error("Ports must be numbers.")
        return

    if start < 1 or end > 65535 or start > end:
        print_error("Port range must be between 1 and 65535.")
        return

    if end - start > 2000:
        print_error("For safety, this tool limits a scan to 2000 ports at a time.")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_error("Could not resolve target.")
        return

    print_info(f"Target: {target} ({target_ip})")
    print_info(f"Scanning TCP ports {start}-{end} ...")

    common = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-alt",
    }

    opened = []

    for port in range(start, end + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = common.get(port, "Unknown")
                opened.append((port, service))
                print(f"{C.GREEN}[OPEN]{C.RESET} {port:5d}  {service}")
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

    if not opened:
        print_warn("No open TCP ports found in the selected range.")
    else:
        print_ok(f"Found {len(opened)} open port(s).")


# ============================================================
# 03 URL ANALYZER
# ============================================================

def normalize_url(url):
    if not re.match(r"^https?://", url, re.I):
        return "https://" + url
    return url


def analyze_url():
    header("URL ANALYZER")

    url = safe_input("Enter URL: ")
    if not url:
        print_warn("No URL entered.")
        return

    url = normalize_url(url)
    parsed = urlparse(url)

    print(f"{C.CYAN}Scheme    :{C.RESET} {parsed.scheme or 'None'}")
    print(f"{C.CYAN}Hostname  :{C.RESET} {parsed.hostname or 'None'}")
    print(f"{C.CYAN}Port      :{C.RESET} {parsed.port or 'Default'}")
    print(f"{C.CYAN}Path      :{C.RESET} {parsed.path or '/'}")
    print(f"{C.CYAN}Query     :{C.RESET} {parsed.query or 'None'}")
    print(f"{C.CYAN}Fragment  :{C.RESET} {parsed.fragment or 'None'}")
    print(f"{C.CYAN}Length    :{C.RESET} {len(url)} characters")

    if parsed.scheme == "https":
        print_ok("HTTPS scheme detected.")
    else:
        print_warn("URL is not using HTTPS.")


# ============================================================
# 04 PHISHING URL DETECTOR
# ============================================================

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account",
    "update", "password", "wallet", "banking", "signin",
    "confirm", "urgent", "free", "bonus", "credential"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"
}


def score_url(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    score = 0
    findings = []

    if parsed.scheme != "https":
        score += 15
        findings.append("HTTPS is not used")

    if len(url) > 100:
        score += 15
        findings.append("Very long URL")

    if "@" in url:
        score += 20
        findings.append("@ symbol can obscure the destination")

    if host and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 25
        findings.append("Hostname is an IP address")

    if host in SHORTENERS:
        score += 20
        findings.append("URL shortening service detected")

    if host.count(".") >= 3:
        score += 10
        findings.append("Many hostname levels")

    if host.startswith("xn--") or ".xn--" in host:
        score += 15
        findings.append("Punycode hostname detected")

    if url.count("-") >= 3:
        score += 10
        findings.append("Many hyphens")

    words = set(re.findall(r"[a-zA-Z]{3,}", url.lower()))
    hits = sorted(words & SUSPICIOUS_WORDS)

    if hits:
        score += min(20, 5 * len(hits))
        findings.append("Suspicious keywords: " + ", ".join(hits))

    score = min(score, 100)

    if score < 31:
        level = "LOW"
    elif score < 61:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "url": url,
        "score": score,
        "level": level,
        "findings": findings,
    }


def detect_phishing():
    header("PHISHING URL DETECTOR")

    url = safe_input("URL to analyze: ")
    if not url:
        print_warn("No URL entered.")
        return

    try:
        result = score_url(url)

        print(f"Analyzed URL : {result['url']}")
        print(f"Risk score   : {result['score']}/100")

        if result["level"] == "LOW":
            color = C.GREEN
        elif result["level"] == "MEDIUM":
            color = C.YELLOW
        else:
            color = C.RED

        print(f"Risk level   : {color}{result['level']}{C.RESET}")

        if result["findings"]:
            print("\nFindings:")
            for item in result["findings"]:
                print(f"{C.YELLOW}[!]{C.RESET} {item}")
        else:
            print_ok("No obvious heuristic indicators found.")

        print(
            f"\n{C.DIM}Note: heuristic detection is not proof that a URL "
            f"is safe or malicious.{C.RESET}"
        )

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 05 HASH GENERATOR
# ============================================================

def generate_hash():
    header("HASH GENERATOR")

    path_text = safe_input("Enter file path: ")
    if not path_text:
        print_warn("No file path entered.")
        return

    path = Path(path_text)

    if not path.is_file():
        print_error("File does not exist.")
        return

    algorithms = ["md5", "sha1", "sha256", "sha512"]

    try:
        data = path.read_bytes()

        print(f"\n{C.CYAN}File:{C.RESET} {path}")
        print(f"{C.CYAN}Size:{C.RESET} {len(data)} bytes\n")

        for name in algorithms:
            digest = hashlib.new(name, data).hexdigest()
            print(f"{name.upper():8} : {digest}")

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 06 FILE INTEGRITY MONITOR
# ============================================================

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def integrity_menu():
    header("FILE INTEGRITY MONITOR")

    print("1. Create baseline")
    print("2. Compare with baseline")

    choice = safe_input("\nSelect: ")

    path_text = safe_input("Enter file path: ")
    if not path_text:
        print_warn("No file path entered.")
        return

    path = Path(path_text)

    if not path.is_file():
        print_error("File does not exist.")
        return

    baseline_path = path.with_name(path.name + ".sha256")

    try:
        current = file_hash(path)

        if choice == "1":
            baseline_path.write_text(current, encoding="utf-8")
            print_ok(f"Baseline saved: {baseline_path}")

        elif choice == "2":
            if not baseline_path.is_file():
                print_error("Baseline not found. Create one first.")
                return

            saved = baseline_path.read_text(encoding="utf-8").strip()

            if saved == current:
                print_ok("File integrity verified. No change detected.")
            else:
                print_warn("File has changed since the baseline was created.")

        else:
            print_warn("Invalid option.")

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 07 LOG ANALYZER
# ============================================================

def analyze_log():
    header("LOG ANALYZER")

    path_text = safe_input("Enter log file path: ")
    if not path_text:
        print_warn("No file path entered.")
        return

    path = Path(path_text)

    if not path.is_file():
        print_error("Log file does not exist.")
        return

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        error_count = len(re.findall(r"\b(error|critical|fatal)\b", text, re.I))
        warning_count = len(re.findall(r"\b(warn|warning)\b", text, re.I))
        failed_count = len(re.findall(r"\b(failed|failure|denied)\b", text, re.I))

        print(f"Total lines       : {len(lines)}")
        print(f"Error/Critical    : {error_count}")
        print(f"Warnings          : {warning_count}")
        print(f"Failed/Denied     : {failed_count}")

        print("\nRecent suspicious lines:")

        suspicious = []
        patterns = re.compile(
            r"error|critical|fatal|failed|failure|denied|unauthorized|attack",
            re.I,
        )

        for line in lines:
            if patterns.search(line):
                suspicious.append(line.strip())

        if not suspicious:
            print_ok("No matching suspicious keywords found.")
        else:
            for line in suspicious[-10:]:
                print(f"{C.YELLOW}[!] {line}{C.RESET}")

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 08 DNS SECURITY CHECKER
# ============================================================

def dns_check():
    header("DNS SECURITY CHECKER")

    domain = safe_input("Enter domain: ").lower()

    if not domain:
        print_warn("No domain entered.")
        return

    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]

    try:
        addresses = socket.getaddrinfo(domain, None)
        ips = sorted({item[4][0] for item in addresses})

        print(f"{C.CYAN}Domain:{C.RESET} {domain}")
        print(f"{C.CYAN}Resolved addresses:{C.RESET}")

        for ip in ips:
            print(f"  {C.GREEN}{ip}{C.RESET}")

        try:
            cname = socket.getfqdn(domain)
            print(f"{C.CYAN}Resolved name:{C.RESET} {cname}")
        except Exception:
            pass

        print_warn(
            "This checker performs basic DNS resolution only; "
            "it does not prove that DNS is secure."
        )

    except socket.gaierror:
        print_error("DNS resolution failed.")
    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 09 SSL/TLS CHECKER
# ============================================================

def ssl_check():
    header("SSL/TLS CHECKER")

    hostname = safe_input("Enter hostname (example.com): ")

    if not hostname:
        print_warn("No hostname entered.")
        return

    hostname = re.sub(r"^https?://", "", hostname).split("/")[0]

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:

                version = secure_sock.version()
                cipher = secure_sock.cipher()
                certificate = secure_sock.getpeercert()

                print_ok("TLS connection established.")
                print(f"TLS version : {version}")
                print(f"Cipher      : {cipher[0] if cipher else 'Unknown'}")

                subject = certificate.get("subject", ())
                issuer = certificate.get("issuer", ())

                print(f"Certificate subject : {subject}")
                print(f"Certificate issuer  : {issuer}")

    except Exception as exc:
        print_error(f"TLS check failed: {exc}")


# ============================================================
# 10 PCAP ANALYZER
# ============================================================

def analyze_pcap():
    header("PCAP ANALYZER")

    path_text = safe_input("Enter .pcap file path: ")
    if not path_text:
        print_warn("No file path entered.")
        return

    path = Path(path_text)

    if not path.is_file():
        print_error("PCAP file does not exist.")
        return

    try:
        with path.open("rb") as f:
            header_data = f.read(24)

        if len(header_data) < 24:
            print_error("File is too small to be a valid PCAP.")
            return

        magic = header_data[:4]

        magic_names = {
            b"\xd4\xc3\xb2\xa1": ("PCAP", "little-endian"),
            b"\xa1\xb2\xc3\xd4": ("PCAP", "big-endian"),
            b"\x4d\x3c\xb2\xa1": ("PCAP", "nanosecond little-endian"),
            b"\xa1\xb2\x3c\x4d": ("PCAP", "nanosecond big-endian"),
        }

        if magic not in magic_names:
            print_warn(
                "Unknown PCAP magic number. "
                "This may be PCAP-NG or another format."
            )
            return

        fmt, endian = magic_names[magic]

        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            order = "<"
        else:
            order = ">"

        version_major, version_minor, tz, sigfigs, snaplen, network = struct.unpack(
            order + "HHIIII", header_data[4:24]
        )

        print(f"Format       : {fmt}")
        print(f"Byte order   : {endian}")
        print(f"Version      : {version_major}.{version_minor}")
        print(f"Snap length  : {snaplen}")
        print(f"Link type    : {network}")

        packet_count = 0

        with path.open("rb") as f:
            f.seek(24)

            while True:
                packet_header = f.read(16)

                if len(packet_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    order + "IIII", packet_header
                )

                f.seek(incl_len, os.SEEK_CUR)
                packet_count += 1

                if packet_count > 100000:
                    break

        print(f"Packets      : {packet_count}")

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# 11 THREAT INTELLIGENCE
# ============================================================

def threat_lookup():
    header("THREAT INTELLIGENCE")

    value = safe_input("Enter IP address or domain: ")

    if not value:
        print_warn("No value entered.")
        return

    value = value.strip()

    try:
        ipaddress.ip_address(value)
        target_type = "IP address"
    except ValueError:
        if re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}",
            value,
        ):
            target_type = "Domain"
        else:
            print_error("Enter a valid IP address or domain.")
            return

    print(f"{C.CYAN}Type  :{C.RESET} {target_type}")
    print(f"{C.CYAN}Value :{C.RESET} {value}")

    if target_type == "IP address":
        try:
            host = socket.gethostbyaddr(value)
            print(f"{C.CYAN}Reverse DNS:{C.RESET} {host[0]}")
        except Exception:
            print_warn("No reverse DNS hostname was found.")
    else:
        try:
            addresses = socket.getaddrinfo(value, None)
            ips = sorted({x[4][0] for x in addresses})
            print(f"{C.CYAN}Resolved IPs:{C.RESET}")
            for ip in ips:
                print(f"  {ip}")
        except Exception:
            print_warn("DNS resolution failed.")

    print_warn(
        "This offline module does not query a live threat-intelligence "
        "database, so it does not label the target malicious or safe."
    )


# ============================================================
# 12 PHISHING AWARENESS SIMULATOR
# ============================================================

def run_simulation():
    header("PHISHING AWARENESS SIMULATOR")

    print("This is an educational quiz. No real messages or credentials are used.\n")

    questions = [
        {
            "question": "A message asks you to click a link urgently to verify your bank account. What should you do?",
            "options": [
                "A. Click immediately",
                "B. Verify through the bank's official app/site",
                "C. Reply with your password",
                "D. Forward your OTP",
            ],
            "answer": "B",
        },
        {
            "question": "A website address contains a misspelled company name. What is a good response?",
            "options": [
                "A. Enter your password",
                "B. Ignore the spelling",
                "C. Treat it as suspicious and verify the real domain",
                "D. Enter your OTP first",
            ],
            "answer": "C",
        },
        {
            "question": "Someone asks for your one-time password over chat. What should you do?",
            "options": [
                "A. Share it",
                "B. Post it publicly",
                "C. Do not share it",
                "D. Send it after checking their profile",
            ],
            "answer": "C",
        },
    ]

    score = 0

    for number, q in enumerate(questions, 1):
        print(f"{C.YELLOW}Question {number}:{C.RESET} {q['question']}")

        for option in q["options"]:
            print("  " + option)

        answer = safe_input("Answer: ").upper()

        if answer == q["answer"]:
            print_ok("Correct!")
            score += 1
        else:
            print_warn(f"Incorrect. Correct answer: {q['answer']}")

        print()

    print(f"{C.CYAN}Awareness score: {score}/{len(questions)}{C.RESET}")
    print_warn("This simulator is for security awareness education only.")


# ============================================================
# 13 SECURITY REPORT GENERATOR
# ============================================================

def save_report():
    header("SECURITY REPORT GENERATOR")

    report = {
        "toolkit": "Cybersecurity Toolkit",
        "version": "1.0",
        "created_by": "Rudrapratap",
        "generated_at": datetime.now().astimezone().isoformat(),
        "checks": [],
    }

    print("1. Add a URL analysis result")
    print("2. Add a phishing URL analysis result")
    print("3. Create a basic report")

    choice = safe_input("\nSelect: ")

    if choice == "1":
        url = safe_input("Enter URL: ")

        if not url:
            print_warn("No URL entered.")
            return

        normalized = normalize_url(url)
        parsed = urlparse(normalized)

        report["checks"].append({
            "type": "URL Analysis",
            "url": normalized,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "path": parsed.path,
        })

    elif choice == "2":
        url = safe_input("Enter URL: ")

        if not url:
            print_warn("No URL entered.")
            return

        result = score_url(url)

        report["checks"].append({
            "type": "Phishing URL Heuristic",
            "url": result["url"],
            "risk_score": result["score"],
            "risk_level": result["level"],
            "findings": result["findings"],
        })

    elif choice == "3":
        report["checks"].append({
            "type": "Basic Security Report",
            "status": "No automated finding was added.",
        })

    else:
        print_warn("Invalid option.")
        return

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    filename = reports_dir / (
        "security_report_" +
        datetime.now().strftime("%Y%m%d_%H%M%S") +
        ".json"
    )

    try:
        filename.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8",
        )

        print_ok(f"Report saved: {filename}")

    except Exception as exc:
        print_error(str(exc))


# ============================================================
# MAIN
# ============================================================

TOOLS = {
    "1": network_scan,
    "01": network_scan,
    "2": port_scan,
    "02": port_scan,
    "3": analyze_url,
    "03": analyze_url,
    "4": detect_phishing,
    "04": detect_phishing,
    "5": generate_hash,
    "05": generate_hash,
    "6": integrity_menu,
    "06": integrity_menu,
    "7": analyze_log,
    "07": analyze_log,
    "8": dns_check,
    "08": dns_check,
    "9": ssl_check,
    "09": ssl_check,
    "10": analyze_pcap,
    "11": threat_lookup,
    "12": run_simulation,
    "13": save_report,
}


def main():
    while True:
        clear_screen()
        show_banner()
        show_menu()

        choice = safe_input(
            C.YELLOW + "  Select option: " + C.WHITE
        ).lower()

        if choice in ("0", "00", "exit", "quit"):
            print()
            print(C.GREEN + "╔" + "═" * 58 + "╗")
            print(C.GREEN + "║" + "     Thank you for using Cybersecurity Toolkit!     " + "║")
            print(C.GREEN + "║" + "                  Stay Secure!                      " + "║")
            print(C.GREEN + "╚" + "═" * 58 + "╝" + C.RESET)
            print()
            break

        tool = TOOLS.get(choice)

        if tool is None:
            print_error("Invalid option. Choose 01-13 or 00.")
            time.sleep(1.5)
            continue

        clear_screen()

        try:
            tool()
        except KeyboardInterrupt:
            print()
            print_warn("Operation cancelled by user.")
        except Exception as exc:
            print_error(str(exc))

        pause()


if __name__ == "__main__":
    main()
