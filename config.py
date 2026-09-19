APP_NAME = "Cybersecurity Toolkit"
VERSION = "1.0"
AUTHOR = "Rudrapratap"

# Safety boundary for active network checks:
# Only localhost and private IPv4 addresses are accepted.
ALLOWED_PRIVATE_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)
MAX_PORTS = 1024
REPORT_DIR = "reports"
LOG_DIR = "logs"
