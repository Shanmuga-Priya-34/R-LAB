"""
Configuration for Exam Lab Monitoring (Detection + Prevention).
Edit to suit your network/environment.
"""

# Network: LAN ranges to treat as internal (CIDR strings)
LAN_RANGES = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12"
]

# Admin/teacher IPs that should never be blocked
WHITELIST_IPS = [
    # "192.168.1.1",
    # "192.168.1.10",  # exam server
]

# Firewall/prevention behavior
PREVENTION = {
    "enabled": True,                   # master switch for prevention
    "block_duration_seconds": 300,     # how long to block a specific offending IP (seconds)
    "block_all_external_on_detection": False,  # if True, block all external traffic when first detection occurs
    "block_local_communication": True, # block LAN-to-LAN student-to-student if detected
    "block_smb_immediately": True,     # block SMB ports when SMB activity detected
    "disable_usb_on_insert": False,    # if True, will disable usb_storage kernel module on detection
}

# Paths for logs and DB (logger.py will create)
LOGS_DIR = "logs"
EVENTS_CSV = f"{LOGS_DIR}/events.csv"
EVENTS_JSON = f"{LOGS_DIR}/events.json"
EVENTS_DB = f"{LOGS_DIR}/events.db"
DAILY_REPORT = f"{LOGS_DIR}/daily_report.txt"

# Network interface default (change to your interface, e.g., enp3s0)
DEFAULT_INTERFACE = "eth0"

# Suspicious ports - mapping for alerts/prevention
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT2",
    9000: "CUSTOM-NC",
}

# How long to keep temporary iptables rules (seconds)
TEMP_RULE_TTL = PREVENTION["block_duration_seconds"]
