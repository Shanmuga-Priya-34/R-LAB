"""
Drive & mount monitoring using journalctl tails.
Detects mount/unmount events, CIFS/SMB mounts, NFS, and triggers prevention for SMB.
"""

import subprocess
import time
import re
from logger import log_event
from config import PREVENTION
import prevent

def monitor_journalctl():
    print("[DRIVE] Starting journalctl follow")
    # Tail system journal, watching for udev/mount messages
    p = subprocess.Popen(["journalctl", "-f", "-o", "short"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        line = p.stdout.readline()
        if line is None:
            time.sleep(0.1)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            # look for mount keywords, cifs, nfs, smb
            if re.search(r"\bmount\b", line, re.IGNORECASE) or re.search(r"\bCIFS\b", line, re.IGNORECASE) \
               or re.search(r"\bNFS\b", line, re.IGNORECASE) or re.search(r"\bSMB\b", line, re.IGNORECASE) \
               or re.search(r"\bmount\(", line, re.IGNORECASE) or re.search(r"cifs|nfs|smb|mount", line, re.IGNORECASE):
                log_event("DRIVE_EVENT", line[:400])
                # If SMB detected, trigger prevention
                if PREVENTION.get("enabled", True) and PREVENTION.get("block_smb_immediately", True):
                    prevent.block_smb_ports()
                    log_event("PREVENTION", "SMB ports blocked due to drive events")
        except Exception as e:
            print(f"[DRIVE] parse error: {e}")

def start_monitoring():
    while True:
        try:
            monitor_journalctl()
        except Exception as e:
            print(f"[DRIVE] Monitor crashed: {e}. Restarting in 5s")
            time.sleep(5)

if __name__ == "__main__":
    start_monitoring()
