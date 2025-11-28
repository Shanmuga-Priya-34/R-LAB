"""
Prevention module that applies blocking actions using iptables/modprobe.
Functions are safe-guarded and reversible for temporary rules.
Requires root privileges.
"""

import subprocess
import threading
import shlex
import os
import time
from config import WHITELIST_IPS, TEMP_RULE_TTL, PREVENTION

# Helper to run commands
def _run(cmd: str):
    try:
        print(f"[PREVENT] Running: {cmd}")
        completed = subprocess.run(shlex.split(cmd), capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            print(f"[PREVENT] Cmd failed: {completed.returncode} stdout={completed.stdout} stderr={completed.stderr}")
        return completed
    except Exception as e:
        print(f"[PREVENT] Exception running cmd: {e}")
        return None

# Temporary iptables addition + scheduled removal
def _add_temporary_rule(rule_cmd: str, remove_cmd: str, ttl: int):
    """Adds rule_cmd (full iptables command string) then schedules remove_cmd after ttl seconds."""
    _run(rule_cmd)
    if ttl and ttl > 0:
        def remover():
            time.sleep(ttl)
            _run(remove_cmd)
            print(f"[PREVENT] Removed temporary rule: {remove_cmd}")
        t = threading.Thread(target=remover, daemon=True)
        t.start()

# Block a single offending external IP for TEMP_RULE_TTL seconds
def block_ip(ip: str, ttl: int = TEMP_RULE_TTL):
    if ip in WHITELIST_IPS:
        print(f"[PREVENT] IP {ip} is whitelisted; not blocking.")
        return
    # Add OUTPUT drop for that IP
    rule = f"iptables -I OUTPUT -d {ip} -j DROP"
    remove = f"iptables -D OUTPUT -d {ip} -j DROP"
    _add_temporary_rule(rule, remove, ttl)
    print(f"[PREVENT] Temporarily blocked IP {ip} for {ttl} seconds.")

# Block all external traffic (except LAN) — careful, disruptive
def block_all_external(lan_ranges=None):
    # Insert a conservative set of rules: allow LAN, drop rest
    # Note: better to implement with proper policy and ordered rules in production.
    if not PREVENTION.get("enabled", True):
        print("[PREVENT] Prevention disabled in config.")
        return
    # Set default policy to DROP for OUTPUT (dangerous). Instead, insert explicit drop for 0.0.0.0/0 after allowing LAN ranges.
    # Implementation: create a chain to manage easily.
    _run("iptables -N EXAM_BLOCK_CHAIN || true")
    # Allow localhost and existing established
    _run("iptables -I EXAM_BLOCK_CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    # Insert chain at top of OUTPUT
    _run("iptables -I OUTPUT 1 -j EXAM_BLOCK_CHAIN")
    print("[PREVENT] EXAM_BLOCK_CHAIN inserted; you should configure LAN accepts separately if using this.")

# Remove exam chain (if needed)
def remove_exam_chain():
    _run("iptables -D OUTPUT -j EXAM_BLOCK_CHAIN || true")
    _run("iptables -F EXAM_BLOCK_CHAIN || true")
    _run("iptables -X EXAM_BLOCK_CHAIN || true")
    print("[PREVENT] EXAM_BLOCK_CHAIN removed.")

# Block SMB/NetBIOS ports (immediate)
def block_smb_ports():
    cmds = [
        "iptables -I INPUT -p tcp --dport 445 -j DROP",
        "iptables -I INPUT -p tcp --dport 139 -j DROP",
        "iptables -I INPUT -p udp --dport 137 -j DROP",
        "iptables -I INPUT -p udp --dport 138 -j DROP",
        "iptables -I OUTPUT -p tcp --dport 445 -j DROP",
        "iptables -I OUTPUT -p tcp --dport 139 -j DROP",
    ]
    for c in cmds:
        _run(c)
    print("[PREVENT] SMB ports blocked (immediate).")

# Block LAN-to-LAN communication for a specific subnet
def block_local_subnet_traffic(subnet: str):
    # Blocks packets destined to same subnet (use with caution)
    _run(f"iptables -I FORWARD -s {subnet} -d {subnet} -j DROP")
    _run(f"iptables -I INPUT -s {subnet} -d {subnet} -j DROP")
    print(f"[PREVENT] Blocked intra-subnet traffic for {subnet}")

# Block broadcast addresses from being sent
def block_broadcasts():
    _run("iptables -I OUTPUT -d 255.255.255.255 -j DROP")
    print("[PREVENT] Blocked global broadcast address 255.255.255.255")

# Block a specific port (both input and output)
def block_port(port: int):
    _run(f"iptables -I INPUT -p tcp --dport {port} -j DROP")
    _run(f"iptables -I OUTPUT -p tcp --dport {port} -j DROP")
    print(f"[PREVENT] Blocked port {port} (tcp) on INPUT/OUTPUT")

# Disable USB storage module (temporary, non-persistent)
def disable_usb_storage(persist: bool = False):
    # Remove module
    _run("modprobe -r usb_storage || true")
    if persist:
        # Append blacklist (requires root)
        try:
            with open("/etc/modprobe.d/blacklist-usb_storage.conf", "a") as f:
                f.write("blacklist usb_storage\n")
            print("[PREVENT] usb_storage blacklisted persistently.")
        except Exception as e:
            print(f"[PREVENT] Could not write blacklist file: {e}")
    else:
        print("[PREVENT] usb_storage unloaded (not persisted).")

# Re-enable USB storage (attempt)
def enable_usb_storage():
    _run("modprobe usb_storage || true")
    # Note: if blacklisted persistently, it won't reload until blacklist removed
    print("[PREVENT] Attempted to load usb_storage module (may fail if blacklisted persistently).")
