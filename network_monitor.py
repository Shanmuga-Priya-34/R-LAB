"""
Advanced Network Monitor (Detection + Prevention triggers).
Listens to IP packets and logs/acts on:
- OUTBOUND_EXTERNAL
- INBOUND_EXTERNAL
- LAN_COMMUNICATION
- BROADCAST_TRAFFIC
- SUSPICIOUS_PORT
"""

import time
import ipaddress
from scapy.all import sniff, IP, TCP, UDP
from logger import log_event
from config import LAN_RANGES, DEFAULT_INTERFACE, SUSPICIOUS_PORTS, PREVENTION
import prevent  # prevention actions
import socket

def is_lan_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for lan in LAN_RANGES:
            if ip_obj in ipaddress.ip_network(lan, strict=False):
                return True
        return False
    except Exception:
        return False

def is_broadcast(ip: str) -> bool:
    return ip.endswith(".255") or ip == "255.255.255.255"

def get_proto(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    return "OTHER"

def check_ports(packet):
    try:
        sport = dport = None
        if TCP in packet:
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif UDP in packet:
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        for port, name in SUSPICIOUS_PORTS.items():
            if sport == port or dport == port:
                return port, name
    except Exception:
        pass
    return None, None

def packet_callback(packet):
    if IP not in packet:
        return
    src = packet[IP].src
    dst = packet[IP].dst
    proto = get_proto(packet)
    port, port_name = check_ports(packet)

    # Outbound external
    if is_lan_ip(src) and not is_lan_ip(dst):
        details = f"{src} -> {dst} [{proto}]"
        log_event("OUTBOUND_EXTERNAL", details)
        if PREVENTION.get("enabled", True):
            # either block specific dst IP or block all external if configured
            if PREVENTION.get("block_all_external_on_detection", False):
                prevent.block_all_external()
                log_event("PREVENTION", "block_all_external triggered")
            else:
                prevent.block_ip(dst, ttl=PREVENTION.get("block_duration_seconds", 300))
                log_event("PREVENTION", f"blocked external ip {dst} temporarily")

    # Inbound external (rare)
    if not is_lan_ip(src) and is_lan_ip(dst):
        details = f"{src} -> {dst} [{proto}]"
        log_event("INBOUND_EXTERNAL", details)
        if PREVENTION.get("enabled", True):
            prevent.block_ip(src, ttl=PREVENTION.get("block_duration_seconds", 300))
            log_event("PREVENTION", f"blocked inbound sender {src} temporarily")

    # LAN to LAN
    if is_lan_ip(src) and is_lan_ip(dst):
        details = f"{src} -> {dst} [{proto}]"
        log_event("LAN_COMMUNICATION", details)
        if PREVENTION.get("enabled", True) and PREVENTION.get("block_local_communication", True):
            # Block traffic between these two IPs for TTL
            prevent.block_ip(dst, ttl=PREVENTION.get("block_duration_seconds", 300))
            log_event("PREVENTION", f"blocked intra-lan destination {dst} temporarily")

    # Broadcast detection
    if is_broadcast(dst):
        details = f"{src} -> {dst} [{proto}]"
        log_event("BROADCAST_TRAFFIC", details)
        if PREVENTION.get("enabled", True):
            prevent.block_broadcasts()
            log_event("PREVENTION", "blocked broadcasts (global 255.255.255.255)")

    # Suspicious ports
    if port is not None:
        details = f"{src} -> {dst} proto={proto} port={port} ({port_name})"
        log_event("SUSPICIOUS_PORT", details)
        if PREVENTION.get("enabled", True):
            # block that port
            prevent.block_port(port)
            log_event("PREVENTION", f"blocked port {port} ({port_name})")

def start_monitoring(interface: str = DEFAULT_INTERFACE):
    print(f"[Network] Starting on interface {interface}")
    try:
        sniff(iface=interface, prn=packet_callback, filter="ip", store=False)
    except Exception as e:
        print(f"[Network] Sniffer error: {e}; retrying in 5s")
        time.sleep(5)
        start_monitoring(interface)

if __name__ == "__main__":
    start_monitoring()
