"""
USB monitor (pyudev). Detection + optional prevention of USB storage.
When a USB block device is added, logs and (optionally) disables usb_storage.
"""

import pyudev
import time
from logger import log_event
from config import PREVENTION
import prevent

def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')
    print("[USB] Monitoring started")
    for device in iter(monitor.poll, None):
        try:
            action = device.action  # 'add' or 'remove'
            if action not in ("add", "remove"):
                continue
            devnode = device.get("DEVNAME") or device.device_node or "unknown"
            vendor = device.get("ID_VENDOR") or device.get("ID_VENDOR_FROM_DATABASE") or "unknown"
            model = device.get("ID_MODEL") or device.get("ID_MODEL_FROM_DATABASE") or "unknown"
            details = f"action={action} dev={devnode} vendor={vendor} model={model}"
            if action == "add":
                log_event("USB_INSERT", details)
                if PREVENTION.get("enabled", True) and PREVENTION.get("disable_usb_on_insert", False):
                    prevent.disable_usb_storage(persist=False)
                    log_event("PREVENTION", "usb_storage module removed (temporary)")
            else:
                log_event("USB_REMOVE", details)
        except Exception as e:
            print(f"[USB] Error: {e}")

def start_monitoring():
    while True:
        try:
            monitor_usb()
        except Exception as e:
            print(f"[USB] Monitor crashed: {e}. Restarting in 5s")
            time.sleep(5)

if __name__ == "__main__":
    start_monitoring()
