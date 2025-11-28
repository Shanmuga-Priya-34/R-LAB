"""
Main orchestrator: starts network, usb and drive monitors in parallel.
Ensures prevention module is available and optionally runs daily reporter.
Run as root (sudo).
"""

import signal
import sys
import time
from multiprocessing import Process
import network_monitor
import usb_monitor
import drive_monitor
from report_generator import generate_daily_report
from config import DEFAULT_INTERFACE

processes = []

def start_all():
    # Start monitors as separate processes
    net_proc = Process(target=network_monitor.start_monitoring, args=(DEFAULT_INTERFACE,), daemon=True)
    usb_proc = Process(target=usb_monitor.start_monitoring, daemon=True)
    drive_proc = Process(target=drive_monitor.start_monitoring, daemon=True)

    procs = [net_proc, usb_proc, drive_proc]
    for p in procs:
        p.start()
        processes.append(p)

    print("[MAIN] All monitors started.")

    # Run daily report generation loop (non-blocking main)
    try:
        while True:
            # generate daily report at UTC midnight: simple sleep loop; for demo, generate every 24h
            time.sleep(86400)
            generate_daily_report()
    except KeyboardInterrupt:
        print("[MAIN] KeyboardInterrupt received. Shutting down...")
        shutdown()

def shutdown():
    print("[MAIN] Terminating child processes...")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(0)

if __name__ == "__main__":
    start_all()
