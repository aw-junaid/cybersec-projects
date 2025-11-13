#!/usr/bin/env python3
"""
arp_monitor.py — defensive ARP observer.

Requirements:
  - Python 3.8+
  - scapy  (install: pip install scapy)
Run as root (Linux/macOS) because packet capture requires elevated privileges.

What it does:
  - Sniffs ARP packets on the chosen interface (default: auto).
  - Maintains recent mappings IP -> set(MACs) with timestamps.
  - Alerts when an IP is observed with a different MAC within a short window.
  - Logs events to stdout and optional file.
"""

import argparse
import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, ARP, conf

# Configuration defaults
DEFAULT_WINDOW_SECONDS = 300   # keep records for 5 minutes
ANOMALY_THRESHOLD = 1         # number of distinct alternate MACs to trigger alert

class ARPMonitor:
    def __init__(self, iface=None, window_seconds=DEFAULT_WINDOW_SECONDS, logfile=None):
        self.iface = iface
        self.window = window_seconds
        # observed[ip] = deque of (mac, timestamp)
        self.observed = defaultdict(deque)
        self.lock = threading.Lock()
        self.logfile = logfile
        if logfile:
            self.log_f = open(logfile, "a", buffering=1)
        else:
            self.log_f = None

    def log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{ts}] {msg}"
        print(line)
        if self.log_f:
            self.log_f.write(line + "\n")

    def cleanup_task(self):
        while True:
            time.sleep(max(1, self.window // 5))
            cutoff = time.time() - self.window
            with self.lock:
                removed = 0
                for ip, dq in list(self.observed.items()):
                    # pop left while too old
                    while dq and dq[0][1] < cutoff:
                        dq.popleft()
                        removed += 1
                    if not dq:
                        del self.observed[ip]
                if removed:
                    self.log(f"Cleanup removed {removed} old records.")

    def on_arp(self, pkt):
        if not pkt.haslayer(ARP):
            return
        a = pkt[ARP]
        is_reply = (a.op == 2)
        ip = a.psrc  # protocol source address (sender IP)
        mac = a.hwsrc.lower()
        ts = time.time()

        with self.lock:
            dq = self.observed[ip]
            # append current observation (we store duplicates too, will dedupe when checking)
            dq.append((mac, ts))
            # drop older than window
            cutoff = ts - self.window
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            # check distinct MAC set in window
            distinct_macs = {m for (m, t) in dq}
            if len(distinct_macs) > 1:
                # anomaly detected
                self.log(f"ALERT: IP {ip} observed with multiple MACs within {self.window}s: {sorted(distinct_macs)}")
            else:
                # For verbosity: log new mapping events
                if len(dq) == 1:  # first observation
                    tag = "REPLY" if is_reply else "REQUEST"
                    self.log(f"Info: {tag} - {ip} -> {mac}")

    def start(self):
        # start cleanup thread
        t = threading.Thread(target=self.cleanup_task, daemon=True)
        t.start()
        self.log(f"Starting ARP sniff on iface={self.iface or 'auto'} (window={self.window}s). Press Ctrl-C to stop.")
        # sniff ARP packets only
        sniff(filter="arp", prn=self.on_arp, store=False, iface=self.iface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Defensive ARP monitor (read-only).")
    parser.add_argument("-i", "--interface", help="interface to listen on (default: scapy's conf.iface)", default=None)
    parser.add_argument("-w", "--window", help="time window in seconds to consider (default 300)", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("-l", "--logfile", help="append log to file", default=None)
    args = parser.parse_args()

    if args.interface is None:
        iface = conf.iface  # scapy default
    else:
        iface = args.interface

    monitor = ARPMonitor(iface=iface, window_seconds=args.window, logfile=args.logfile)
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nStopped by user.")
