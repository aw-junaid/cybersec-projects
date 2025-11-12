#!/usr/bin/env python3
"""
Benign Rootkit Simulator (sandbox-only)
- Create hidden files/processes in a controlled environment
- Demonstrate hiding and cleanup
- For educational lab use ONLY
"""

import os
import json
import time
import tempfile
import threading
from pathlib import Path

# Config
SANDBOX_ENV = "ROOTKIT_SANDBOX"
LOG_FILE = "rk_log.json"

def safety_check():
    if os.environ.get(SANDBOX_ENV) != "1":
        print("[!] ROOTKIT_SANDBOX env not set. Abort for safety.")
        exit(1)

def create_hidden_file(sandbox_dir, name, content=""):
    hidden_path = Path(sandbox_dir) / f".rk_hidden_{name}"
    with open(hidden_path, "w") as f:
        f.write(content)
    print(f"[+] Hidden file created: {hidden_path}")
    return str(hidden_path)

def fake_process(name, duration=10):
    """Simulate a hidden process using thread"""
    print(f"[+] Starting fake process: {name}")
    time.sleep(duration)
    print(f"[+] Fake process {name} finished")

def log_action(sandbox_dir, action, artifact):
    log_path = Path(sandbox_dir) / LOG_FILE
    entry = {"action": action, "artifact": artifact, "ts": time.time()}
    logs = []
    if log_path.exists():
        with open(log_path, "r") as f:
            logs = json.load(f)
    logs.append(entry)
    with open(log_path, "w") as f:
        json.dump(logs, f, indent=2)

def run_simulation(sandbox_dir):
    # Hidden files
    hidden1 = create_hidden_file(sandbox_dir, "file1.txt", "Secret data")
    hidden2 = create_hidden_file(sandbox_dir, "file2.log", "Simulated log")
    log_action(sandbox_dir, "create_file", hidden1)
    log_action(sandbox_dir, "create_file", hidden2)

    # Fake processes
    t1 = threading.Thread(target=fake_process, args=("proc1",5))
    t2 = threading.Thread(target=fake_process, args=("proc2",7))
    t1.start()
    t2.start()
    log_action(sandbox_dir, "start_process", "proc1")
    log_action(sandbox_dir, "start_process", "proc2")
    t1.join()
    t2.join()

def cleanup(sandbox_dir):
    print("[*] Cleaning up sandbox artifacts...")
    for p in Path(sandbox_dir).glob(".rk_hidden_*"):
        p.unlink()
        print(f"[-] Removed hidden file: {p}")
    log_path = Path(sandbox_dir) / LOG_FILE
    if log_path.exists():
        log_path.unlink()
        print(f"[-] Removed log file: {log_path}")

def main():
    safety_check()
    sandbox_dir = input("Enter sandbox dir (must exist): ").strip()
    if not Path(sandbox_dir).exists():
        print("[!] Sandbox directory does not exist.")
        exit(1)
    choice = input("Run simulation or cleanup? (run/cleanup): ").strip().lower()
    if choice == "run":
        run_simulation(sandbox_dir)
    elif choice == "cleanup":
        cleanup(sandbox_dir)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
